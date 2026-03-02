#!/usr/bin/env python3
"""
SOAP Request Sender - A generic, high-performance tool for sending templated SOAP requests
"""

import sys
import os
import argparse
import logging
import time
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from string import Template
from queue import Queue, Empty
from threading import Thread, Lock, Event
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class Config:
    """Configuration for SOAP sender"""
    input_file: str
    template_file: str
    endpoints: List[str]
    host: str = "127.0.0.1:2222"
    username: Optional[str] = None
    password: Optional[str] = None
    num_threads: int = 20
    burst_rate: int = 50
    queue_size: int = 10000
    batch_size: int = 100
    timeout: int = 60
    max_retries: int = 3
    retry_backoff: int = 60
    rate_limit_error: str = "<error>That ASP is currently operating at its max rate (tx/sec)</error>"
    csv_delimiter: str = ","
    log_level: str = "INFO"
    error_file: Optional[str] = None
    success_file: Optional[str] = None


@dataclass
class Stats:
    """Thread-safe statistics tracking"""
    success: int = 0
    errors: int = 0
    retries: int = 0
    rate_limited: int = 0
    _lock: Lock = field(default_factory=Lock, repr=False)
    
    def increment(self, metric: str, amount: int = 1):
        """Thread-safe increment"""
        with self._lock:
            setattr(self, metric, getattr(self, metric) + amount)
    
    def get_all(self) -> Dict[str, int]:
        """Get all stats as dictionary"""
        with self._lock:
            return {
                'success': self.success,
                'errors': self.errors,
                'retries': self.retries,
                'rate_limited': self.rate_limited
            }


class TemplateParser:
    """Handles XML template parsing and substitution"""
    
    def __init__(self, template_content: str):
        self.template = template_content.strip()
        self.has_repeat = '<!--Repeat-->' in self.template
        self._parse_template()
    
    def _parse_template(self):
        """Parse template into repeatable and non-repeatable sections"""
        if not self.has_repeat:
            self.sections = [(self.template, False)]
            return
        
        self.sections = []
        parts = self.template.split('<!--Repeat-->')
        
        # Add non-repeatable prefix
        if parts[0]:
            self.sections.append((parts[0], False))
        
        # Parse repeatable section
        if len(parts) > 1:
            repeat_parts = parts[1].split('<!--End repeat-->')
            if len(repeat_parts) == 2:
                self.sections.append((repeat_parts[0], True))
                if repeat_parts[1]:
                    self.sections.append((repeat_parts[1], False))
    
    def substitute(self, data: List[str]) -> str:
        """Substitute placeholders with data values"""
        if not self.has_repeat:
            return self._simple_substitute(data)
        return self._complex_substitute(data)
    
    def _simple_substitute(self, data: List[str]) -> str:
        """Simple placeholder replacement"""
        result = self.template
        for value in data:
            result = result.replace('$', str(value), 1)
        
        # Check if all placeholders were replaced
        if '$' in result:
            raise ValueError(f"Not enough data values. Expected {result.count('$') + len(data)}, got {len(data)}")
        
        return result
    
    def _complex_substitute(self, data: List[str]) -> str:
        """Complex substitution with repeatable sections"""
        result = []
        data_ptr = 0
        
        for section, is_repeatable in self.sections:
            num_placeholders = section.count('$')
            
            if num_placeholders == 0:
                result.append(section)
                continue
            
            if not is_repeatable:
                # Non-repeatable section
                if data_ptr + num_placeholders > len(data):
                    raise ValueError(f"Insufficient data for non-repeatable section")
                
                section_result = section
                for _ in range(num_placeholders):
                    section_result = section_result.replace('$', str(data[data_ptr]), 1)
                    data_ptr += 1
                result.append(section_result)
            else:
                # Repeatable section
                remaining_data = len(data) - data_ptr
                if remaining_data % num_placeholders != 0:
                    raise ValueError(
                        f"Data count mismatch for repeatable section. "
                        f"Expected multiple of {num_placeholders}, got {remaining_data}"
                    )
                
                # Repeat section for remaining data
                while data_ptr < len(data):
                    section_result = section
                    for _ in range(num_placeholders):
                        section_result = section_result.replace('$', str(data[data_ptr]), 1)
                        data_ptr += 1
                    result.append(section_result)
        
        return ''.join(result)


class SOAPSender:
    """Main SOAP sender with connection pooling and rate limiting"""
    
    def __init__(self, config: Config):
        self.config = config
        self.stats = Stats()
        self.logger = self._setup_logging()
        self.template_parser = self._load_template()
        self.stop_event = Event()
        self.error_file = None
        self.success_file = None
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging"""
        logging.basicConfig(
            level=getattr(logging, self.config.log_level.upper()),
            format='%(asctime)s - %(threadName)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger(__name__)
    
    def _load_template(self) -> TemplateParser:
        """Load and parse XML template"""
        try:
            with open(self.config.template_file, 'r', encoding='utf-8') as f:
                content = f.read()
            # Remove whitespace while preserving structure
            content = ''.join(line.strip() for line in content.splitlines())
            return TemplateParser(content)
        except Exception as e:
            self.logger.error(f"Failed to load template: {e}")
            raise
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic and connection pooling"""
        session = requests.Session()
        
        # Configure retries for connection errors
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"]
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set headers
        headers = {
            "Host": self.config.host,
            "Content-Type": "text/xml",
            "User-Agent": "SOAP-Sender/2.0"
        }
        
        if self.config.username and self.config.password:
            headers["username"] = self.config.username
            headers["password"] = self.config.password
        
        session.headers.update(headers)
        return session
    
    def _process_row(self, row_data: Tuple[int, str], session: requests.Session, 
                     endpoint: str) -> Dict[str, any]:
        """Process a single row of data"""
        row_num, row = row_data
        
        try:
            # Parse CSV row
            data = [x.strip() for x in row.strip().split(self.config.csv_delimiter)]
            
            # Substitute template
            soap_body = self.template_parser.substitute(data)
            
            # Send request with rate limiting
            response = self._send_with_rate_limit(session, endpoint, soap_body)
            
            # Check for rate limit error
            if self.config.rate_limit_error in response.text:
                self.logger.warning(f"Row {row_num}: Rate limited, retrying...")
                self.stats.increment('rate_limited')
                time.sleep(self.config.retry_backoff)
                response = session.post(
                    url=endpoint,
                    data=soap_body,
                    timeout=self.config.timeout
                )
            
            # Check response
            if "Result" in response.text or response.status_code == 200:
                self.stats.increment('success')
                return {
                    'status': 'success',
                    'row': row_num,
                    'data': row.strip()
                }
            else:
                self.stats.increment('errors')
                return {
                    'status': 'error',
                    'row': row_num,
                    'data': row.strip(),
                    'error': response.text
                }
                
        except ValueError as e:
            self.logger.error(f"Row {row_num}: Template parsing error - {e}")
            self.stats.increment('errors')
            return {
                'status': 'error',
                'row': row_num,
                'data': row.strip(),
                'error': f"Template parsing error: {e}"
            }
        except Exception as e:
            self.logger.error(f"Row {row_num}: Request failed - {e}")
            self.stats.increment('errors')
            return {
                'status': 'error',
                'row': row_num,
                'data': row.strip(),
                'error': str(e)
            }
    
    def _send_with_rate_limit(self, session: requests.Session, 
                              endpoint: str, data: str) -> requests.Response:
        """Send request with rate limiting"""
        response = session.post(
            url=endpoint,
            data=data,
            timeout=self.config.timeout
        )
        return response
    
    def _worker(self, worker_id: int, task_queue: Queue, endpoint: str):
        """Worker thread for processing requests"""
        session = self._create_session()
        requests_sent = 0
        last_sleep = time.time()
        
        self.logger.info(f"Worker {worker_id} started")
        
        while not self.stop_event.is_set():
            try:
                row_data = task_queue.get(timeout=1)
                
                # Rate limiting
                requests_sent += 1
                if requests_sent % self.config.burst_rate == 0:
                    elapsed = time.time() - last_sleep
                    if elapsed < 1.0:
                        time.sleep(1.0 - elapsed)
                    last_sleep = time.time()
                
                # Process row
                result = self._process_row(row_data, session, endpoint)
                
                # Log result
                if result['status'] == 'error':
                    if self.error_file:
                        self.error_file.write(
                            f"Row {result['row']}: {result['data']}\n"
                            f"Error: {result['error']}\n\n"
                        )
                        self.error_file.flush()
                elif self.success_file:
                    self.success_file.write(f"Row {result['row']}: {result['data']}\n")
                    self.success_file.flush()
                
                task_queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"Worker {worker_id} error: {e}")
        
        session.close()
        self.logger.info(f"Worker {worker_id} stopped")
    
    def run(self):
        """Main execution loop"""
        self.logger.info(f"Starting SOAP Sender")
        self.logger.info(f"Input file: {self.config.input_file}")
        self.logger.info(f"Template: {self.config.template_file}")
        self.logger.info(f"Threads: {self.config.num_threads}")
        self.logger.info(f"Burst rate: {self.config.burst_rate}/sec per thread")
        
        # Open error and success files
        error_file_path = self.config.error_file or f"{self.config.input_file}.errors"
        success_file_path = self.config.success_file or f"{self.config.input_file}.success"
        
        self.error_file = open(error_file_path, 'w')
        self.success_file = open(success_file_path, 'w')
        
        try:
            # Create task queue
            task_queue = Queue(maxsize=self.config.queue_size)
            
            # Start worker threads
            threads = []
            for i in range(self.config.num_threads):
                endpoint = self.config.endpoints[i % len(self.config.endpoints)]
                thread = Thread(
                    target=self._worker,
                    args=(i, task_queue, endpoint),
                    daemon=True
                )
                thread.start()
                threads.append(thread)
            
            # Read and queue data
            start_time = time.time()
            row_count = 0
            
            with open(self.config.input_file, 'r', encoding='utf-8') as f:
                for row_num, line in enumerate(f, 1):
                    if line.strip():
                        task_queue.put((row_num, line))
                        row_count += 1
                        
                        # Progress update
                        if row_num % 1000 == 0:
                            stats = self.stats.get_all()
                            self.logger.info(
                                f"Progress: {row_num} rows queued | "
                                f"Success: {stats['success']} | "
                                f"Errors: {stats['errors']} | "
                                f"Rate limited: {stats['rate_limited']}"
                            )
            
            # Wait for all tasks to complete
            self.logger.info(f"Waiting for {row_count} tasks to complete...")
            task_queue.join()
            
            # Stop workers
            self.stop_event.set()
            for thread in threads:
                thread.join(timeout=5)
            
            # Final stats
            elapsed_time = time.time() - start_time
            stats = self.stats.get_all()
            
            self.logger.info("=" * 60)
            self.logger.info("FINAL STATISTICS")
            self.logger.info("=" * 60)
            self.logger.info(f"Total rows processed: {row_count}")
            self.logger.info(f"Successful requests: {stats['success']}")
            self.logger.info(f"Failed requests: {stats['errors']}")
            self.logger.info(f"Rate limited: {stats['rate_limited']}")
            self.logger.info(f"Elapsed time: {elapsed_time:.2f} seconds")
            self.logger.info(f"Average rate: {row_count/elapsed_time:.2f} requests/sec")
            self.logger.info(f"Error log: {error_file_path}")
            self.logger.info(f"Success log: {success_file_path}")
            self.logger.info("=" * 60)
            
        finally:
            if self.error_file:
                self.error_file.close()
            if self.success_file:
                self.success_file.close()


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Generic SOAP Request Sender with high performance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  %(prog)s -i data.csv -t template.xml -e http://server:8080/soap
  
  # Multiple endpoints with authentication
  %(prog)s -i data.csv -t template.xml \\
    -e http://server1:8080/soap,http://server2:8080/soap \\
    -u admin -p secret
  
  # High throughput configuration
  %(prog)s -i data.csv -t template.xml -e http://server:8080/soap \\
    -n 50 -b 100 -q 20000
        """
    )
    
    # Required arguments
    parser.add_argument('-i', '--input', required=True,
                       help='Input CSV file path')
    parser.add_argument('-t', '--template', required=True,
                       help='SOAP XML template file path')
    parser.add_argument('-e', '--endpoints', required=True,
                       help='Comma-separated list of SOAP endpoints')
    
    # Optional arguments
    parser.add_argument('-H', '--host', default='127.0.0.1:2222',
                       help='Host header value (default: 127.0.0.1:2222)')
    parser.add_argument('-u', '--username',
                       help='Authentication username')
    parser.add_argument('-p', '--password',
                       help='Authentication password')
    parser.add_argument('-n', '--threads', type=int, default=20,
                       help='Number of worker threads (default: 20)')
    parser.add_argument('-b', '--burst-rate', type=int, default=50,
                       help='Max requests per second per thread (default: 50)')
    parser.add_argument('-q', '--queue-size', type=int, default=10000,
                       help='Queue size (default: 10000)')
    parser.add_argument('-T', '--timeout', type=int, default=60,
                       help='Request timeout in seconds (default: 60)')
    parser.add_argument('-d', '--delimiter', default=',',
                       help='CSV delimiter (default: ,)')
    parser.add_argument('-l', '--log-level', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO',
                       help='Log level (default: INFO)')
    parser.add_argument('--error-file',
                       help='Custom error log file path')
    parser.add_argument('--success-file',
                       help='Custom success log file path')
    parser.add_argument('--rate-limit-error',
                       help='Custom rate limit error string to detect')
    
    args = parser.parse_args()
    
    # Validate files exist
    if not os.path.exists(args.input):
        print(f"Error: Input file not found: {args.input}")
        sys.exit(1)
    
    if not os.path.exists(args.template):
        print(f"Error: Template file not found: {args.template}")
        sys.exit(1)
    
    # Parse endpoints
    endpoints = [e.strip() for e in args.endpoints.split(',')]
    
    # Create config
    config = Config(
        input_file=args.input,
        template_file=args.template,
        endpoints=endpoints,
        host=args.host,
        username=args.username,
        password=args.password,
        num_threads=args.threads,
        burst_rate=args.burst_rate,
        queue_size=args.queue_size,
        timeout=args.timeout,
        csv_delimiter=args.delimiter,
        log_level=args.log_level,
        error_file=args.error_file,
        success_file=args.success_file
    )
    
    if args.rate_limit_error:
        config.rate_limit_error = args.rate_limit_error
    
    # Run sender
    sender = SOAPSender(config)
    try:
        sender.run()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sender.stop_event.set()
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
