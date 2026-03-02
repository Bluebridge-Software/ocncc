# SOAP Request Sender - Complete Documentation

## Table of Contents

1. [Overview](#overview)
2. [Key Improvements](#key-improvements)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Detailed Usage Guide](#detailed-usage-guide)
6. [XML Template Format](#xml-template-format)
7. [Configuration Options](#configuration-options)
8. [Performance Tuning](#performance-tuning)
9. [Error Handling](#error-handling)
10. [Examples](#examples)
11. [Troubleshooting](#troubleshooting)
12. [Migration from Original Script](#migration-from-original-script)

---

## Overview

The SOAP Request Sender is a high-performance Python tool designed to send templated SOAP requests to remote endpoints. It reads data from CSV files, substitutes values into XML templates, and sends requests concurrently to one or more SOAP endpoints.

### Primary Use Cases

- Bulk provisioning operations in telecom platforms (e.g., OCNCC)
- Mass updates to subscriber databases
- Load testing SOAP services
- Automated data migration via SOAP APIs
- High-throughput transaction processing

### Architecture

- **Multi-threaded**: Concurrent workers for parallel request processing
- **Connection pooling**: Reuses HTTP connections for better performance
- **Rate limiting**: Built-in burst rate control per thread
- **Load balancing**: Round-robin distribution across multiple endpoints
- **Resilient**: Automatic retries with exponential backoff
- **Observable**: Real-time statistics and comprehensive logging

---

## Key Improvements

The improved version offers significant enhancements over the original implementation:

### 1. **Modern Python (Python 3.12+)**
- Uses type hints for better code clarity
- Dataclasses for configuration management
- Context managers for resource cleanup
- f-strings for readable string formatting

### 2. **Better Performance**
- Connection pooling with `urllib3` retry strategies
- Efficient queue management
- Reduced lock contention with thread-safe statistics
- Better CPU utilisation

### 3. **Enhanced Reliability**
- Structured error handling
- Automatic retry logic for transient failures
- Graceful shutdown on interruption
- Separate error and success logging

### 4. **Improved Usability**
- Modern argparse-based CLI with help text
- Comprehensive logging with configurable levels
- Real-time progress reporting
- Better validation and error messages

### 5. **More Generic Design**
- Configurable CSV delimiter
- Multiple endpoint support
- Customisable rate limit error detection
- Template validation on startup
- No hardcoded OCNCC-specific logic

### 6. **Better Observability**
- Detailed statistics (success/error/rate-limited/retry counts)
- Timestamp-based logging
- Separate success and error log files
- Performance metrics (requests/second)

---

## Installation

### Requirements

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install requests --break-system-packages
```

Or using a virtual environment (recommended):

```bash
python3 -m venv soap-env
source soap-env/bin/activate  # On Windows: soap-env\Scripts\activate
pip install requests
```

### Download the Script

```bash
# Make the script executable
chmod +x soap_sender.py

# Optionally, move to your PATH
sudo cp soap_sender.py /usr/local/bin/soap-sender
```

---

## Quick Start

### 1. Prepare Your CSV File

Create a CSV file with your data (e.g., `subscribers.csv`):

```csv
32495559424,31,0,1501,20170301230000,20170401230000
32495559425,31,0,1501,20170301230000,20170401230000
32495559426,31,0,1501,20170301230000,20170401230000
```

### 2. Create Your SOAP Template

Create an XML template file (e.g., `wallet_update.xml`):

```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:sub="http://example.com/subscriber.wsdl">
<soapenv:Header/>
<soapenv:Body>
<sub:WalletUpdateRequest>
    <username>user</username>
    <password>pass</password>
    <CC_Calling_Party_Id>$</CC_Calling_Party_Id>
    <Bill_Cycle_List_List>
        <!--Repeat-->
        <Bill_Cycle_List>
            <Balance_Type_ID>$</Balance_Type_ID>
            <Bucket_ID>$</Bucket_ID>
            <Bucket_Value>$</Bucket_Value>
            <Start_Date>$</Start_Date>
            <Expiry_Date>$</Expiry_Date>
        </Bill_Cycle_List>
        <!--End repeat-->
    </Bill_Cycle_List_List>
</sub:WalletUpdateRequest>
</soapenv:Body>
</soapenv:Envelope>
```

### 3. Run the Tool

```bash
python soap_sender.py \
  -i subscribers.csv \
  -t wallet_update.xml \
  -e http://10.0.17.179:2222/soap
```

### 4. Monitor Progress

The tool will display real-time statistics:

```
2026-03-02 10:00:00 - Thread-0 - INFO - Worker 0 started
2026-03-02 10:00:05 - MainThread - INFO - Progress: 1000 rows queued | Success: 950 | Errors: 50 | Rate limited: 10
```

---

## Detailed Usage Guide

### Command-Line Options

#### Required Arguments

| Option | Description |
|--------|-------------|
| `-i, --input FILE` | Path to input CSV file |
| `-t, --template FILE` | Path to SOAP XML template file |
| `-e, --endpoints URL` | Comma-separated list of SOAP endpoints |

#### Optional Arguments

| Option | Default | Description |
|--------|---------|-------------|
| `-H, --host HOST` | 127.0.0.1:2222 | Host header value for HTTP requests |
| `-u, --username USER` | None | Authentication username (sent in header) |
| `-p, --password PASS` | None | Authentication password (sent in header) |
| `-n, --threads NUM` | 20 | Number of concurrent worker threads |
| `-b, --burst-rate NUM` | 50 | Max requests per second per thread |
| `-q, --queue-size NUM` | 10000 | Internal queue size for buffering |
| `-T, --timeout SEC` | 60 | Request timeout in seconds |
| `-d, --delimiter CHAR` | , | CSV field delimiter |
| `-l, --log-level LEVEL` | INFO | Logging level (DEBUG/INFO/WARNING/ERROR) |
| `--error-file FILE` | input.csv.errors | Custom error log file path |
| `--success-file FILE` | input.csv.success | Custom success log file path |
| `--rate-limit-error STR` | (default) | Custom rate limit error string to detect |

### Basic Usage Patterns

#### Single Endpoint

```bash
python soap_sender.py \
  -i data.csv \
  -t template.xml \
  -e http://server:8080/soap
```

#### Multiple Endpoints (Load Balancing)

```bash
python soap_sender.py \
  -i data.csv \
  -t template.xml \
  -e http://server1:8080/soap,http://server2:8080/soap,http://server3:8080/soap
```

Requests are distributed round-robin across endpoints.

#### With Authentication

```bash
python soap_sender.py \
  -i data.csv \
  -t template.xml \
  -e http://server:8080/soap \
  -u admin \
  -p secretpass
```

#### High Throughput Configuration

```bash
python soap_sender.py \
  -i large_dataset.csv \
  -t template.xml \
  -e http://server:8080/soap \
  -n 50 \
  -b 100 \
  -q 20000
```

This configuration:
- Uses 50 threads (more parallelism)
- Allows 100 requests/second per thread
- Buffers up to 20,000 rows in memory

#### Debug Mode

```bash
python soap_sender.py \
  -i data.csv \
  -t template.xml \
  -e http://server:8080/soap \
  -l DEBUG
```

---

## XML Template Format

### Placeholder Syntax

Use `$` as a placeholder that will be replaced with CSV values sequentially:

```xml
<Field1>$</Field1>
<Field2>$</Field2>
```

For CSV row: `value1,value2`
Result: `<Field1>value1</Field1><Field2>value2</Field2>`

### Simple Templates

For fixed-structure requests:

```xml
<soap:Envelope>
<soap:Body>
<Request>
    <MSISDN>$</MSISDN>
    <OfferID>$</OfferID>
    <ExpiryDate>$</ExpiryDate>
</Request>
</soap:Body>
</soap:Envelope>
```

CSV format: `msisdn,offer_id,expiry_date`

### Repeatable Sections

For variable-length data, use `<!--Repeat-->` and `<!--End repeat-->` comments:

```xml
<soap:Envelope>
<soap:Body>
<Request>
    <MSISDN>$</MSISDN>
    <Balances>
        <!--Repeat-->
        <Balance>
            <Type>$</Type>
            <Amount>$</Amount>
        </Balance>
        <!--End repeat-->
    </Balances>
</Request>
</soap:Body>
</soap:Envelope>
```

**CSV Examples:**

```csv
# Single balance
123456789,VOICE,1000

# Multiple balances (must be multiples of 2 parameters)
123456789,VOICE,1000,DATA,5000
123456789,VOICE,1000,DATA,5000,SMS,100
```

**Important Rules for Repeatable Sections:**

1. Only ONE repeatable section per template
2. Must be at the END of the template
3. Number of remaining CSV values must be divisible by placeholders in section
4. First value(s) before the repeatable section are assigned to fixed placeholders

### Template Structure Examples

#### Example 1: Wallet Update with Multiple Balances

```xml
<WalletUpdateRequest>
    <MSISDN>$</MSISDN>
    <Balances>
        <!--Repeat-->
        <Balance>
            <TypeID>$</TypeID>
            <BucketID>$</BucketID>
            <Value>$</Value>
            <StartDate>$</StartDate>
            <ExpiryDate>$</ExpiryDate>
        </Balance>
        <!--End repeat-->
    </Balances>
</WalletUpdateRequest>
```

CSV: `msisdn,type1,bucket1,value1,start1,expiry1,type2,bucket2,value2,start2,expiry2`

#### Example 2: Service Provisioning

```xml
<ProvisionRequest>
    <SubscriberID>$</SubscriberID>
    <Services>
        <!--Repeat-->
        <Service>
            <ServiceCode>$</ServiceCode>
            <Status>$</Status>
        </Service>
        <!--End repeat-->
    </Services>
</ProvisionRequest>
```

CSV: `subscriber_id,service1,status1,service2,status2,service3,status3`

---

## Configuration Options

### Threading Configuration

**Number of Threads (`-n`)**
- More threads = higher throughput but more resource usage
- Recommended: 20-50 for most cases
- Consider server capacity and network bandwidth

**Burst Rate (`-b`)**
- Requests per second per thread
- Total rate ≈ threads × burst_rate
- Start conservative and increase if no errors

**Example Calculations:**

| Threads | Burst Rate | Total Req/Sec |
|---------|------------|---------------|
| 20 | 50 | ~1,000 |
| 50 | 100 | ~5,000 |
| 100 | 50 | ~5,000 |

### Queue Size

- Buffer for rows waiting to be processed
- Larger = more memory usage but smoother operation
- Default 10,000 is good for most cases

### Timeout

- How long to wait for a SOAP response
- Increase for slow servers or complex operations
- Default 60 seconds

### CSV Delimiter

Use `-d` for non-comma delimiters:

```bash
# Tab-separated
python soap_sender.py -i data.tsv -t template.xml -e http://server/soap -d $'\t'

# Pipe-separated
python soap_sender.py -i data.txt -t template.xml -e http://server/soap -d '|'

# Semicolon-separated
python soap_sender.py -i data.csv -t template.xml -e http://server/soap -d ';'
```

---

## Performance Tuning

### Optimising Throughput

1. **Start with baseline configuration:**
   ```bash
   -n 20 -b 50
   ```

2. **Monitor error rates:**
   - If < 1% errors: increase threads or burst rate
   - If > 5% errors: decrease load or check server

3. **Increase gradually:**
   ```bash
   # Step 1: Increase burst rate
   -n 20 -b 100
   
   # Step 2: Increase threads
   -n 50 -b 100
   
   # Step 3: Fine-tune
   -n 40 -b 80
   ```

4. **Multiple endpoints for horizontal scaling:**
   ```bash
   -e http://server1/soap,http://server2/soap,http://server3/soap
   ```

### Bottleneck Analysis

**CPU-bound (tool limitation):**
- Symptoms: Low CPU usage on server, high on client
- Solution: Increase threads
- Note: Python GIL limits single-process parallelism

**Network-bound:**
- Symptoms: High latency, timeouts
- Solution: Multiple endpoints, increase timeout
- Check network bandwidth

**Server-bound:**
- Symptoms: High error rates, rate limiting
- Solution: Decrease burst rate, add more server instances
- Monitor server CPU/memory

### Recommended Configurations

**Conservative (testing):**
```bash
-n 10 -b 20 -q 5000
```
~200 req/sec

**Standard (production):**
```bash
-n 20 -b 50 -q 10000
```
~1,000 req/sec

**Aggressive (high-capacity servers):**
```bash
-n 50 -b 100 -q 20000
```
~5,000 req/sec

**Maximum (distributed setup):**
```bash
-n 100 -b 100 -q 50000 -e server1,server2,server3
```
~10,000+ req/sec

---

## Error Handling

### Error Types

1. **Template Parsing Errors**
   - Wrong number of CSV fields
   - Repeatable section mismatch
   - Logged immediately, row skipped

2. **Network Errors**
   - Connection timeouts
   - Connection refused
   - Automatic retry (up to 3 times)

3. **Rate Limiting**
   - Server returns rate limit error
   - Automatic 60-second backoff and retry
   - Tracked in statistics

4. **Response Errors**
   - Invalid SOAP response
   - Application-level errors
   - Logged to error file

### Error Files

**Error Log (`input.csv.errors`):**
```
Row 123: 32495559424,31,0,1501,20170301230000
Error: Template parsing error: Insufficient data for non-repeatable section

Row 456: 32495559425,31,0,1501
Error: Connection timeout after 60 seconds
```

**Success Log (`input.csv.success`):**
```
Row 1: 32495559424,31,0,1501,20170301230000,20170401230000
Row 2: 32495559425,31,0,1501,20170301230000,20170401230000
```

### Retry Strategy

1. **Connection errors:** Auto-retry 3 times with backoff
2. **Rate limiting:** 60-second pause, then retry once
3. **Other errors:** No retry, logged to error file

### Handling Failed Rows

After completion, reprocess errors:

```bash
# Extract failed rows from error log
grep "^Row" input.csv.errors | cut -d: -f2 > failed_rows.csv

# Rerun with lower rate
python soap_sender.py \
  -i failed_rows.csv \
  -t template.xml \
  -e http://server/soap \
  -n 5 -b 10
```

---

## Examples

### Example 1: Basic Subscriber Provisioning

**CSV file (`subscribers.csv`):**
```csv
447700900001,John,Doe,PREPAID
447700900002,Jane,Smith,POSTPAID
447700900003,Bob,Jones,PREPAID
```

**Template (`provision.xml`):**
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body>
<ProvisionSubscriber>
    <MSISDN>$</MSISDN>
    <FirstName>$</FirstName>
    <LastName>$</LastName>
    <AccountType>$</AccountType>
</ProvisionSubscriber>
</soapenv:Body>
</soapenv:Envelope>
```

**Command:**
```bash
python soap_sender.py \
  -i subscribers.csv \
  -t provision.xml \
  -e http://10.0.17.179:8080/provisioning \
  -u api_user \
  -p api_pass
```

### Example 2: Multi-Service Activation

**CSV file (`activations.csv`):**
```csv
447700900001,VOICE,ACTIVE,DATA,ACTIVE,SMS,ACTIVE
447700900002,VOICE,ACTIVE,DATA,INACTIVE
447700900003,VOICE,ACTIVE
```

**Template (`activate_services.xml`):**
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body>
<ActivateServices>
    <MSISDN>$</MSISDN>
    <Services>
        <!--Repeat-->
        <Service>
            <Type>$</Type>
            <Status>$</Status>
        </Service>
        <!--End repeat-->
    </Services>
</ActivateServices>
</soapenv:Body>
</soapenv:Envelope>
```

**Command:**
```bash
python soap_sender.py \
  -i activations.csv \
  -t activate_services.xml \
  -e http://10.0.17.179:8080/services \
  -n 30 \
  -b 75
```

### Example 3: Wallet Top-Up with Multiple Balances

**CSV file (`topups.csv`):**
```csv
447700900001,VOICE,100,20260301,20260401,DATA,500,20260301,20260401
447700900002,VOICE,200,20260301,20260401,DATA,1000,20260301,20260401,SMS,50,20260301,20260401
```

**Template (`wallet_topup.xml`):**
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body>
<WalletTopUp>
    <MSISDN>$</MSISDN>
    <Balances>
        <!--Repeat-->
        <Balance>
            <Type>$</Type>
            <Amount>$</Amount>
            <StartDate>$</StartDate>
            <ExpiryDate>$</ExpiryDate>
        </Balance>
        <!--End repeat-->
    </Balances>
</WalletTopUp>
</soapenv:Body>
</soapenv:Envelope>
```

**Command:**
```bash
python soap_sender.py \
  -i topups.csv \
  -t wallet_topup.xml \
  -e http://10.0.17.179:2222/wallet,http://10.0.17.180:2222/wallet \
  -n 40 \
  -b 80 \
  -H 10.0.17.179:2222
```

### Example 4: Tab-Separated Values

**TSV file (`data.tsv`):**
```tsv
123456	VALUE1	VALUE2	VALUE3
123457	VALUE1	VALUE2	VALUE3
```

**Command:**
```bash
python soap_sender.py \
  -i data.tsv \
  -t template.xml \
  -e http://server/soap \
  -d $'\t'
```

---

## Troubleshooting

### Common Issues

#### 1. "Template parsing error: Insufficient data"

**Cause:** CSV row has fewer fields than placeholders in template

**Solution:**
- Check CSV format matches template
- Count $ symbols in template
- Verify CSV delimiter is correct

```bash
# Count placeholders in template
grep -o '\$' template.xml | wc -l

# Check CSV field count
head -1 data.csv | tr ',' '\n' | wc -l
```

#### 2. "Connection refused" or "Connection timeout"

**Cause:** Server not reachable or not running

**Solution:**
- Verify endpoint URL: `curl -v http://server:port/soap`
- Check firewall rules
- Verify server is running: `netstat -an | grep port`

#### 3. "Rate limited" messages

**Cause:** Sending too many requests per second

**Solution:**
- Decrease burst rate: `-b 25`
- Decrease threads: `-n 10`
- Add more server instances

#### 4. High error rate (>5%)

**Causes:** Server overloaded, network issues, malformed requests

**Solution:**
- Enable DEBUG logging: `-l DEBUG`
- Review error log
- Test with single thread: `-n 1 -b 1`
- Check server logs

#### 5. "Data count mismatch for repeatable section"

**Cause:** Remaining CSV fields not divisible by repeatable section placeholders

**Example:**
```
Template has 3 placeholders in repeat section
CSV: value1,value2,value3,value4,value5
After value1: 4 remaining values
4 is not divisible by 3 → ERROR
```

**Solution:**
- Ensure repeatable data comes in complete sets
- If template has 3 fields per repeat, CSV must have 3, 6, 9, etc. fields for that section

#### 6. Memory usage too high

**Cause:** Queue size too large or too many threads

**Solution:**
- Decrease queue size: `-q 5000`
- Process file in chunks
- Reduce threads: `-n 10`

### Debug Workflow

1. **Test with minimal config:**
   ```bash
   python soap_sender.py -i data.csv -t template.xml -e http://server/soap -n 1 -b 1 -l DEBUG
   ```

2. **Verify template substitution:**
   - Add print statement in code (temporarily)
   - Check first request in DEBUG log

3. **Test endpoint manually:**
   ```bash
   curl -X POST http://server/soap \
     -H "Content-Type: text/xml" \
     -d @manual_request.xml
   ```

4. **Gradual scaling:**
   - Start: `-n 1 -b 1`
   - Then: `-n 5 -b 10`
   - Then: `-n 20 -b 50`
   - Monitor error rates at each step

---

## Migration from Original Script

### Key Differences

| Original | Improved |
|----------|----------|
| Python 2.x | Python 3.8+ |
| `Queue.Queue` | `queue.Queue` |
| Manual threading | ThreadPoolExecutor-ready |
| Positional args via getopt | Named args via argparse |
| Global state | Encapsulated in classes |
| Manual retry logic | Built-in retry with requests |
| Single error log | Error + success logs |
| Implicit config | Explicit Config dataclass |

### Migration Steps

1. **Update Python version:**
   ```bash
   python3 --version  # Ensure 3.8+
   ```

2. **Update command syntax:**
   
   **Old:**
   ```bash
   python sendSOAP.py -i data.csv -r template.xml -u user -p pass -b 50 -n 20
   ```
   
   **New:**
   ```bash
   python soap_sender.py -i data.csv -t template.xml -e http://server/soap -u user -p pass -b 50 -n 20
   ```
   
   Changes:
   - `-r` → `-t` (template)
   - Must specify `-e` (endpoints) explicitly
   - No default endpoint

3. **Update endpoint configuration:**
   
   **Old (hardcoded in script):**
   ```python
   urlList=["http://10.0.17.179:2222"]
   ```
   
   **New (CLI argument):**
   ```bash
   -e http://10.0.17.179:2222
   ```

4. **Review template files:**
   - Templates remain compatible
   - `<!--Repeat-->` sections work identically
   - No changes needed

5. **Test with small dataset:**
   ```bash
   # Create test file with 10 rows
   head -10 original_data.csv > test_data.csv
   
   # Run with new tool
   python soap_sender.py -i test_data.csv -t template.xml -e http://server/soap
   ```

6. **Compare outputs:**
   - Check error log format
   - Verify success log
   - Compare statistics

### Backward Compatibility

For full compatibility, create a wrapper script:

```bash
#!/bin/bash
# sendSOAP_wrapper.sh - Maintains old syntax

while getopts "i:r:u:p:b:n:h" opt; do
  case $opt in
    i) INPUT="$OPTARG" ;;
    r) TEMPLATE="$OPTARG" ;;
    u) USER="$OPTARG" ;;
    p) PASS="$OPTARG" ;;
    b) BURST="$OPTARG" ;;
    n) THREADS="$OPTARG" ;;
    h) echo "Legacy wrapper for sendSOAP.py"; exit 0 ;;
  esac
done

# Call new script with translated arguments
python soap_sender.py \
  -i "$INPUT" \
  -t "$TEMPLATE" \
  -e "http://10.0.17.179:2222" \
  ${USER:+-u "$USER"} \
  ${PASS:+-p "$PASS"} \
  ${BURST:+-b "$BURST"} \
  ${THREADS:+-n "$THREADS"}
```

Usage:
```bash
chmod +x sendSOAP_wrapper.sh
./sendSOAP_wrapper.sh -i data.csv -r template.xml -u user -p pass
```

---

## Advanced Topics

### Custom Rate Limit Detection

If your server uses a different rate limit message:

```bash
python soap_sender.py \
  -i data.csv \
  -t template.xml \
  -e http://server/soap \
  --rate-limit-error "Rate limit exceeded"
```

### Distributed Execution

Split large datasets across multiple machines:

```bash
# Machine 1: Rows 1-100000
head -100000 data.csv > chunk1.csv
python soap_sender.py -i chunk1.csv -t template.xml -e http://server/soap

# Machine 2: Rows 100001-200000
tail -n +100001 data.csv | head -100000 > chunk2.csv
python soap_sender.py -i chunk2.csv -t template.xml -e http://server/soap
```

### Log Rotation

For long-running operations:

```bash
# Run in background with log rotation
nohup python soap_sender.py \
  -i huge_dataset.csv \
  -t template.xml \
  -e http://server/soap \
  > soap_sender.log 2>&1 &

# Monitor progress
tail -f soap_sender.log
```

### Integration with Monitoring

Export metrics to monitoring systems:

```bash
# Parse final statistics
python soap_sender.py ... | grep "FINAL STATISTICS" -A 10 > metrics.txt

# Send to monitoring
# (custom integration based on your monitoring system)
```

---

## Best Practices

1. **Always test with small dataset first**
   - 10-100 rows for validation
   - Check template substitution
   - Verify endpoint response

2. **Monitor server capacity**
   - Start with conservative settings
   - Gradually increase load
   - Watch for error rate increase

3. **Use multiple endpoints for HA**
   - Distribute load
   - Failover capability
   - Better throughput

4. **Review logs regularly**
   - Check error patterns
   - Identify data quality issues
   - Optimise configuration

5. **Backup before mass operations**
   - Database snapshots
   - Configuration backups
   - Rollback plan

6. **Schedule during off-peak hours**
   - Less impact on production
   - More server capacity
   - Easier troubleshooting

---

## Support and Contribution

### Getting Help

For issues or questions:
1. Check this documentation
2. Review error logs with `-l DEBUG`
3. Test with minimal configuration
4. Consult server documentation

### Reporting Issues

When reporting problems, include:
- Command used
- Python version: `python --version`
- Sample data (anonymised)
- Error messages
- Debug logs (first 50 lines)

### Performance Benchmarks

Typical performance (varies by server and network):

| Config | Req/Sec | Best For |
|--------|---------|----------|
| 10 threads, 20 burst | ~200 | Testing |
| 20 threads, 50 burst | ~1,000 | Production |
| 50 threads, 100 burst | ~5,000 | High-load |
| 100 threads, 100 burst | ~10,000 | Extreme loads |

---

## License

This tool is provided as-is for internal use. Modify and distribute according to your organisation's policies.

---

## Appendix: Quick Reference

### Most Common Commands

```bash
# Basic
python soap_sender.py -i data.csv -t template.xml -e http://server/soap

# With auth
python soap_sender.py -i data.csv -t template.xml -e http://server/soap -u user -p pass

# High throughput
python soap_sender.py -i data.csv -t template.xml -e http://server/soap -n 50 -b 100

# Debug mode
python soap_sender.py -i data.csv -t template.xml -e http://server/soap -l DEBUG

# Multiple endpoints
python soap_sender.py -i data.csv -t template.xml -e http://s1/soap,http://s2/soap
```

### Error Code Reference

| Error Type | Meaning | Action |
|------------|---------|--------|
| Template parsing | CSV/template mismatch | Fix CSV or template |
| Connection timeout | Server unreachable | Check network/server |
| Rate limited | Too many requests | Reduce burst rate |
| Response error | Invalid SOAP response | Check server logs |

### Performance Targets

| Dataset Size | Estimated Time | Recommended Config |
|--------------|----------------|-------------------|
| 1,000 rows | 1-2 minutes | Default settings |
| 10,000 rows | 10-20 minutes | Default settings |
| 100,000 rows | 1.5-3 hours | -n 30 -b 75 |
| 1,000,000 rows | 15-30 hours | -n 50 -b 100 + split |

---

*Document Version: 2.0*
*Last Updated: March 2026*
