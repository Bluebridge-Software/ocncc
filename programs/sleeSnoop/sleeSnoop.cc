/******************************************************************************
 *
 * File: sleeSnoop.cc
 *
 * Description: Self-contained passive shared-memory snooper for SLEE events.
 *
 *****************************************************************************/

#include "sleeSnoop.h"
#include <algorithm>
#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sstream>

char FileDescriptor::buffer[10240];

// --- Simple Mock Error Logging (No SDK dependency for logging) ---
#define LOG_ERROR(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  printf("[INFO] " fmt "\n", ##__VA_ARGS__)

/******************************************************************************
 * ConnectionManager
 *****************************************************************************/
ConnectionManager::ConnectionManager() { FD_ZERO(&storedFDSet); }

void ConnectionManager::add(FileDescriptor *fd) {
  fds.insert(fd);
  FD_SET(fd->fileDescriptor, &storedFDSet);
}

void ConnectionManager::remove(FileDescriptor *fd) {
  FD_CLR(fd->fileDescriptor, &storedFDSet);
  fds.erase(fd);
}

void ConnectionManager::process() {
  fd_set working;
  struct timeval tv = {0, 100000}; // 100ms poll
  working = storedFDSet;
  int ret = select(FD_SETSIZE, &working, NULL, NULL, &tv);

  if (ret > 0) {
    std::vector<FileDescriptor *> currentFds(fds.begin(), fds.end());
    for (auto fd : currentFds) {
      if (fds.count(fd) && fd->isReadable(&working)) {
        fd->process();
      }
    }
  }
}

FileDescriptor::~FileDescriptor() {}

/******************************************************************************
 * SnoopManager
 *****************************************************************************/
SnoopManager::SnoopManager() : root(NULL), pcapFile(NULL), capturing(false), eventCount(0) {}

SnoopManager::~SnoopManager() { stop(); }

bool SnoopManager::attach() {
    key_t key = ftok("/tmp/slee", 'a');
    if (key == -1) {
        const char* env = getenv("SLEE_FILE");
        if (env) key = ftok(env, 'a');
    }
    
    if (key == -1) return false;
    
    int shmid = shmget(key, 0, 0);
    if (shmid == -1) return false;
    
    void* addr = shmat(shmid, (void*)0x80000000, 0);
    if (addr == (void*)-1) {
        addr = shmat(shmid, NULL, 0); // Try auto-offset
    }
    
    if (addr == (void*)-1) return false;
    
    root = (SnoopRoot*)addr;
    return true;
}

bool SnoopManager::start(const std::string &filename) {
  if (capturing) return false;
  pcapFile = fopen(filename.c_str(), "wb");
  if (!pcapFile) return false;

  writePcapHeader();
  capturing = true;
  eventCount = 0;
  seenEvents.clear();
  return true;
}

void SnoopManager::stop() {
  if (pcapFile) {
    fclose(pcapFile);
    pcapFile = NULL;
  }
  capturing = false;
}

void SnoopManager::setFilter(const std::string &name) {
  if (name.empty()) filters.clear();
  else filters.insert(name);
}

void SnoopManager::writePcapHeader() {
  pcap_hdr_s header;
  header.magic_number = 0xa1b2c3d4;
  header.version_major = 2;
  header.version_minor = 4;
  header.thiszone = 0;
  header.sigfigs = 0;
  header.snaplen = 65535;
  header.network = 147;
  fwrite(&header, sizeof(header), 1, pcapFile);
}

uint32_t simpleHash(const void *data, size_t len) {
  uint32_t hash = 5381;
  const uint8_t *p = (const uint8_t *)data;
  for (size_t i = 0; i < std::min(len, (size_t)64); i++) {
    hash = ((hash << 5) + hash) + p[i];
  }
  return hash;
}

void SnoopManager::scrape() {
  if (!capturing || !root) return;

  // Note: We don't actually lock the semaphores here to remain "silent" and avoid 
  // blocking the SLEE if we crash. This is a "dirty read" snoop.
  
  // 1. Interfaces
  SnoopInterfaceInstance* ii = root->interfaceInstanceList.list.headElement.next;
  while (ii && ii != (void*)&root->interfaceInstanceList.list.headElement) {
      const char* name = ii->interfaceName;
      
      if (!filters.empty() && filters.find(name) == filters.end()) {
          ii = ii->base.next;
          continue;
      }
      
      SnoopEvent* ev = ii->eventList.list.headElement.next;
      while (ev && ev != (void*)&ii->eventList.list.headElement) {
          EventSignature sig = {ev, ev->length, simpleHash(ev->data, ev->length)};
          if (seenEvents.find(sig) == seenEvents.end()) {
              writeEvent(ev, name, 0);
              seenEvents.insert(sig);
              eventCount++;
          }
          ev = ev->base.next;
      }
      ii = ii->base.next;
  }
  
  // 2. Applications
  SnoopApplicationInstance* ai = root->applicationInstanceList.list.headElement.next;
  while (ai && ai != (void*)&root->applicationInstanceList.list.headElement) {
      SnoopEvent* ev = ai->currentEvent; // Apps often have one active event
      if (ev) {
          EventSignature sig = {ev, ev->length, simpleHash(ev->data, ev->length)};
          if (seenEvents.find(sig) == seenEvents.end()) {
              writeEvent(ev, "AppEvent", 1);
              seenEvents.insert(sig);
              eventCount++;
          }
      }
      ai = ai->base.next;
  }

  if (seenEvents.size() > 5000) seenEvents.clear();
}

void SnoopManager::writeEvent(SnoopEvent *ev, const char* name, int direction) {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  slee_snoop_hdr_t snoopHdr;
  snoopHdr.version = 1;
  snoopHdr.direction = direction;
  snoopHdr.interface_id = 0; 
  snoopHdr.dialog_id = ev->dialog ? 1 : 0;
  
  if (ev->eventType) {
      strncpy(snoopHdr.event_type, ev->eventType->typeName, sizeof(snoopHdr.event_type) - 1);
  } else {
      strcpy(snoopHdr.event_type, "Unknown");
  }

  uint32_t totalLen = sizeof(snoopHdr) + ev->length;
  pcaprec_hdr_s rec;
  rec.ts_sec = tv.tv_sec;
  rec.ts_usec = tv.tv_usec;
  rec.incl_len = totalLen;
  rec.orig_len = totalLen;

  fwrite(&rec, sizeof(rec), 1, pcapFile);
  fwrite(&snoopHdr, sizeof(snoopHdr), 1, pcapFile);
  fwrite(ev->data, ev->length, 1, pcapFile);
  fflush(pcapFile);
}

std::string SnoopManager::listComponents() {
    return "LIST command not available in standalone mode (requires offsets)\n";
}

/******************************************************************************
 * Telnet Server
 *****************************************************************************/
TelnetListener::TelnetListener(int port, SnoopManager &mgr, ConnectionManager &conn)
    : snoopMgr(mgr), connMgr(conn) {
  fileDescriptor = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(fileDescriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  bind(fileDescriptor, (struct sockaddr *)&addr, sizeof(addr));
  listen(fileDescriptor, 5);
  connMgr.add(this);
}

void TelnetListener::process() {
  int sock = accept(fileDescriptor, NULL, NULL);
  if (sock != -1) new TelnetFD(sock, snoopMgr, connMgr);
}

TelnetFD::TelnetFD(int sock, SnoopManager &mgr, ConnectionManager &conn)
    : snoopMgr(mgr), connMgr(conn) {
  fileDescriptor = sock;
  connMgr.add(this);
  std::string welcome = "SLEE Snoop Standalone Terminal\nCommands: START <file>, STOP, STATUS, QUIT\n> ";
  ::write(fileDescriptor, welcome.c_str(), welcome.length());
}

TelnetFD::~TelnetFD() {
  close(fileDescriptor);
  connMgr.remove(this);
}

void TelnetFD::write(const char *text, int size) { ::write(fileDescriptor, text, size); }

void TelnetFD::process() {
  int n = read(fileDescriptor, buffer, sizeof(buffer) - 1);
  if (n <= 0) { delete this; return; }
  buffer[n] = 0;
  std::string cmd(buffer);
  cmd.erase(std::remove(cmd.begin(), cmd.end(), '\r'), cmd.end());
  cmd.erase(std::remove(cmd.begin(), cmd.end(), '\n'), cmd.end());

  if (cmd.substr(0, 5) == "START") {
    std::string file = cmd.length() > 6 ? cmd.substr(6) : "snoop.pcap";
    if (snoopMgr.start(file)) write("Started capture\n", 16);
    else write("Failed to start\n", 16);
  } else if (cmd == "STOP") {
    snoopMgr.stop();
    write("Stopped capture\n", 16);
  } else if (cmd == "STATUS") {
    char stat[128];
    sprintf(stat, "Status: %s, Events: %lu\n", snoopMgr.isActive() ? "Capturing" : "Idle", snoopMgr.getEventCount());
    write(stat, strlen(stat));
  } else if (cmd == "QUIT") {
    delete this;
    return;
  }
  write("> ", 2);
}

int main(int argc, char **argv) {
  ConnectionManager conn;
  SnoopManager snoop;
  
  if (!snoop.attach()) {
      LOG_ERROR("Failed to attach to SLEE shared memory. Is SLEE running?");
      return 1;
  }
  
  TelnetListener telnet(9999, snoop, conn);
  LOG_INFO("sleeSnoop Standalone: Management port 9999, Startup Successful");

  while (true) {
    conn.process();
    snoop.scrape();
    usleep(10000);
  }
  return 0;
}
