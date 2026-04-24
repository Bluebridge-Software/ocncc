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
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

char FileDescriptor::buffer[10240];

#define LOG_ERROR(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)

// Globals for discovered offsets
static SnoopLockedList<SnoopInterfaceInstance> *g_interfaceList = NULL;
static SnoopLockedList<SnoopApplicationInstance> *g_applicationList = NULL;

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
SnoopManager::SnoopManager()
    : root(NULL), pcapFile(NULL), capturing(false), eventCount(0) {}

SnoopManager::~SnoopManager() { stop(); }

bool SnoopManager::attach() {
  const char *sleeFile = getenv("SLEE_FILE");
  if (sleeFile == NULL)
    sleeFile = "/IN/service_packages/SLEE/tmp/slee";

  key_t key = ftok(sleeFile, 'a');
  if (key == -1) {
    LOG_ERROR("ftok(%s, 'a') failed: %s", sleeFile, strerror(errno));
    return false;
  }

  int shmid = shmget(key, 0, 0);
  if (shmid == -1) {
    LOG_ERROR("shmget(0x%lx) failed: %s", (long)key, strerror(errno));
    return false;
  }

  void *addr = shmat(shmid, (void *)0x80000000, SHM_RDONLY);
  if (addr == (void *)-1)
    addr = shmat(shmid, NULL, SHM_RDONLY);
  if (addr == (void *)-1) {
    LOG_ERROR("shmat failed: %s", strerror(errno));
    return false;
  }

  root = (SnoopRoot *)addr;
  LOG_INFO("Attached to SHM at %p. Scanning for list offsets...", addr);

  // Dynamic Discovery: Look for lists
  // A SnoopLockedList signature: headElement.next and .prev point to
  // headElement
  std::vector<void *> foundLists;
  uintptr_t *p = (uintptr_t *)addr;
  for (int i = 1; i < 10000; i++) {
    uintptr_t currentAddr = (uintptr_t)&p[i];
    if (p[i + 1] == currentAddr && p[i + 2] == currentAddr &&
        p[i] == (uintptr_t)&p[i - 1]) {
      foundLists.push_back((void *)&p[i - 1]);
      LOG_INFO("Discovered potential list #%lu at %p", foundLists.size(), &p[i-1]);
    }
  }

  LOG_INFO("Found %lu potential lists in SHM", foundLists.size());
  if (foundLists.size() >= 10) {
    // Interface list is usually the 9th or 10th
    g_interfaceList = (SnoopLockedList<SnoopInterfaceInstance> *)foundLists[8];
    g_applicationList =
        (SnoopLockedList<SnoopApplicationInstance> *)foundLists[10];
    LOG_INFO("Selected InterfaceList at %p, ApplicationList at %p",
             g_interfaceList, g_applicationList);
  } else {
    LOG_ERROR("Could not identify SLEE lists. Offsets might be wrong.");
    return false;
  }

  return true;
}

bool SnoopManager::start(const std::string &filename) {
  if (capturing)
    return false;
  pcapFile = fopen(filename.c_str(), "wb");
  if (!pcapFile) {
    LOG_ERROR("Failed to open %s for writing: %s", filename.c_str(),
              strerror(errno));
    return false;
  }

  writePcapHeader();
  capturing = true;
  eventCount = 0;
  seenEvents.clear();
  LOG_INFO("Started capture to %s", filename.c_str());
  return true;
}

void SnoopManager::stop() {
  if (pcapFile) {
    fclose(pcapFile);
    pcapFile = NULL;
    LOG_INFO("Stopped capture");
  }
  capturing = false;
}

void SnoopManager::setFilter(const std::string &name) {
  if (name.empty()) {
    filters.clear();
    LOG_INFO("Filters cleared");
  } else {
    filters.insert(name);
    LOG_INFO("Added filter: %s", name.c_str());
  }
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
  if (!capturing || !g_interfaceList)
    return;

  static bool loggedOnce = false;
  int iiCount = 0;

  // 1. Interfaces
  SnoopInterfaceInstance *ii = g_interfaceList->list.headElement.next;
  while (ii && ii != (void *)&g_interfaceList->list.headElement) {
    iiCount++;
    const char *name = ii->interfaceName;
    if (name[0] < 32 || name[0] > 126) name = "Unknown";
    
    if (!loggedOnce) {
        LOG_INFO("Scraper: Found interface '%s' at %p, eventList size: %d", name, ii, ii->eventList.list.size);
    }

    if (!filters.empty() && filters.find(name) == filters.end()) {
      ii = ii->base.next;
      continue;
    }

    SnoopEvent *ev = ii->eventList.list.headElement.next;
    int evInList = 0;
    while (ev && ev != (void *)&ii->eventList.list.headElement) {
      evInList++;
      EventSignature sig = {ev, (size_t)ev->length,
                            simpleHash(ev->data, (size_t)ev->length)};
      if (seenEvents.find(sig) == seenEvents.end()) {
        writeEvent(ev, name, 0);
        seenEvents.insert(sig);
        eventCount++;
      }
      ev = ev->base.next;
      if (evInList > 1000) break; // Safety
    }
    ii = ii->base.next;
    if (iiCount > 100) break; // Safety
  }
  
  if (!loggedOnce && iiCount > 0) {
      LOG_INFO("Scraper: Total interfaces scanned: %d", iiCount);
      loggedOnce = true;
  }

  // 2. Applications
  if (g_applicationList) {
    SnoopApplicationInstance *ai = g_applicationList->list.headElement.next;
    while (ai && ai != (void *)&g_applicationList->list.headElement) {
      SnoopEvent *ev = ai->currentEvent;
      if (ev) {
        EventSignature sig = {ev, (size_t)ev->length,
                              simpleHash(ev->data, (size_t)ev->length)};
        if (seenEvents.find(sig) == seenEvents.end()) {
          writeEvent(ev, "AppEvent", 1);
          seenEvents.insert(sig);
          eventCount++;
        }
      }
      ai = ai->base.next;
    }
  }

  if (seenEvents.size() > 10000)
    seenEvents.clear();
}

void SnoopManager::writeEvent(SnoopEvent *ev, const char *name, int direction) {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  slee_snoop_hdr_t snoopHdr;
  snoopHdr.version = 1;
  snoopHdr.direction = direction;
  snoopHdr.interface_id = 0;
  snoopHdr.dialog_id = ev->dialog ? 1 : 0;

  if (ev->eventType) {
    strncpy(snoopHdr.event_type, ev->eventType->typeName,
            sizeof(snoopHdr.event_type) - 1);
    snoopHdr.event_type[sizeof(snoopHdr.event_type) - 1] = '\0';
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

/******************************************************************************
 * Telnet Server
 *****************************************************************************/
TelnetListener::TelnetListener(int port, SnoopManager &mgr,
                               ConnectionManager &conn)
    : snoopMgr(mgr), connMgr(conn) {
  fileDescriptor = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(fileDescriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(fileDescriptor, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    LOG_ERROR("Failed to bind to port %d", port);
  }
  listen(fileDescriptor, 5);
  connMgr.add(this);
}

void TelnetListener::process() {
  int sock = accept(fileDescriptor, NULL, NULL);
  if (sock != -1)
    new TelnetFD(sock, snoopMgr, connMgr);
}

TelnetFD::TelnetFD(int sock, SnoopManager &mgr, ConnectionManager &conn)
    : snoopMgr(mgr), connMgr(conn) {
  fileDescriptor = sock;
  connMgr.add(this);
  std::string welcome = "SLEE Snoop Terminal\nCommands: START <file>, STOP, "
                        "FILTER <name>, CLEAR, STATUS, QUIT\n> ";
  ::write(fileDescriptor, welcome.c_str(), welcome.length());
}

TelnetFD::~TelnetFD() {
  close(fileDescriptor);
  connMgr.remove(this);
}

void TelnetFD::write(const char *text, int size) {
  ::write(fileDescriptor, text, size);
}

void TelnetFD::process() {
  int n = read(fileDescriptor, buffer, sizeof(buffer) - 1);
  if (n <= 0) {
    delete this;
    return;
  }
  buffer[n] = 0;

  std::stringstream ss(buffer);
  std::string line;
  while (std::getline(ss, line)) {
    if (line.empty())
      continue;
    if (line.back() == '\r')
      line.pop_back();

    std::stringstream lss(line);
    std::string cmd, arg;
    lss >> cmd >> arg;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);

    if (cmd == "START") {
      if (snoopMgr.start(arg.empty() ? "snoop.pcap" : arg))
        write("Started capture\n", 16);
      else
        write("Failed to start\n", 16);
    } else if (cmd == "STOP") {
      snoopMgr.stop();
      write("Stopped capture\n", 16);
    } else if (cmd == "FILTER") {
      snoopMgr.setFilter(arg);
      write("Filter set\n", 11);
    } else if (cmd == "CLEAR") {
      snoopMgr.setFilter("");
      write("Filters cleared\n", 16);
    } else if (cmd == "STATUS") {
      char stat[128];
      sprintf(stat, "Status: %s, Events: %llu\n",
              snoopMgr.isActive() ? "Capturing" : "Idle",
              (unsigned long long)snoopMgr.getEventCount());
      write(stat, strlen(stat));
    } else if (cmd == "QUIT" || cmd == "EXIT") {
      delete this;
      return;
    }
    write("> ", 2);
  }
}

int main(int argc, char **argv) {
  ConnectionManager conn;
  SnoopManager snoop;

  if (!snoop.attach())
    return 1;

  TelnetListener telnet(9999, snoop, conn);
  LOG_INFO("Snoop Terminal ready on port 9999");

  while (true) {
    conn.process();
    if (snoop.isActive())
      snoop.scrape();
    usleep(10000);
  }
  return 0;
}
