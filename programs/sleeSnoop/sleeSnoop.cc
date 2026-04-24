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
#include <vector>

char FileDescriptor::buffer[10240];

#define LOG_ERROR(fmt, ...) printf("[ERROR] " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  printf("[INFO] " fmt "\n", ##__VA_ARGS__)

static SnoopInterfaceInstance* g_firstInterface = NULL;
static SnoopApplicationInstance* g_firstAppInst = NULL;

/******************************************************************************
 * ConnectionManager
 *****************************************************************************/
ConnectionManager::ConnectionManager() { FD_ZERO(&storedFDSet); }
void ConnectionManager::add(FileDescriptor *fd) { fds.insert(fd); FD_SET(fd->fileDescriptor, &storedFDSet); }
void ConnectionManager::remove(FileDescriptor *fd) { FD_CLR(fd->fileDescriptor, &storedFDSet); fds.erase(fd); }
void ConnectionManager::process() {
  fd_set working;
  struct timeval tv = {0, 100000}; 
  working = storedFDSet;
  int ret = select(FD_SETSIZE, &working, NULL, NULL, &tv);
  if (ret > 0) {
    std::vector<FileDescriptor *> currentFds(fds.begin(), fds.end());
    for (auto fd : currentFds) {
      if (fds.count(fd) && fd->isReadable(&working)) fd->process();
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
  const char *sleeFile = getenv("SLEE_FILE");
  if (sleeFile == NULL) sleeFile = "/IN/service_packages/SLEE/tmp/slee";

  key_t key = ftok(sleeFile, 'a');
  if (key == -1) { LOG_ERROR("ftok failed"); return false; }
  int shmid = shmget(key, 0, 0);
  if (shmid == -1) { LOG_ERROR("shmget failed"); return false; }
  void *addr = shmat(shmid, (void *)0x80000000, SHM_RDONLY);
  if (addr == (void *)-1) addr = shmat(shmid, NULL, SHM_RDONLY);
  if (addr == (void *)-1) return false;

  root = (SnoopRoot *)addr;
  LOG_INFO("Attached to SHM at %p.", addr);
  
  LOG_INFO("First 64 bytes:");
  unsigned char* dump = (unsigned char*)addr;
  for (int i = 0; i < 64; i += 16) {
      printf("[DEBUG] %04x: ", i);
      for (int j = 0; j < 16; j++) printf("%02x ", dump[i+j]);
      printf("\n");
  }

  uintptr_t nameAddr = 0;
  char* search = (char*)addr;
  LOG_INFO("Exhaustively searching 100MB of SHM for identifiers...");
  const char* targets[] = {"Timer", "beVWARS0", "beVWARS1", "textInterface", "sleeManagement", "watchdog"};
  
  for (size_t i = 0; i < 100000000; i++) {
      for (int t = 0; t < 6; t++) {
          size_t tlen = strlen(targets[t]);
          if (memcmp(&search[i], targets[t], tlen) == 0) {
              nameAddr = (uintptr_t)&search[i];
              LOG_INFO("Found identifier '%s' at offset 0x%lx (Address %p)", targets[t], (long)i, (void*)nameAddr);
              
              uintptr_t* rootPtrs = (uintptr_t*)addr;
              for (int offset = 0; offset < 600; offset += 4) {
                  uintptr_t objStart = nameAddr - offset;
                  for (int j = 0; j < 1024; j++) {
                      if (rootPtrs[j] == objStart) {
                          LOG_INFO("IDENTIFIED SleeRoot offset 0x%lx -> %p", (long)j*8, (void*)objStart);
                          if (j*8 == 0x2a0) g_firstInterface = (SnoopInterfaceInstance*)objStart;
                          if (j*8 == 0x268) g_firstAppInst = (SnoopApplicationInstance*)objStart;
                      }
                  }
              }
          }
      }
  }

  uintptr_t* rootPtrs = (uintptr_t*)addr;
  if (!g_firstInterface && (rootPtrs[0x2a0/8] & 0x80000000)) {
      g_firstInterface = (SnoopInterfaceInstance*)rootPtrs[0x2a0/8];
      LOG_INFO("Using fallback for g_firstInterface: %p", g_firstInterface);
  }
  if (!g_firstAppInst && (rootPtrs[0x268/8] & 0x80000000)) {
      g_firstAppInst = (SnoopApplicationInstance*)rootPtrs[0x268/8];
      LOG_INFO("Using fallback for g_firstAppInst: %p", g_firstAppInst);
  }

  if (!g_firstInterface && !g_firstAppInst) {
      LOG_ERROR("Could not identify interfaces or apps. Is SLEE fully started?");
      return false;
  }
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

void SnoopManager::stop() { if (pcapFile) { fclose(pcapFile); pcapFile = NULL; } capturing = false; }

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

static std::vector<SnoopLockedList<SnoopEvent>*> g_globalLists;

void SnoopManager::scrape() {
  if (!capturing) return;

  // 0. Comprehensive mapping once
  static bool mapped = false;
  if (!mapped) {
      mapped = true;
      uintptr_t targetEvent = 0x802afd60;
      uintptr_t* p = (uintptr_t*)root;
      LOG_INFO("Exhaustively scanning 100MB of SHM for pointers to event %p...", (void*)targetEvent);
      for (long i = 0; i < 12500000; i++) {
          if (p[i] == targetEvent) {
              LOG_INFO("Found pointer to event %p at address %p (Offset 0x%lx)", (void*)targetEvent, &p[i], (long)i*8);
          }
      }
      
      LOG_INFO("Dumping event memory at 0x802afd60 (128 bytes):");
      unsigned char* ed = (unsigned char*)((char*)root + 0x2afd60);
      for (int k = 0; k < 128; k += 16) {
          printf("[DEBUG] %04x: ", k);
          for (int j = 0; j < 16; j++) printf("%02x ", ed[k+j]);
          printf("\n");
      }
      for (int i = 0; i < 2000; i++) {
          uintptr_t val = p[i];
          if (val >= 0x80000000 && val < 0x8fffffff && (val % 8 == 0)) {
              // 1. Search for global event list array
              // check said 0x80000818 is a list. Let's see if we find a pointer to it.
              if (val == 0x80000818) {
                  LOG_INFO("Found eventListArray at SleeRoot offset 0x%lx -> %p", (long)i*8, (void*)val);
                  int stride = 0;
                  // Find stride by searching for the next list signature
                  for (int s = 16; s < 512; s += 8) {
                      for (int m = 0; m <= 64; m += 4) {
                          uintptr_t* lp = (uintptr_t*)((char*)val + s + m);
                          if ((uintptr_t)lp > 0x80000000 && (uintptr_t)lp < 0x8fffffff) {
                              if (lp[0] == (uintptr_t)lp && lp[1] == (uintptr_t)lp) {
                                  stride = s; break;
                              }
                          }
                      }
                      if (stride) break;
                  }
                  if (!stride) stride = 144; // fallback
                  LOG_INFO("Detected global list stride: %d", stride);
                  for (int k = 0; k < 64; k++) {
                      g_globalLists.push_back((SnoopLockedList<SnoopEvent>*)((char*)val + k * stride));
                  }
              }

              // 2. Search for Interface/App instances by name
              for (int offset = 0; offset < 600; offset += 4) {
                  char* name = (char*)val + offset;
                  if (name[0] >= 32 && name[0] <= 126 && name[1] >= 32 && name[1] <= 126) {
                      if (strcmp(name, "Timer") == 0) {
                          g_firstInterface = (SnoopInterfaceInstance*)val;
                          LOG_INFO("Found g_firstInterface ('Timer') at SleeRoot offset 0x%lx -> %p", (long)i*8, (void*)val);
                      }
                      if (strcmp(name, "beVWARS0") == 0 && !g_firstInterface) {
                          g_firstInterface = (SnoopInterfaceInstance*)val; // use as fallback
                      }
                  }
              }
          }
      }
      LOG_INFO("Mapped %lu global lists", (unsigned long)g_globalLists.size());
  }

  // 1. Scan Global Lists
  for (auto el : g_globalLists) {
      SnoopEvent *ev = el->list.headElement.next;
      int evCount = 0;
      while (ev && ev != (void *)&el->list.headElement && evCount < 200) {
        evCount++;
        if ((uintptr_t)ev < 0x80000000 || (uintptr_t)ev > 0x8fffffff) break;
        uint32_t len = (uint32_t)ev->length;
        if (len < 65535) {
            uint32_t h = 0;
            if (len > 0) {
                unsigned char* d = (unsigned char*)ev->data;
                for(uint32_t k=0; k<len && k<64; k++) h = (h*31) + d[k];
            }
            EventSignature sig = {ev, (size_t)len, h};
            if (seenEvents.find(sig) == seenEvents.end()) {
              writeEvent(ev, "Global", 0);
              seenEvents.insert(sig);
              eventCount++;
            }
        }
        ev = ev->base.next;
      }
  }

  // 2. Scan Instance Lists
  static int eventListOffset = -1;
  if (g_firstInterface) {
    for (int i = 0; i < 100; i++) {
      SnoopInterfaceInstance* ii = (SnoopInterfaceInstance*)((char*)g_firstInterface + i * 560);
      if ((uintptr_t)ii < 0x80000000 || (uintptr_t)ii > 0x90000000) break;
      char* name = (char*)ii + 240;
      if (name[0] < 32 || name[0] > 126) continue;
      
      if (eventListOffset == -1) {
          uintptr_t* p = (uintptr_t*)ii;
          for (int j = 1; j < 40; j++) {
              if (p[j] == (uintptr_t)&p[j] && p[j+1] == (uintptr_t)&p[j]) {
                  eventListOffset = (j-1) * 8;
                  break;
              }
          }
      }
      if (eventListOffset == -1) continue;

      SnoopLockedList<SnoopEvent>* el = (SnoopLockedList<SnoopEvent>*)((char*)ii + eventListOffset);
      SnoopEvent *ev = el->list.headElement.next;
      int evCount = 0;
      while (ev && ev != (void *)&el->list.headElement && evCount < 100) {
        evCount++;
        if ((uintptr_t)ev < 0x80000000 || (uintptr_t)ev > 0x8fffffff) break;
        uint32_t len = (uint32_t)ev->length;
        if (len < 65535) {
            uint32_t h = 0;
            if (len > 0) {
                unsigned char* d = (unsigned char*)ev->data;
                for(uint32_t k=0; k<len && k<64; k++) h = (h*31) + d[k];
            }
            EventSignature sig = {ev, (size_t)len, h};
            if (seenEvents.find(sig) == seenEvents.end()) {
              static bool firstDump = false;
              if (!firstDump) {
                  firstDump = true;
                  LOG_INFO("Dumping first event at %p:", ev);
                  unsigned char* d = (unsigned char*)ev;
                  for (int k = 0; k < 64; k += 16) {
                      printf("[DEBUG] %04x: ", k);
                      for (int j = 0; j < 16; j++) printf("%02x ", d[k+j]);
                      printf("\n");
                  }
              }
              writeEvent(ev, name, 0);
              seenEvents.insert(sig);
              eventCount++;
            }
        }
        ev = ev->base.next;
      }
    }
  }

  if (g_firstAppInst) {
    for (int i = 0; i < 100; i++) {
      SnoopApplicationInstance* ai = (SnoopApplicationInstance*)((char*)g_firstAppInst + i * 560);
      if ((uintptr_t)ai < 0x80000000 || (uintptr_t)ai > 0x90000000) break;
      if (eventListOffset == -1) continue;
      SnoopLockedList<SnoopEvent>* el = (SnoopLockedList<SnoopEvent>*)((char*)ai + eventListOffset);
      SnoopEvent *ev = el->list.headElement.next;
      int evCount = 0;
      while (ev && ev != (void *)&el->list.headElement && evCount < 100) {
        evCount++;
        if ((uintptr_t)ev < 0x80000000 || (uintptr_t)ev > 0x8fffffff) break;
        uint32_t len = (uint32_t)ev->length;
        if (len < 65535) {
            uint32_t h = 0;
            if (len > 0) {
                unsigned char* d = (unsigned char*)ev->data;
                for(uint32_t k=0; k<len && k<64; k++) h = (h*31) + d[k];
            }
            EventSignature sig = {ev, (size_t)len, h};
            if (seenEvents.find(sig) == seenEvents.end()) {
              writeEvent(ev, "App", 0);
              seenEvents.insert(sig);
              eventCount++;
            }
        }
        ev = ev->base.next;
      }
    }
  }
}

void SnoopManager::writeEvent(SnoopEvent *ev, const char *name, int direction) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  slee_snoop_hdr_t snoopHdr;
  memset(&snoopHdr, 0, sizeof(snoopHdr));
  snoopHdr.version = 1;
  snoopHdr.direction = direction;
  uint32_t len = (uint32_t)ev->length;
  pcaprec_hdr_s rec = { (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec, (uint32_t)(sizeof(snoopHdr) + len), (uint32_t)(sizeof(snoopHdr) + len) };
  fwrite(&rec, sizeof(rec), 1, pcapFile);
  fwrite(&snoopHdr, sizeof(snoopHdr), 1, pcapFile);
  fwrite(ev->data, len, 1, pcapFile);
  fflush(pcapFile);
}

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
void TelnetListener::process() { int sock = accept(fileDescriptor, NULL, NULL); if (sock != -1) new TelnetFD(sock, snoopMgr, connMgr); }
TelnetFD::TelnetFD(int sock, SnoopManager &mgr, ConnectionManager &conn) : snoopMgr(mgr), connMgr(conn) {
  fileDescriptor = sock; connMgr.add(this);
  std::string welcome = "SLEE Snoop Terminal\nCommands: START <file>, STOP, STATUS, QUIT\n> ";
  ::write(fileDescriptor, welcome.c_str(), welcome.length());
}
TelnetFD::~TelnetFD() { close(fileDescriptor); connMgr.remove(this); }
void TelnetFD::write(const char *text, int size) { ::write(fileDescriptor, text, size); }
void TelnetFD::process() {
  int n = read(fileDescriptor, buffer, sizeof(buffer) - 1);
  if (n <= 0) { delete this; return; }
  buffer[n] = 0;
  std::stringstream ss(buffer);
  std::string line;
  while (std::getline(ss, line)) {
    if (line.empty()) continue;
    if (line.back() == '\r') line.pop_back();
    std::stringstream lss(line);
    std::string cmd, arg;
    lss >> cmd >> arg;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);
    if (cmd == "START") {
      if (snoopMgr.start(arg.empty() ? "snoop.pcap" : arg)) write("Started\n", 8);
      else write("Failed\n", 7);
    } else if (cmd == "STOP") {
      snoopMgr.stop(); write("Stopped\n", 8);
    } else if (cmd == "STATUS") {
      char stat[128];
      sprintf(stat, "Status: %s, Events: %llu\n", snoopMgr.isActive() ? "Capturing" : "Idle", (unsigned long long)snoopMgr.getEventCount());
      write(stat, strlen(stat));
    } else if (cmd == "QUIT" || cmd == "EXIT") { delete this; return; }
    write("> ", 2);
  }
}

int main() {
  ConnectionManager conn;
  SnoopManager snoop;
  if (!snoop.attach()) return 1;
  TelnetListener telnet(9999, snoop, conn);
  LOG_INFO("Snoop Terminal ready on port 9999");
  while (true) {
    conn.process();
    if (snoop.isActive()) snoop.scrape();
    usleep(10000);
  }
  return 0;
}
