#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/time.h>
#include <thread>
#include <atomic>
#include "sleeSnoop.h"

#define LOG_INFO(msg, ...) printf("[INFO] " msg "\n", ##__VA_ARGS__)
#define LOG_DEBUG(msg, ...) printf("[DEBUG] " msg "\n", ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) printf("[ERROR] " msg "\n", ##__VA_ARGS__)

static SnoopInterfaceInstance* g_firstInterface = nullptr;
static SnoopApplicationInstance* g_firstAppInst = nullptr;
static std::vector<SnoopLockedList<SnoopEvent>*> g_globalLists;

SnoopManager::SnoopManager() : root(nullptr), pcapFile(nullptr), capturing(false), eventCount(0) {}
SnoopManager::~SnoopManager() { stop(); }

bool SnoopManager::attach() {
  char* sleeFile = getenv("SLEE_FILE");
  if (!sleeFile) sleeFile = (char*)"/IN/service_packages/SLEE/tmp/slee";
  key_t key = ftok(sleeFile, 'a');
  int shmid = shmget(key, 0, 0);
  if (shmid < 0) {
    LOG_ERROR("Could not find SHM segment (key 0x%08x). Error: %s. Is SLEE running?", key, strerror(errno));
    return false;
  }
  void* addr = shmat(shmid, (void*)0x80000000, SHM_RDONLY);
  if (addr == (void*)-1) {
    LOG_ERROR("Could not attach to SHM at 0x80000000.");
    return false;
  }
  root = (SnoopRoot*)addr;
  LOG_INFO("Attached to SHM at %p.", root);
  return true;
}

bool SnoopManager::start(const std::string& filename) {
  LOG_INFO("SnoopManager::start called with %s", filename.c_str());
  pcapFile = fopen(filename.c_str(), "wb");
  if (!pcapFile) {
    LOG_ERROR("Could not open PCAP file %s", filename.c_str());
    return false;
  }
  writePcapHeader();
  seenEvents.clear();
  eventCount = 0;
  capturing = true;
  return true;
}

void SnoopManager::stop() {
  LOG_INFO("SnoopManager::stop called");
  capturing = false;
  if (pcapFile) {
    fclose(pcapFile);
    pcapFile = nullptr;
  }
}

void SnoopManager::writePcapHeader() {
  pcap_hdr_s header = { 0xa1b2c3d4, 2, 4, 0, 0, 65535, 147 };
  fwrite(&header, sizeof(header), 1, pcapFile);
}

void SnoopManager::scrape() {
  static bool firstScrape = true;
  if (firstScrape && capturing) {
      firstScrape = false;
      LOG_INFO("Scrape loop active and capturing!");
      fflush(stdout);
  }
  if (!capturing) return;

  static bool mapped = false;
  if (!mapped) {
    mapped = true;
    uintptr_t* p = (uintptr_t*)root;
    for (int i = 0; i < 2000; i++) {
      uintptr_t val = p[i];
      if (val == 0x80000818) {
        LOG_INFO("Found eventListArray at SleeRoot offset 0x%lx -> %p", (long)i*8, (void*)val);
        for (int k = 0; k < 128; k++) {
          g_globalLists.push_back((SnoopLockedList<SnoopEvent>*)((char*)val + k * 144));
        }
      }
      if (val >= 0x80000000 && val < 0x8fffffff && (val % 8 == 0)) {
        for (int offset = 0; offset < 600; offset += 4) {
          char* name = (char*)val + offset;
          if (name[0] >= 32 && name[0] <= 126 && name[1] >= 32 && name[1] <= 126) {
            if (strcmp(name, "Timer") == 0) {
              g_firstInterface = (SnoopInterfaceInstance*)val;
              LOG_INFO("Found g_firstInterface ('Timer') at SleeRoot offset 0x%lx -> %p", (long)i*8, (void*)val);
            }
          }
        }
      }
    }
    
    LOG_INFO("Scanning 100MB SHM for ALL events in ALL lists...");
    g_globalLists.clear();
    int totalEvents = 0;
    for (long i = 0; i < 12500000; i++) {
        uintptr_t selfAddr = (uintptr_t)((char*)root + i * 8);
        uintptr_t next = p[i];
        uintptr_t prev = p[i+1];
        if (next >= 0x80000000 && next < 0x90000000 && 
            prev >= 0x80000000 && prev < 0x90000000) {
            if (next != selfAddr && prev != selfAddr) {
                uint32_t size = ((uint32_t*)root)[i*2 - 2];
                if (size > 0 && size < 5000) {
                    // Walk this list
                    uintptr_t* head = (uintptr_t*)((char*)root + i*8);
                    uintptr_t* curr = (uintptr_t*)next;
                    int count = 0;
                    while (curr && curr != head && count < size + 10) {
                        count++;
                        totalEvents++;
                        uint32_t len = ((uint32_t*)curr)[12];
                        if (len > 0 && len < 10000) {
                            char* data = (char*)curr + 64;
                            bool isEscher = false;
                            for (uint32_t k = 0; k < len && k < 100; k++) {
                                if (memcmp(data + k, "Escher", 6) == 0) isEscher = true;
                            }
                            if (isEscher) LOG_INFO("Found ESCHER event at %p len %u", curr, len);
                            
                            EventSignature sig = { (SnoopEvent*)curr, (size_t)len, 0 }; // Simple sig
                            if (seenEvents.find(sig) == seenEvents.end()) {
                                writeEvent((SnoopEvent*)curr, "Scanned", 0);
                                seenEvents.insert(sig);
                                eventCount++;
                            }
                        }
                        curr = (uintptr_t*)curr[2]; // Next pointer at offset 16? Or 32?
                        // Let's check offset 16 (curr[2]) and 32 (curr[4])
                        if (curr && ((uintptr_t)curr < 0x80000000 || (uintptr_t)curr > 0x8fffffff)) break;
                    }
                }
            }
        }
    }
    LOG_INFO("Total unique events found in scan: %d", (int)seenEvents.size());
    fflush(stdout);
  }

  // 1. Scan Global Lists
  for (auto el : g_globalLists) {
    uintptr_t* head = (uintptr_t*)((char*)el + 16);
    SnoopEvent* ev = (SnoopEvent*)head[0];
    int evCount = 0;
    while (ev && (uintptr_t)ev != (uintptr_t)head && evCount < 200) {
      evCount++;
      if ((uintptr_t)ev < 0x80000000 || (uintptr_t)ev > 0x8fffffff) break;
      uint32_t len = ((uint32_t*)ev)[12];
      if (len > 10000) len = 0;
      uint32_t h = 0;
      if (len > 0) {
        unsigned char* d = (unsigned char*)((char*)ev + 64);
        for (uint32_t k = 0; k < len && k < 64; k++) h = (h * 31) + d[k];
      }
      EventSignature sig = { ev, (size_t)len, h };
      if (seenEvents.find(sig) == seenEvents.end()) {
        LOG_DEBUG("Found Global event %p len %u", ev, len);
        writeEvent(ev, "Global", 0);
        seenEvents.insert(sig);
        eventCount++;
      }
      ev = (SnoopEvent*)((uintptr_t*)ev)[2];
    }
  }

  // 2. Scan Instance Lists
  static int eventListOffset = -1;
  if (g_firstInterface) {
    for (int i = 0; i < 400; i++) {
      SnoopInterfaceInstance* ii = (SnoopInterfaceInstance*)((char*)g_firstInterface + i * 560);
      if ((uintptr_t)ii < 0x80000000 || (uintptr_t)ii > 0x90000000) break;
      char* name = (char*)ii + 240;
      if (name[0] < 32 || name[0] > 126) continue;

      if (eventListOffset == -1) {
        uintptr_t* p = (uintptr_t*)ii;
        for (int j = 1; j < 60; j++) {
          if (p[j] == (uintptr_t)&p[j] && p[j + 1] == (uintptr_t)&p[j]) {
            eventListOffset = (j - 1) * 8;
            break;
          }
        }
      }
      if (eventListOffset == -1) continue;

      SnoopLockedList<SnoopEvent>* el = (SnoopLockedList<SnoopEvent>*)((char*)ii + eventListOffset);
      uintptr_t* head = (uintptr_t*)((char*)el + 16);
      SnoopEvent* ev = (SnoopEvent*)head[0];
      int evCount = 0;
      while (ev && (uintptr_t)ev != (uintptr_t)head && evCount < 100) {
        evCount++;
        if ((uintptr_t)ev < 0x80000000 || (uintptr_t)ev > 0x8fffffff) break;
        uint32_t len = ((uint32_t*)ev)[12];
        if (len > 10000) len = 0;
        uint32_t h = 0;
        if (len > 0) {
          unsigned char* d = (unsigned char*)((char*)ev + 64);
          for (uint32_t k = 0; k < len && k < 64; k++) h = (h * 31) + d[k];
        }
        EventSignature sig = { ev, (size_t)len, h };
        if (seenEvents.find(sig) == seenEvents.end()) {
          LOG_DEBUG("Found Instance event %p len %u on %s", ev, len, name);
          writeEvent(ev, name, 0);
          seenEvents.insert(sig);
          eventCount++;
        }
        ev = (SnoopEvent*)((uintptr_t*)ev)[2];
      }
    }
  }
}

void SnoopManager::writeEvent(SnoopEvent* ev, const char* name, int direction) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  slee_snoop_hdr_t snoopHdr;
  memset(&snoopHdr, 0, sizeof(snoopHdr));
  snoopHdr.version = 1;
  snoopHdr.direction = direction;
  strncpy(snoopHdr.event_type, name, 31);
  uint32_t len = ((uint32_t*)ev)[12];
  if (len > 10000) len = 0;

  pcaprec_hdr_s rec = { (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec, (uint32_t)(sizeof(snoopHdr) + len), (uint32_t)(sizeof(snoopHdr) + len) };
  fwrite(&rec, sizeof(rec), 1, pcapFile);
  fwrite(&snoopHdr, sizeof(snoopHdr), 1, pcapFile);
  if (len > 0) fwrite((char*)ev + 64, len, 1, pcapFile);
  fflush(pcapFile);
}

FileDescriptor::~FileDescriptor() {}

TelnetFD::TelnetFD(int sockID, SnoopManager& mgr, ConnectionManager& conn) : snoopMgr(mgr), connMgr(conn) {
    fileDescriptor = sockID;
    LOG_INFO("New telnet connection from client %d", sockID);
    dprintf(fileDescriptor, "Snoop Snoop Terminal Ready\n> ");
}
TelnetFD::~TelnetFD() { close(fileDescriptor); }
char FileDescriptor::buffer[10240];

void TelnetFD::process() {
    int n = read(fileDescriptor, buffer, 10239);
    if (n <= 0) { connMgr.remove(this); delete this; return; }
    buffer[n] = 0;
    if (strncasecmp(buffer, "START", 5) == 0) {
        char* file = strchr(buffer, ' ');
        if (file) {
            while (*file == ' ') file++;
            char* end = strchr(file, '\r');
            if (!end) end = strchr(file, '\n');
            if (end) *end = 0;
            snoopMgr.start(file);
            dprintf(fileDescriptor, "OK Capture started to %s\n", file);
        }
    } else if (strncasecmp(buffer, "STOP", 4) == 0) {
        snoopMgr.stop();
        dprintf(fileDescriptor, "OK Capture stopped\n");
    } else if (strncasecmp(buffer, "STATUS", 6) == 0) {
        dprintf(fileDescriptor, "Capturing: %s, Events: %lu\n", snoopMgr.isActive() ? "YES" : "NO", (unsigned long)snoopMgr.getEventCount());
    } else if (strncasecmp(buffer, "QUIT", 4) == 0) {
        connMgr.remove(this); delete this; return;
    }
    dprintf(fileDescriptor, "> ");
}

TelnetListener::TelnetListener(int port, SnoopManager& mgr, ConnectionManager& conn) : snoopMgr(mgr), connMgr(conn) {
    fileDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fileDescriptor, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(fileDescriptor, (struct sockaddr*)&addr, sizeof(addr));
    listen(fileDescriptor, 5);
}
void TelnetListener::process() {
    int clientFd = accept(fileDescriptor, NULL, NULL);
    if (clientFd >= 0) connMgr.add(new TelnetFD(clientFd, snoopMgr, connMgr));
}

ConnectionManager::ConnectionManager() { FD_ZERO(&storedFDSet); }
void ConnectionManager::add(FileDescriptor* fd) { fds.insert(fd); FD_SET(fd->fileDescriptor, &storedFDSet); }
void ConnectionManager::remove(FileDescriptor* fd) { fds.erase(fd); FD_CLR(fd->fileDescriptor, &storedFDSet); }
void ConnectionManager::process() {
    fd_set readSet = storedFDSet;
    struct timeval tv = {0, 100000}; // 100ms
    int maxFd = 0;
    for (auto f : fds) if (f->fileDescriptor > maxFd) maxFd = f->fileDescriptor;
    if (select(maxFd + 1, &readSet, NULL, NULL, &tv) > 0) {
        std::vector<FileDescriptor*> currentFds(fds.begin(), fds.end());
        for (auto f : currentFds) if (f->isReadable(&readSet)) f->process();
    }
}

int main() {
  SnoopManager mgr;
  if (!mgr.attach()) return 1;
  ConnectionManager conn;
  TelnetListener* listener = new TelnetListener(9999, mgr, conn);
  conn.add(listener);

  LOG_INFO("Snoop Terminal ready on port 9999");
  
  std::thread scraperThread([&]() {
    LOG_INFO("Scraper thread started");
    fflush(stdout);
    while (true) {
      mgr.scrape();
      usleep(10000); // 10ms
    }
  });
  scraperThread.detach();

  while (true) conn.process();
  return 0;
}
