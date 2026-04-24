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

#define LOG_INFO(msg, ...) printf("[INFO] " msg "\n", ##__VA_MAX_ARGS__)
#define LOG_DEBUG(msg, ...) printf("[DEBUG] " msg "\n", ##__VA_MAX_ARGS__)
#define LOG_ERROR(msg, ...) printf("[ERROR] " msg "\n", ##__VA_MAX_ARGS__)

static SnoopInterfaceInstance* g_firstInterface = nullptr;
static SnoopApplicationInstance* g_firstAppInst = nullptr;
static std::vector<SnoopLockedList<SnoopEvent>*> g_globalLists;

struct EventSignature {
  SnoopEvent* addr;
  size_t len;
  uint32_t hash;
  bool operator<(const EventSignature& other) const {
    if (addr != other.addr) return addr < other.addr;
    if (len != other.len) return len < other.len;
    return hash < other.hash;
  }
};

class SnoopManager {
public:
  SnoopManager() : root(nullptr), pcapFile(nullptr), capturing(false), eventCount(0) {}
  bool attach();
  void startCapture(const char* filename);
  void stopCapture();
  void scrape();
  void writeEvent(SnoopEvent* ev, const char* name, int direction);
  bool isCapturing() { return capturing; }
  int getEventCount() { return eventCount; }

private:
  void* root;
  FILE* pcapFile;
  std::atomic<bool> capturing;
  int eventCount;
  std::set<EventSignature> seenEvents;
};

bool SnoopManager::attach() {
  char* sleeFile = getenv("SLEE_FILE");
  if (!sleeFile) sleeFile = (char*)"/IN/service_packages/SLEE/tmp/slee";
  key_t key = ftok(sleeFile, 'S');
  int shmid = shmget(key, 0, 0);
  if (shmid < 0) {
    LOG_ERROR("Could not find SHM segment. Is SLEE running?");
    return false;
  }
  root = shmat(shmid, (void*)0x80000000, SHM_RDONLY);
  if (root == (void*)-1) {
    LOG_ERROR("Could not attach to SHM at 0x80000000.");
    return false;
  }
  LOG_INFO("Attached to SHM at %p.", root);
  return true;
}

void SnoopManager::startCapture(const char* filename) {
  pcapFile = fopen(filename, "wb");
  if (!pcapFile) return;
  pcap_hdr_s header = { 0xa1b2c3d4, 2, 4, 0, 0, 65535, 147 };
  fwrite(&header, sizeof(header), 1, pcapFile);
  seenEvents.clear();
  eventCount = 0;
  capturing = true;
}

void SnoopManager::stopCapture() {
  capturing = false;
  if (pcapFile) {
    fclose(pcapFile);
    pcapFile = nullptr;
  }
}

void SnoopManager::scrape() {
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
      if (val > 0x80000000 && val < 0x8fffffff && (val % 8 == 0)) {
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
  strncpy(snoopHdr.interfaceName, name, 31);
  uint32_t len = ((uint32_t*)ev)[12];
  if (len > 10000) len = 0;

  pcaprec_hdr_s rec = { (uint32_t)tv.tv_sec, (uint32_t)tv.tv_usec, (uint32_t)(sizeof(snoopHdr) + len), (uint32_t)(sizeof(snoopHdr) + len) };
  fwrite(&rec, sizeof(rec), 1, pcapFile);
  fwrite(&snoopHdr, sizeof(snoopHdr), 1, pcapFile);
  if (len > 0) fwrite((char*)ev + 64, len, 1, pcapFile);
  fflush(pcapFile);
}

class Connection {
public:
  Connection(int fd, SnoopManager& mgr) : fd(fd), mgr(mgr) {}
  void run() {
    char buf[1024];
    while (true) {
      int n = read(fd, buf, 1023);
      if (n <= 0) break;
      buf[n] = 0;
      if (strncmp(buf, "START", 5) == 0) {
        char* file = strchr(buf, ' ');
        if (file) {
          while (*file == ' ') file++;
          char* end = strchr(file, '\r');
          if (!end) end = strchr(file, '\n');
          if (end) *end = 0;
          mgr.startCapture(file);
          dprintf(fd, "OK Capture started to %s\n", file);
        }
      } else if (strncmp(buf, "STOP", 4) == 0) {
        mgr.stopCapture();
        dprintf(fd, "OK Capture stopped\n");
      } else if (strncmp(buf, "STATUS", 6) == 0) {
        dprintf(fd, "Capturing: %s, Events: %d\n", mgr.isCapturing() ? "YES" : "NO", mgr.getEventCount());
      } else if (strncmp(buf, "QUIT", 4) == 0) {
        break;
      }
    }
    close(fd);
  }
private:
  int fd;
  SnoopManager& mgr;
};

int main() {
  SnoopManager mgr;
  if (!mgr.attach()) return 1;

  int serverFd = socket(AF_INET, SOCK_STREAM, 0);
  int one = 1;
  setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(9999);
  addr.sin_addr.s_addr = INADDR_ANY;
  bind(serverFd, (struct sockaddr*)&addr, sizeof(addr));
  listen(serverFd, 5);

  LOG_INFO("Snoop Terminal ready on port 9999");

  std::thread scraperThread([&]() {
    while (true) {
      mgr.scrape();
      usleep(10000); // 10ms
    }
  });

  while (true) {
    int clientFd = accept(serverFd, NULL, NULL);
    if (clientFd >= 0) {
      std::thread([&, clientFd]() {
        Connection conn(clientFd, mgr);
        conn.run();
      }).detach();
    }
  }

  return 0;
}
