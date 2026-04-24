/******************************************************************************
 *
 * File: sleeSnoop.h
 *
 * Description: Self-contained passive shared-memory snooper for SLEE events.
 *              No dependency on internal SLEE headers.
 *
 *****************************************************************************/

#ifndef _SLEE_SNOOP_H
#define _SLEE_SNOOP_H

#include <stdio.h>
#include <string>
#include <set>
#include <vector>
#include <stdint.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/time.h>

// --- SLEE Internal Constants ---
#define INTERFACE_NAME_SIZE         20
#define APPLICATION_NAME_SIZE       40
#define EVENT_TYPE_NAME_SIZE        64
#define INTERFACE_EXEC_SIZE         20
#define INTERFACE_PATH_SIZE         100

// --- PCAP Headers ---
struct pcap_hdr_s {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcaprec_hdr_s {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct slee_snoop_hdr_t {
    uint16_t version;
    uint16_t direction;      /* 0: Inbound, 1: Outbound */
    uint32_t interface_id;
    uint32_t dialog_id;
    char     event_type[32];
};

// --- SLEE Memory Mirror Structures ---

struct SnoopFastSemaphore {
    volatile long fastLock[1];
};

struct SnoopSemaphore {
    int type;
    SnoopFastSemaphore fast;
    char padding[56]; // Pad to size of union
};

template <class T>
struct SnoopListElement {
    void* currentList;
    T* next;
    T* prev;
    int owningProcess;
};

template <class T>
struct SnoopList {
    int size;
    int lowLimit;
    SnoopListElement<T> headElement;
};

template <class T>
struct SnoopLockedList {
    SnoopList<T> list;
    SnoopSemaphore lock;
};

struct SnoopEventType {
    SnoopListElement<SnoopEventType> base;
    char typeName[EVENT_TYPE_NAME_SIZE];
};

struct SnoopEvent {
    SnoopListElement<SnoopEvent> base;
    void* dialog;
    long length;
    bool lastEvent;
    SnoopEventType* eventType;
    char data[1];
};

struct SnoopInterfaceInstance {
    SnoopListElement<SnoopInterfaceInstance> base;
    void* vtable; 
    SnoopLockedList<SnoopEvent> eventList;
    SnoopLockedList<SnoopEvent> managementEvents;
    
    // Member variables for offset calculation
    long watchdogId;
    SnoopSemaphore semaphore;
    int intState;
    int intType;
    int processID;
    char interfaceExec[INTERFACE_EXEC_SIZE];
    char interfaceName[INTERFACE_NAME_SIZE];
};

struct SnoopApplicationInstance {
    void* vtable;
    SnoopListElement<SnoopApplicationInstance> base;
    SnoopEvent* currentEvent;
    SnoopLockedList<SnoopEvent> managementEvents;
    
    // ...
    char padding[100];
    char applicationName[APPLICATION_NAME_SIZE];
};

struct SnoopRoot {
    int eventsHandled;
    char padding[8]; // Alignment
    
    // We skip the first few lists and jump to interfaceInstanceList
    // This part is very sensitive to the exact order in sleeRoot.h
    // Based on sleeRoot.h:
    // callInstanceList, usedCallInstanceList, serviceList, usedServiceList,
    // serviceKeyList, applicationList, usedApplicationList, dialogList,
    // interfaceInstanceList ...
    
    SnoopLockedList<void*> lists[8]; 
    SnoopLockedList<SnoopInterfaceInstance> interfaceInstanceList;
    SnoopLockedList<void*> usedInterfaceInstanceList;
    SnoopLockedList<SnoopApplicationInstance> applicationInstanceList;
};

// --- Management Classes ---

class FileDescriptor {
public:
    virtual ~FileDescriptor();
    virtual void process() = 0;
    bool isReadable(fd_set *workingSet) { return FD_ISSET(fileDescriptor, workingSet); }
    int fileDescriptor;
protected:
    static char buffer[10240];
};

class ConnectionManager {
public:
    ConnectionManager();
    void add(FileDescriptor *fd);
    void remove(FileDescriptor *fd);
    void process();
    fd_set &getFDSet() { return storedFDSet; }
private:
    fd_set storedFDSet;
    std::set<FileDescriptor *> fds;
};

class SnoopManager {
public:
    SnoopManager();
    ~SnoopManager();

    bool attach();
    bool start(const std::string &filename);
    void stop();
    void setFilter(const std::string &name);
    void scrape();
    std::string listComponents();
    
    bool isActive() const { return capturing; }
    uint64_t getEventCount() const { return eventCount; }

private:
    void writePcapHeader();
    void writeEvent(SnoopEvent *event, const char* name, int direction);

    SnoopRoot* root;
    FILE *pcapFile;
    bool capturing;
    std::set<std::string> filters;
    uint64_t eventCount;
    
    struct EventSignature {
        void* ptr;
        size_t len;
        uint32_t hash;
        bool operator<(const EventSignature& other) const {
            if (ptr != other.ptr) return ptr < other.ptr;
            if (len != other.len) return len < other.len;
            return hash < other.hash;
        }
    };
    std::set<EventSignature> seenEvents;
};

class TelnetFD : public FileDescriptor {
public:
    TelnetFD(int sockID, SnoopManager &mgr, ConnectionManager &conn);
    virtual ~TelnetFD();
    virtual void process();
    void write(const char *text, int size);
private:
    SnoopManager &snoopMgr;
    ConnectionManager &connMgr;
};

class TelnetListener : public FileDescriptor {
public:
    TelnetListener(int port, SnoopManager &mgr, ConnectionManager &conn);
    virtual void process();
private:
    SnoopManager &snoopMgr;
    ConnectionManager &connMgr;
};

#endif
