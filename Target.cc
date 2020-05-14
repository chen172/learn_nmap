#include <iostream>
#include <list>
#include <time.h>
#include <linux/socket.h> //sockaddr_storage
#include <arpa/inet.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned short u16;

//#include "libnetutil/netutil.h"
typedef enum { devt_ethernet, devt_loopback, devt_p2p, devt_other  } devtype;

//osscan2.h
/* How many syn packets do we send to TCP sequence a host? */
#define NUM_SEQ_SAMPLES 6
struct seq_info {
  int responses;
  int ts_seqclass; /* TS_SEQ_* defines in nmap.h */
  int ipid_seqclass; /* IPID_SEQ_* defines in nmap.h */
  u32 seqs[NUM_SEQ_SAMPLES];
  u32 timestamps[NUM_SEQ_SAMPLES];
  int index;
  u16 ipids[NUM_SEQ_SAMPLES];
  time_t lastboot; /* 0 means unknown */
};

//osscan2.h
/* The method used to calculate the Target::distance, included in OS
   fingerprints. */
enum dist_calc_method {
        DIST_METHOD_NONE,
        DIST_METHOD_LOCALHOST,
        DIST_METHOD_DIRECT,
        DIST_METHOD_ICMP,
        DIST_METHOD_TRACEROUTE
};

//timing.h
struct timeout_info {
  int srtt; /* Smoothed rtt estimate (microseconds) */
  int rttvar; /* Rout trip time variance */
  int timeout; /* Current timeout threshold (microseconds) */
};

//Target.h
struct host_timeout_nfo {
  unsigned long msecs_used; /* How many msecs has this Target used? */
  bool toclock_running; /* Is the clock running right now? */
  struct timeval toclock_start; /* When did the clock start? */
  time_t host_start, host_end; /* The absolute start and end for this host */
};


//nbase_misc.c
/* This function is an easier version of inet_ntop because you don't
   need to pass a dest buffer.  Instead, it returns a static buffer that
   you can use until the function is called again (by the same or another
   thread in the process).  If there is a weird error (like sslen being
   too short) then NULL will be returned. */
const char *inet_ntop_ez(const struct sockaddr_storage *ss, size_t sslen) {

  const struct sockaddr_in *sin = (struct sockaddr_in *) ss;
  static char str[INET6_ADDRSTRLEN];
#if HAVE_IPV6
  const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) ss;
#endif

  str[0] = '\0';

  if (sin->sin_family == AF_INET) {
    if (sslen < sizeof(struct sockaddr_in))
      return NULL;
    return inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str));
  }
#if HAVE_IPV6
  else if(sin->sin_family == AF_INET6) {
    if (sslen < sizeof(struct sockaddr_in6))
      return NULL;
    return inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str));
  }
#endif
  //Some laptops report the ip and address family of disabled wifi cards as null
  //so yes, we will hit this sometimes.
  return NULL;
}


//Target.h
struct TracerouteHop {
  struct sockaddr_storage tag;
  bool timedout;
  std::string name;
  struct sockaddr_storage addr;
  int ttl;
  float rtt; /* In milliseconds. */

  int display_name(char *buf, size_t len) {
    if (name.empty())
      //return Snprintf(buf, len, "%s", inet_ntop_ez(&addr, sizeof(addr)));
	return snprintf(buf, len, "%s", inet_ntop_ez(&addr, sizeof(addr)));
    else
      //return Snprintf(buf, len, "%s (%s)", name.c_str(), inet_ntop_ez(&addr, sizeof(addr)));
	return snprintf(buf, len, "%s (%s)", name.c_str(), inet_ntop_ez(&addr, sizeof(addr)));
  }
};

//liblua/lauxlib.h:
#define LUA_NOREF       (-2)


//nse_main.h
class ScriptResult
{
  private:
    std::string id;
    /* Structured output table, an integer ref in L_NSE[LUA_REGISTRYINDEX]. */
    int output_ref;
    /* Unstructured output string, for scripts that do not return a structured
       table, or return a string in addition to a table. */
    std::string output_str;
  public:
    ScriptResult() {
      output_ref = LUA_NOREF;
    }
    void clear (void);
    //void set_output_tab (lua_State *, int);
    void set_output_str (const char *);
    void set_output_str (const char *, size_t);
    std::string get_output_str (void) const;
    void set_id (const char *);
    const char *get_id (void) const;
    void write_xml() const;
};

typedef std::list<ScriptResult> ScriptResults;

//portreasons.h
typedef unsigned short reason_t;
/* stored inside a Port Object and describes
 * why a port is in a specific state */
typedef struct port_reason {
        reason_t reason_id;
        union {
                struct sockaddr_in in;
                struct sockaddr_in6 in6;
                struct sockaddr sockaddr;
        } ip_addr;
        unsigned short ttl;

        int set_ip_addr(const struct sockaddr_storage *ss);
} state_reason_t;

//probespec.h
//////////////////////////////////////////////////////////////////////////////////
struct probespec_tcpdata {
  u16 dport;
  u8 flags;
};

struct probespec_udpdata {
  u16 dport;
};

struct probespec_sctpdata {
  u16 dport;
  u8 chunktype;
};

struct probespec_icmpdata {
  u8 type;
  u8 code;
};

struct probespec_icmpv6data {
  u8 type;
  u8 code;
};

#define PS_NONE 0
#define PS_TCP 1
#define PS_UDP 2
#define PS_PROTO 3
#define PS_ICMP 4
#define PS_ARP 5
#define PS_CONNECTTCP 6
#define PS_SCTP 7
#define PS_ICMPV6 8
#define PS_ND 9

/* The size of this structure is critical, since there can be tens of
   thousands of them stored together ... */
typedef struct probespec {
  /* To save space, I changed this from private enum (took 4 bytes) to
     u8 that uses #defines above */
  u8 type;
  u8 proto; /* If not PS_ARP -- Protocol number ... eg IPPROTO_TCP, etc. */
  union {
    struct probespec_tcpdata tcp; /* If type is PS_TCP or PS_CONNECTTCP. */
    struct probespec_udpdata udp; /* PS_UDP */
    struct probespec_sctpdata sctp; /* PS_SCTP */
    struct probespec_icmpdata icmp; /* PS_ICMP */
    struct probespec_icmpv6data icmpv6; /* PS_ICMPV6 */
    /* Nothing needed for PS_ARP, since src mac and target IP are
       avail from target structure anyway */
  } pd;
} probespec;
/////////////////////////////////////////////////////////////////////////////

using namespace std;

class FingerPrintResults;


//portlist.h



class Target {
 public: /* For now ... TODO: a lot of the data members should be made private */
  Target();
  ~Target();
  /* Recycles the object by freeing internal objects and reinitializing
     to default state */
  void Recycle();
  /* Returns the address family of the destination address. */
  int af() const;
  /* Fills a sockaddr_storage with the AF_INET or AF_INET6 address
     information of the target.  This is a preferred way to get the
     address since it is portable for IPv6 hosts.  Returns 0 for
     success. ss_len must be provided.  It is not examined, but is set
     to the size of the sockaddr copied in. */
  int TargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len) const;
  const struct sockaddr_storage *TargetSockAddr() const;
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setTargetSockAddr(const struct sockaddr_storage *ss, size_t ss_len);
  // Returns IPv4 target host address or {0} if unavailable.
  struct in_addr v4host() const;
  const struct in_addr *v4hostip() const;
  const struct in6_addr *v6hostip() const;
  /* The source address used to reach the target */
  int SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) const;
  const struct sockaddr_storage *SourceSockAddr() const;
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setSourceSockAddr(const struct sockaddr_storage *ss, size_t ss_len);
  struct sockaddr_storage source() const;
  const struct in_addr *v4sourceip() const;
  const struct in6_addr *v6sourceip() const;
  /* The IPv4 or IPv6 literal string for the target host */
  const char *targetipstr() const { return targetipstring; }
  /* The IPv4 or IPv6 literal string for the source address */
  const char *sourceipstr() const { return sourceipstring; }
  /* Give the name from the last setHostName() call, which should be
   the name obtained from reverse-resolution (PTR query) of the IP (v4
   or v6).  If the name has not been set, or was set to NULL, an empty
   string ("") is returned to make printing easier. */
  const char *HostName() const { return hostname? hostname : "";  }
  /* You can set to NULL to erase a name or if it failed to resolve -- or
     just don't call this if it fails to resolve.  The hostname is blown
     away when you setTargetSockAddr(), so make sure you do these in proper
     order
  */
  void setHostName(const char *name);
  /* Generates a printable string consisting of the host's IP
     address and hostname (if available).  Eg "www.insecure.org
     (64.71.184.53)" or "fe80::202:e3ff:fe14:1102".  The name is
     written into the buffer provided, which is also returned.  Results
     that do not fit in buflen will be truncated. */
  const char *NameIP(char *buf, size_t buflen) const;
  /* This next version returns a STATIC buffer -- so no concurrency */
  const char *NameIP() const;

  /* Give the name from the last setTargetName() call, which is the
   name of the target given on the command line if it's a named
   host. */
  const char *TargetName() { return targetname; }
  /* You can set to NULL to erase a name.  The targetname is blown
     away when you setTargetSockAddr(), so make sure you do these in proper
     order
  */
  void setTargetName(const char *name);

  /* If the host is directly connected on a network, set and retrieve
     that information here.  directlyConnected() will abort if it hasn't
     been set yet.  */
  void setDirectlyConnected(bool connected);
  bool directlyConnected() const;
  int directlyConnectedOrUnset() const; /* 1-directly connected, 0-no, -1-we don't know*/

  /* If the host is NOT directly connected, you can set the next hop
     value here. It is OK to pass in a sockaddr_in or sockaddr_in6
     casted to sockaddr_storage*/
  void setNextHop(struct sockaddr_storage *next_hop, size_t next_hop_len);
  /* Returns the next hop for sending packets to this host.  Returns true if
     next_hop was filled in.  It might be false, for example, if
     next_hop has never been set */
  bool nextHop(struct sockaddr_storage *next_hop, size_t *next_hop_len);

  void setMTU(int devmtu);
  int MTU(void);

  /* Sets the interface type to one of:
     devt_ethernet, devt_loopback, devt_p2p, devt_other
   */
  void setIfType(devtype iftype) { interface_type = iftype; }
  /* Returns -1 if it has not yet been set with setIfType() */
  devtype ifType() { return interface_type; }
  /* Starts the timeout clock for the host running (e.g. you are
     beginning a scan).  If you do not have the current time handy,
     you can pass in NULL.  When done, call stopTimeOutClock (it will
     also automatically be stopped of timedOut() returns true) */
  void startTimeOutClock(const struct timeval *now);
  /* The complement to startTimeOutClock. */
  void stopTimeOutClock(const struct timeval *now);
  /* Is the timeout clock currently running? */
  bool timeOutClockRunning() { return htn.toclock_running; }
  /* Returns whether the host is timedout.  If the timeoutclock is
     running, counts elapsed time for that.  Pass NULL if you don't have the
     current time handy.  You might as well also pass NULL if the
     clock is not running, as the func won't need the time. */
  bool timedOut(const struct timeval *now);
  /* Return time_t for the start and end time of this host */
  time_t StartTime() { return htn.host_start; }
  time_t EndTime() { return htn.host_end; }

  /* Takes a 6-byte MAC address */
  int setMACAddress(const u8 *addy);
  int setSrcMACAddress(const u8 *addy);
  int setNextHopMACAddress(const u8 *addy); // this should be the target's own MAC if directlyConnected()

  /* Returns a pointer to 6-byte MAC address, or NULL if none is set */
  const u8 *MACAddress() const;
  const u8 *SrcMACAddress() const;
  const u8 *NextHopMACAddress() const;

/* Set the device names so that they can be returned by deviceName()
   and deviceFullName().  The normal name may not include alias
   qualifier, while the full name may include it (e.g. "eth1:1").  If
   these are non-null, they will overwrite the stored version */
  void setDeviceNames(const char *name, const char *fullname);
  const char *deviceName() const;
  const char *deviceFullName() const;

  int osscanPerformed(void);
  void osscanSetFlag(int flag);

  struct seq_info seq;
  int distance;
  enum dist_calc_method distance_calculation_method;
  FingerPrintResults *FPR; /* FP results get by the OS scan system. */
  //PortList ports;

  int weird_responses; /* echo responses from other addresses, Ie a network broadcast address */
  int flags; /* HOST_UNKNOWN, HOST_UP, or HOST_DOWN. */
  struct timeout_info to;
  char *hostname; // Null if unable to resolve or unset
  char * targetname; // The name of the target host given on the command line if it is a named host

  struct probespec traceroute_probespec;
  std::list <TracerouteHop> traceroute_hops;

  /* If the address for this target came from a DNS lookup, the list of
     resultant addresses (sometimes there are more than one) that were not scanned. */
  std::list<struct sockaddr_storage> unscanned_addrs;

#ifndef NOLUA
  ScriptResults scriptResults;
#endif

  state_reason_t reason;

  /* A probe that is known to receive a response. This is used to hold the
     current timing ping probe type during scanning. */
  probespec pingprobe;
  /* The state the port or protocol entered when the response to pingprobe was
     received. */
  int pingprobe_state;

  private:
  void Initialize();
  void FreeInternal(); // Free memory allocated inside this object
 // Creates a "presentation" formatted string out of the target's IPv4/IPv6 address
  void GenerateTargetIPString();
 // Creates a "presentation" formatted string out of the source IPv4/IPv6 address.
  void GenerateSourceIPString();
  struct sockaddr_storage targetsock, sourcesock, nexthopsock;
  size_t targetsocklen, sourcesocklen, nexthopsocklen;
  int directly_connected; // -1 = unset; 0 = no; 1 = yes
  char targetipstring[INET6_ADDRSTRLEN];
  char sourceipstring[INET6_ADDRSTRLEN];
  mutable char *nameIPBuf; /* for the NameIP(void) function to return */
  u8 MACaddress[6], SrcMACaddress[6], NextHopMACaddress[6];
  bool MACaddress_set, SrcMACaddress_set, NextHopMACaddress_set;
  struct host_timeout_nfo htn;
  devtype interface_type;
  char devname[32];
  char devfullname[32];
  int mtu;
  /* 0 (OS_NOTPERF) if os detection not performed
   * 1 (OS_PERF) if os detection performed
   * 2 (OS_PERF_UNREL) if an unreliable os detection has been performed */
  int osscan_flag;
};

int main()
{
	cout << "hello\n";
	return 0;
}
