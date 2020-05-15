#include <iostream>
#include <sstream>
#include <stdio.h>
#include <list>
#include <time.h>
#include <linux/socket.h> //sockaddr_storage
#include <arpa/inet.h>
#include <vector>
#include <assert.h>
#include <netdb.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned short u16;

//#include "libnetutil/netutil.h"
typedef enum { devt_ethernet, devt_loopback, devt_p2p, devt_other  } devtype;

//osscan2.h
/* How many syn packets do we send to TCP sequence a host? */
//要发送的syn包的个数
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
//用来计算Target::distance的方法
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


#include "NmapOps.h"
class Target {
 public: /* For now ... TODO: a lot of the data members should be made private */
  Target();
  ~Target();
  /* Recycles the object by freeing internal objects and reinitializing
     to default state */
	//通过释放内部对象和重初始化到默认状态来重新回收对象
  void Recycle();
	//返回目标地址的地址族
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

//选项结构体的一个过渡
/* This struct is used is a temporary storage place that holds options that
   can't be correctly parsed and interpreted before the entire command line has
   been read. Examples are -6 and -S. Trying to set the source address without
   knowing the address family first could result in a failure if you pass an
   IPv6 address and the address family is still IPv4. */
//这个结构体被用来作为一个短暂的储存空间，包含了选项，不能被正确解析和解释的，在整个命令行被读之前。比如-6和-S，试着设置源地址不知道地址族可能会导致失败，如果你传递一个ipv6地址而地址族还是ipv4
static struct delayed_options {
public:
	//构造函数,初始化参数
  delayed_options() {
    this->pre_max_parallelism   = -1;
    this->pre_scan_delay        = -1;
    this->pre_max_scan_delay    = -1;
    this->pre_init_rtt_timeout  = -1;
    this->pre_min_rtt_timeout   = -1;
    this->pre_max_rtt_timeout   = -1;
    this->pre_max_retries       = -1;
    this->pre_host_timeout      = -1;
#ifndef NOLUA
    this->pre_scripttimeout     = -1;
#endif
    this->iflist                = false;
    this->advanced              = false;
    this->af                    = AF_UNSPEC;
    this->decoys                = false;
    this->raw_scan_options      = false;
  }

  // Pre-specified timing parameters.
  // These are stored here during the parsing of the arguments so that we can
  // set the defaults specified by any timing template options (-T2, etc) BEFORE
  // any of these. In other words, these always take precedence over the templates.
  int   pre_max_parallelism, pre_scan_delay, pre_max_scan_delay;
  int   pre_init_rtt_timeout, pre_min_rtt_timeout, pre_max_rtt_timeout;
  int   pre_max_retries;
  long  pre_host_timeout;
#ifndef NOLUA
  double pre_scripttimeout;
#endif
  char  *machinefilename, *kiddiefilename, *normalfilename, *xmlfilename;
  bool  iflist, decoys, advanced, raw_scan_options;
  char  *exclude_spec, *exclude_file;
  char  *spoofSource, *decoy_arguments;
  const char *spoofmac;
  int af;
  std::vector<std::string> verbose_out;

  void warn_deprecated (const char *given, const char *replacement) {
    std::ostringstream os;
    os << "Warning: The -" << given << " option is deprecated. Please use -" << replacement;
    this->verbose_out.push_back(os.str());
  }

} delayed_options;
NmapOps o;

//scan_lists.h
/* just flags to indicate whether a particular port number should get tcp
 * scanned, udp scanned, or both
 */
#define SCAN_TCP_PORT	(1 << 0)
#define SCAN_UDP_PORT	(1 << 1)
#define SCAN_SCTP_PORT	(1 << 2)
#define SCAN_PROTOCOLS	(1 << 3)

/* The various kinds of port/protocol scans we can have
 * Each element is to point to an array of port/protocol numbers
 */
struct scan_lists {
        /* The "synprobes" are also used when doing a connect() ping */
        unsigned short *syn_ping_ports;
        unsigned short *ack_ping_ports;
        unsigned short *udp_ping_ports;
        unsigned short *sctp_ping_ports;
        unsigned short *proto_ping_ports;
        int syn_ping_count;
        int ack_ping_count;
        int udp_ping_count;
        int sctp_ping_count;
        int proto_ping_count;
        //the above fields are only used for host discovery
        //the fields below are only used for port scanning
        unsigned short *tcp_ports;
        int tcp_count;
        unsigned short *udp_ports;
        int udp_count;
        unsigned short *sctp_ports;
        int sctp_count;
        unsigned short *prots;
        int prot_count;
};
struct scan_lists ports = { 0 };

/* getpts() and getpts_simple() (see above) are wrappers for this function */

static void getpts_aux(const char *origexpr, int nested, u8 *porttbl, int range_type, int *portwarning, bool change_range_type) {
  long rangestart = -2343242, rangeend = -9324423;
  const char *current_range;
  char *endptr;
  char servmask[128];  // A protocol name can be up to 127 chars + nul byte
  int i;

  /* An example of proper syntax to use in error messages. */
  const char *syntax_example;
  if (change_range_type)
    syntax_example = "-100,200-1024,T:3000-4000,U:60000-";
  else
    syntax_example = "-100,200-1024,3000-4000,60000-";

  current_range = origexpr;
  do {
    while (isspace((int) (unsigned char) *current_range))
      current_range++; /* I don't know why I should allow spaces here, but I will */

    

    if (*current_range == '[') {
      if (nested)
        printf("Can't nest [] brackets in port/protocol specification");

      //getpts_aux(++current_range, 1, porttbl, range_type, portwarning);

      // Skip past the ']'. This is OK because we can't nest []s
      while (*current_range != ']' && *current_range != '\0')
        current_range++;
      if (*current_range == ']')
        current_range++;

      // Skip over a following ',' so we're ready to keep parsing
      if (*current_range == ',')
        current_range++;

      continue;
    } else if (*current_range == ']') {
      if (!nested)
        printf("Unexpected ] character in port/protocol specification");

      return;
    } else if (*current_range == '-') {
      if (range_type & SCAN_PROTOCOLS)
        rangestart = 0;
      else
        rangestart = 1;
    } else if (isdigit((int) (unsigned char) *current_range)) {
	//得到了端口号
      rangestart = strtol(current_range, &endptr, 10);
      if (range_type & SCAN_PROTOCOLS) {
        if (rangestart < 0 || rangestart > 255)
          printf("Protocols specified must be between 0 and 255 inclusive");
      } else {
        if (rangestart < 0 || rangestart > 65535)
          printf("Ports specified must be between 0 and 65535 inclusive");
      }
      current_range = endptr;
      while (isspace((int) (unsigned char) *current_range)) current_range++;
    } else {
      printf("Error #485: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }

    /* Now I have a rangestart, time to go after rangeend */
	//现在有了rangestart
    if (!*current_range || *current_range == ',' || *current_range == ']') {
      /* Single port specification */
	//单个端口
      rangeend = rangestart;
    } else if (*current_range == '-') {
      current_range++;
      if (!*current_range || *current_range == ',' || *current_range == ']') {
        /* Ended with a -, meaning up until the last possible port */
        if (range_type & SCAN_PROTOCOLS)
          rangeend = 255;
        else
          rangeend = 65535;
      } else if (isdigit((int) (unsigned char) *current_range)) {
        rangeend = strtol(current_range, &endptr, 10);
        if (range_type & SCAN_PROTOCOLS) {
          if (rangeend < 0 || rangeend > 255)
            printf("Protocols specified must be between 0 and 255 inclusive");
        } else {
          if (rangeend < 0 || rangeend > 65535)
            printf("Ports specified must be between 0 and 65535 inclusive");
        }
        current_range = endptr;
      } else {
        printf("Error #486: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
      }
      if (rangeend < rangestart) {
        printf("Your %s range %ld-%ld is backwards. Did you mean %ld-%ld?",
              (range_type & SCAN_PROTOCOLS) ? "protocol" : "port",
              rangestart, rangeend, rangeend, rangestart);
      }
    } else {
      printf("Error #487: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }

	//现在有了rangeend,不处理
    /* Now I have a rangestart and a rangeend, so I can add these ports */
    while (rangestart <= rangeend) {
	#if 1
      if (porttbl[rangestart] & range_type) {
        if (!(*portwarning)) {
          printf("WARNING: Duplicate port number(s) specified.  Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm).");
          (*portwarning)++;
        }
      } else {
        if (nested) {
          ;
        } else { //在这里赋值
          porttbl[rangestart] |= range_type;
        }
      }
	#endif
      rangestart++;
    }

    /* Find the next range */
    while (isspace((int) (unsigned char) *current_range)) current_range++;

    if (*current_range == ']') {
      if (!nested)
        printf("Unexpected ] character in port/protocol specification");
      return;
    }

    if (*current_range && *current_range != ',') {
      printf("Error #488: Your port specifications are illegal.  Example of proper form: \"%s\"", syntax_example);
    }
    if (*current_range == ',')
      current_range++;
  } while (current_range && *current_range);

}

/* This function is like getpts except it only allocates space for and stores
  values into one unsigned short array, instead of an entire scan_lists struct
  For that reason, T:, U:, S: and P: restrictions are not allowed and only one
  bit in range_type may be set. */
	//这个函数像getpts,除了它只分配空间和储存值给unsigned short数组,而不是整个scan_lists结构
void getpts_simple(const char *origexpr, int range_type,
                   unsigned short **list, int *count) {
  u8 *porttbl;
  int portwarning = 0;
  int i, j;

  /* Make sure that only one bit in range_type is set (or that range_type is 0,
     which is useless but not incorrect). */
  assert((range_type & (range_type - 1)) == 0);

	//初始化为0
  porttbl = (u8 *) calloc(65536, 1);

  /* Get the ports but do not allow changing the type with T:, U:, or P:. */
	//把端口赋值给porttbl
  getpts_aux(origexpr, 0, porttbl, range_type, &portwarning, false);

  /* Count how many are set. */
	//得到端口的个数
  *count = 0;
  for (i = 0; i <= 65535; i++) {
    if (porttbl[i] & range_type)
      (*count)++;
  }
	
  if (*count == 0) {
    free(porttbl);
    return;
  }

  *list = (unsigned short *) calloc(*count * sizeof(unsigned short), 1);

  /* Fill in the list. */
	//填充端口，作为返回值
  for (i = 0, j = 0; i <= 65535; i++) {
    if (porttbl[i] & range_type)
      (*list)[j++] = i;
  }

  free(porttbl);
}
void validate_scan_lists(scan_lists &vports, NmapOps &vo) {

	
	//处理这个
  if (vo.pingtype == PINGTYPE_UNKNOWN) {
    
	//扫描的是TCP端口
	//PINGTYPE_TCP是16
      vo.pingtype = PINGTYPE_TCP; // if nonr00t
	//得到要扫描的端口号和端口数量,SCAN_TCP_PORT是1
	//#define DEFAULT_PING_CONNECT_PORT_SPEC "80,443",默认的端口范围
      getpts_simple(DEFAULT_PING_CONNECT_PORT_SPEC, SCAN_TCP_PORT,
                    &vports.syn_ping_ports, &vports.syn_ping_count);

  }
	
//	for (int i = 0; i < vports.syn_ping_count; i++)
//		printf("port is %d\n", vports.syn_ping_ports[i]);
	#if 1
	
  if ((vo.pingtype & PINGTYPE_TCP) && (!vo.isr00t)) {
	
  
    vo.pingtype &= ~PINGTYPE_TCP_USE_ACK;
    vo.pingtype |= PINGTYPE_TCP_USE_SYN;
  }

  if (!vo.isr00t) {
    if (vo.pingtype & (PINGTYPE_ICMP_PING | PINGTYPE_ICMP_MASK | PINGTYPE_ICMP_TS)) {
      printf("Warning:  You are not root -- using TCP pingscan rather than ICMP");
      vo.pingtype = PINGTYPE_TCP;
      if (vports.syn_ping_count == 0) {
        getpts_simple(DEFAULT_TCP_PROBE_PORT_SPEC, SCAN_TCP_PORT, &vports.syn_ping_ports, &vports.syn_ping_count);
        assert(vports.syn_ping_count > 0);
      }
    }
  }
#endif
}

//services.cc
/* This structure is the key for looking up services in the
   port/proto -> service map. */
struct port_spec {
  int portno;
  std::string proto;

  /* Sort in the usual nmap-services order. */
  bool operator<(const port_spec& other) const {
    if (this->portno < other.portno)
      return true;
    else if (this->portno > other.portno)
      return false;
    else
      return this->proto < other.proto;
  }
};

//nmap.cc
#if 0
/* Search for a file in the standard data file locations. The result is stored
   in filename_returned, which must point to an allocated buffer of at least
   bufferlen bytes. Returns true iff the search should be considered finished
   (i.e., the caller shouldn't try to search anywhere else for the file).

   Options like --servicedb and --versiondb set explicit locations for
   individual data files. If any of these were used those locations are checked
   first, and no other locations are checked.

   After that, the following directories are searched in order. First an
   NMAP_UPDATE_CHANNEL subdirectory is checked in all of them, then they are all
   tried again directly.
    * --datadir
    * $NMAPDIR
    * [Non-Windows only] ~/.nmap
    * [Windows only] ...\Users\<user>\AppData\Roaming\nmap
    * The directory containing the nmap binary
    * [Non-Windows only] The directory containing the nmap binary plus
      "/../share/nmap"
    * NMAPDATADIR */
int nmap_fetchfile(char *filename_returned, int bufferlen, const char *file) {
  const char *UPDATES_PREFIX = "updates/" NMAP_UPDATE_CHANNEL "/";
  std::map<std::string, std::string>::iterator iter;
  char buf[BUFSIZ];
  int res;

  /* Check the map of requested data file names. */
  iter = o.requested_data_files.find(file);
  if (iter != o.requested_data_files.end()) {
    strncpy(filename_returned, iter->second.c_str(), bufferlen);
    /* If a special file name was requested, we must not return any other file
       name. Return a positive result even if the file doesn't exist or is not
       readable. It is the caller's responsibility to report the error if the
       file can't be accessed. */
    res = file_is_readable(filename_returned);
    return res != 0 ? res : 1;
  }

  /* Try updates directory first. */
  strncpy(buf, UPDATES_PREFIX, sizeof(buf));
  strncpy(buf + strlen(UPDATES_PREFIX), file, sizeof(buf) - strlen(UPDATES_PREFIX));
  res = nmap_fetchfile_sub(filename_returned, bufferlen, buf);

  if (!res)
    res = nmap_fetchfile_sub(filename_returned, bufferlen, file);

  return res;
}
#endif


/* This is a servent augmented by a frequency ratio. */
struct service_node : public servent {
public:
  double ratio;
};

/* Compare the ratios of two service nodes for top-ports purposes. Larger ratios
   come before smaller. */
bool service_node_ratio_compare(const service_node& a, const service_node& b) {
  return a.ratio > b.ratio;
}

static int numtcpports;
static int numudpports;
static int numsctpports;
static std::map<port_spec, service_node> service_table;
static std::list<service_node> services_by_ratio;
static int services_initialized;
static int ratio_format; // 0 = /etc/services no-ratio format. 1 = new nmap format

//初始化service_table和services_by_ratio
static int nmap_services_init() {
  if (services_initialized) return 0;

  char filename[512];
	
  FILE *fp;
  char servicename[128], proto[16];
  u16 portno;
  char *p;
  char line[1024];
  int lineno = 0;
  int res;
  double ratio;
  int ratio_n, ratio_d;
  char ratio_str[32];

  numtcpports = 0;
  numudpports = 0;
  numsctpports = 0;
  service_table.clear();
  services_by_ratio.clear();
  ratio_format = 0;

	//得到文件名字
	#if 0
  if (nmap_fetchfile(filename, sizeof(filename), "nmap-services") != 1) {
#ifndef WIN32
    error("Unable to find nmap-services!  Resorting to /etc/services");
    strcpy(filename, "/etc/services");
#else
        int len, wnt = GetVersion() < 0x80000000;
    error("Unable to find nmap-services!  Resorting to /etc/services");
        if(wnt)
                len = GetSystemDirectory(filename, 480);	//	be safe
        else
                len = GetWindowsDirectory(filename, 480);	//	be safe
        if(!len)
                error("Get%sDirectory failed (%d) @#!#@",
                 wnt ? "System" : "Windows", GetLastError());
        else
        {
                if(wnt)
                        strcpy(filename + len, "\\drivers\\etc\\services");
                else
                        strcpy(filename + len, "\\services");
        }
#endif
  }
	#endif
	strncpy(filename, "your nmap services file", 49);
	printf("filename is %s\n", filename);
	//打开文件
  fp = fopen(filename, "r");
  if (!fp) {
    printf("Unable to open %s for reading service information", filename);
  }
	
  /* Record where this data file was found. */
	//记录下找到的文件
  o.loaded_data_files["nmap-services"] = filename;

	//每次读取一行
  while(fgets(line, sizeof(line), fp)) {
    lineno++;
    p = line;
	//空的或者空白字符
    while(*p && isspace((int) (unsigned char) *p))
      p++;
	//注释行
    if (*p == '#')
      continue;

	//得到一行的信息
    res = sscanf(line, "%127s %hu/%15s %31s", servicename, &portno, proto, ratio_str);

    if (res == 3) {
      ratio = 0;
    } else if (res == 4) {
      if (strchr(ratio_str, '/')) {
        res = sscanf(ratio_str, "%d/%d", &ratio_n, &ratio_d);
        if (res != 2)
          printf("%s:%d contains invalid port ratio string: %s", filename, lineno, ratio_str);

        if (ratio_n < 0 || ratio_d < 0)
          printf("%s:%d contains an invalid negative value", filename, lineno);

        if (ratio_n > ratio_d)
          printf("%s:%d has a ratio %g. All ratios must be < 1", filename, lineno, (double)ratio_n/ratio_d);

        if (ratio_d == 0)
          printf("%s:%d has a ratio denominator of 0 causing a division by 0 error", filename, lineno);

        ratio = (double)ratio_n / ratio_d;
        ratio_format = 1;
      } else if (strncmp(ratio_str, "0.", 2) == 0) {
        /* We assume the ratio is in floating point notation already */
        ratio = strtod(ratio_str, NULL);
        ratio_format = 1;
      } else {
        ratio = 0;
      }
    } else {
      continue;
    }
	//赋值
    port_spec ps;
    ps.portno = portno;
    ps.proto = proto;

    /* Now we make sure our service table doesn't have duplicates */
    std::map<port_spec, service_node>::iterator i;
	//看service_table是否已经存在了相同的port_spec
    i = service_table.find(ps);
    if (i != service_table.end()) {
      if (o.debugging)
        printf("Port %d proto %s is duplicated in services file %s", portno, proto, filename);
      continue;
    }

    if (strncasecmp(proto, "tcp", 3) == 0) {
      numtcpports++;
    } else if (strncasecmp(proto, "udp", 3) == 0) {
      numudpports++;
    } else if (strncasecmp(proto, "sctp", 4) == 0) {
      numsctpports++;
    } else if (strncasecmp(proto, "ddp", 3) == 0) {
      /* ddp is some apple thing...we don't "do" that */
    } else if (strncasecmp(proto, "divert", 6) == 0) {
      /* divert sockets are for freebsd's natd */
    } else if (strncasecmp(proto, "#", 1) == 0) {
      /* possibly misplaced comment, but who cares? */
    } else {
      if (o.debugging)
        printf("Unknown protocol (%s) on line %d of services file %s.", proto, lineno, filename);
      continue;
    }

    struct service_node sn;

	
    //sn.s_name = cp_strdup(servicename);
	sn.s_name = (char*)malloc(sizeof(servicename));
	
	strcpy(sn.s_name, servicename);
    sn.s_port = portno;
    //sn.s_proto = cp_strdup(proto);
	sn.s_proto = (char*)malloc(sizeof(proto));
	strcpy(sn.s_proto, proto);
	
    sn.s_aliases = NULL;
    sn.ratio = ratio;

    service_table[ps] = sn;

    services_by_ratio.push_back(sn);
  }
	

  /* Sort the list of ports sorted by frequency for top-ports purposes. */
  services_by_ratio.sort(service_node_ratio_compare);

  fclose(fp);
  services_initialized = 1;
	
  return 0;
}
// gettoppts() sets its third parameter, a scan_list, with the most
// common ports scanned by Nmap according to the ratios specified in
// the nmap-services file.
//
// If level is below 1.0 then we treat it as a minimum ratio and we
// add all ports with ratios above level.
//
// If level is 1 or above, we treat it as a "top ports" directive
// and return the N highest ratio ports (where N==level).
//
// If the fourth parameter is not NULL, then the specified ports
// are excluded first and only then are the top N ports taken
//
// This function doesn't support IP protocol scan so only call this
// function if o.TCPScan() || o.UDPScan() || o.SCTPScan()

//设置它的第三个参数，scan_lists

//分析这个函数
void gettoppts(double level, char *portlist, struct scan_lists * ports, char *exclude_ports) {
  int ti=0, ui=0, si=0;
  struct scan_lists ptsdata = { 0 };
  bool ptsdata_initialized = false;
  const struct service_node *current;
  std::list<service_node>::iterator i;

  if (!services_initialized && nmap_services_init() == -1)
    printf("%s: Couldn't get port numbers", __func__);
#if 0
  if (ratio_format == 0) {
    if (level != -1)
      printf("Unable to use --top-ports or --port-ratio with an old style (no-ratio) services file");

    if (portlist){
      getpts(portlist, ports);
      return;
    }else if (o.fastscan){
      getpts("[-]", ports);
      return;
    }else{
      getpts("1-1024,[1025-]", ports);
      return;
    }
  }

  // TOP PORT DEFAULTS
  if (level == -1) {
    if (portlist){
      getpts(portlist, ports);
      return;
    }
    if (o.fastscan) level = 100;
    else level = 1000;
  }

  if (portlist){
    getpts(portlist, &ptsdata);
    ptsdata_initialized = true;
  } else if (exclude_ports) {
    getpts("-", &ptsdata);
    ptsdata_initialized = true;
  }

  if (ptsdata_initialized && exclude_ports)
    removepts(exclude_ports, &ptsdata);

  if (level < 1) {
    for (i = services_by_ratio.begin(); i != services_by_ratio.end(); i++) {
      current = &(*i);
      if (ptsdata_initialized && !is_port_member(&ptsdata, current))
        continue;
      if (current->ratio >= level) {
        if (o.TCPScan() && strcmp(current->s_proto, "tcp") == 0)
          ports->tcp_count++;
        else if (o.UDPScan() && strcmp(current->s_proto, "udp") == 0)
          ports->udp_count++;
        else if (o.SCTPScan() && strcmp(current->s_proto, "sctp") == 0)
          ports->sctp_count++;
      } else {
        break;
      }
    }

    if (ports->tcp_count)
      ports->tcp_ports = (unsigned short *)safe_zalloc(ports->tcp_count * sizeof(unsigned short));

    if (ports->udp_count)
      ports->udp_ports = (unsigned short *)safe_zalloc(ports->udp_count * sizeof(unsigned short));

    if (ports->sctp_count)
      ports->sctp_ports = (unsigned short *)safe_zalloc(ports->sctp_count * sizeof(unsigned short));

    ports->prots = NULL;

    for (i = services_by_ratio.begin(); i != services_by_ratio.end(); i++) {
      current = &(*i);
      if (ptsdata_initialized && !is_port_member(&ptsdata, current))
        continue;
      if (current->ratio >= level) {
        if (o.TCPScan() && strcmp(current->s_proto, "tcp") == 0)
          ports->tcp_ports[ti++] = current->s_port;
        else if (o.UDPScan() && strcmp(current->s_proto, "udp") == 0)
          ports->udp_ports[ui++] = current->s_port;
        else if (o.SCTPScan() && strcmp(current->s_proto, "sctp") == 0)
          ports->sctp_ports[si++] = current->s_port;
      } else {
        break;
      }
    }
  } else if (level >= 1) {
    if (level > 65536)
      printf("Level argument to gettoppts (%g) is too large", level);

    if (o.TCPScan()) {
      ports->tcp_count = MIN((int) level, numtcpports);
      ports->tcp_ports = (unsigned short *)safe_zalloc(ports->tcp_count * sizeof(unsigned short));
    }
    if (o.UDPScan()) {
      ports->udp_count = MIN((int) level, numudpports);
      ports->udp_ports = (unsigned short *)safe_zalloc(ports->udp_count * sizeof(unsigned short));
    }
    if (o.SCTPScan()) {
      ports->sctp_count = MIN((int) level, numsctpports);
      ports->sctp_ports = (unsigned short *)safe_zalloc(ports->sctp_count * sizeof(unsigned short));
    }

    ports->prots = NULL;

    for (i = services_by_ratio.begin(); i != services_by_ratio.end(); i++) {
      current = &(*i);
      if (ptsdata_initialized && !is_port_member(&ptsdata, current))
        continue;
      if (o.TCPScan() && strcmp(current->s_proto, "tcp") == 0 && ti < ports->tcp_count)
        ports->tcp_ports[ti++] = current->s_port;
      else if (o.UDPScan() && strcmp(current->s_proto, "udp") == 0 && ui < ports->udp_count)
        ports->udp_ports[ui++] = current->s_port;
      else if (o.SCTPScan() && strcmp(current->s_proto, "sctp") == 0 && si < ports->sctp_count)
        ports->sctp_ports[si++] = current->s_port;
    }

    if (ti < ports->tcp_count) ports->tcp_count = ti;
    if (ui < ports->udp_count) ports->udp_count = ui;
    if (si < ports->sctp_count) ports->sctp_count = si;
  } else
    printf("Argument to gettoppts (%g) should be a positive ratio below 1 or an integer of 1 or higher", level);

  if (ptsdata_initialized) {
    free_scan_lists(&ptsdata);
    ptsdata_initialized = false;
  }

  if (ports->tcp_count > 1)
    qsort(ports->tcp_ports, ports->tcp_count, sizeof(unsigned short), &port_compare);

  if (ports->udp_count > 1)
    qsort(ports->udp_ports, ports->udp_count, sizeof(unsigned short), &port_compare);

  if (ports->sctp_count > 1)
    qsort(ports->sctp_ports, ports->sctp_count, sizeof(unsigned short), &port_compare);
#endif
}

//这个函数填充NmapOps结构和scan_lists结构
void  apply_delayed_options() {
  int i;
  char tbuf[128];
  struct sockaddr_storage ss;
  size_t sslen;

	//函数
  // Default IPv4
	//设置地址族,第一次填充NmapOps
  o.setaf(delayed_options.af == AF_UNSPEC ? AF_INET : delayed_options.af);

	

	//-A选项设置为true
  if (delayed_options.advanced) {
    o.servicescan = true;
#ifndef NOLUA
    o.script = true;
#endif
	//是否以root运行
    if (o.isr00t) {
      o.osscan = true;
      o.traceroute = true;
    }
  }
	
  

	#if 0
	//os扫描,不用root运行，则不处理	
  if (o.osscan) {
    if (o.af() == AF_INET)
        o.reference_FPs = parse_fingerprint_reference_file("nmap-os-db");
    else if (o.af() == AF_INET6)
        o.os_labels_ipv6 = load_fp_matches();
  }
	#endif
	
	
	//端口扫描，构建得到ports,即填充scan_lists结构体
  validate_scan_lists(ports, o);
	
	//检查选项是否正确
  //o.ValidateOptions();

		
 if (!o.noportscan) {
	//在这里出错
	//设置ports,得到端口
    gettoppts(o.topportlevel, o.portlist, &ports, o.exclude_portlist);
  }
	
	#if 0
  /* Warn if setuid/setgid. */
	//如果setuid/setgid,警告
  check_setugid();

  /* Remove any ports that are in the exclusion list */
	//去除在exclusion list的端口
  removepts(o.exclude_portlist, &ports);

  



	//设置这个参数
  o.exclude_spec = delayed_options.exclude_spec;	
  /* Set up host address also in array of decoys! */
	//设置主机地址
  if (o.decoyturn == -1) {
	
    o.decoyturn = (o.numdecoys == 0) ?  0 : get_random_uint() % o.numdecoys;
    o.numdecoys++;
    for (i = o.numdecoys - 1; i > o.decoyturn; i--)
      o.decoys[i] = o.decoys[i - 1];
  }
	#endif
}
int main()
{
	std::vector<Target *> Targets;

	Targets.reserve(100);
	//解析选项
	//对于选项A
	delayed_options.advanced = true;
	//用这个函数来进行过渡，这个函数填充NmapOps结构和scan_lists结构	
	apply_delayed_options();
	nmap_services_init();
	cout << "hello\n";
	return 0;
}
