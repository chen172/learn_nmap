
/***************************************************************************
 * NmapOps.h -- The NmapOps class contains global options, mostly based on *
 * user-provided command-line settings.                                    *
 *                                                                         *
*/



#include <string>
#include <map>
#include <vector>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>

//nmap.h:
//////////////////////////////////////////////////////////////////

#ifndef NMAP_VERSION
/* Edit this definition only within the quotes, because it is read from this
   file by the makefiles. */
#define NMAP_VERSION "7.80SVN"
#define NMAP_NUM_VERSION "7.0.80.100"
#endif
/* The version number of updates retrieved by the nmap-update
   program. It can be different (but should always be the same or
   earlier) than NMAP_VERSION. */
#define NMAP_UPDATE_CHANNEL "7.80"

#define NMAP_XMLOUTPUTVERSION "1.04"

/* User configurable #defines: */
#define MAX_PROBE_PORTS 10     /* How many TCP probe ports are allowed ? */
/* Default number of ports in parallel.  Doesn't always involve actual
   sockets.  Can also adjust with the -M command line option.  */
#define MAX_SOCKETS 36

#define MAX_TIMEOUTS MAX_SOCKETS   /* How many timed out connection attempts
                                      in a row before we decide the host is
                                      dead? */
#define _STR(X) #X
#define STR(X)  _STR(X)
#define DEFAULT_TCP_PROBE_PORT 80 /* The ports TCP ping probes go to if
                                     unspecified by user -- uber hackers
                                     change this to 113 */
#define DEFAULT_TCP_PROBE_PORT_SPEC STR(DEFAULT_TCP_PROBE_PORT)
#define DEFAULT_UDP_PROBE_PORT 40125 /* The port UDP ping probes go to
                                          if unspecified by user */
#define DEFAULT_UDP_PROBE_PORT_SPEC STR(DEFAULT_UDP_PROBE_PORT)
#define DEFAULT_SCTP_PROBE_PORT 80 /* The port SCTP probes go to
                                      if unspecified by
                                      user */
#define DEFAULT_SCTP_PROBE_PORT_SPEC STR(DEFAULT_SCTP_PROBE_PORT)
#define DEFAULT_PROTO_PROBE_PORT_SPEC "1,2,4" /* The IPProto ping probes to use
                                                 if unspecified by user */

#define MAX_DECOYS 128 /* How many decoys are allowed? */

/* TCP Options for TCP SYN probes: MSS 1460 */
#define TCP_SYN_PROBE_OPTIONS "\x02\x04\x05\xb4"
#define TCP_SYN_PROBE_OPTIONS_LEN (sizeof(TCP_SYN_PROBE_OPTIONS)-1)

/* Default maximum send delay between probes to the same host */
#ifndef MAX_TCP_SCAN_DELAY
#define MAX_TCP_SCAN_DELAY 1000
#endif

#ifndef MAX_UDP_SCAN_DELAY
#define MAX_UDP_SCAN_DELAY 1000
#endif

#ifndef MAX_SCTP_SCAN_DELAY
#define MAX_SCTP_SCAN_DELAY 1000
#endif

/* Maximum number of extra hostnames, OSs, and devices, we
   consider when outputting the extra service info fields */
#define MAX_SERVICE_INFO_FIELDS 5

/* We wait at least 100 ms for a response by default - while that
   seems aggressive, waiting too long can cause us to fail to detect
   drops until many probes later on extremely low-latency
   networks (such as localhost scans).  */
#ifndef MIN_RTT_TIMEOUT
#define MIN_RTT_TIMEOUT 100
#endif

#ifndef MAX_RTT_TIMEOUT
#define MAX_RTT_TIMEOUT 10000 /* Never allow more than 10 secs for packet round
                                 trip */
#endif

#define INITIAL_RTT_TIMEOUT 1000 /* Allow 1 second initially for packet responses */
#define INITIAL_ARP_RTT_TIMEOUT 200 /* The initial timeout for ARP is lower */

#ifndef MAX_RETRANSMISSIONS
#define MAX_RETRANSMISSIONS 10    /* 11 probes to port at maximum */
#endif

/* Number of hosts we pre-ping and then scan.  We do a lot more if
   randomize_hosts is set.  Every one you add to this leads to ~1K of
   extra always-resident memory in nmap */
#define PING_GROUP_SZ 4096

/* DO NOT change stuff after this point */
#define UC(b)   (((int)b)&0xff)
#define SA    struct sockaddr  /*Ubertechnique from R. Stevens */

#define HOST_UNKNOWN 0
#define HOST_UP 1
#define HOST_DOWN 2

#define PINGTYPE_UNKNOWN 0
#define PINGTYPE_NONE 1
#define PINGTYPE_ICMP_PING 2
#define PINGTYPE_ICMP_MASK 4
#define PINGTYPE_ICMP_TS 8
#define PINGTYPE_TCP  16
#define PINGTYPE_TCP_USE_ACK 32
#define PINGTYPE_TCP_USE_SYN 64
/* # define PINGTYPE_RAWTCP 128 used to be here, but was never used. */
#define PINGTYPE_CONNECTTCP 256
#define PINGTYPE_UDP  512
/* #define PINGTYPE_ARP 1024 // Not used; see o.implicitARPPing */
#define PINGTYPE_PROTO 2048
#define PINGTYPE_SCTP_INIT 4096

/* Empirically determined optimum combinations of different numbers of probes:
     -PE
     -PE -PA80
     -PE -PA80 -PS443
     -PE -PA80 -PS443 -PP
     -PE -PA80 -PS443 -PP -PU40125
   We use the four-probe combination. */
#define DEFAULT_IPV4_PING_TYPES (PINGTYPE_ICMP_PING|PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_TCP_USE_SYN|PINGTYPE_ICMP_TS)
#define DEFAULT_IPV6_PING_TYPES (PINGTYPE_ICMP_PING|PINGTYPE_TCP|PINGTYPE_TCP_USE_ACK|PINGTYPE_TCP_USE_SYN)
#define DEFAULT_PING_ACK_PORT_SPEC "80"
#define DEFAULT_PING_SYN_PORT_SPEC "443"
/* For nonroot. */
#define DEFAULT_PING_CONNECT_PORT_SPEC "80,443"

/* The max length of each line of the subject fingerprint when
   wrapped. */
#define FP_RESULT_WRAP_LINE_LEN 74

/* Length of longest DNS name */
#define FQDN_LEN 254

/* Max payload: Worst case is IPv4 with 40bytes of options and TCP with 20
 * bytes of options. */
#define MAX_PAYLOAD_ALLOWED 65535-60-40

#ifndef recvfrom6_t
#  define recvfrom6_t int
#endif
///////////////////////////////////////////////////////////

//nbase_rnd.c
#if 0
int get_random_bytes(void *buf, int numbytes) {
  static nrand_h state;
  static int state_init = 0;

  /* Initialize if we need to */
  if (!state_init) {
    nrand_init(&state);
    state_init = 1;
  }

  /* Now fill our buffer */
  nrand_get(&state, buf, numbytes);

  return 0;
}

unsigned int get_random_uint() {
  unsigned int i;
  get_random_bytes(&i, sizeof(unsigned int));
  return i;
}
#endif





//output.h:
#define LOG_NUM_FILES 4 /* # of values that actual files (they must come first */

//nsock/include/nsock.h:
typedef struct proxy_chain *nsock_proxychain;

//scan_lists.h
typedef enum {
  STYPE_UNKNOWN,
  HOST_DISCOVERY,
  ACK_SCAN,
  SYN_SCAN,
  FIN_SCAN,
  XMAS_SCAN,
  UDP_SCAN,
  CONNECT_SCAN,
  NULL_SCAN,
  WINDOW_SCAN,
  SCTP_INIT_SCAN,
  SCTP_COOKIE_ECHO_SCAN,
  MAIMON_SCAN,
  IPPROT_SCAN,
  PING_SCAN,
  PING_SCAN_ARP,
  IDLE_SCAN,
  BOUNCE_SCAN,
  SERVICE_SCAN,
  OS_SCAN,
  SCRIPT_PRE_SCAN,
  SCRIPT_SCAN,
  SCRIPT_POST_SCAN,
  TRACEROUTE,
  PING_SCAN_ND
} stype;

struct FingerPrintDB;
//osscan.h
////////////////////////////////
struct OS_Classification {
  const char *OS_Vendor;
  const char *OS_Family;
  const char *OS_Generation; /* Can be NULL if unclassified */
  const char *Device_Type;
  std::vector<const char *> cpe;
};

/* A description of an operating system: a human-readable name and a list of
   classifications. */
struct FingerMatch {
  int line; /* For reference prints, the line # in nmap-os-db */
  /* For IPv6 matches, the number of fingerprints that contributed to this
   * classification group */
  unsigned short numprints;
  char *OS_name;
  std::vector<OS_Classification> OS_class;

  FingerMatch() {
    line = -1;
    OS_name = NULL;
  }
};
//////////////////////////////////////////

//选项结构
class NmapOps {
 public:
	//构造函数
  NmapOps();
  ~NmapOps();
	//重新初始化这个类到默认状态
  void ReInit(); // Reinitialize the class to default state
	//设置地址
  void setaf(int af) { addressfamily = af; }
	//得到地址
  int af() { return addressfamily; }
  // no setpf() because it is based on setaf() values
  int pf();
  /* Returns 0 for success, nonzero if no source has been set or any other
     failure */
  int SourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len);
  /* Returns a const pointer to the source address if set, or NULL if unset. */
  const struct sockaddr_storage *SourceSockAddr() const;
  /* Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
  void setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len);

// The time this obj. was instantiated   or last ReInit()ed.
	//得到开始的时间
  const struct timeval *getStartTime() { return &start_time; }
  // Number of seconds since getStartTime().  The current time is an
  // optional argument to avoid an extra gettimeofday() call.
	//开始之后的时间
  float TimeSinceStart(const struct timeval *now=NULL);


	//如果至少有一个选项类型是TCP
  bool TCPScan(); /* Returns true if at least one chosen scan type is TCP */
  bool UDPScan(); /* Returns true if at least one chosen scan type is UDP */
  bool SCTPScan(); /* Returns true if at least one chosen scan type is SCTP */

  /* Returns true if at least one chosen scan type uses raw packets.
     It does not currently cover cases such as TCP SYN ping scan which
     can go either way based on whether the user is root or IPv6 is
     being used.  It will return false in those cases where a RawScan
     is not necessarily used. */
	//如果至少有一个选项类型是raw packets
  bool RawScan();
	//检查选项是否合理，如果不合理，这个函数会退出Nmap或者做一些小的调整
  void ValidateOptions(); /* Checks that the options given are
                             reasonable and consistent.  If they aren't, the
                             function may bail out of Nmap or make small
                             adjustments (quietly or with a warning to the
                             user). */
  int isr00t;
  /* Whether we have pcap functions (can be false on Windows). */
	//是否有pcap函数
  bool have_pcap;
  u8 debugging;
  bool resuming;

#define PACKET_SEND_NOPREF 1
#define PACKET_SEND_ETH_WEAK 2
#define PACKET_SEND_ETH_STRONG 4
#define PACKET_SEND_ETH 6
#define PACKET_SEND_IP_WEAK 8
#define PACKET_SEND_IP_STRONG 16
#define PACKET_SEND_IP 24

  /* How should we send raw IP packets?  Nmap can generally use either
     ethernet or raw ip sockets.  Which is better depends on platform
     and goals.  A _STRONG preference means that Nmap should use the
     preferred method whenever it is possible (obviously it isn't
     always possible -- sending ethernet frames won't work over a PPP
     connection).  This is useful when the other type doesn't work at
     all.  A _WEAK preference means that Nmap may use the other type
     where it is substantially more efficient to do so. For example,
     Nmap will still do an ARP ping scan of a local network even when
     the pref is SEND_IP_WEAK */
  int sendpref;
  bool packetTrace() { return (debugging >= 3)? true : pTrace;  }
  bool versionTrace() { return packetTrace()? true : vTrace;  }
#ifndef NOLUA
  bool scriptTrace() { return packetTrace()? true : scripttrace; }
#endif
  // Note that packetTrace may turn on at high debug levels even if
  // setPacketTrace(false) has been called
  void setPacketTrace(bool pt) { pTrace = pt;  }
  void setVersionTrace(bool vt) { vTrace = vt;  }
  bool openOnly() { return open_only; }
  void setOpenOnly(bool oo) { open_only = oo; }
  u8 verbose;
  /* The requested minimum packet sending rate, or 0.0 if unset. */
  float min_packet_send_rate;
  /* The requested maximum packet sending rate, or 0.0 if unset. */
  float max_packet_send_rate;
  /* The requested auto stats printing interval, or 0.0 if unset. */
  float stats_interval;
  bool randomize_hosts;
  bool randomize_ports;
  bool spoofsource; /* -S used */
  bool fastscan;
  char device[64];
  int ping_group_sz;
  bool nogcc; /* Turn off group congestion control with --nogcc */
  bool generate_random_ips; /* -iR option */
	//用来作为os扫描的
  FingerPrintDB *reference_FPs; /* Used in the new OS scan system. */
  std::vector<FingerMatch> os_labels_ipv6;
  u16 magic_port; /* The source port set by -g or --source-port. */
  bool magic_port_set; /* Was this set by user? */

  /* Scan timing/politeness issues */
  int timing_level; // 0-5, corresponding to Paranoid, Sneaky, Polite, Normal, Aggressive, Insane
  int max_parallelism; // 0 means it has not been set
  int min_parallelism; // 0 means it has not been set
  double topportlevel; // -1 means it has not been set

  /* The maximum number of OS detection (gen2) tries we will make
     without any matches before giving up on a host.  We may well give
     up after fewer tries anyway, particularly if the target isn't
     ideal for unknown fingerprint submissions */
  int maxOSTries() { return max_os_tries; }
  void setMaxOSTries(int mot);

  /* These functions retrieve and set the Round Trip Time timeouts, in
   milliseconds.  The set versions do extra processing to insure sane
   values and to adjust each other to insure consistence (e.g. that
   max is always at least as high as min) */
  int maxRttTimeout() { return max_rtt_timeout; }
  int minRttTimeout() { return min_rtt_timeout; }
  int initialRttTimeout() { return initial_rtt_timeout; }
  void setMaxRttTimeout(int rtt);
  void setMinRttTimeout(int rtt);
  void setInitialRttTimeout(int rtt);
  void setMaxRetransmissions(int max_retransmit);
  unsigned int getMaxRetransmissions() { return max_retransmissions; }

  /* Similar functions for Host group size */
  int minHostGroupSz() { return min_host_group_sz; }
  int maxHostGroupSz() { return max_host_group_sz; }
  void setMinHostGroupSz(unsigned int sz);
  void setMaxHostGroupSz(unsigned int sz);
  unsigned int maxTCPScanDelay() { return max_tcp_scan_delay; }
  unsigned int maxUDPScanDelay() { return max_udp_scan_delay; }
  unsigned int maxSCTPScanDelay() { return max_sctp_scan_delay; }
  void setMaxTCPScanDelay(unsigned int delayMS) { max_tcp_scan_delay = delayMS; }
  void setMaxUDPScanDelay(unsigned int delayMS) { max_udp_scan_delay = delayMS; }
  void setMaxSCTPScanDelay(unsigned int delayMS) { max_sctp_scan_delay = delayMS; }

  /* Sets the Name of the XML stylesheet to be printed in XML output.
     If this is never called, a default stylesheet distributed with
     Nmap is used.  If you call it with NULL as the xslname, no
     stylesheet line is printed. */
  void setXSLStyleSheet(const char *xslname);
  /* Returns the full path or URL that should be printed in the XML
     output xml-stylesheet element.  Returns NULL if the whole element
     should be skipped */
  char *XSLStyleSheet();

  /* Sets the spoofed MAC address */
  void setSpoofMACAddress(u8 *mac_data);
  /* Gets the spoofed MAC address, but returns NULL if it hasn't been set */
  const u8 *spoofMACAddress() { return spoof_mac_set? spoof_mac : NULL; }

  unsigned int max_ips_to_scan; // Used for Random input (-iR) to specify how
                       // many IPs to try before stopping. 0 means unlimited.
  int extra_payload_length; /* These two are for --data-length op */
  char *extra_payload;
  unsigned long host_timeout;
  /* Delay between probes, in milliseconds */
  unsigned int scan_delay;
  bool open_only;

  int scanflags; /* if not -1, this value should dictate the TCP flags
                    for the core portscanning routine (eg to change a
                    FIN scan into a PSH scan.  Sort of a hack, but can
                    be very useful sometimes. */

  bool defeat_rst_ratelimit; /* Solaris 9 rate-limits RSTs so scanning is very
            slow against it. If we don't distinguish between closed and filtered ports,
            we can get the list of open ports very fast */

  bool defeat_icmp_ratelimit; /* If a host rate-limits ICMP responses, then scanning
            is very slow against it. This option prevents Nmap to adjust timing
            when it changes the port's state because of ICMP response, as the latter
            might be rate-limited. Doing so we can get scan results faster. */

  struct in_addr resume_ip; /* The last IP in the log file if user
                               requested --restore .  Otherwise
                               restore_ip.s_addr == 0.  Also
                               target_struct_get will eventually set it
                               to 0. */

  // Version Detection Options
  bool override_excludeports;
  int version_intensity;

  struct sockaddr_storage decoys[MAX_DECOYS];
  bool osscan_limit; /* Skip OS Scan if no open or no closed TCP ports */
  bool osscan_guess;   /* Be more aggressive in guessing OS type */
  int numdecoys;
  int decoyturn;
  bool osscan;
  bool servicescan;
  int pingtype;
  int listscan;
  int fragscan; /* 0 or MTU (without IPv4 header size) */
  int ackscan;
  int bouncescan;
  int connectscan;
  int finscan;
  int idlescan;
  char* idleProxy; /* The idle host used to "Proxy" an idle scan */
  int ipprotscan;
  int maimonscan;
  int nullscan;
  int synscan;
  int udpscan;
  int sctpinitscan;
  int sctpcookieechoscan;
  int windowscan;
  int xmasscan;
  bool noresolve;
  bool noportscan;
  bool append_output; /* Append to any output files rather than overwrite */
  FILE *logfd[LOG_NUM_FILES];
  FILE *nmap_stdout; /* Nmap standard output */
  int ttl; // Time to live
  bool badsum;
  char *datadir;
  /* A map from abstract data file names like "nmap-services" and "nmap-os-db"
     to paths which have been requested by the user. nmap_fetchfile will return
     the file names defined in this map instead of searching for a matching
     file. */
  std::map<std::string, std::string> requested_data_files;
  /* A map from data file names to the paths at which they were actually found.
     Only files that were actually read should be in this map. */
  std::map<std::string, std::string> loaded_data_files;
  bool mass_dns;
  bool always_resolve;
  bool resolve_all;
  char *dns_servers;

  /* Do IPv4 ARP or IPv6 ND scan of directly connected Ethernet hosts, even if
     non-ARP host discovery options are used? This is normally more efficient,
     not only because ARP/ND scan is faster, but because we need the MAC
     addresses provided by ARP or ND scan in order to do IP-based host discovery
     anyway. But when a network uses proxy ARP, all hosts will appear to be up
     unless you do an IP host discovery on them. This option is true by default. */
  bool implicitARPPing;

  // If true, write <os><osclass/><osmatch/></os> as in xmloutputversion 1.03
  // rather than <os><osmatch><osclass/></osmatch></os> as in 1.04 and later.
  bool deprecated_xml_osclass;

  bool traceroute;
  bool reason;
  bool adler32;
  FILE *excludefd;
  char *exclude_spec;
  FILE *inputfd;
	//端口列表
  char *portlist; /* Ports list specified by user */
  char *exclude_portlist; /* exclude-ports list specified by user */

  nsock_proxychain proxy_chain;

#ifndef NOLUA
  bool script;
  char *scriptargs;
  char *scriptargsfile;
  bool scriptversion;
  bool scripttrace;
  bool scriptupdatedb;
  bool scripthelp;
  double scripttimeout;
  void chooseScripts(char* argument);
  std::vector<std::string> chosenScripts;
#endif

  /* ip options used in build_*_raw() */
  u8 *ipoptions;
  int ipoptionslen;
  int ipopt_firsthop;	// offset in ipoptions where is first hop for source/strict routing
  int ipopt_lasthop;	// offset in ipoptions where is space for targets ip for source/strict routing

  // Statistics Options set in nmap.cc
  unsigned int numhosts_scanned;
  unsigned int numhosts_up;
  int numhosts_scanning;
  stype current_scantype;
  bool noninteractive;

  bool release_memory;	/* suggest to release memory before quitting. used to find memory leaks. */
 private:
  int max_os_tries;
  int max_rtt_timeout;
  int min_rtt_timeout;
  int initial_rtt_timeout;
  unsigned int max_retransmissions;
  unsigned int max_tcp_scan_delay;
  unsigned int max_udp_scan_delay;
  unsigned int max_sctp_scan_delay;
  unsigned int min_host_group_sz;
  unsigned int max_host_group_sz;
	//初始化，构造函数会调用它
  void Initialize();
	//地址族
  int addressfamily; /*  Address family:  AF_INET or AF_INET6 */
  struct sockaddr_storage sourcesock;
  size_t sourcesocklen;
  struct timeval start_time;
  bool pTrace; // Whether packet tracing has been enabled
  bool vTrace; // Whether version tracing has been enabled
  bool xsl_stylesheet_set;
  char *xsl_stylesheet;
  u8 spoof_mac[6];
  bool spoof_mac_set;
};

//NmapOps类的方法

//构造函数
NmapOps::NmapOps() {
  datadir = NULL;
  xsl_stylesheet = NULL;
  Initialize();
}

//初始化函数，构造函数会调用它
void NmapOps::Initialize() {
  setaf(AF_INET);
#if defined WIN32 || defined __amigaos__
  isr00t = 1;
#else
  if (getenv("NMAP_PRIVILEGED"))
    isr00t = 1;
  else if (getenv("NMAP_UNPRIVILEGED"))
    isr00t = 0;
  else
    isr00t = !(geteuid());
#endif
  have_pcap = true;
  debugging = 0;
  verbose = 0;
  min_packet_send_rate = 0.0; /* Unset. */
  max_packet_send_rate = 0.0; /* Unset. */
  stats_interval = 0.0; /* Unset. */
  randomize_hosts = false;
  randomize_ports = true;
  sendpref = PACKET_SEND_NOPREF;
  spoofsource = false;
  fastscan = false;
  device[0] = '\0';
  ping_group_sz = PING_GROUP_SZ;
  nogcc = false;
  generate_random_ips = false;
  reference_FPs = NULL;
  //magic_port = 33000 + (get_random_uint() % 31000);
  magic_port_set = false;
  timing_level = 3;
  max_parallelism = 0;
  min_parallelism = 0;
  max_os_tries = 5;
  max_rtt_timeout = MAX_RTT_TIMEOUT;
  min_rtt_timeout = MIN_RTT_TIMEOUT;
  initial_rtt_timeout = INITIAL_RTT_TIMEOUT;
  max_retransmissions = MAX_RETRANSMISSIONS;
  min_host_group_sz = 1;
  max_host_group_sz = 100000; // don't want to be restrictive unless user sets
  max_tcp_scan_delay = MAX_TCP_SCAN_DELAY;
  max_udp_scan_delay = MAX_UDP_SCAN_DELAY;
  max_sctp_scan_delay = MAX_SCTP_SCAN_DELAY;
  max_ips_to_scan = 0;
  extra_payload_length = 0;
  extra_payload = NULL;
  scan_delay = 0;
  open_only = false;
  scanflags = -1;
  defeat_rst_ratelimit = false;
  defeat_icmp_ratelimit = false;
  resume_ip.s_addr = 0;
  osscan_limit = false;
  osscan_guess = false;
  numdecoys = 0;
  decoyturn = -1;
  osscan = false;
  servicescan = false;
  override_excludeports = false;
  version_intensity = 7;
  pingtype = PINGTYPE_UNKNOWN;
  listscan = ackscan = bouncescan = connectscan = 0;
  nullscan = xmasscan = fragscan = synscan = windowscan = 0;
  maimonscan = idlescan = finscan = udpscan = ipprotscan = 0;
  noportscan = noresolve = false;
  sctpinitscan = 0;
  sctpcookieechoscan = 0;
  append_output = false;
  memset(logfd, 0, sizeof(FILE *) * LOG_NUM_FILES);
  ttl = -1;
  badsum = false;
  nmap_stdout = stdout;
  gettimeofday(&start_time, NULL);
  pTrace = vTrace = false;
  reason = false;
  adler32 = false;
  if (datadir) free(datadir);
  datadir = NULL;
  xsl_stylesheet_set = false;
  if (xsl_stylesheet) free(xsl_stylesheet);
  xsl_stylesheet = NULL;
  spoof_mac_set = false;
  mass_dns = true;
  deprecated_xml_osclass = false;
  always_resolve = false;
  resolve_all = false;
  dns_servers = NULL;
  implicitARPPing = true;
  numhosts_scanned = 0;
  numhosts_up = 0;
  numhosts_scanning = 0;
  noninteractive = false;
  current_scantype = STYPE_UNKNOWN;
  ipoptions = NULL;
  ipoptionslen = 0;
  ipopt_firsthop = 0;
  ipopt_lasthop  = 0;
  release_memory = false;
  topportlevel = -1;
#ifndef NOLUA
  script = false;
  scriptargs = NULL;
  scriptversion = false;
  scripttrace = false;
  scriptupdatedb = false;
  scripthelp = false;
  scripttimeout = 0;
  chosenScripts.clear();
#endif
  memset(&sourcesock, 0, sizeof(sourcesock));
  sourcesocklen = 0;
  excludefd = NULL;
  exclude_spec = NULL;
  inputfd = NULL;
  idleProxy = NULL;
  portlist = NULL;
  exclude_portlist = NULL;
  proxy_chain = NULL;
  resuming = false;
}

NmapOps::~NmapOps() {
  //TO DO
}


