#include "xconf.h"
#include "scan-modules/scan-modules.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef NOT_FOUND_OPENSSL
#include <openssl/opensslv.h>
#endif

#ifndef NOT_FOUND_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#ifndef NOT_FOUND_LIBXML2
#include <libxml/xmlversion.h>
#endif

#ifndef NOT_FOUND_BSON
#include <bson/bson.h>
#endif

#ifndef NOT_FOUND_MONGOC
#include <mongoc/mongoc.h>
#endif

#include "version.h"
#include "dedup/dedup.h"
#include "smack/smack.h"
#include "nmap/nmap-service.h"
#include "pixie/pixie-timer.h"
#include "proto/proto-http-maker.h"

#include "templ/templ-init.h"
#include "templ/templ-opts.h"
#include "templ/templ-tcp.h"
#include "stack/stack-tcp-core.h"

#include "crypto/crypto-base64.h"
#include "crypto/crypto-blackrock.h"
#include "crypto/crypto-siphash24.h"
#include "crypto/crypto-lcg.h"

#include "util-scan/rst-filter.h"
#include "util-data/safe-string.h"
#include "util-data/fine-malloc.h"
#include "util-data/data-chain.h"
#include "util-out/xprint.h"
#include "util-out/logger.h"
#include "util-misc/misc.h"
#include "util-misc/checksum.h"
#include "util-misc/configer.h"

#include "target/target-set.h"
#include "target/target-parse.h"
#include "target/target-ipaddress.h"
#include "target/target-rangeport.h"

#ifdef _WIN32
#include <direct.h>
#define getcwd      _getcwd
#define strcasecmp  _stricmp
#define strncasecmp _strnicmp
#else
#include <unistd.h>
#endif

#if defined(_MSC_VER)
#define strdup _strdup
#endif

extern ConfParam config_parameters[];

// clang-format off
static const char ascii_xtate1[] =
" /$$   /$$ /$$$$$$$$ /$$$$$$  /$$$$$$$$ /$$$$$$$$\n"
"| $$  / $$|__  $$__//$$__  $$|__  $$__/| $$_____/\n"
"|  $$/ $$/   | $$  | $$  \\ $$   | $$   | $$      \n"
" \\  $$$$/    | $$  | $$$$$$$$   | $$   | $$$$$   \n"
"  >$$  $$    | $$  | $$__  $$   | $$   | $$__/   \n"
" /$$/\\  $$   | $$  | $$  | $$   | $$   | $$      \n"
"| $$  \\ $$   | $$  | $$  | $$   | $$   | $$$$$$$$\n"
"|__/  |__/   |__/  |__/  |__/   |__/   |________/\n"
;


static const char ascii_xtate2[] =
"`YMM'   `MP'MMP\"\"MM\"\"YMM   db   MMP\"\"MM\"\"YMM `7MM\"\"\"YMM  \n"
"  VMb.  ,P  P'   MM   `7  ;MM:  P'   MM   `7   MM    `7  \n"
"   `MM.M'        MM      ,V^MM.      MM        MM   d    \n"
"     MMb         MM     ,M  `MM      MM        MMmmMM    \n"
"   ,M'`Mb.       MM     AbmmmqMA     MM        MM   Y  , \n"
"  ,P   `MM.      MM    A'     VML    MM        MM     ,M \n"
".MM:.  .:MMa.  .JMML..AMA.   .AMMA..JMML.    .JMMmmmmMMM \n"
;

static const char work_flow[] =
"+--------------------------------------------------------------------------------------------+\n"
"|                                                                                            |\n"
"|      New Targets Generation     Tx Threads           Packet  Transmit         Tx Threads   |\n"
"|     +----------------------+  ------------->  +---------------------------+  ----------->  |\n"
"|     | 1.GenerateModule     |  ------------->  | 1.ProbeModule Hello Making|  ----------->  |\n"
"|     | 2.Scan Rate Control  |  ------------->  | 2.ScanModule Transmiting  |  ----------->  |\n"
"|     +----------------------+                  +---------------------------+                |\n"
"|                                                                                            |\n"
"|                                                                            ^               |\n"
"|                                                                            |               |\n"
"|     Packets need to be send   +-----------------------+  Send in priority  |               |\n"
"|  +--------------------------->| Pakcets Sending Queue +--------------------+               |\n"
"|  |                            +-----------------------+                                    |\n"
"|  |                                                                                         |\n"
"|  |                                                                                         |\n"
"|  |         ScanModule Handling                        ScanModule Validation                |\n"
"|  |  +-----------------------------+ Handle Threads +-----------------------+               |\n"
"|  |  | 1.ProbeModule Handling      | <------------- | 1.Packet Record       |   Rx  Thread  |\n"
"|  |  | 2.OutputModule save results | <------------- | 2.Deduplication       | <-----------  |\n"
"|  +--| 3.More packets to send      | <------------- | 3.ProbeModule Validate|               |\n"
"|     +-----------------------------+                +-----------------------+               |\n"
"|                                                                                            |\n"
"+--------------------------------------------------------------------------------------------+\n"
;

static const char scan_probe_module_rela[] =
"+----------------------------------------------------------------------+\n"
"|    Free supporting for new scan strategies and protocols through     |\n"
"|    flexible ScanModules and ProbeModules creating and combination    |\n"
"|                                                                      |\n"
"|     +--------------------+           +-------------------------+     |\n"
"|     |  Application Layer +---------->|                         |     |\n"
"|     +--------------------+           |     ProbeModules        |     |\n"
"|                                      |                         |     |\n"
"|     +--------------------+           |       e.g. HTTP         |     |\n"
"|     | Presentation Layer +---------->|            DNS          |     |\n"
"|     +--------------------+           |            Netbios      |     |\n"
"|                                      |            TLS          |     |\n"
"|     +--------------------+           |                         |     |\n"
"|     |   Session Layer    +---------->|                         |     |\n"
"|     +--------------------+           +-------------------------+     |\n"
"|                                                                      |\n"
"|     +--------------------+           +-------------------------+     |\n"
"|     |   Transport Layer  +---------->|                         |     |\n"
"|     +--------------------+           |      ScanModules        |     |\n"
"|                                      |                         |     |\n"
"|     +--------------------+           |       e.g. TCP          |     |\n"
"|     |   Network Layer    +---------->|            UDP          |     |\n"
"|     +--------------------+           |            ICMP         |     |\n"
"|                                      |            NDP          |     |\n"
"|     +--------------------+           |            ARP          |     |\n"
"|     |   Data-link Layer  +---------->|                         |     |\n"
"|     +--------------------+           +-------------------------+     |\n"
"|                                                                      |\n"
"|     +--------------------+                                           |\n"
"|     |   Physical Layer   +---------->     Stop kidding!!!            |\n"
"|     +--------------------+                                           |\n"
"|                                                                      |\n"
"+----------------------------------------------------------------------+\n"
;
// clang-format on

static const unsigned short top_udp_ports[] = {
    161,   /* SNMP - should be found on all network equipment */
    135,   /* MS-RPC - should be found on all modern Windows */
    500,   /* ISAKMP - for establishing IPsec tunnels */
    137,   /* NetBIOS-NameService - should be found on old Windows */
    138,   /* NetBIOS-Datagram - should be found on old Windows */
    445,   /* SMB datagram service */
    67,    /* DHCP */
    53,    /* DNS */
    1900,  /* UPnP - Microsoft-focused local discovery */
    5353,  /* mDNS - Apple-focused local discovery */
    4500,  /* nat-t-ike - IPsec NAT traversal */
    514,   /* syslog - all Unix machiens */
    69,    /* TFTP */
    49152, /* first of modern ephemeral ports */
    631,   /* IPP - printing protocol for Linux */
    123,   /* NTP network time protocol */
    1434,  /* MS-SQL server*/
    520,   /* RIP - routers use this protocol sometimes */
    7,     /* Echo */
    111,   /* SunRPC portmapper */
    2049,  /* SunRPC NFS */
    5683,  /* COAP */
    11211, /* memcached */
    1701,  /* L2TP */
    27960, /* quaked amplifier */
    1645,  /* RADIUS */
    1812,  /* RADIUS */
    1646,  /* RADIUS */
    1813,  /* RADIUS */
    3343,  /* Microsoft Cluster Services */
    2535,  /* MADCAP rfc2730 TODO FIXME */

};

static const unsigned short top_tcp_ports[] = {
    80,    443,   8080,        /* also web */
    21,    990,                /* FTP, oldie but goodie */
    22,                        /* SSH, so much infrastructure */
    23,    992,                /* Telnet, oldie but still around*/
    24,                        /* people put things here instead of TelnetSSH*/
    25,    465,   587,   2525, /* SMTP email*/
    5800,  5900,  5901,        /* VNC */
    111,                       /* SunRPC */
    139,   445,                /* Microsoft Windows networking */
    135,                       /* DCEPRC, more Microsoft Windows */
    3389,                      /* Microsoft Windows RDP */
    88,                        /* Kerberos, also Microsoft windows */
    389,   636,                /* LDAP and MS Win */
    1433,                      /* MS SQL */
    53,                        /* DNS */
    2083,  2096,               /* cPanel */
    9050,                      /* ToR */
    8140,                      /* Puppet */
    11211,                     /* memcached */
    1098,  1099,               /* Java RMI */
    6000,  6001,               /* XWindows */
    5060,  5061,               /* SIP - session initiation protocool */
    554,                       /* RTSP */
    548,                       /* AFP */

    1,     3,     4,     6,     7,     9,     13,    17,    19,    20,    26,
    30,    32,    33,    37,    42,    43,    49,    70,    79,    81,    82,
    83,    84,    85,    89,    90,    99,    100,   106,   109,   110,   113,
    119,   125,   143,   144,   146,   161,   163,   179,   199,   211,   212,
    222,   254,   255,   256,   259,   264,   280,   301,   306,   311,   340,
    366,   406,   407,   416,   417,   425,   427,   444,   458,   464,   465,
    481,   497,   500,   512,   513,   514,   515,   524,   541,   543,   544,
    545,   554,   555,   563,   593,   616,   617,   625,   631,   646,   648,
    666,   667,   668,   683,   687,   691,   700,   705,   711,   714,   720,
    722,   726,   749,   765,   777,   783,   787,   800,   801,   808,   843,
    873,   880,   888,   898,   900,   901,   902,   903,   911,   912,   981,
    987,   993,   995,   999,   1000,  1001,  1002,  1007,  1009,  1010,  1011,
    1021,  1022,  1023,  1024,  1025,  1026,  1027,  1028,  1029,  1030,  1031,
    1032,  1033,  1034,  1035,  1036,  1037,  1038,  1039,  1040,  1041,  1042,
    1043,  1044,  1045,  1046,  1047,  1048,  1049,  1050,  1051,  1052,  1053,
    1054,  1055,  1056,  1057,  1058,  1059,  1060,  1061,  1062,  1063,  1064,
    1065,  1066,  1067,  1068,  1069,  1070,  1071,  1072,  1073,  1074,  1075,
    1076,  1077,  1078,  1079,  1080,  1081,  1082,  1083,  1084,  1085,  1086,
    1087,  1088,  1089,  1090,  1091,  1092,  1093,  1094,  1095,  1096,  1097,
    1100,  1102,  1104,  1105,  1106,  1107,  1108,  1110,  1111,  1112,  1113,
    1114,  1117,  1119,  1121,  1122,  1123,  1124,  1126,  1130,  1131,  1132,
    1137,  1138,  1141,  1145,  1147,  1148,  1149,  1151,  1152,  1154,  1163,
    1164,  1165,  1166,  1169,  1174,  1175,  1183,  1185,  1186,  1187,  1192,
    1198,  1199,  1201,  1213,  1216,  1217,  1218,  1233,  1234,  1236,  1244,
    1247,  1248,  1259,  1271,  1272,  1277,  1287,  1296,  1300,  1301,  1309,
    1310,  1311,  1322,  1328,  1334,  1352,  1417,  1434,  1443,  1455,  1461,
    1494,  1500,  1501,  1503,  1521,  1524,  1533,  1556,  1580,  1583,  1594,
    1600,  1641,  1658,  1666,  1687,  1688,  1700,  1717,  1718,  1719,  1720,
    1721,  1723,  1755,  1761,  1782,  1783,  1801,  1805,  1812,  1839,  1840,
    1862,  1863,  1864,  1875,  1900,  1914,  1935,  1947,  1971,  1972,  1974,
    1984,  1998,  1999,  2000,  2001,  2002,  2003,  2004,  2005,  2006,  2007,
    2008,  2009,  2010,  2013,  2020,  2021,  2022,  2030,  2033,  2034,  2035,
    2038,  2040,  2041,  2042,  2043,  2045,  2046,  2047,  2048,  2049,  2065,
    2068,  2099,  2100,  2103,  2105,  2106,  2107,  2111,  2119,  2121,  2126,
    2135,  2144,  2160,  2161,  2170,  2179,  2190,  2191,  2196,  2200,  2222,
    2251,  2260,  2288,  2301,  2323,  2366,  2381,  2382,  2383,  2393,  2394,
    2399,  2401,  2492,  2500,  2522,  2557,  2601,  2602,  2604,  2605,  2607,
    2608,  2638,  2701,  2702,  2710,  2717,  2718,  2725,  2800,  2809,  2811,
    2869,  2875,  2909,  2910,  2920,  2967,  2968,  2998,  3000,  3001,  3003,
    3005,  3006,  3007,  3011,  3013,  3017,  3030,  3031,  3052,  3071,  3077,
    3128,  3168,  3211,  3221,  3260,  3261,  3268,  3269,  3283,  3300,  3301,
    3306,  3322,  3323,  3324,  3325,  3333,  3351,  3367,  3369,  3370,  3371,
    3372,  3389,  3390,  3404,  3476,  3493,  3517,  3527,  3546,  3551,  3580,
    3659,  3689,  3690,  3703,  3737,  3766,  3784,  3800,  3801,  3809,  3814,
    3826,  3827,  3828,  3851,  3869,  3871,  3878,  3880,  3889,  3905,  3914,
    3918,  3920,  3945,  3971,  3986,  3995,  3998,  4000,  4001,  4002,  4003,
    4004,  4005,  4006,  4045,  4111,  4125,  4126,  4129,  4224,  4242,  4279,
    4321,  4343,  4443,  4444,  4445,  4446,  4449,  4550,  4567,  4662,  4848,
    4899,  4900,  4998,  5000,  5001,  5002,  5003,  5004,  5009,  5030,  5033,
    5050,  5051,  5054,  5080,  5087,  5100,  5101,  5102,  5120,  5190,  5200,
    5214,  5221,  5222,  5225,  5226,  5269,  5280,  5298,  5357,  5405,  5414,
    5431,  5432,  5440,  5500,  5510,  5544,  5550,  5555,  5560,  5566,  5631,
    5633,  5666,  5678,  5679,  5718,  5730,  5801,  5802,  5810,  5811,  5815,
    5822,  5825,  5850,  5859,  5862,  5877,  5902,  5903,  5904,  5906,  5907,
    5910,  5911,  5915,  5922,  5925,  5950,  5952,  5959,  5960,  5961,  5962,
    5963,  5987,  5988,  5989,  5998,  5999,  6002,  6003,  6004,  6005,  6006,
    6007,  6009,  6025,  6059,  6100,  6101,  6106,  6112,  6123,  6129,  6156,
    6346,  6389,  6502,  6510,  6543,  6547,  6565,  6566,  6567,  6580,  6646,
    6666,  6667,  6668,  6669,  6689,  6692,  6699,  6779,  6788,  6789,  6792,
    6839,  6881,  6901,  6969,  7000,  7001,  7002,  7004,  7007,  7019,  7025,
    7070,  7100,  7103,  7106,  7200,  7201,  7402,  7435,  7443,  7496,  7512,
    7625,  7627,  7676,  7741,  7777,  7778,  7800,  7911,  7920,  7921,  7937,
    7938,  7999,  8000,  8001,  8002,  8007,  8008,  8009,  8010,  8011,  8021,
    8022,  8031,  8042,  8045,  8080,  8081,  8082,  8083,  8084,  8085,  8086,
    8087,  8088,  8089,  8090,  8093,  8099,  8100,  8180,  8181,  8192,  8193,
    8194,  8200,  8222,  8254,  8290,  8291,  8292,  8300,  8333,  8383,  8400,
    8402,  8443,  8500,  8600,  8649,  8651,  8652,  8654,  8701,  8800,  8873,
    8888,  8899,  8994,  9000,  9001,  9002,  9003,  9009,  9010,  9011,  9040,
    9071,  9080,  9081,  9090,  9091,  9099,  9100,  9101,  9102,  9103,  9110,
    9111,  9200,  9207,  9220,  9290,  9415,  9418,  9485,  9500,  9502,  9503,
    9535,  9575,  9593,  9594,  9595,  9618,  9666,  9876,  9877,  9878,  9898,
    9900,  9917,  9929,  9943,  9944,  9968,  9998,  9999,  10000, 10001, 10002,
    10003, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243,
    10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967,
    12000, 12174, 12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441,
    14442, 15000, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016,
    16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101,
    19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222,
    20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
    27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768,
    32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779,
    32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573,
    35500, 38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100,
    48080, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161,
    49163, 49165, 49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003,
    50006, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848,
    52869, 54045, 54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797,
    58080, 60020, 60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129,
    65389};

int xconf_set_parameter_in_kv(XConf *xconf, char *line, size_t len) {
    char *name;
    char *value;

    safe_trim(line, len);

    /*filter out comments*/
    if (ispunct(line[0] & 0xFF) || line[0] == '\0')
        return 1;

    name  = line;
    value = strchr(line, '=');
    if (value == NULL)
        return 2;
    *value = '\0';
    value++;
    safe_trim(name, len);

    /*
     * For value, must consider wrapper of double quotes or single quotes.
     * In other word, we don't need to wrap with quotes while echoing.
     * */
    safe_trim(value, len);
    if (value[0] == '"') {
        safe_trim_char(value, len, '"');
        safe_trim(value, len);
    } else if (value[0] == '\'') {
        safe_trim_char(value, len, '\'');
        safe_trim(value, len);
    }

    return xconf_set_parameter(xconf, name, value);
}

static ConfRes SET_scan_module(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->scanner) {
            fprintf(xconf->echo, "scan-module = %s\n", xconf->scanner->name);
        }
        return 0;
    }

    xconf->scanner = get_scan_module_by_name(value);
    if (!xconf->scanner) {
        LOG(LEVEL_ERROR, "fail %s: no such scan module named %s\n", name,
            value);
        return Conf_ERR;
    }

    if (xconf->op == Op_Default)
        xconf->op = Op_Scan;

    return Conf_OK;
}

static ConfRes SET_help_scan_module(void *conf, const char *name,
                                    const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    xconf->scanner = get_scan_module_by_name(value);
    if (!xconf->scanner) {
        LOG(LEVEL_ERROR, "fail %s: no such scan module named %s\n", name,
            value);
        return Conf_ERR;
    }

    xconf->op = Op_HelpScanModule;

    return Conf_OK;
}

static ConfRes SET_help_probe_module(void *conf, const char *name,
                                     const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    xconf->probe = get_probe_module_by_name(value);
    if (!xconf->probe) {
        LOG(LEVEL_ERROR, "fail %s: no such probe module named %s\n", name,
            value);
        return Conf_ERR;
    }

    xconf->op = Op_HelpProbeModule;

    return Conf_OK;
}

static ConfRes SET_help_generate_module(void *conf, const char *name,
                                        const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    xconf->generator = get_generate_module_by_name(value);
    if (!xconf->generator) {
        LOG(LEVEL_ERROR, "fail %s: no such generate module named %s\n", name,
            value);
        return Conf_ERR;
    }

    xconf->op = Op_HelpGenerateModule;

    return Conf_OK;
}

static ConfRes SET_help_output_module(void *conf, const char *name,
                                      const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    xconf->out_conf.output_module = get_output_module_by_name(value);
    if (!xconf->out_conf.output_module) {
        LOG(LEVEL_ERROR, "fail %s: no such output module named %s\n", name,
            value);
        return Conf_ERR;
    }

    xconf->op = Op_HelpOutputModule;

    return Conf_OK;
}

static ConfRes SET_probe_module(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->probe) {
            fprintf(xconf->echo, "probe-module = %s\n", xconf->probe->name);
        }
        return 0;
    }

    /* support cancellation */
    if (value[0] == 0) {
        xconf->probe = NULL;
        return Conf_OK;
    }

    xconf->probe = get_probe_module_by_name(value);
    if (!xconf->probe) {
        LOG(LEVEL_ERROR, "fail %s: no such probe module\n", value);
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_generate_module(void *conf, const char *name,
                                   const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->generator) {
            fprintf(xconf->echo, "generate-module = %s\n",
                    xconf->generator->name);
        }
        return 0;
    }

    xconf->generator = get_generate_module_by_name(value);
    if (!xconf->generator) {
        LOG(LEVEL_ERROR, "fail %s: no such generate module\n", value);
        return Conf_ERR;
    }

    if (xconf->op == Op_Default)
        xconf->op = Op_Scan;

    return Conf_OK;
}

static ConfRes SET_output_module(void *conf, const char *name,
                                 const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->out_conf.output_module) {
            fprintf(xconf->echo, "output-module = %s\n",
                    xconf->out_conf.output_module->name);
        }
        return 0;
    }

    /* allow cancellation*/
    if (value[0] == 0) {
        xconf->out_conf.output_module = NULL;
        return Conf_OK;
    }

    xconf->out_conf.output_module = get_output_module_by_name(value);
    if (!xconf->out_conf.output_module) {
        LOG(LEVEL_ERROR, "fail %s: no such output module\n", value);
        return Conf_ERR;
    }

    if (xconf->op == Op_Default)
        xconf->op = Op_Scan;

    return Conf_OK;
}

static ConfRes SET_output_as_info(void *conf, const char *name,
                                  const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->echo_all || xconf->out_conf.output_as_info) {
            fprintf(xconf->echo, "output-as-info = %s\n",
                    xconf->out_conf.output_as_info ? "true" : "false");
        }
        return 0;
    }

    xconf->out_conf.output_as_info = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_ip2asn_v6(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->ip2asn_v6_filename && xconf->ip2asn_v6_filename[0]) {
            fprintf(xconf->echo, "ip2asn-v6 = %s\n", xconf->ip2asn_v6_filename);
        }
        return 0;
    }

    FREE(xconf->ip2asn_v6_filename);
    xconf->ip2asn_v6_filename = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_ip2asn_v4(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->ip2asn_v4_filename && xconf->ip2asn_v4_filename[0]) {
            fprintf(xconf->echo, "ip2asn-v4 = %s\n", xconf->ip2asn_v4_filename);
        }
        return 0;
    }

    FREE(xconf->ip2asn_v4_filename);
    xconf->ip2asn_v4_filename = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_output_filename(void *conf, const char *name,
                                   const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->out_conf.output_filename[0]) {
            fprintf(xconf->echo, "output-file = %s\n",
                    xconf->out_conf.output_filename);
        }
        return 0;
    }

    safe_strcpy(xconf->out_conf.output_filename,
                sizeof(xconf->out_conf.output_filename), value);

    return Conf_OK;
}

static ConfRes SET_show_output(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->out_conf.is_show_failed) {
            fprintf(xconf->echo, "show-output = failed\n");
        }
        if (xconf->out_conf.is_show_info) {
            fprintf(xconf->echo, "show-output = info\n");
        }
        if (xconf->out_conf.no_show_success) {
            fprintf(xconf->echo, "no-show-output = success\n");
        }
        return 0;
    }

    if (conf_equals("failed", value) || conf_equals("fail", value) ||
        conf_equals("failure", value)) {
        xconf->out_conf.is_show_failed = true;
    } else if (conf_equals("info", value) ||
               conf_equals("information", value)) {
        xconf->out_conf.is_show_info = true;
    } else if (conf_equals("success", value) ||
               conf_equals("successed", value)) {
        xconf->out_conf.no_show_success = false;
    } else {
        LOG(LEVEL_ERROR, "fail %s: no item named %s\n", name, value);
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_no_show_output(void *conf, const char *name,
                                  const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_show_output*/
        return 0;
    }

    if (conf_equals("failed", value) || conf_equals("fail", value)) {
        xconf->out_conf.is_show_failed = false;
    } else if (conf_equals("info", value) ||
               conf_equals("information", value)) {
        xconf->out_conf.is_show_info = false;
    } else if (conf_equals("success", value)) {
        xconf->out_conf.no_show_success = true;
    } else {
        LOG(LEVEL_ERROR, "fail %s: no item named %s\n", name, value);
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_no_ansi(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->is_no_ansi || xconf->echo_all) {
            fprintf(xconf->echo, "no-ansi = %s\n",
                    xconf->is_no_ansi ? "true" : "false");
        }
        return 0;
    }

    xconf->is_no_ansi = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_no_escape(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->no_escape_char || xconf->echo_all) {
            fprintf(xconf->echo, "no-escape = %s\n",
                    xconf->no_escape_char ? "true" : "false");
        }
        return 0;
    }

    xconf->no_escape_char = conf_parse_bool(value);
    dach_no_escape_char();

    return Conf_OK;
}

static ConfRes SET_print_status(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->is_status_queue) {
            fprintf(xconf->echo, "print-status = queue\n");
        }
        if (xconf->is_status_info_num) {
            fprintf(xconf->echo, "print-status = info-num\n");
        }
        if (xconf->is_status_hit_rate) {
            fprintf(xconf->echo, "print-status = hit-rate\n");
        }
        return 0;
    }

    if (conf_equals("queue", value)) {
        xconf->is_status_queue = true;
    } else if (conf_equals("info-num", value) || conf_equals("info", value)) {
        xconf->is_status_info_num = true;
    } else if (conf_equals("hit-rate", value) || conf_equals("hit", value)) {
        xconf->is_status_hit_rate = true;
    } else {
        LOG(LEVEL_ERROR, "fail %s: no item named %s\n", name, value);
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_scan_module_args(void *conf, const char *name,
                                    const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->scanner_args && xconf->scanner_args[0]) {
            fprintf(xconf->echo, "scan-module-args = %s\n",
                    xconf->scanner_args);
        }
        return 0;
    }

    FREE(xconf->scanner_args);
    xconf->scanner_args = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_probe_module_args(void *conf, const char *name,
                                     const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->probe_args && xconf->probe_args[0]) {
            fprintf(xconf->echo, "probe-module-args = %s\n", xconf->probe_args);
        }
        return 0;
    }

    FREE(xconf->probe_args);
    xconf->probe_args = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_generate_module_args(void *conf, const char *name,
                                        const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->generator_args && xconf->generator_args[0]) {
            fprintf(xconf->echo, "generate-module-args = %s\n",
                    xconf->generator_args);
        }
        return 0;
    }

    FREE(xconf->generator_args);
    xconf->generator_args = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_output_module_args(void *conf, const char *name,
                                      const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->out_conf.output_args && xconf->out_conf.output_args[0]) {
            fprintf(xconf->echo, "output-module-args = %s\n",
                    xconf->out_conf.output_args);
        }
        return 0;
    }

    FREE(xconf->out_conf.output_args);
    xconf->out_conf.output_args = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_list_scan_modules(void *conf, const char *name,
                                     const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }
    xconf->op = conf_parse_bool(value) ? Op_ListScanModules : xconf->op;
    return Conf_OK;
}

static ConfRes SET_list_probe_modules(void *conf, const char *name,
                                      const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }
    xconf->op = conf_parse_bool(value) ? Op_ListProbeModules : xconf->op;
    return Conf_OK;
}

static ConfRes SET_list_generate_modules(void *conf, const char *name,
                                         const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }
    xconf->op = conf_parse_bool(value) ? Op_ListGenerateModules : xconf->op;
    return Conf_OK;
}

static ConfRes SET_list_output_modules(void *conf, const char *name,
                                       const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }
    xconf->op = conf_parse_bool(value) ? Op_ListOutputModules : xconf->op;
    return Conf_OK;
}

static ConfRes SET_listif(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value))
        xconf->op = Op_ListAdapters;
    return Conf_OK;
}

static ConfRes SET_help_param(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->help_param);
    xconf->help_param = STRDUP(value);
    xconf->op         = Op_HelpParam;

    return Conf_OK;
}

static ConfRes SET_search_param(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->search_param);
    xconf->search_param = STRDUP(value);
    xconf->op           = Op_SearchParam;

    return Conf_OK;
}

static ConfRes SET_search_module(void *conf, const char *name,
                                 const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->search_module);
    xconf->search_module = STRDUP(value);
    xconf->op            = Op_SearchModule;

    return Conf_OK;
}

static ConfRes SET_list_target(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;

    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value))
        xconf->op = Op_ListTargets;

    char *opt = conf_parse_opt_str(name);
    if (opt) {
        if (strcmp(opt, "order") == 0 || strcmp(opt, "norandom") == 0)
            xconf->listtargets_in_order = 1;
    }

    return Conf_OK;
}

static ConfRes SET_list_range(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value))
        xconf->op = Op_ListRange;

    return Conf_OK;
}

#ifndef NOT_FOUND_PCRE2
static ConfRes SET_list_nmap_probes(void *conf, const char *name,
                                    const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->nmap_file);
    xconf->nmap_file = STRDUP(value);
    xconf->op        = Op_ListNmapProbes;

    return Conf_OK;
}
#endif

#ifndef NOT_FOUND_BSON
static ConfRes SET_parse_bson(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->parse_bson_file);
    xconf->parse_bson_file = STRDUP(value);
    xconf->op              = Op_ParseBson;

    return Conf_OK;
}
#endif

#ifndef NOT_FOUND_MONGOC
static ConfRes SET_store_json(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->store_json_file);
    xconf->store_json_file = STRDUP(value);
    xconf->op              = Op_StoreJson;

    return Conf_OK;
}

static ConfRes SET_store_bson(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->store_bson_file);
    xconf->store_bson_file = STRDUP(value);
    xconf->op              = Op_StoreBson;

    return Conf_OK;
}

static ConfRes SET_mongodb_uri(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->mongodb_uri);
    xconf->mongodb_uri = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_mongodb_db(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->mongodb_db);
    xconf->mongodb_db = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_mongodb_col(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->mongodb_col);
    xconf->mongodb_col = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_mongodb_app(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    FREE(xconf->mongodb_app);
    xconf->mongodb_app = STRDUP(value);

    return Conf_OK;
}
#endif

static ConfRes SET_pfring(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_pfring || xconf->echo_all)
            fprintf(xconf->echo, "pfring = %s\n",
                    xconf->is_pfring ? "true" : "false");
        return 0;
    }

    xconf->is_pfring = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_rawsocket(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_rawsocket || xconf->echo_all)
            fprintf(xconf->echo, "raw-socket = %s\n",
                    xconf->is_rawsocket ? "true" : "false");
        return 0;
    }

    xconf->is_rawsocket = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_noresume(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->is_noresume || xconf->echo_all) {
            fprintf(xconf->echo, "no-resume = %s\n",
                    xconf->is_noresume ? "true" : "false");
        }
        return 0;
    }

    xconf->is_noresume = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_nodedup(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->is_nodedup || xconf->echo_all) {
            fprintf(xconf->echo, "no-dedup = %s\n",
                    xconf->is_nodedup ? "true" : "false");
        }
        return 0;
    }

    xconf->is_nodedup = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_tcp_window(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->tcp_window != XCONF_DFT_TCP_OTHER_WINSIZE || xconf->echo_all)
            fprintf(xconf->echo, "tcp-window = %u\n", xconf->tcp_window);
        return 0;
    }

    unsigned x = conf_parse_int(value);
    if (x > 65535) {
        LOG(LEVEL_ERROR, "%s=<n>: expected number less than 65535\n", name);
        return Conf_ERR;
    } else {
        xconf->tcp_window = x;
    }

    return Conf_OK;
}

static ConfRes SET_tcp_init_window(void *conf, const char *name,
                                   const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->tcp_init_window != XCONF_DFT_TCP_SYN_WINSIZE ||
            xconf->echo_all)
            fprintf(xconf->echo, "tcp-init-window = %u\n",
                    xconf->tcp_init_window);
        return 0;
    }

    unsigned x = conf_parse_int(value);
    if (x > 65535) {
        LOG(LEVEL_ERROR, "%s=<n>: expected number less than 65535\n", name);
        return Conf_ERR;
    } else {
        xconf->tcp_init_window = x;
    }

    return Conf_OK;
}

static ConfRes SET_packet_ttl(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->packet_ttl != XCONF_DFT_PACKET_TTL || xconf->echo_all)
            fprintf(xconf->echo, "packet-ttl = %u\n", xconf->packet_ttl);
        return 0;
    }

    unsigned x = conf_parse_int(value);
    if (x >= 256) {
        LOG(LEVEL_ERROR, "%s=%u: expected number less than 256\n", name, x);
        return Conf_ERR;
    } else {
        xconf->packet_ttl = x;
    }

    return Conf_OK;
}

static ConfRes SET_dedup_win(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->dedup_win != XCONF_DFT_DEDUP_WIN || xconf->echo_all)
            fprintf(xconf->echo, "dedup-win = %u\n", xconf->dedup_win);
        return 0;
    }

    if (conf_parse_int(value) < 1024) {
        LOG(LEVEL_ERROR, "%s: dedup-win must >= 1024.\n", name);
        return Conf_ERR;
    }

    xconf->dedup_win = conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_stack_buf_count(void *conf, const char *name,
                                   const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->stack_buf_count != XCONF_DFT_STACK_BUF_COUNT ||
            xconf->echo_all) {
            fprintf(xconf->echo, "stack-buf-count = %u\n",
                    xconf->stack_buf_count);
        }
        return 0;
    }

    uint64_t v = conf_parse_int(value);
    if (v < 2048) {
        LOG(LEVEL_ERROR, "%s: stack-buf-count must >= 2048.\n", value);
        return Conf_ERR;
    } else if (!conf_is_power_of_2(v)) {
        LOG(LEVEL_ERROR, "%s: stack-buf-count must be power of 2.\n", value);
        return Conf_ERR;
    } else if (v > RTE_RING_SZ_MASK) {
        LOG(LEVEL_ERROR, "%s: stack-buf-count exceeded size limit.\n", value);
        return Conf_ERR;
    }

    xconf->stack_buf_count = v;

    return Conf_OK;
}

static ConfRes SET_dispatch_buf_count(void *conf, const char *name,
                                      const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->dispatch_buf_count != XCONF_DFT_DISPATCH_BUF_COUNT ||
            xconf->echo_all) {
            fprintf(xconf->echo, "dispatch-buf-count = %u\n",
                    xconf->dispatch_buf_count);
        }
        return 0;
    }

    uint64_t v = conf_parse_int(value);
    if (v < 2048) {
        LOG(LEVEL_ERROR, "%s: dispatch-buf-count must >= 2048.\n", value);
        return Conf_ERR;
    } else if (!conf_is_power_of_2(v)) {
        LOG(LEVEL_ERROR, "%s: dispatch-buf-count must be power of 2.\n", value);
        return Conf_ERR;
    } else if (v > RTE_RING_SZ_MASK) {
        LOG(LEVEL_ERROR, "%s: dispatch-buf-count exceeded size limit.\n",
            value);
        return Conf_ERR;
    }

    xconf->dispatch_buf_count = v;

    return Conf_OK;
}

static ConfRes SET_forever(void *conf, const char *name, const char *value) {
    UNUSEDPARM(name);
    UNUSEDPARM(value);

    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    xconf->wait = INT_MAX;

    return Conf_OK;
}

static ConfRes SET_wait(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->wait != XCONF_DFT_WAIT || xconf->echo_all) {
            if (xconf->wait == INT_MAX)
                fprintf(xconf->echo, "forever = true\n");
            else
                fprintf(xconf->echo, "wait = %u\n", xconf->wait);
        }
        return 0;
    }

    xconf->wait = (unsigned)conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_rx_handler_count(void *conf, const char *name,
                                    const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->rx_handler_count > 1 || xconf->echo_all) {
            fprintf(xconf->echo, "rx-handler-count = %u\n",
                    xconf->rx_handler_count);
        }
        return 0;
    }

    unsigned count = conf_parse_int(value);
    if (count <= 0) {
        LOG(LEVEL_ERROR, "%s: receive handler thread count cannot be zero.\n",
            name);
        return Conf_ERR;
    } else if (!conf_is_power_of_2(count)) {
        LOG(LEVEL_ERROR,
            "%s: receive handler thread count must be power of 2.\n", value);
        return Conf_ERR;
    } else if (count > 256) {
        /* dispatch hashes source IP to 8 bits; masks above 256 would leave
         * the high handler queues permanently empty. */
        LOG(LEVEL_ERROR, "%s: receive handler thread count must be <= 256.\n",
            name);
        return Conf_ERR;
    }

    xconf->rx_handler_count = count;

    return Conf_OK;
}

static ConfRes SET_tx_thread_count(void *conf, const char *name,
                                   const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->tx_thread_count > 1 || xconf->echo_all) {
            fprintf(xconf->echo, "tx-thread-count = %u\n",
                    xconf->tx_thread_count);
        }
        return 0;
    }

    unsigned count = conf_parse_int(value);
    if (count == 0) {
        LOG(LEVEL_ERROR, "%s: transmit thread count cannot be zero.\n", name);
        return Conf_ERR;
    }

    xconf->tx_thread_count = count;

    return Conf_OK;
}

static ConfRes SET_adapter(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.ifname[0]) {
            fprintf(xconf->echo, "adapter = %s\n", xconf->nic.ifname);
        }
        return 0;
    }

    snprintf(xconf->nic.ifname, sizeof(xconf->nic.ifname), "%s", value);

    return Conf_OK;
}

static ConfRes SET_source_ip(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.src.ipv4.first != 0 || xconf->nic.src.ipv4.last != 0) {
            ipaddress_formatted_t ipv4_first =
                ipv4address_fmt((ipv4address)(xconf->nic.src.ipv4.first));
            ipaddress_formatted_t ipv4_last =
                ipv4address_fmt((ipv4address)(xconf->nic.src.ipv4.last));
            if (xconf->nic.src.ipv4.first == xconf->nic.src.ipv4.last) {
                fprintf(xconf->echo, "source-ipv4 = %s\n", ipv4_first.string);
            } else if (xconf->nic.src.ipv4.first < xconf->nic.src.ipv4.last) {
                fprintf(xconf->echo, "source-ipv4 = %s-%s\n", ipv4_first.string,
                        ipv4_last.string);
            }
        }

        if (xconf->nic.src.ipv6.range) {
            ipaddress_formatted_t ipv6_first =
                ipv6address_fmt(xconf->nic.src.ipv6.first);
            ipaddress_formatted_t ipv6_last =
                ipv6address_fmt(xconf->nic.src.ipv6.last);
            if (ipv6address_is_lessthan(xconf->nic.src.ipv6.first,
                                        xconf->nic.src.ipv6.last)) {
                fprintf(xconf->echo, "source-ipv6 = %s-%s\n", ipv6_first.string,
                        ipv6_last.string);
            } else {
                fprintf(xconf->echo, "source-ipv6 = %s\n", ipv6_first.string);
            }
        }

        return 0;
    }

    /* Send packets FROM this IP address */
    struct Range  range;
    struct Range6 range6;
    int           err;

    /* Grab the next IPv4 or IPv6 range */
    err = target_parse_range(value, 0, 0, &range, &range6);
    switch (err) {
        case Ipv4_Address:
            /* If more than one IP address given, make the range is
             * a power of two (1, 2, 4, 8, 16, ...) */
            if (!conf_is_power_of_2((uint64_t)range.end - range.begin + 1)) {
                LOG(LEVEL_ERROR, "range must be power of two: %s=%s\n", name,
                    value);
                return Conf_ERR;
            }
            xconf->nic.src.ipv4.first = range.begin;
            xconf->nic.src.ipv4.last  = range.end;
            xconf->nic.src.ipv4.range = range.end - range.begin + 1;
            break;
        case Ipv6_Address:
            if (range6.begin.hi != range6.end.hi) {
                LOG(LEVEL_ERROR,
                    "range of ipv6 source addresses is too large.\n");
                return Conf_ERR;
            }
            /* If more than one IP address given, make the range is
             * a power of two (1, 2, 4, 8, 16, ...) */
            if (!conf_is_power_of_2(range6.end.lo - range6.begin.lo + 1)) {
                LOG(LEVEL_ERROR, "range must be power of two: %s=%s\n", name,
                    value);
                return Conf_ERR;
            }
            xconf->nic.src.ipv6.first = range6.begin;
            xconf->nic.src.ipv6.last  = range6.end;
            xconf->nic.src.ipv6.range = range6.end.lo - range6.begin.lo + 1;
            break;
        default:
            LOG(LEVEL_ERROR, "bad source IP address: %s=%s\n", name, value);
            LOG(LEVEL_HINT, "addresses looks like \"192.168.1.23\" or "
                            "\"2001:db8:1::1ce9\".\n");
            return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_source_port(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->nic.src.port.first) {
            fprintf(xconf->echo, "source-port = %d", xconf->nic.src.port.first);
            if (xconf->nic.src.port.first != xconf->nic.src.port.last) {
                /* --adapter-port <first>-<last> */
                fprintf(xconf->echo, "-%d", xconf->nic.src.port.last);
            }
            fprintf(xconf->echo, "\n");
        }
        return 0;
    }

    /* Send packets FROM this port number */
    unsigned         is_error = 0;
    struct RangeList ports    = {0};

    rangelist_parse_ports(&ports, value, &is_error, 0);

    /* Check if there was an error in parsing */
    if (is_error) {
        LOG(LEVEL_ERROR, "bad source port specification: %s\n", name);
        return Conf_ERR;
    }

    /* Only allow one range of ports */
    if (ports.list_len != 1) {
        LOG(LEVEL_ERROR,
            "only one '%s' range may be specified, found %u ranges\n", name,
            ports.list_len);
        return Conf_ERR;
    }

    /* verify range is power of 2 (1, 2, 4, 8, 16, ...) */
    if (!conf_is_power_of_2(ports.list[0].end - ports.list[0].begin + 1)) {
        LOG(LEVEL_ERROR, "source port range must be power of two: %s=%s\n",
            name, value);
        return Conf_ERR;
    }

    xconf->nic.src.port.first = ports.list[0].begin;
    xconf->nic.src.port.last  = ports.list[0].end;
    xconf->nic.src.port.range = ports.list[0].end - ports.list[0].begin + 1;

    return Conf_OK;
}

static ConfRes SET_target_output(void *conf, const char *name,
                                 const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        rangeport_println(&xconf->targets.ports, xconf->echo);
        /*
         * IPv4 address targets
         */
        unsigned i;
        for (i = 0; i < xconf->targets.ipv4.list_len; i++) {
            unsigned     prefix_bits;
            struct Range range = xconf->targets.ipv4.list[i];

            if (range.begin == range.end) {
                fprintf(xconf->echo, "range = %u.%u.%u.%u",
                        (range.begin >> 24) & 0xFF, (range.begin >> 16) & 0xFF,
                        (range.begin >> 8) & 0xFF, (range.begin >> 0) & 0xFF);
            } else if (range_is_cidr(range, &prefix_bits)) {
                fprintf(xconf->echo, "range = %u.%u.%u.%u/%u",
                        (range.begin >> 24) & 0xFF, (range.begin >> 16) & 0xFF,
                        (range.begin >> 8) & 0xFF, (range.begin >> 0) & 0xFF,
                        prefix_bits);
            } else {
                fprintf(xconf->echo, "range = %u.%u.%u.%u-%u.%u.%u.%u",
                        (range.begin >> 24) & 0xFF, (range.begin >> 16) & 0xFF,
                        (range.begin >> 8) & 0xFF, (range.begin >> 0) & 0xFF,
                        (range.end >> 24) & 0xFF, (range.end >> 16) & 0xFF,
                        (range.end >> 8) & 0xFF, (range.end >> 0) & 0xFF);
            }
            fprintf(xconf->echo, "\n");
        }
        for (i = 0; i < xconf->targets.ipv6.list_len; i++) {
            bool                  exact = false;
            struct Range6         range = xconf->targets.ipv6.list[i];
            ipaddress_formatted_t fmt   = ipv6address_fmt(range.begin);

            fprintf(xconf->echo, "range = %s", fmt.string);
            if (!ipv6address_is_equal(range.begin, range.end)) {
                unsigned cidr_bits = range6list_cidr_bits(&range, &exact);

                if (exact && cidr_bits) {
                    fprintf(xconf->echo, "/%u", cidr_bits);
                } else {
                    fmt = ipv6address_fmt(range.end);
                    fprintf(xconf->echo, "-%s", fmt.string);
                }
            }
            fprintf(xconf->echo, "\n");
        }
    }

    return Conf_OK;
}

static ConfRes SET_target_ip(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    rangelist_rm_all(&xconf->targets.ipv4);
    range6list_rm_all(&xconf->targets.ipv6);
    xconf->targets.count_ipv4s    = 0;
    xconf->targets.count_ipv6s.hi = 0;
    xconf->targets.count_ipv6s.lo = 0;

    int err;
    err = targetset_add_ip_str(&xconf->targets, value);
    if (err) {
        LOG(LEVEL_ERROR, "bad IP address/range: %s\n", value);
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_target_asn_v4(void *conf, const char *name,
                                 const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    FREE(xconf->target_asn_v4);
    xconf->target_asn_v4 = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_target_asn_v6(void *conf, const char *name,
                                 const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    FREE(xconf->target_asn_v6);
    xconf->target_asn_v6 = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_exclude_asn_v4(void *conf, const char *name,
                                  const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    FREE(xconf->exclude_asn_v4);
    xconf->exclude_asn_v4 = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_exclude_asn_v6(void *conf, const char *name,
                                  const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    FREE(xconf->exclude_asn_v6);
    xconf->exclude_asn_v6 = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_adapter_snaplen(void *conf, const char *name,
                                   const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.snaplen != XCONF_DFT_SNAPLEN || xconf->echo_all) {
            fprintf(xconf->echo, "adapter-snaplen = %u\n", xconf->nic.snaplen);
        }
        return 0;
    }

    xconf->nic.snaplen = (unsigned)conf_parse_int(value);
    if (xconf->nic.snaplen > 65535) {
        LOG(LEVEL_ERROR, "snaplen must be less than 65535.\n");
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_adapter_vlan(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->nic.is_vlan) {
            fprintf(xconf->echo, "adapter-vlan = %u\n", xconf->nic.vlan_id);
        }
        return 0;
    }

    xconf->nic.is_vlan = 1;
    xconf->nic.vlan_id = (unsigned)conf_parse_int(value);

    return Conf_OK;
}

static ConfRes SET_port_them(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    rangelist_rm_all(&xconf->targets.ports);
    xconf->targets.count_ports = 0;

    unsigned is_error = 0;

    rangelist_parse_ports(&xconf->targets.ports, value, &is_error, 0);

    if (is_error) {
        LOG(LEVEL_ERROR, "fail to set target port.\n");
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_top_port(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    unsigned maxports = conf_parse_int(value);

    if (!maxports) {
        LOG(LEVEL_ERROR, "fail %s: value of top-port must > 0.\n", name);
        return Conf_ERR;
    }

    struct RangeList     *ports         = &xconf->targets.ports;
    static const unsigned max_tcp_ports = ARRAY_SIZE(top_tcp_ports);
    static const unsigned max_udp_ports = ARRAY_SIZE(top_udp_ports);

    unsigned i;
    if (name[0] == 'u') {
        LOG(LEVEL_DETAIL, "adding UDP top-ports = %u\n", maxports);
        for (i = 0; i < maxports && i < max_udp_ports; i++)
            rangelist_add_range_udp(ports, top_udp_ports[i], top_udp_ports[i]);
    } else {
        LOG(LEVEL_DETAIL, "adding TCP top-ports = %u\n", maxports);
        for (i = 0; i < maxports && i < max_tcp_ports; i++)
            rangelist_add_range_tcp(ports, top_tcp_ports[i], top_tcp_ports[i]);
    }

    /* Targets must be sorted after every change, before being used */
    rangelist_sort(ports);

    return Conf_OK;
}

static ConfRes SET_exclude_ip(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    rangelist_rm_all(&xconf->exclude.ipv4);
    range6list_rm_all(&xconf->exclude.ipv6);
    xconf->exclude.count_ipv4s    = 0;
    xconf->exclude.count_ipv6s.hi = 0;
    xconf->exclude.count_ipv6s.lo = 0;

    int err;
    err = targetset_add_ip_str(&xconf->exclude, value);
    if (err) {
        LOG(LEVEL_ERROR, "bad exclude address/range: %s\n", value);
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_exclude_port(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    rangelist_rm_all(&xconf->exclude.ports);
    xconf->exclude.count_ports = 0;

    unsigned defaultrange = 0;
    int      err;

    err = targetset_add_port_str(&xconf->exclude, value, defaultrange);
    if (err) {
        LOG(LEVEL_ERROR, "bad exclude port: %s\n", value);
        LOG(LEVEL_HINT, "a port is a number [0..65535]\n");
        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_include_file(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    rangelist_rm_all(&xconf->targets.ipv4);
    range6list_rm_all(&xconf->targets.ipv6);
    xconf->targets.count_ipv4s    = 0;
    xconf->targets.count_ipv6s.hi = 0;
    xconf->targets.count_ipv6s.lo = 0;

    int         err;
    const char *filename = value;

    err = targetset_parse_file(&xconf->targets, filename);
    if (err) {
        LOG(LEVEL_ERROR, "reading from include file\n");

        rangelist_rm_all(&xconf->targets.ipv4);
        range6list_rm_all(&xconf->targets.ipv6);
        xconf->targets.count_ipv4s    = 0;
        xconf->targets.count_ipv6s.hi = 0;
        xconf->targets.count_ipv6s.lo = 0;

        return Conf_ERR;
    }

    return Conf_OK;
}

static ConfRes SET_exclude_file(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        /*echo in SET_target_output*/
        return 0;
    }

    rangelist_rm_all(&xconf->exclude.ipv4);
    range6list_rm_all(&xconf->exclude.ipv6);
    xconf->exclude.count_ipv4s    = 0;
    xconf->exclude.count_ipv6s.hi = 0;
    xconf->exclude.count_ipv6s.lo = 0;

    unsigned    count1 = xconf->exclude.ipv4.list_len;
    unsigned    count2;
    int         err;
    const char *filename = value;

    // LOG(LEVEL_DETAIL, "excluding: %s\n", value);
    err = targetset_parse_file(&xconf->exclude, filename);
    if (err) {
        LOG(LEVEL_ERROR, "fail reading from exclude file\n");

        rangelist_rm_all(&xconf->exclude.ipv4);
        range6list_rm_all(&xconf->exclude.ipv6);
        xconf->exclude.count_ipv4s    = 0;
        xconf->exclude.count_ipv6s.hi = 0;
        xconf->exclude.count_ipv6s.lo = 0;

        return Conf_ERR;
    }
    /* Detect if this file has made any change, otherwise don't print
     * a message */
    count2 = xconf->exclude.ipv4.list_len;
    if (count2 - count1)
        LOG(LEVEL_HINT, "%s: excluding %u ranges from file\n", value,
            count2 - count1);

    return Conf_OK;
}

static ConfRes SET_source_mac(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->nic.my_mac_count) {
            ipaddress_formatted_t fmt = macaddress_fmt(xconf->nic.source_mac);
            fprintf(xconf->echo, "source-mac = %s\n", fmt.string);
        }
        return 0;
    }

    /* Send packets FROM this MAC address */
    macaddress_t source_mac;
    int          err;

    err = conf_parse_mac(value, &source_mac);
    if (err) {
        LOG(LEVEL_ERROR, "(CONF) bad MAC address: %s = %s\n", name, value);
        return Conf_ERR;
    }

    /* Check for duplicates */
    if (macaddress_is_equal(xconf->nic.source_mac, source_mac)) {
        /* suppresses warning message about duplicate MAC addresses if
         * they are in fact the same */
        return Conf_OK;
    }

    /* Warn if we are overwriting a Mac address */
    if (xconf->nic.my_mac_count != 0) {
        ipaddress_formatted_t fmt1 = macaddress_fmt(xconf->nic.source_mac);
        ipaddress_formatted_t fmt2 = macaddress_fmt(source_mac);
        LOG(LEVEL_HINT, "overwriting MAC address, was %s, now %s\n",
            fmt1.string, fmt2.string);
    }

    xconf->nic.source_mac   = source_mac;
    xconf->nic.my_mac_count = 1;

    return Conf_OK;
}

static ConfRes SET_router_ip(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->nic.router_ip) {
            ipaddress_formatted_t router_ip =
                ipv4address_fmt(xconf->nic.router_ip);
            fprintf(xconf->echo, "router-ip = %s\n", router_ip.string);
        }

        return 0;
    }

    /* Send packets FROM this IP address */
    struct Range range;

    range = range_parse_ipv4(value, 0, 0);

    /* Check for bad format */
    if (range.begin != range.end) {
        LOG(LEVEL_ERROR, "bad source IPv4 address: %s=%s\n", name, value);
        LOG(LEVEL_HINT, "addresses look like \"19.168.1.23\"\n");
        return Conf_ERR;
    }

    xconf->nic.router_ip = range.begin;

    return Conf_OK;
}

static ConfRes SET_router_mac(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (!macaddress_is_zero(xconf->nic.router_mac_ipv4)) {
            ipaddress_formatted_t fmt =
                macaddress_fmt(xconf->nic.router_mac_ipv4);
            fprintf(xconf->echo, "router-mac-ipv4 = %s\n", fmt.string);
        }
        if (!macaddress_is_zero(xconf->nic.router_mac_ipv6)) {
            ipaddress_formatted_t fmt =
                macaddress_fmt(xconf->nic.router_mac_ipv6);
            fprintf(xconf->echo, "router-mac-ipv6 = %s\n", fmt.string);
        }

        return 0;
    }

    macaddress_t router_mac;
    int          err;
    err = conf_parse_mac(value, &router_mac);
    if (err) {
        LOG(LEVEL_ERROR, "(CONF): bad MAC address: %s = %s\n", name, value);
        return Conf_ERR;
    }
    if (conf_equals("router-mac-ipv4", name))
        xconf->nic.router_mac_ipv4 = router_mac;
    else if (conf_equals("router-mac-ipv6", name))
        xconf->nic.router_mac_ipv6 = router_mac;
    else {
        xconf->nic.router_mac_ipv4 = router_mac;
        xconf->nic.router_mac_ipv6 = router_mac;
    }

    return Conf_OK;
}

static ConfRes SET_meta_filename(void *conf, const char *name,
                                 const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->meta_filename[0])
            fprintf(xconf->echo, "meta-file = %s\n", xconf->meta_filename);
        return 0;
    }

    safe_strcpy(xconf->meta_filename, sizeof(xconf->meta_filename), value);

    return Conf_OK;
}

/**
 * read conf file and set params directly
 */
static ConfRes SET_read_conf(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    int err = xconf_read_conf(xconf, value);
    if (err)
        return Conf_ERR;

    xconf->have_read_conf = 1;

    return Conf_OK;
}

static ConfRes SET_packet_trace(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_packet_trace || xconf->echo_all)
            fprintf(xconf->echo, "packet-trace = %s\n",
                    xconf->is_packet_trace ? "true" : "false");
        return 0;
    }
    xconf->is_packet_trace = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_ndjson_status(void *conf, const char *name,
                                 const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_status_ndjson || xconf->echo_all)
            fprintf(xconf->echo, "ndjson-status = %s\n",
                    xconf->is_status_ndjson ? "true" : "false");
        return 0;
    }
    xconf->is_status_ndjson = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_no_status(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_no_status || xconf->echo_all)
            fprintf(xconf->echo, "no-status = %s\n",
                    xconf->is_no_status ? "true" : "false");
        return 0;
    }
    xconf->is_no_status = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_append(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->out_conf.is_append || xconf->echo_all)
            fprintf(xconf->echo, "append-output = %s\n",
                    xconf->out_conf.is_append ? "true" : "false");
        return 0;
    }
    xconf->out_conf.is_append = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_out_screen(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->out_conf.is_out_screen || xconf->echo_all)
            fprintf(xconf->echo, "output-screen = %s\n",
                    xconf->out_conf.is_out_screen ? "true" : "false");
        return 0;
    }
    xconf->out_conf.is_out_screen = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_interactive_mode(void *conf, const char *name,
                                    const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    xconf->interactive_mode = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_offline(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_offline || xconf->echo_all)
            fprintf(xconf->echo, "offline = %s\n",
                    xconf->is_offline ? "true" : "false");
        return 0;
    }
    xconf->is_offline = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_no_cpu_bind(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_no_cpu_bind || xconf->echo_all)
            fprintf(xconf->echo, "no-cpu-bind = %s\n",
                    xconf->is_no_cpu_bind ? "true" : "false");
        return 0;
    }
    xconf->is_no_cpu_bind = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_static_seed(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_static_seed || xconf->echo_all)
            fprintf(xconf->echo, "static-seed = %s\n",
                    xconf->is_static_seed ? "true" : "false");
        return 0;
    }
    xconf->is_static_seed = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_infinite(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_infinite || xconf->echo_all)
            fprintf(xconf->echo, "infinite = %s\n",
                    xconf->is_infinite ? "true" : "false");
        return 0;
    }
    xconf->is_infinite = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_pcap_filename(void *conf, const char *name,
                                 const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->pcap_filename[0])
            fprintf(xconf->echo, "pcap-filename = %s\n", xconf->pcap_filename);
        return 0;
    }
    if (value)
        safe_strcpy(xconf->pcap_filename, sizeof(xconf->pcap_filename), value);
    return Conf_OK;
}

static ConfRes SET_echo(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    if (conf_equals("echo", name) && conf_parse_bool(value))
        xconf->op = Op_Echo;
    else if (conf_equals("echo-all", name) && conf_parse_bool(value)) {
        xconf->op       = Op_Echo;
        xconf->echo_all = 1;
    }

    return Conf_OK;
}

static ConfRes SET_debugif(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value))
        xconf->op = Op_DebugIF;

    return Conf_OK;
}

static ConfRes SET_benchmark(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value))
        xconf->op = Op_Benchmark;

    return Conf_OK;
}

static ConfRes SET_selftest(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value))
        xconf->op = Op_Selftest;

    return Conf_OK;
}

static ConfRes SET_list_cidr(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value))
        xconf->op = Op_ListCidr;

    return Conf_OK;
}

static ConfRes SET_lan_mode(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value)) {
        SET_router_mac(xconf, "router-mac", "ff-ff-ff-ff-ff-ff");
    }

    return Conf_OK;
}

static ConfRes SET_bypass_os(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_bypass_os || xconf->echo_all)
            fprintf(xconf->echo, "bypass-os = %s\n",
                    xconf->is_bypass_os ? "true" : "false");
        return 0;
    }

    xconf->is_bypass_os = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_init_ipv4(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->set_ipv4_adapter)
            fprintf(xconf->echo, "init-ipv4-adapter = %s",
                    xconf->init_ipv4_adapter ? "true" : "false");
        return 0;
    }

    xconf->set_ipv4_adapter  = 1;
    xconf->init_ipv4_adapter = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_init_ipv6(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->set_ipv6_adapter)
            fprintf(xconf->echo, "init-ipv6-adapter = %s",
                    xconf->init_ipv6_adapter ? "true" : "false");
        return 0;
    }

    xconf->set_ipv6_adapter  = 1;
    xconf->init_ipv6_adapter = conf_parse_bool(value);

    return Conf_OK;
}

static ConfRes SET_fake_router_mac(void *conf, const char *name,
                                   const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        return 0;
    }

    if (conf_parse_bool(value)) {
        SET_router_mac(xconf, "router-mac", "01-02-03-04-05-06");
    }

    return Conf_OK;
}

static ConfRes SET_rate(void *conf, const char *name, const char *value) {
    XConf   *xconf = (XConf *)conf;
    double   rate  = 0.0;
    double   point = 10.0;
    unsigned i;

    if (xconf->echo) {
        if ((unsigned)(xconf->max_rate * 100000) % 100000) {
            /* print as floating point number, which is rare */
            fprintf(xconf->echo, "rate = %f\n", xconf->max_rate);
        } else {
            /* pretty print as just an integer, which is what most people
             * expect */
            fprintf(xconf->echo, "rate = %.0f\n", xconf->max_rate);
        }
        return 0;
    }

    for (i = 0; value[i] && value[i] != '.'; i++) {
        char c = value[i];
        if (c < '0' || '9' < c) {
            LOG(LEVEL_ERROR, "(CONF) non-digit in rate spec: %s=%s\n", name,
                value);
            return Conf_ERR;
        }
        rate = rate * 10.0 + (c - '0');
    }

    if (value[i] == '.') {
        i++;
        while (value[i]) {
            char c = value[i];
            if (c < '0' || '9' < c) {
                LOG(LEVEL_ERROR, "(CONF) non-digit in rate spec: %s=%s\n", name,
                    value);
                return Conf_ERR;
            }
            rate += (c - '0') / point;
            point *= 10.0;
            value++;
        }
    }

    xconf->max_rate = rate;
    return Conf_OK;
}

static ConfRes SET_max_packet_len(void *conf, const char *name,
                                  const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->max_packet_len != XCONF_DFT_MAX_PKT_LEN || xconf->echo_all) {
            fprintf(xconf->echo, "max-packet-len = %u\n",
                    xconf->max_packet_len);
        }
        return 0;
    }
    xconf->max_packet_len = conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_resume_index(void *conf, const char *name,
                                const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->resume.index != 0 || xconf->echo_all) {
            fprintf(xconf->echo, "resume-index = %" PRIu64 "\n",
                    xconf->resume.index);
        }
        return 0;
    }
    xconf->resume.index = conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_no_bpf(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_no_bpf || xconf->echo_all)
            fprintf(xconf->echo, "no-bpf-filter = %s\n",
                    xconf->is_no_bpf ? "true" : "false");
        return 0;
    }
    xconf->is_no_bpf = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_bpf_filter(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->bpf_filter && xconf->bpf_filter[0])
            fprintf(xconf->echo, "bpf-filter = %s\n", xconf->bpf_filter);
        return 0;
    }

    FREE(xconf->bpf_filter);
    xconf->bpf_filter = STRDUP(value);

    return Conf_OK;
}

static ConfRes SET_seed(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    if (xconf->echo) {
        fprintf(xconf->echo, "seed = %" PRIu64 "\n", xconf->seed);
        return 0;
    }
    if (conf_equals("time", value))
        xconf->seed = time(0);
    else
        xconf->seed = conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_nothing(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }
    return Conf_OK;
}

static ConfRes SET_version(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    xconf->op = Op_PrintVersion;

    return Conf_OK;
}

static ConfRes SET_usage(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    xconf->op = Op_PrintUsage;

    return Conf_OK;
}

static ConfRes SET_print_intro(void *conf, const char *name,
                               const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    xconf->op = Op_PrintIntro;

    return Conf_OK;
}

static ConfRes SET_print_help(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (xconf->echo) {
        return 0;
    }

    xconf->op = Op_PrintHelp;

    return Conf_OK;
}

static ConfRes SET_log_level(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(value);
    if (xconf->echo) {
        int level = LOG_get_level();
        if (level > 0) {
            for (unsigned i = 0; i < level; i++) {
                fprintf(xconf->echo, "%c", 'd');
            }
            fprintf(xconf->echo, " = true\n");
        }
        return 0;
    }

    LOG_add_level(strlen(name));

    return Conf_OK;
}

static ConfRes SET_shard(void *conf, const char *name, const char *value) {
    XConf   *xconf = (XConf *)conf;
    unsigned one   = 0;
    unsigned of    = 0;

    UNUSEDPARM(name);
    if (xconf->echo) {
        if (xconf->shard.of > 1 || xconf->echo_all)
            fprintf(xconf->echo, "shard = %u/%u\n", xconf->shard.one,
                    xconf->shard.of);
        return 0;
    }
    while (isdigit(*value))
        one = one * 10 + (*(value++)) - '0';
    while (ispunct(*value))
        value++;
    while (isdigit(*value))
        of = of * 10 + (*(value++)) - '0';

    if (one < 1) {
        LOG(LEVEL_ERROR, "shard index can't be zero\n");
        LOG(LEVEL_HINT, "shard goes like 1/4 2/4 3/4 4/4\n");
        return Conf_ERR;
    }
    if (one > of) {
        LOG(LEVEL_ERROR, "shard spec is wrong\n");
        LOG(LEVEL_HINT, "shard goes like 1/4 2/4 3/4 4/4\n");
        return Conf_ERR;
    }
    xconf->shard.one = one;
    xconf->shard.of  = of;
    return Conf_OK;
}

static ConfRes SET_tcp_mss(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;

    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_mss) {
                case Default:
                    break;
                case Add:
                    if (xconf->templ_opts->tcp.mss == TCP_DEFAULT_MSS)
                        fprintf(xconf->echo, "tcp-mss = %s\n", "enable");
                    else
                        fprintf(xconf->echo, "tcp-mss = %u\n",
                                xconf->templ_opts->tcp.mss);
                    break;
                case Remove:
                    fprintf(xconf->echo, "tcp-mss = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (xconf->templ_opts == NULL)
        xconf->templ_opts = CALLOC(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        /* no following parameter, so interpret this to mean "enable" */
        xconf->templ_opts->tcp.is_mss = Add;
        xconf->templ_opts->tcp.mss    = TCP_DEFAULT_MSS;
    } else if (conf_is_bool(value)) {
        /* looking for "enable" or "disable", but any boolean works,
         * like "true/false" or "off/on" */
        if (conf_parse_bool(value)) {
            xconf->templ_opts->tcp.is_mss = Add;
            xconf->templ_opts->tcp.mss    = TCP_DEFAULT_MSS;
        } else
            xconf->templ_opts->tcp.is_mss = Remove;
    } else if (conf_is_int(value)) {
        /* A specific number was specified */
        uint64_t num = conf_parse_int(value);
        if (num >= 0x10000)
            goto fail;
        xconf->templ_opts->tcp.is_mss = Add;
        xconf->templ_opts->tcp.mss    = (unsigned)num;
    } else
        goto fail;

    return Conf_OK;
fail:
    LOG(LEVEL_ERROR, "%s: bad value: %s\n", name, value);
    return Conf_ERR;
}

static ConfRes SET_tcp_wscale(void *conf, const char *name, const char *value) {
    XConf                *xconf         = (XConf *)conf;
    static const unsigned default_value = 3;

    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_wscale) {
                case Default:
                    break;
                case Add:
                    if (xconf->templ_opts->tcp.wscale == default_value)
                        fprintf(xconf->echo, "tcp-wscale = %s\n", "enable");
                    else
                        fprintf(xconf->echo, "tcp-wscale = %u\n",
                                xconf->templ_opts->tcp.wscale);
                    break;
                case Remove:
                    fprintf(xconf->echo, "tcp-wscale = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (xconf->templ_opts == NULL)
        xconf->templ_opts = CALLOC(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        xconf->templ_opts->tcp.is_wscale = Add;
        xconf->templ_opts->tcp.wscale    = default_value;
    } else if (conf_is_bool(value)) {
        if (conf_parse_bool(value)) {
            xconf->templ_opts->tcp.is_wscale = Add;
            xconf->templ_opts->tcp.wscale    = default_value;
        } else
            xconf->templ_opts->tcp.is_wscale = Remove;
    } else if (conf_is_int(value)) {
        uint64_t num = conf_parse_int(value);
        if (num >= 255)
            goto fail;
        xconf->templ_opts->tcp.is_wscale = Add;
        xconf->templ_opts->tcp.wscale    = (unsigned)num;
    } else
        goto fail;

    return Conf_OK;
fail:
    LOG(LEVEL_ERROR, "%s: bad value: %s\n", name, value);
    return Conf_ERR;
}

static ConfRes SET_tcp_tsecho(void *conf, const char *name, const char *value) {
    XConf                *xconf         = (XConf *)conf;
    static const unsigned default_value = TCP_DEFAULT_TSECHO;

    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_tsecho) {
                case Default:
                    break;
                case Add:
                    if (xconf->templ_opts->tcp.tsecho == default_value)
                        fprintf(xconf->echo, "tcp-tsecho = %s\n", "enable");
                    else
                        fprintf(xconf->echo, "tcp-tsecho = %u\n",
                                xconf->templ_opts->tcp.tsecho);
                    break;
                case Remove:
                    fprintf(xconf->echo, "tcp-tsecho = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (xconf->templ_opts == NULL)
        xconf->templ_opts = CALLOC(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        xconf->templ_opts->tcp.is_tsecho = Add;
        xconf->templ_opts->tcp.tsecho    = default_value;
    } else if (conf_is_bool(value)) {
        if (conf_parse_bool(value)) {
            xconf->templ_opts->tcp.is_tsecho = Add;
            xconf->templ_opts->tcp.tsecho    = default_value;
        } else
            xconf->templ_opts->tcp.is_tsecho = Remove;
    } else if (conf_is_int(value)) {
        uint64_t num                     = conf_parse_int(value);
        xconf->templ_opts->tcp.is_tsecho = Add;
        xconf->templ_opts->tcp.tsecho    = (unsigned)num;
    } else
        goto fail;

    return Conf_OK;
fail:
    LOG(LEVEL_ERROR, "%s: bad value: %s\n", name, value);
    return Conf_ERR;
}

static ConfRes SET_tcp_sackok(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    if (xconf->echo) {
        if (xconf->templ_opts) {
            switch (xconf->templ_opts->tcp.is_sackok) {
                case Default:
                    break;
                case Add:
                    fprintf(xconf->echo, "tcp-sackok = %s\n", "enable");
                    break;
                case Remove:
                    fprintf(xconf->echo, "tcp-sackok = %s\n", "disable");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }

    if (xconf->templ_opts == NULL)
        xconf->templ_opts = CALLOC(1, sizeof(*xconf->templ_opts));

    if (value == 0 || value[0] == '\0') {
        xconf->templ_opts->tcp.is_sackok = Add;
    } else if (conf_is_bool(value)) {
        if (conf_parse_bool(value)) {
            xconf->templ_opts->tcp.is_sackok = Add;
        } else
            xconf->templ_opts->tcp.is_sackok = Remove;
    } else if (conf_is_int(value)) {
        if (conf_parse_int(value) != 0)
            xconf->templ_opts->tcp.is_sackok = Add;
    } else
        goto fail;

    return Conf_OK;
fail:
    LOG(LEVEL_ERROR, "%s: bad value: %s\n", name, value);
    return Conf_ERR;
}

static ConfRes SET_repeat(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->repeat || xconf->echo_all)
            fprintf(xconf->echo, "repeat = %" PRIu64 "\n", xconf->repeat);
        return 0;
    }

    xconf->repeat = (unsigned)conf_parse_int(value);
    if (xconf->repeat) {
        xconf->is_infinite = 1;
    } else {
        LOG(LEVEL_ERROR, "repeat must > 0.\n");
        return Conf_ERR;
    }
    return Conf_OK;
}

static ConfRes SET_sendmmsg(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_sendmmsg || xconf->echo_all)
            fprintf(xconf->echo, "sendmmsg = %s\n",
                    xconf->is_sendmmsg ? "true" : "false");
        return 0;
    }

    xconf->is_sendmmsg = conf_parse_bool(value);
    return Conf_OK;
}

static ConfRes SET_sendmmsg_batch(void *conf, const char *name,
                                  const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->sendmmsg_batch != XCONF_DFT_SENDMMSG_BATCH ||
            xconf->echo_all)
            fprintf(xconf->echo, "sendmmsg-batch = %u\n",
                    xconf->sendmmsg_batch);
        return 0;
    }

    xconf->sendmmsg_batch = conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_sendmmsg_retries(void *conf, const char *name,
                                    const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->sendmmsg_retries != XCONF_DFT_SENDMMSG_RETRIES ||
            xconf->echo_all)
            fprintf(xconf->echo, "sendmmsg-retries = %u\n",
                    xconf->sendmmsg_retries);
        return 0;
    }

    xconf->sendmmsg_retries = conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_sendq_size(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->sendq_size != XCONF_DFT_SENDQUEUE_SIZE || xconf->echo_all)
            fprintf(xconf->echo, "sendq-size = %u\n", xconf->sendq_size);
        return 0;
    }

    xconf->sendq_size = conf_parse_int(value);
    return Conf_OK;
}

static ConfRes SET_send_queue(void *conf, const char *name, const char *value) {
    XConf *xconf = (XConf *)conf;
    UNUSEDPARM(name);

    if (xconf->echo) {
        if (xconf->is_sendq || xconf->echo_all)
            fprintf(xconf->echo, "send-queue = %s\n",
                    xconf->is_sendq ? "true" : "false");
        return 0;
    }

    xconf->is_sendq = conf_parse_bool(value);
    return Conf_OK;
}

ConfParam config_parameters[] = {
    {"BASIC PARAMITERS", SET_nothing, 0, {0}, NULL},

    {"seed",
     SET_seed,
     Type_ARG,
     {0},
     "Set a global seed for randomizing of target addresses(ports), and to "
     "generate cookies in some ScanModules & ProbeModules."
     "Specify an integer that seeds the random number generator for randomizing"
     " targets and cookie(for ScanModules & ProbeModules) generation. Using a"
     " different seed will cause packets to be sent in a different random "
     "order. Instead of an integer, the string time can be specified, which "
     "seeds using the local timestamp, automatically generating a different "
     "random order of scans. If no seed specified, time is the default.",
     "Set a global seed for randomizing target and generate cookies."},
    {"rate",
     SET_rate,
     Type_ARG,
     {"max-rate", 0},
     "Specifies the desired rate for transmitting packets. This can be very "
     "small numbers, like 0.1 for transmitting packets at rates of one every "
     "10 seconds, for very large numbers like 10000000, which attempts to "
     "transmit at 10 million packets/second. In usual experience, Windows can"
     " do 250 thousand packets per second, and latest versions of Linux can "
     "do 2.5 million packets per second. The PF_RING driver is needed to get "
     "to 25 million packets/second. This rate(packets per second) is for total"
     " speed of all transmit threads.",
     "Specifies the desired rate for transmitting packets."},
    {"wait",
     SET_wait,
     Type_ARG,
     {0},
     "How many seconds should " XTATE_NAME_TITLE_CASE " waiting and handling "
     "incoming packets after all transmit threads finished. Default is 10s."
     "Specifies the number of seconds after transmit is done to wait for "
     "receiving packets before exiting the program. The default is 10 "
     "seconds.",
     "Seconds of time to wait packets after tx threads finished."},
    {"forever",
     SET_forever,
     Type_FLAG,
     {0},
     "Set `--wait` to a large enough time."},
    {"shard",
     SET_shard,
     Type_ARG,
     {"shards", 0},
     "Set a string like \"x/y\" to splits the scan among instances. x is the "
     "id for this scan, while y is the total number of instances. For example,"
     " --shard 1/2 tells an instance to send every other packet, starting with"
     " index 0. Likewise, --shard 2/2 sends every other packet, but starting "
     "with index 1, so that it doesn't overlap with the first example.\n"
     "NOTE: This effective for default Generate Module. Others may not "
     "implement this feature.",
     "Set a string like \"x/y\" to splits the scan among instances."},
    {"tx-thread-count",
     SET_tx_thread_count,
     Type_ARG,
     {"tx-count", "tx-num", 0},
     "Specify the number of transmit threads. " XTATE_NAME_TITLE_CASE " could"
     " has multiple transmit threads but only one receive thread. Every "
     "thread will be lock on a CPU kernel if the number of all threads is no"
     " more than kernel's.\n"
     "NOTE: Default valude is 4. However, 4 transmit threads could got a stable"
     " and high send rate in most conditions.",
     "Specify the number of transmit threads."},
    {"rx-handler-count",
     SET_rx_handler_count,
     Type_ARG,
     {"rx-count", "rx-num", 0},
     "Specify the number of receive handler threads. " XTATE_NAME_TITLE_CASE
     " could"
     " has multiple receive handler threads but only one receive thread. Every "
     "handler thread will be dispatched recv packets by (dst_IP, dst_Port, "
     "src_IP, src_Port) and executes the `handler_cb` of ScanModule. This is "
     "for some necessary but slow action while ScanModule handling consecutive"
     " communication (e.g. stateful TLS connection). If the action is "
     "irrespective"
     " with consecutive communication (e.g. results processing), it is better"
     " to use special thread-pool.\n"
     "The number of receive handler must be the power of 2. (Default 1)",
     "Specify the number of receive handler threads."},
    {"d",
     SET_log_level,
     Type_FLAG,
     {"dd", "ddd", 0},
     "Set the log level by the number of \"d\". You can set \"-d\", \"-dd\" "
     "or \"-ddd\" for:\n"
     "Level 0 (default): print OUT, HINT, ERROR and WARN logs.\n"
     "Level 1: print INFO logs in addition to level 0.\n"
     "Level 2: print DEBUG logs in addition to level 1.\n"
     "Level 3: print DETAIL logs in addition to level 2.",
     "Set the log level by the number of \"d\"."},
    {"interactive-mode",
     SET_interactive_mode,
     Type_FLAG,
     {"interactive", "interact", 0},
     "Start " XTATE_NAME_TITLE_CASE " in an interactive mode.\n"
     "NOTE1: Interactive mode need a modern terminal that supports controlling "
     "chars.\n"
     "NOTE2: " XTATE_NAME_TITLE_CASE
     " will save conf to " XCONF_DFT_RECOVER_FILENAME " automatically.\n"
     "NOTE3: " XTATE_NAME_TITLE_CASE " will automatically reboot with conf "
     "after finishing one scanning task while using interactive mode on Linux.",
     "Start " XTATE_NAME_TITLE_CASE " in an interactive mode."},
    {"version",
     SET_version,
     Type_FLAG,
     {"v", 0},
     "Print the version and compilation info."},
    {"usage",
     SET_usage,
     Type_FLAG,
     {0},
     "Print basic usage with some examples."},
    {"help",
     SET_print_help,
     Type_FLAG,
     {"h", 0},
     "Print the detailed help text of all parameters."},
    {"introduction",
     SET_print_intro,
     Type_FLAG,
     {"intro", 0},
     "Print the introduction of work flow."},

    {"TARGET SETTINGS", SET_nothing, 0, {0}, NULL},

    {"target-ip",
     SET_target_ip,
     Type_ARG,
     {"range", "ranges", "dst-ip", "ip", 0},
     "Specifies IP addresses or ranges as static targets. "
     "There are three valid formats. The first is a single IP address like "
     "192.168.0.1 or 2001:db8::1. The second is a range like "
     "10.0.0.1-10.0.0.100."
     " The third is a CIDR address, like 0.0.0.0/0 or 2001:db8::/90. At least"
     " one target must be specified. Multiple targets can be specified. This "
     "can be specified as multiple options separated by a comma as a single "
     "option, such as 10.0.0.0/8,192.168.0.1,2001:db8::1.",
     "Specifies IP addresses or ranges as static targets."},
    {"port",
     SET_port_them,
     Type_ARG,
     {"p", "ports", 0},
     "Specifies ports or ranges to scan. A single port can be specified, "
     "like -p 80. A range of ports can be specified, like -p 20-25. A list of"
     " ports/ranges can be specified, like -p 80,20-25. UDP ports can be"
     " specified, like --ports U:161,u:1024-1100. SCTP ports can be specified"
     " like --ports S:36412,s:38412, too.\n"
     "NOTE: We also support `--ports O:16` to present non-port number in range"
     " [0..65535] for some ScanModules.",
     "Specifies ports or ranges to scan."},
    {"top-port",
     SET_top_port,
     Type_ARG,
     {"top", "tcp-top", "top-tcp", 0},
     "Add a number of tcp ports to scan from predefined top list."},
    {"udp-top-port",
     SET_top_port,
     Type_ARG,
     {"udp-top", "top-udp", 0},
     "Add a number of udp ports to scan from predefined top list."},
    {"include-file",
     SET_include_file,
     Type_ARG,
     {"iL", 0},
     "Read a list of ranges from specified file in the same target format "
     "described above for IP addresses and ranges. These range lists is for "
     "some GenerateModules and this file can contain millions of addresses and "
     "ranges.\n"
     "NOTE: we can use `-` to read range lists from stdin.",
     "Read a list of IP ranges as targets from specified file."},
    {"exclude",
     SET_exclude_ip,
     Type_ARG,
     {"exclude-range", "exlude-ranges", "exclude-ip", 0},
     "Blacklist IP addresses or ranges, preventing it from being scanned. "
     "This overrides any target specification, guaranteeing that this "
     "address/range won't be scanned. This has the same format as the normal "
     "target specification.",
     "Blacklist IP addresses or ranges from scanning."},
    {"exclude-port",
     SET_exclude_port,
     Type_ARG,
     {"exclude-ports", 0},
     "Blacklist ports to preventing it from being scanned. This overrides "
     "any port specification. This has the same format as the normal port "
     "specification.",
     "Blacklist ports or ranges from scanning."},
    {"exclude-file",
     SET_exclude_file,
     Type_ARG,
     {0},
     "Reads a list of exclude ranges, in the same target format described "
     "above. These ranges override any targets, preventing them from being "
     "scanned.",
     "Reads a list of exclude IP ranges."},
    {"target-asn-v4",
     SET_target_asn_v4,
     Type_ARG,
     {"asn-v4", "asn-4", 0},
     "Specifies a series of ASNs to add IPv4 addresses of them as targets. AS "
     "info is from ip2asn file specified by --ip2asn-v4.",
     "Specifies a series of IPv4 ASNs as targets."},
    {"target-asn-v6",
     SET_target_asn_v6,
     Type_ARG,
     {"asn-v6", "asn-6", 0},
     "Specifies a series of ASNs to add IPv6 addresses of them as targets. AS "
     "info is from ip2asn file specified by --ip2asn-v6.\n"
     "NOTE: Range of one IPv6 AS is also too large for scanning. Maybe we "
     "needs some excluding.",
     "Specifies a series of IPv6 ASNs as targets."},
    {"exclude-asn-v4",
     SET_exclude_asn_v4,
     Type_ARG,
     {"exclude-asn-v4", "exclude-asn-4", 0},
     "Specifies a series of ASNs to exclude IPv4 addresses of them as targets. "
     "AS info is from ip2asn file specified by --ip2asn-v4.",
     "Specifies a series of IPv4 ASNs to be excluded."},
    {"exclude-asn-v6",
     SET_exclude_asn_v6,
     Type_ARG,
     {"exclude-asn-v6", "exclude-asn-6", 0},
     "Specifies a series of ASNs to exclude IPv6 addresses of them as targets. "
     "AS info is from ip2asn file specified by --ip2asn-v6.",
     "Specifies a series of IPv6 ASNs to be excluded."},

    {"INTERFACE ADJUSTMENT", SET_nothing, 0, {0}, NULL},

    {"adapter",
     SET_adapter,
     Type_ARG,
     {"if", "interface", 0},
     "Use the named raw network interface, such as \"eth0\" or \"dna1\". If "
     "not specified, the first network interface found with a default gateway"
     " will be used.",
     "Specifies a network interface to use."},
    {"source-ip",
     SET_source_ip,
     Type_ARG,
     {"src-ip", "source-ipv4", "source-ipv6", 0},
     "Send packets using this IP address. If not specified, then the first IP"
     " address bound to the network interface will be used. Instead of a "
     "single IP address, a range may be specified.\n"
     "NOTE1: The size of the range must be a power of 2, such as "
     "1, 2, 4, 8, 16, 1024 etc.\n"
     "NOTE2: " XTATE_NAME_TITLE_CASE
     " could get source ipv6 address with global"
     " scope include NAT6 network. But we need to specified manually if use "
     "ipv6 address in local link scope.",
     "Specifies source IP addresses for scanning."},
    {"source-port",
     SET_source_port,
     Type_ARG,
     {"src-port", 0},
     "Send packets using this port number as the source. If not specified, a"
     " random port will be chosen in the range 40000 through 60000. This port"
     " should be filtered by the host firewall (like iptables) to prevent the"
     " host network stack from interfering with arriving packets. Instead of "
     "a single port, a range can be specified, like 40000-40003.\n"
     "NOTE: The size of the range must be a power of 2, such as "
     "the example above that has a total of 4 addresses.",
     "Specifies source ports for scanning."},
    {"source-mac",
     SET_source_mac,
     Type_ARG,
     {"src-mac", 0},
     "Send packets using this as the source MAC address. If not specified, "
     "then the first MAC address bound to the network interface will be "
     "used.",
     "Specifies source MAC address for scanning."},
    {"router-ip",
     SET_router_ip,
     Type_ARG,
     {0},
     "Set an IP as router's address. Just for IPv4."},
    {"router-mac",
     SET_router_mac,
     Type_ARG,
     {"gateway-mac", "router-mac-ipv4", "router-mac-ipv6", 0},
     "Send packets to this MAC address as the destination. If not specified, "
     "then the gateway address of the network interface will be get by ARP "
     "and used.\n"
     "NOTE: We could specify different router MAC address for IPv4 and "
     "IPv6 by adding a suffix to the flag.",
     "Set gateway router's MAC addressfor IPv4 and/or IPv6."},
    {"adapter-vlan",
     SET_adapter_vlan,
     Type_ARG,
     {"vlan", "vlan-id", 0},
     "Send packets using this 802.1q VLAN ID."},
    {"adapter-snaplen",
     SET_adapter_snaplen,
     Type_ARG,
     {"snaplen", 0},
     "Set the maximum packet capture len of pcap or pfring. It means we can "
     "just got snaplen size at most for any packet even just like a kind of "
     "truncation. This is a non-commonly used switch for some special "
     "experimental tests. Default snaplen is 65535 and must be less than "
     "65535.\n"
     "NOTE: Be cared to the interaction with --tcp-win and --max-packet-len.",
     "Set the maximum packet capture len of pcap or pfring."},
    {"lan-mode",
     SET_lan_mode,
     Type_FLAG,
     {"local", "lan", 0},
     "Set the router MAC address to a broadcast address(ff-ff-ff-ff-ff-ff). "
     "This can make " XTATE_NAME_TITLE_CASE
     " be able to scan in a local network.\n"
     "NOTE: This flag must set while we do some layer-2 protocol scan "
     "like ARP.\n"
     "NOTE: It does not resolve a per-target MAC. Use it only for deliberate "
     "layer-2/broadcast scans; for normal TCP/UDP scans leave it off first, "
     "because a broadcast destination can fail across routed, Docker/bridge "
     "or filtered segments.",
     "Set router MAC to broadcast (L2 scans; avoid for normal TCP/UDP)."},
    {"fake-router-mac",
     SET_fake_router_mac,
     Type_FLAG,
     {"no-router-mac", "fake-gateway-mac", 0},
     "Set the router MAC address to a invalid address(01-02-03-04-05-06). "
     "This can stop " XTATE_NAME_TITLE_CASE " to resolve router MAC address."
     "It's useful when the ScanModule will specify destination MAC address "
     "dynamicly for different target. e.g. NdpNsScan.\n"
     "HINT: If we want to test the highest sending rate and not bother anyone"
     ", this param would be helpful with `--infinite`.",
     "Set the router MAC address to a invalid address."},
    {"bypass-os",
     SET_bypass_os,
     Type_FLAG,
     {"bypass", 0},
     "Completely bypass the OS protocol stack. This means we can set a proper"
     " `--src-ip`(in the local subnet) and `--src-mac` different from the OS "
     "to scan. Because " XTATE_NAME_TITLE_CASE
     " will do reponse to special ARP "
     "& NDP request for our new IP as if we are real member of the local "
     "subnet.\n"
     "NOTE1: There's no need to set some firewall rules for Linux while we are"
     " in bypassing mode. And we can't use the feature of OS protocol stack "
     "like responsing TCP RST or ICMP Port Unreachable.\n"
     "NOTE2: This function may need to receive different type of packets from "
     "ScanModule so that the BPF filter needs to be configured properly.",
     "Completely bypass the OS protocol stack."},
    {"init-ipv4-adapter",
     SET_init_ipv4,
     Type_FLAG,
     {"init-ipv4", "ipv4", 0},
     "Manually specifies if initiate adapter for IPv4 or not. This is for some "
     "generators that cannot initiate automatically.",
     "Specifies if initiate adapter for IPv4 or not."},
    {"init-ipv6-adapter",
     SET_init_ipv6,
     Type_FLAG,
     {"init-ipv6", "ipv6", 0},
     "Manually specifies if initiate adapter for IPv6 or not. This is for some "
     "generators that cannot initiate automatically.",
     "Specifies if initiate adapter for IPv4 or not."},

    {"OPERATION SELECTION", SET_nothing, 0, {0}, NULL},

    {"echo",
     SET_echo,
     Type_FLAG,
     {"echo-all", 0},
     "Do not run, but instead print the current configurations. Use --echo to "
     "dump configurations that are different from default value. Use --echo-all"
     " to dump configurations with explicit value. The configurations can be "
     "save to a file as config and then be used with the --conf option.",
     "Print the current configurations."},
    {"debug-if",
     SET_debugif,
     Type_FLAG,
     {"if-debug", 0},
     "Run special selftest for code about interface. This is useful to figure"
     " out why the interface doesn't work.",
     "Run special selftest for code about interface."},
    {"benchmark",
     SET_benchmark,
     Type_FLAG,
     {0},
     "Run a global benchmark for key units."},
    {"selftest",
     SET_selftest,
     Type_FLAG,
     {"regress", "regression", 0},
     "Run a global regression test to check if new changes in code healthy."},
    {"list-cidr",
     SET_list_cidr,
     Type_FLAG,
     {0},
     "Do not run, but instead print all IP targets in CIDR format."},
    {"list-range",
     SET_list_range,
     Type_FLAG,
     {"list-ranges", 0},
     "Do not run, but instead print all IP targets in ranges."},
    {"list-target",
     SET_list_target,
     Type_FLAG,
     {"list-targets", "list-ip", "list-ip-port", 0},
     "Do not run, but print every unique targets in random. We can got ordered "
     "targets with `--list-target[order]` or `--list-target[norandom]`. Also "
     "can print relative AS info if `--out-as-info` is on.",
     "Print every unique targets in random or not."},
    {"list-if",
     SET_listif,
     Type_FLAG,
     {"list-interface", "list-adapter", 0},
     "Do not run, but instead print informations of all adapters in this "
     "machine.",
     "Print informations of all adapters"},
    {"help-parameter",
     SET_help_param,
     Type_ARG,
     {"help-param", 0},
     "Print the help text for specified parameter if it exists in global "
     "configuration.",
     "Print the help text of specified global parameter."},
    {"search-parameter",
     SET_search_param,
     Type_ARG,
     {"search-param", "param-search", 0},
     "Search specified parameter in global configuration by fuzzy matching."},
    {"search-module",
     SET_search_module,
     Type_ARG,
     {"module-search", 0},
     "Search specified module by fuzzy matching."},
#ifndef NOT_FOUND_PCRE2
    {"list-nmap-probes",
     SET_list_nmap_probes,
     Type_ARG,
     {"list-nmap-probe", "list-nmap", 0},
     "Do not run, but instead print all probes within specified nmap service "
     "probes file.",
     "Print probes within nmap service probes file."},
#endif
#ifndef NOT_FOUND_BSON
    {"parse-bson-file",
     SET_parse_bson,
     Type_ARG,
     {"parse-bson", 0},
     "Parse BSON format result file generated from Bson Output Module to JSON "
     "format and output to stdout.",
     "Parse BSON format result file."},
#endif
#ifndef NOT_FOUND_MONGOC
    {"store-json-file",
     SET_store_json,
     Type_ARG,
     {"store-json", 0},
     "Specifies NDJSON format result file generated from ndjson Output Module "
     "and store the results to MongoDB.\n"
     "NOTE: This need every JSON result in NDJSON file be valid. So we'd "
     "better use --no-escape param to avoid single backslash while recording "
     "banner data to that NDJSON file.",
     "Store specified NDJSON format result file to MongoDB."},
    {"store-bson-file",
     SET_store_bson,
     Type_ARG,
     {"store-bson", 0},
     "Specifies BSON format result file generated from Bson Output Module and "
     "store the results to MongoDB.",
     "Store specified BSON format result file to MongoDB."},
    {"mongodb-uri",
     SET_mongodb_uri,
     Type_ARG,
     {0},
     "Specifies MongoDB URI to store result file generated from some Output "
     "Module."},
    {"mongodb-db-name",
     SET_mongodb_db,
     Type_ARG,
     {"mongodb-db", "mongodb-database", 0},
     "Specifies MongoDB DataBase to store result file generated from some "
     "Output Module."},
    {"mongodb-col-name",
     SET_mongodb_col,
     Type_ARG,
     {"mongodb-col", "mongodb-collection", 0},
     "Specifies MongoDB collection to store result file generated from some "
     "Output Module."},
    {"mongodb-app-name",
     SET_mongodb_app,
     Type_ARG,
     {"mongodb-app", "mongodb-application", 0},
     "Specifies MongoDB application name to register for tracking in the "
     "profile logs while storing result file generated from "
     "some Output Module.",
     "Specifies MongoDB application name to register."},
#endif

    {"SCAN MODULES CONFIG", SET_nothing, 0, {0}, NULL},

    {"scan-module",
     SET_scan_module,
     Type_ARG,
     {"scan", "scanner", 0},
     "Specifies a ScanModule to perform scanning. Use --list-scan to get "
     "informations of all ScanModules.\nNOTE: A ScanModule must be used in "
     "every time we scan. TcpSynModule will be default if we did not "
     "specify.",
     "Specifies a ScanModule to perform scanning."},
    {"list-scan-modules",
     SET_list_scan_modules,
     Type_FLAG,
     {"list-scan-module", "list-scan", "list-scanner", 0},
     "List informations of all ScanModules."},
    {"help-scan-module",
     SET_help_scan_module,
     Type_ARG,
     {"help-scan", "help-scanner", 0},
     "Print information and help of specified ScanModule."},
    {"scan-module-args",
     SET_scan_module_args,
     Type_ARG,
     {"scan-module-arg", "scan-arg", "scanner-arg", 0},
     "Specifies module-specific parameters for used ScanModule. Information "
     "of parameters for each ScanModule could be found in --list-scan.",
     "Specifies module-specific parameters for used ScanModule."},

    {"PROBE MODULES CONFIG", SET_nothing, 0, {0}, NULL},

    {"probe-module",
     SET_probe_module,
     Type_ARG,
     {"probe", 0},
     "Specifies a ProbeModule for used ScanModule to perform scanning. Use "
     "--list-probe to get informations of all ProbeModules.\nNOTE: ProbeModule"
     " is not required for all ScanModules and different ScanModule expects "
     "different type of ProbeModule.",
     "Specifies a ProbeModule for used ScanModule to perform scanning."},
    {"list-probe-modules",
     SET_list_probe_modules,
     Type_FLAG,
     {"list-probe-module", "list-probe", "list-probes", 0},
     "List informations of all ProbeModules."},
    {"help-probe-module",
     SET_help_probe_module,
     Type_ARG,
     {"help-probe", 0},
     "Print information and help of specified ProbeModule."},
    {"probe-module-args",
     SET_probe_module_args,
     Type_ARG,
     {"probe-module-arg", "probe-args", "probe-arg", 0},
     "Specifies module-specific parameters for used ProbeModule. Information "
     "of parameters for each ProbeModule could be found in --list-probe.",
     "Specifies module-specific parameters for used ProbeModule."},

    {"OUTPUT MODULES CONFIG", SET_nothing, 0, {0}, NULL},

    {"output-module",
     SET_output_module,
     Type_ARG,
     {"output", "out", 0},
     "Specifies an OutputModule for outputing results in special way. Use "
     "--list-output to get informations of all OutputModules. OutputModule"
     " is non-essential because " XTATE_NAME_TITLE_CASE " output results to "
     "stdout in default.\n"
     "NOTE: " XTATE_NAME_TITLE_CASE " won't output to stdout if we specified "
     "an OutputModule unless we use `-out-screen` switch.",
     "Specifies an OutputModule for outputing results in special way."},
    {"list-output-modules",
     SET_list_output_modules,
     Type_FLAG,
     {"list-output-module", "list-output", "list-out", 0},
     "List informations of all OutputModules."},
    {"help-output-module",
     SET_help_output_module,
     Type_ARG,
     {"help-output", "help-out", 0},
     "Print information and help of specified OutputModule."},
    {"output-module-args",
     SET_output_module_args,
     Type_ARG,
     {"output-module-arg", "output-arg", "out-arg", 0},
     "Specifies module-specific parameters for used OutputModule. Information "
     "of parameters for each OutputModule could be found in --list-output.",
     "Specifies module-specific parameters for used OutputModule."},
    {"output-file",
     SET_output_filename,
     Type_ARG,
     {"out-file", "o", 0},
     "Specifies a \"file\" name for selected OutputModule. The meaning of "
     "\"file\" name can be variable for different OutputModule. (e.g. It can "
     "be a database connecting string)\n"
     "NOTE: For some OutputModules, we can use `-o -` to let them output to "
     "stdout. But we should be care of the conflict while using the "
     "`-out-screen` flag.",
     "Specifies a \"file\" name for selected OutputModule."},
    {"append-output",
     SET_append,
     Type_FLAG,
     {"output-append", "append", 0},
     "Causes output to append mode, rather than overwriting. Performance of "
     "OutputModules can be different for this flag.",
     "Causes output to append mode, rather than overwriting."},
    {"output-screen",
     SET_out_screen,
     Type_FLAG,
     {"out-screen", 0},
     "Also print the results to screen while specifying an OutputModule."},
    {"show-output",
     SET_show_output,
     Type_ARG,
     {"show-out", "show", 0},
     "Tells which type of results should be showed explicitly, such as:\n"
     "'success', 'failed' or 'info'.",
     "Tells which type of results should be showed explicitly."},
    {"no-show-output",
     SET_no_show_output,
     Type_ARG,
     {"no-show-out", "no-show", 0},
     "Tells which type of results should not be showed explicitly, such as:\n"
     "'success', 'failed' or 'info'.",
     "Tells which type of results should not be showed explicitly."},
    {"no-escape-char",
     SET_no_escape,
     Type_FLAG,
     {"no-escape", 0},
     "Use no escaped chars for unprintable chars while normalizing in data "
     "chains of result outputing. This will get valid JSON compatible string "
     "values.\n"
     "NOTE1: use no escaped chars means to escape the escaped chars like "
     "'\\x00\\x01' to '\\\\x00\\\\x01'\n"
     "NOTE2: Some output modules could accept escaped chars and will escape "
     "unprinted chars automaticlly(e.g. Bson Output Module). So don't use the "
     "flag for those modules or we'll get weired string results.",
     "Use no escaped chars for unprintable chars while normalizing result."},
    {"output-as-info",
     SET_output_as_info,
     Type_FLAG,
     {"output-as", "out-as", "output-asn", "out-asn", 0},
     "Add AS info to scan results and listed targets. AS info is from ip2asn "
     "files specified by --ip2asn-v4 or/and ip2asn-v6.\n"
     "NOTE: Maybe a little bit less efficient because of querying.",
     "Add AS info to scan results and listed targets."},

    {"GENERATE MODULES CONFIG", SET_nothing, 0, {0}, NULL},

    {"generate-module",
     SET_generate_module,
     Type_ARG,
     {"generate", "gen", "generator", 0},
     "Specifies a GenerateModule to generate targets for scanning. Use "
     "--list-gen to get informations of all GenerateModules.\n"
     "NOTE: A GenerateModule must be used in every time we scan. BlackRock "
     " module will be default if we did not specify.",
     "Specifies a GenerateModule to generate targets for scanning."},
    {"list-generate-modules",
     SET_list_generate_modules,
     Type_FLAG,
     {"list-generate-module", "list-generator", "list-gen", 0},
     "List informations of all GenerateModules."},
    {"help-generate-module",
     SET_help_generate_module,
     Type_ARG,
     {"help-generate", "help-generator", "help-gen", 0},
     "Print information and help of specified GenerateModule."},
    {"generate-module-args",
     SET_generate_module_args,
     Type_ARG,
     {"generate-module-arg", "generator-arg", "gen-arg", 0},
     "Specifies module-specific parameters for used GenerateModule. "
     "Information of parameters for each GenerateModule could be found in "
     "--help-gen.",
     "Specifies module-specific parameters for used GenerateModule."},

    {"STATUS PRINTING", SET_nothing, 0, {0}, NULL},

    {"print-status",
     SET_print_status,
     Type_ARG,
     {"status-print", "print", 0},
     "Tells which type of status should be printed explicitly, such as:\n"
     "'queue' for real-time capacity of transmit queue and receive queues.\n"
     "'info-num'/'info' for count of information type results.\n"
     "'hit-rate'/'hit' for rate of hiting in terms of total sent for targets"
     " without sent from packet queue. It could be non-sense in some "
     "conditions.",
     "Tells which type of status should be printed explicitly."},
    {"ndjson-status",
     SET_ndjson_status,
     Type_FLAG,
     {"status-ndjson", 0},
     "Print status information in NDJSON format(Newline Delimited JSON)."},
    {"no-status", SET_no_status, Type_FLAG, {0}, "Do not print status info."},

    {"PACKET ATTRIBUTES", SET_nothing, 0, {0}, NULL},

    {"packet-ttl",
     SET_packet_ttl,
     Type_ARG,
     {"ttl", 0},
     "Specifies the TTL of all default template packets, defaults to 128. The "
     "value in packet templates will be used if set to zero.",
     "Specifies the TTL of all default template packets."},
    {"tcp-init-window",
     SET_tcp_init_window,
     Type_ARG,
     {"tcp-init-win", 0},
     "Specifies what value of Window should TCP SYN packets use. The default "
     "value of TCP Window for TCP SYN packets is 64240. The value in packet "
     "templates will be used if set to zero.",
     "Specifies what value of Window should TCP SYN packets use."},
    {"tcp-window",
     SET_tcp_window,
     Type_ARG,
     {"tcp-win", 0},
     "Specifies what value of Window should TCP packets(except for SYN) use. "
     "The default value of TCP Window for TCP packets(except SYN) is 1024. The "
     "value in packet templates will be used if set to zero.\n"
     "NOTE: This value could affects some ScanModules working like ZBanner and "
     "limit communicating rate of stateful ScanModules. Be cared to the "
     "interaction with --snaplen and --max-packet-len.",
     "Specifies what value of Window should TCP packets(except for SYN) use."},
    {"tcp-wscale",
     SET_tcp_wscale,
     Type_ARG,
     {0},
     "Specifies whether or what value of TCP Window Scaling option should TCP"
     " SYN packets use. e.g. --tcp-wscale true, --tcp-wscale 8. The default "
     "value of Window Scaling is 3 and not be used in template of TCP SYN "
     "packet. The value in packet templates will be used if not set.",
     "Specifies whether or what value of Window Scaling option should SYN "
     "packets use."},
    {"tcp-mss",
     SET_tcp_mss,
     Type_ARG,
     {0},
     "Specifies whether or what value of TCP MMS(Maximum Segment Size) option"
     " should TCP SYN packets use. e.g. --tcp-mss false, --tcp-mss 64000. The "
     "default MMS value is 1460.",
     "Specifies whether or what value of MMS option should SYN packets use."},
    {"tcp-sackok",
     SET_tcp_sackok,
     Type_FLAG,
     {"tcp-sack", 0},
     "Specifies whether should TCP SYN packets use TCP Selective "
     "Acknowledgement option. e.g. --tcp-sackok true. The default template of "
     "TCP SYN packet does not use TCP Selective Acknowledgement option. The "
     "value in packet templates will be used if not set.",
     "Specifies whether should SYN packets use SACK option."},
    {"tcp-tsecho",
     SET_tcp_tsecho,
     Type_ARG,
     {0},
     "Specifies whether or what value of timestamp in TCP Timestamp option"
     " should TCP SYN packets use for timestamp echoing. e.g. --tcp-tsecho "
     "true, --tcp-tsecho <value>. The default timestamp value is 0x12345678 "
     " and is not be used in template of TCP SYN packet. The value in packet "
     "templates will be used if not set.\n"
     "NOTE: Some router would delete timestamp option. So we cannot received "
     "an SYN-ACK segment with 4 NOP in a row instead of expected timestamp "
     "option.",
     "Specifies whether or what value of Timestamp option should SYN packets "
     "use."},
    {"packet-trace",
     SET_packet_trace,
     Type_FLAG,
     {"trace-packet", 0},
     "Prints a summary of packets we sent and received. This is useful for "
     "debugging at low rates, like a few packets per second, but will "
     "overwhelm the terminal at high rates.",
     "Prints a summary of packets we sent and received."},
    {"bpf-filter",
     SET_bpf_filter,
     Type_ARG,
     {"bpf", 0},
     "Specifies a string as BPF filter for pcap to replace the default BPF "
     "filter string in ScanModule.\n"
     "NOTE: Every ScanModule has its own BPF filter and we can check them "
     "with --help-scan <module>. The BPF filter we set with --bpf-filter will"
     " constrain the packets we received with ScanModules.",
     "Specifies a string as BPF filter for pcap."},
    {"no-bpf-filter",
     SET_no_bpf,
     Type_FLAG,
     {"no-bpf", 0},
     "Do not compile any BPF filter from ScanModules or users. Some machines"
     " does not support part or all of BPF filters and this switch "
     "makes " XTATE_NAME_TITLE_CASE " working again.",
     "Do not compile any BPF filter from ScanModules or users."},
    {"max-packet-len",
     SET_max_packet_len,
     Type_ARG,
     {"max-pkt-len", 0},
     XTATE_NAME_TITLE_CASE
     " won't handle a received packet that is more than "
     "max-packet-len. Default is 1514."
     "NOTE: Be cared to the interaction with --tcp-win and --snaplen.",
     "Do not handle a received packet whose len is more than the specified "
     "size."},

    {"TRANSMITTING WAYS", SET_nothing, 0, {0}, NULL},

    {"raw-socket",
     SET_rawsocket,
     Type_FLAG,
     {"raw-sock", 0},
     "Use raw socket to send packets instead of pcap on Linux if possible. Just"
     " support working on link layer because " XTATE_NAME_TITLE_CASE
     " needs to handle both IPv4/IPv6.\n"
     "NOTE: " XTATE_NAME_TITLE_CASE " always uses pcap to recv in default.",
     "Use raw socket to send packets instead of pcap on Linux if possible."},
    {"sendmmsg",
     SET_sendmmsg,
     Type_FLAG,
     {0},
     "Use sendmmsg syscall to send packets in batch on Linux if raw socket can "
     "be used. This may break the bottle-neck of sending one by one.\n"
     "NOTE: Use sendmmsg in slow send rate is not recommended because of the "
     "latency and packet lossing.",
     "Use sendmmsg syscall to send packets in batch on Linux."},
    {"sendmmsg-batch",
     SET_sendmmsg_batch,
     Type_ARG,
     {0},
     "Set the batch size while sending packets with sendmmsg syscall. Default "
     "is 64.",
     "Set the batch size while sending packets with sendmmsg syscall."},
    {"sendmmsg-retries",
     SET_sendmmsg_retries,
     Type_ARG,
     {"sendmmsg-retry", 0},
     "Max number of times to try to do sendmmsg syscall if failed. Default"
     "is 64.",
     "Max number of times to try to do sendmmsg syscall if failed."},
    {"send-queue",
     SET_send_queue,
     Type_FLAG,
     {"sendq", 0},
     "Use sendqueue feature of Npcap/Winpcap on Windows to transmit packets. "
     "The transmit rate on Windows is really slow, like 40-kpps. The speed "
     "can be increased by using the sendqueue feature to roughly 300-kpps.\n"
     "NOTE: It's not recommended to use sendqueue feature in low send rate, "
     "because this may cause a lot latency for every single packet and affect"
     " some scan modules working with connections.",
     "Use sendqueue feature of Npcap/Winpcap on Windows to transmit packets."},
    {"send-queue-size",
     SET_sendq_size,
     Type_ARG,
     {"sendq-size", 0},
     "Set the buffer size while sending packets with sendqueue of "
     "Npcap/Winpcap on Windows. Default size is 65535*8.",
     "Set the buffer size of Npcap/Winpcap sendqueue on Windows."},
    {"pfring",
     SET_pfring,
     Type_FLAG,
     {0},
     "Force the use of the PF_RING driver. The program will exit if PF_RING "
     "DNA drvers are not available.\n"
     "NOTE: " XTATE_NAME_TITLE_CASE
     " will try to use PF_RING automatically in default.",
     "Force the use of the PF_RING driver."},
    {"offline",
     SET_offline,
     Type_FLAG,
     {"dry-run", 0},
     "Do not actually transmit packets. This is useful with a low rate and "
     "--packet-trace to look at what packets might've been transmitted. Or, "
     "it's useful with --rate 100000000 in order to benchmark how fast "
     "transmit would work (assuming a zero-overhead driver). PF_RING is about"
     " 20% slower than the benchmark result from offline mode.",
     "Do not actually transmit packets."},

    {"MISCELLANEOUS", SET_nothing, 0, {0}, NULL},

    {"config-file",
     SET_read_conf,
     Type_ARG,
     {"conf-file", "conf", "resume", 0},
     "Read configurations from specified file. If not specified, then will read"
     " from /etc/xtate/xtate.conf by default. We could specifies a "
     "configuration file generated by " XTATE_NAME_TITLE_CASE
     " automatically after break by user to resume an unfinished scanning.",
     "Read configurations from specified file."},
    {"resume-index",
     SET_resume_index,
     Type_ARG,
     {0},
     "The point in the scan at when it was paused."},
    {"no-resume-file",
     SET_noresume,
     Type_FLAG,
     {"no-resume", 0},
     "Do not save scan info to resume file(" XCONF_DFT_RESUME_FILENAME ") for "
     "resuming. This is useful when our target list is too large and scattered "
     "and spend too much time to save.",
     "Do not save scan info to resume file(" XCONF_DFT_RESUME_FILENAME ") for "
     "resuming."},
    {"meta-filename",
     SET_meta_filename,
     Type_ARG,
     {"meta-file", "meta", 0},
     "Save meta information of scanning to a specified file."},
    {"pcap-filename",
     SET_pcap_filename,
     Type_ARG,
     {"pcap", "pcap-file", 0},
     "Save received packets (but not transmitted packets) to the pcap-format "
     "file.",
     "Save received packets to speficied file in pcap-format."},
    {"no-ansi-control",
     SET_no_ansi,
     Type_FLAG,
     {"no-ansi", "no-color", 0},
     "Print result and status to the screen without ANSI controlling(escape) "
     "characters. Some old terminal does not support those charactors.\n"
     "NOTE: displaying maybe not that good if no ansi escape chars.",
     "Print result and status to screen without controlling chars."},
    {"no-dedup",
     SET_nodedup,
     Type_FLAG,
     {0},
     "Do not deduplicate the results."},
    {"dedup-win",
     SET_dedup_win,
     Type_ARG,
     {0},
     "Set the window size of deduplication table. Default size if 1000000.\n"
     "NOTE: " XTATE_NAME_TITLE_CASE
     " uses two different types of deduplication. The"
     " default one is hash buckets with LRU mechanism and window size means the"
     " whole count of entries. The other one is judy array which will be used "
     "automaticly if built with libjudy. In this condition, window size means"
     " the actual size of slide window. I didn't identify the performance and "
     "advantages between them and left the choice to users.",
     "Set the window size of deduplication table."},
    {"stack-buf-count",
     SET_stack_buf_count,
     Type_ARG,
     {"tx-buf-count", 0},
     "Set the buffer size of packets queue(stack) from receive thread to "
     "transmit thread.\n"
     "The value of packets queue must be power of 2. (Default 16384)",
     "Set the buffer size of queue from receive thread to transmit thread."},
    {"dispatch-buf-count",
     SET_dispatch_buf_count,
     Type_ARG,
     {"rx-buf-count", 0},
     "Set the buffer size of dispatch queue from receive thread to receive "
     "handler threads.\n"
     "The value of packets queue must be power of 2. (Default 16384)",
     "Set the buffer size of queue from receive thread to handle thread."},
    {"infinite",
     SET_infinite,
     Type_FLAG,
     {0},
     "Scan the target again and again. Not stop until we hit <Ctrl-C>. This "
     "is useful for us to test the some performance of " XTATE_NAME_TITLE_CASE
     ". The seed will update in every loop while setting infinite mode.\n"
     "HINT: If we just want to test the highest sending rate, try to set an "
     "invalid router mac like `--router-mac 11:22:33:44:55:66` or use `--fake"
     "-router-mac` to send packets in local network.\n"
     "NOTE1: We should be careful to the deduplication in the infinite mode.\n"
     "NOTE2: This switch is useful for default and some generators which "
     "implemented the feature.",
     "Scan the target again and again."},
    {"repeat",
     SET_repeat,
     Type_ARG,
     {"repeats", 0},
     "How many times " XTATE_NAME_TITLE_CASE " should repeat for all targets."
     " It also means the hit count for every target + 1. So default is 0."
     " `--infinite` will be automatically set when we use repeat.\n"
     "NOTE1: We should be careful to the deduplication in the repeat mode.\n"
     "NOTE2: This switch is useful for default and some generators which "
     "implemented the feature.",
     "How many times " XTATE_NAME_TITLE_CASE " should repeat for all targets."},
    {"static-seed",
     SET_static_seed,
     Type_FLAG,
     {"keep-seed", 0},
     "Use same seed to pick up addresses in infinite mode while listing targets"
     ". " XTATE_NAME_TITLE_CASE
     " changes seed for every round to make a different"
     " scan order while repeating. We can use static-seed to keep order of "
     "all rounds.",
     "Use same seed to pick up addresses in infinite mode while listing "
     "targets."},
    {"no-cpu-bind",
     SET_no_cpu_bind,
     Type_FLAG,
     {0},
     "In default, " XTATE_NAME_TITLE_CASE " bind its threads to CPU kernels for"
     " better performance if the number of kernels is great than 1. This "
     "switch allows no CPU binding for all threads and is useful for computers"
     " with outdated hardware.\n"
     "NOTE1: The default CPU-binding order is:\n"
     "    1.Tx Threads\n"
     "    2.Rx Threads\n"
     "    3.Rx Handle Threads\n"
     "NOTE2: As you can see, 3 threads need to be binded at least. (1 tx "
     "thread, 1 rx thread and 1 rx handle thread)",
     "Do not bind threads to CPU kernels."},
    {"ip2asn-v4-file",
     SET_ip2asn_v4,
     Type_ARG,
     {"ip2asn-v4", "ip2asn-4", 0},
     "Specifies a 'ip2asn-v4.tsv' file to load IPv4 ASN info for relative "
     "features like --out-as-info.",
     "Specifies a 'ip2asn-v4.tsv' file to load IPv4 ASN info."},
    {"ip2asn-v6-file",
     SET_ip2asn_v6,
     Type_ARG,
     {"ip2asn-v6", "ip2asn-6", 0},
     "Specifies a 'ip2asn-v6.tsv' file to load IPv6 ASN info for relative "
     "features like --out-as-info.",
     "Specifies a 'ip2asn-v6.tsv' file to load IPv6 ASN info."},
    {"no-back-trace",
     SET_nothing, /*It will be handle before commandline parsing*/
     Type_FLAG,
     {"no-bt", 0},
     "Turn off the backtrace of call stack after segment fault used for "
     "debugging."},

    /*Put it at last for better "help" output*/
    {"TARGET_OUTPUT", SET_target_output, 0, {0}, NULL},

    {0}};

int xconf_set_parameter(XConf *xconf, const char *name, const char *value) {
    return conf_set_one_param(xconf, config_parameters, name, value);
}

int xconf_command_line(XConf *xconf, int argc, char *argv[]) {
    int err =
        conf_set_params_from_args(xconf, config_parameters, argc - 1, argv + 1);

    if (xconf->shard.of > 1 && xconf->seed == 0) {
        LOG(LEVEL_WARN, "using shards without -seed being specified\n");
        LOG(LEVEL_HINT, "all shards must share the same seed\n");
    }

    return err;
}

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all settable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
void xconf_echo(XConf *xconf, FILE *fp) {
    unsigned i;

    /*
     * Print all configuration parameters
     */
    xconf->echo = fp;

    CONFIG_SET_PARAM tmp = NULL;
    for (i = 0; config_parameters[i].name; i++) {
        /**
         * We may use same `set` func more than one times back-to-back
         * in config_paramiters.
         * Do a dedup easily when echoing.
         */
        if (config_parameters[i].setter == tmp)
            continue;
        tmp = config_parameters[i].setter;

        config_parameters[i].setter(xconf, 0, 0);
    }

    xconf->echo     = 0;
    xconf->echo_all = 0;
}

/***************************************************************************
 ***************************************************************************/
int xconf_read_conf(XConf *xconf, const char *filename) {
    FILE *fp;
    char *line = MALLOC(65535 * sizeof(char));
    int   err  = 0;

    fp = fopen(filename, "rt");
    if (fp == NULL) {
        char  dir[512];
        char *x;

        LOGPERROR("reading configuration file");

        x = getcwd(dir, sizeof(dir));
        if (x)
            LOG(LEVEL_ERROR, "cwd = %s\n", dir);
        return -1;
    }

    while (fgets(line, 65535, fp)) {
        err = xconf_set_parameter_in_kv(xconf, line, 65535);
        if (err == -1) {
            break;
        } else if (err == 2) {
            LOG(LEVEL_WARN, "invalid param conf format: %s\n", line);
            break;
        }
    }

    fclose(fp);
    FREE(line);

    if (err)
        return -1;

    return 0;
}

/***************************************************************************
 ***************************************************************************/
int xconf_save_conf(XConf *xconf, const char *filename) {
    FILE *fp = fopen(filename, "wt");

    if (fp == NULL) {
        LOGPERROR("saving configuration file");
        return -1;
    }

    xconf_echo(xconf, fp);

    fclose(fp);

    return 0;
}

/***************************************************************************
 ***************************************************************************/
bool xconf_contains(const char *x, int argc, char **argv) {
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], x) == 0)
            return true;
    }

    return false;
}

void xconf_print_intro() {
    printf("\n");
    printf("Welcome to " XTATE_NAME_TITLE_CASE "!");
    printf("\n");
    xprint(XTATE_DESCRIPTION, 2, 80);
    printf("\n");
    printf("\n");
    printf("  Author : " XTATE_AUTHOR "\n");
    printf("  Github : " XTATE_GITHUB_URL "\n");
    printf("  Contact: " XTATE_CONTACT "\n");
    printf("\n");
    printf("\n");
    printf("\n");
    printf("This is how " XTATE_NAME_TITLE_CASE " working internally:\n");
    printf("\n");
    printf(work_flow);
    printf("\n");
    printf("\n");
    printf("\n");
    printf("This is what ScanModules and ProbeModules mean:\n");
    printf("\n");
    printf(scan_probe_module_rela);
    printf("\n");
    printf("\n");
}

void xconf_print_banner() {
    printf("\n\n\n");
    xprint_with_head(ascii_xtate2, 10, 80);
    printf("\n                             " XTATE_BANNER "\n");

    printf("\n");
    printf("Welcome to " XTATE_NAME_TITLE_CASE "!");
    printf("\n");
    xprint(XTATE_DESCRIPTION, 2, 80);
    printf("\n");
    printf("\n");
    printf("  Author : " XTATE_AUTHOR "\n");
    printf("  Github : " XTATE_GITHUB_URL "\n");
    printf("  Contact: " XTATE_CONTACT "\n");
    printf("\n");
    printf("typical format for scanning with specified module:\n");
    printf("  " XTATE_NAME " [options] -ip IPs [-p PORTs] -scan SCANMODULE "
           "[-probe PROBEMODULE]\n");
    printf("\n");
    printf("enter interactive mode:");
    printf("  `" XTATE_NAME " -interactive`\n");
    printf("\n");
    printf("check basic usage examples:");
    printf("  `" XTATE_NAME " -usage`\n");
    printf("\n");
    printf("detailed help of global params:");
    printf("  `" XTATE_NAME " -help`\n");
    printf("\n");
}

void xconf_print_usage() {
    printf("\n");
    printf("Welcome to " XTATE_NAME_TITLE_CASE "!");
    printf("\n");
    xprint(XTATE_DESCRIPTION, 2, 80);
    printf("\n");
    printf("\n");
    printf("  Author : " XTATE_AUTHOR "\n");
    printf("  Github : " XTATE_GITHUB_URL "\n");
    printf("  Contact: " XTATE_CONTACT "\n");
    printf("\n");
    printf("typical format for scanning with specified module:\n");
    printf("  " XTATE_NAME " [options] -ip IPs [-p PORTs] -scan SCANMODULE "
           "[-probe PROBEMODULE]\n");
    printf("\n");
    printf("basic use examples of " XTATE_NAME ":\n");
    printf("\n");
    printf("  " XTATE_NAME
           " -p 80,8000-8100 -ip 10.0.0.0/8 -scan tcp-syn -rate 10000\n");
    xprint("use TcpSyn ScanModule to scan web ports on 10.x.x.x at 10kpps.\n",
           6, 80);
    printf("\n");
    printf("  " XTATE_NAME
           " -p u:80 -ip 10.0.0.0/8 -scan udp -probe echo -show info\n");
    xprint("use UdpProbe ScanModule to scan UDP 80 port with echo ProbeModule "
           "and also show info results.\n",
           6, 80);
    printf("\n");
    printf("  " XTATE_NAME
           " -ip 10.0.0.0/8 -scan icmp-echo -scan-arg \"-ttl\"\n");
    xprint("use IcmpEcho ScanModule to do ping scan and record TTL.\n", 6, 80);
    printf("\n");
    printf("  " XTATE_NAME " -p 80 -ip 10.0.0.0/8 -scan zbanner -probe http "
           "-scan-arg \"-banner\"\n");
    xprint("use ZBanner ScanModule to grab http banners with http ProbeModule "
           "and ScanModule-specific param.\n",
           6, 80);
    printf("\n");
    printf("  " XTATE_NAME
           " -p s:38412 -ip 10.0.0.0/8 -scan sctp-init -show fail\n");
    xprint("use SctpInit ScanModule to scan SCTP 38412(36412) port and show "
           "fail results.\n",
           6, 80);
    printf("\n");
    printf("  " XTATE_NAME " -ip 192.168.0.1/24 -scan arp-req -lan\n");
    xprint("do ARP scan with LAN mode in local network.\n", 6, 80);
    printf("\n");
    printf("  " XTATE_NAME
           " -ip fe80::1/120 -scan ndp-ns -src-ip fe80::2 -fake-router-mac\n");
    xprint("do NDP NS scan with a link-local source IP in local network.\n", 6,
           80);
    printf("\n");
    printf("  " XTATE_NAME " -list-scan\n");
    xprint("list all ScanModules and other types of module are the same.\n", 6,
           80);
    printf("\n");
    printf("  " XTATE_NAME " -help-scan tcp-syn\n");
    xprint("see help of TcpSyn ScanModule in detail.\n", 6, 80);
    printf("\n");
    printf("  " XTATE_NAME " -interactive\n");
    xprint("set params and do scanning in an user-friendly interactive mode.\n",
           6, 80);
    printf("\n");
    printf("  " XTATE_NAME " -version\n");
    xprint("print version and compilation info.\n", 6, 80);
    printf("\n");
    printf("  " XTATE_NAME " -intro\n");
    xprint("show the design and architecture of " XTATE_NAME_TITLE_CASE ".\n",
           6, 80);
    printf("\n");
    printf("  " XTATE_NAME " -usage\n");
    xprint("display this usage text of using examples.\n", 6, 80);
    printf("\n");
    printf("  " XTATE_NAME " -help\n");
    xprint("display detailed help text of all parameters.\n", 6, 80);
    printf("\n");
}

void xconf_print_version() {
    const char *cpu              = "unknown";
    const char *compiler         = "unknown";
    const char *compiler_version = "unknown";
    const char *os               = "unknown";
    printf("\n");
    printf("  " XTATE_NAME_TITLE_CASE " version %s", XTATE_VERSION);
#ifdef NDEBUG
    printf(" in Release\n");
#else
    printf(" in Debug\n");
#endif
    printf("\n");
    printf("  Author : " XTATE_AUTHOR "\n");
    printf("  Github : " XTATE_GITHUB_URL "\n");
    printf("  Contact: " XTATE_CONTACT "\n");
    printf("\n");
    printf("  Compiled on: %s %s\n", __DATE__, __TIME__);

#if defined(__x86_64) || defined(__x86_64__)
    cpu = "x86";
#endif

#if defined(_MSC_VER)
#if defined(_M_AMD64) || defined(_M_X64)
    cpu = "x86";
#elif defined(_M_IX86)
    cpu = "x86";
#elif defined(_M_ARM_FP)
    cpu = "arm";
#endif

/* clang on Windows defines both _MSC_VER and __clang__ */
#if defined(__clang__)
    compiler         = "clang";
    compiler_version = __clang_version__;
#else

    {
        int msc_ver = _MSC_VER;

        compiler = "VisualStudio";

        if (msc_ver < 1200)
            compiler_version = "pre6.0";
        else if (msc_ver == 1200)
            compiler_version = "6.0 VC++6.0";
        else if (msc_ver == 1300)
            compiler_version = ".NET 2002 VC++7.0";
        else if (msc_ver == 1310)
            compiler_version = ".NET 2003 VC++7.1";
        else if (msc_ver == 1400)
            compiler_version = "2005 VC++8.0";
        else if (msc_ver == 1500)
            compiler_version = "2008 VC++9.0";
        else if (msc_ver == 1600)
            compiler_version = "2010 VC++10.0";
        else if (msc_ver == 1700)
            compiler_version = "2012 VC++11.0";
        else if (msc_ver == 1800)
            compiler_version = "2013 VC++12.0";
        else if (msc_ver == 1900)
            compiler_version = "2015 VC++14.0";
        else if (msc_ver == 1910)
            compiler_version = "2017RTW VC++15.0";
        else if (msc_ver == 1911)
            compiler_version = "2017 VC++15.3";
        else if (msc_ver == 1912)
            compiler_version = "2017 VC++15.5";
        else if (msc_ver == 1913)
            compiler_version = "2017 VC++15.6";
        else if (msc_ver == 1914)
            compiler_version = "2017 VC++15.7";
        else if (msc_ver == 1915)
            compiler_version = "2017 VC++15.8";
        else if (msc_ver == 1916)
            compiler_version = "2017 VC++15.9";
        else if (msc_ver == 1920)
            compiler_version = "2019RTW VC++16.0";
        else if (msc_ver == 1921)
            compiler_version = "2019 VC++16.1";
        else if (msc_ver == 1922)
            compiler_version = "2019 VC++16.2";
        else if (msc_ver == 1923)
            compiler_version = "2019 VC++16.3";
        else if (msc_ver == 1924)
            compiler_version = "2019 VC++16.4";
        else if (msc_ver == 1925)
            compiler_version = "2019 VC++16.5";
        else if (msc_ver == 1926)
            compiler_version = "2019 VC++16.6";
        else if (msc_ver == 1927)
            compiler_version = "2019 VC++16.7";
        else if (msc_ver == 1928)
            compiler_version = "2019 VC++16.8/16.9a";
        else if (msc_ver == 1929)
            compiler_version = "2019 VC++16.10/16.11b";
        else if (msc_ver == 1930)
            compiler_version = "2022RTW VC++17.0";
        else if (msc_ver == 1931)
            compiler_version = "2022 VC++17.1";
        else if (msc_ver == 1932)
            compiler_version = "2022 VC++17.2";
        else if (msc_ver == 1933)
            compiler_version = "2022 VC++17.3";
        else if (msc_ver == 1934)
            compiler_version = "2022 VC++17.4";
        else if (msc_ver == 1935)
            compiler_version = "2022 VC++17.5";
        else if (msc_ver == 1936)
            compiler_version = "2022 VC++17.6";
        else if (msc_ver == 1937)
            compiler_version = "2022 VC++17.7";
        else if (msc_ver == 1938)
            compiler_version = "2022 VC++17.8";
        else if (msc_ver == 1939)
            compiler_version = "2022 VC++17.9";
        else if (msc_ver == 1940)
            compiler_version = "2022 VC++17.10";
        else if (msc_ver == 1941)
            compiler_version = "2022 VC++17.11";
        else if (msc_ver == 1942)
            compiler_version = "2022 VC++17.12";
        else
            compiler_version = "2022-post VC++17.12-post";
    }
#endif

#elif defined(__GNUC__) /*clang and mingw also have __GNUC__*/
#if defined(__clang__)
    compiler         = "clang";
    compiler_version = __clang_version__;
#elif defined(__MINGW64__)
    compiler         = "MinGW-w64 gcc";
    compiler_version = __VERSION__;
#elif defined(__MINGW32__)
    compiler         = "MinGW-w32 gcc";
    compiler_version = __VERSION__;
#else
    compiler         = "gcc";
    compiler_version = __VERSION__;
#endif

#if defined(i386) || defined(__i386) || defined(__i386__)
    cpu = "x86";
#endif

#if defined(__corei7) || defined(__corei7__)
    cpu = "x86-Corei7";
#endif

#endif

#if defined(_WIN32)
    os = "Windows";
#elif defined(__linux__)
    os = "Linux";
#elif defined(__APPLE__)
    os = "Apple";
#elif defined(__MACH__)
    os = "MACH";
#elif defined(__FreeBSD__)
    os = "FreeBSD";
#elif defined(__NetBSD__)
    os = "NetBSD";
#elif defined(unix) || defined(__unix) || defined(__unix__)
    os = "Unix";
#endif

    printf("  Compiler: %s %s\n", compiler, compiler_version);
    printf("  OS: %s\n", os);
    printf("  CPU: %s (%u bits)\n", cpu, (unsigned)(sizeof(void *)) * 8);
    printf("\n");

    printf("  Build with libraries:\n");

#ifndef NOT_FOUND_OPENSSL
    /*This macro is backward compatible*/
    printf("    OpenSSL    %s\n", &OPENSSL_VERSION_TEXT[8]);
#else
    printf("    OpenSSL    (null)\n");
#endif

#ifndef NOT_FOUND_PCRE2
    char version[120];
    pcre2_config(PCRE2_CONFIG_VERSION, version);
    printf("    PCRE2      %s\n", version);
#else
    printf("    PCRE2      (null)\n");
#endif

#ifndef NOT_FOUND_LIBXML2
    printf("    LibXml2    %s\n", LIBXML_DOTTED_VERSION);
#else
    printf("    LibXml2    (null)\n");
#endif

#ifndef NOT_FOUND_BSON
    printf("    libbson    %s\n", BSON_VERSION_S);
#else
    printf("    libbson    (null)\n");
#endif

#ifndef NOT_FOUND_MONGOC
    /**
     * header include must put on top.
     */
    printf("    libmongoc  %s\n", mongoc_get_version());
#else
    printf("    libmongoc  (null)\n");
#endif

    printf("\n");
}

void xconf_print_help() {
    printf("\n\n\n");
    xprint_with_head(ascii_xtate1, 15, 80);
    printf("\n                               " XTATE_BANNER "\n\n");
    printf("\n");
    xprint("Welcome to " XTATE_NAME_TITLE_CASE "!", 2, 80);
    printf("\n");
    xprint(XTATE_DESCRIPTION, 4, 80);
    printf("\n");
    printf("\n");
    printf("  Author : " XTATE_AUTHOR "\n");
    printf("  Github : " XTATE_GITHUB_URL "\n");
    printf("  Contact: " XTATE_CONTACT "\n");
    printf("\n");
    xprint("Here are detailed help text of all parameters "
           "of " XTATE_NAME_TITLE_CASE
           ". I hope these will help you a lot. If any "
           "problem or advice, please contact me.\n",
           2, 80);
    printf("\n");
    printf("\n");
    printf("\n");

    unsigned count = 0;
    for (unsigned i = 0; config_parameters[i].name; i++) {
        if (!config_parameters[i].help_text) {
            if (config_parameters[i].setter == &SET_nothing) {
                /*This is a paragraph name*/
                printf(XPRINT_EQUAL_LINE "\n");
                printf("  %s\n", config_parameters[i].name);
                printf(XPRINT_EQUAL_LINE "\n\n");
            }
            continue;
        }

        printf("  --%s", config_parameters[i].name);

        for (unsigned j = 0; config_parameters[i].alt_names[j]; j++) {
            printf(", %s", config_parameters[i].alt_names[j]);
        }

        printf("\n\n");
        xprint(config_parameters[i].help_text, 6, 80);
        printf("\n\n\n");

        count++;
    }

    // printf(XPRINT_EQUAL_LINE);
    printf("\n\n");
    printf(XPRINT_STAR_LINE "\n");
    printf(
        "            That's all. " XTATE_NAME_TITLE_CASE
        " contains [%d] global parameters now.\n"
        "            Use them to unleash your power!\n"
        "                                                       --Alvin Chen\n",
        count);
    printf(XPRINT_STAR_LINE "\n");
    printf("\n\n\n");
}

void xconf_help_param(const char *param) {
    if (!param || !param[0]) {
        LOG(LEVEL_ERROR, "(help param) invalid param.\n");
        return;
    }

    bool found = false;
    for (unsigned i = 0; config_parameters[i].name; i++) {
        if (!config_parameters[i].help_text) {
            continue;
        }

        if (conf_equals(config_parameters[i].name, param)) {
            found = true;
        } else {
            for (unsigned j = 0; config_parameters[i].alt_names[j]; j++) {
                if (conf_equals(config_parameters[i].alt_names[j], param)) {
                    found = true;
                    break;
                }
            }
        }

        if (!found)
            continue;

        printf("\n");
        printf("  --%s", config_parameters[i].name);

        for (unsigned j = 0; config_parameters[i].alt_names[j]; j++) {
            printf(", %s", config_parameters[i].alt_names[j]);
        }

        printf("\n\n");
        xprint(config_parameters[i].help_text, 6, 80);
        printf("\n\n");

        return;
    }

    LOG(LEVEL_ERROR, "(help param) no global param named \"%s\"\n", param);
}

void xconf_search_param(const char *param) {
    if (!param || !param[0]) {
        LOG(LEVEL_ERROR, "(search param) invalid param.\n");
        return;
    }

    int distance;

    printf("\n");

    for (unsigned i = 0; config_parameters[i].name; i++) {
        bool found = false;
        if (!config_parameters[i].help_text) {
            continue;
        }

        distance = conf_fuzzy_distance(config_parameters[i].name, param);
        if (distance < 0) {
            LOG(LEVEL_ERROR, "(search param) failed to matching.\n");
            break;
        }

        if (distance <= 2) {
            found = true;
        } else {
            for (unsigned j = 0; config_parameters[i].alt_names[j]; j++) {
                distance = conf_fuzzy_distance(
                    config_parameters[i].alt_names[j], param);
                if (distance <= 2) {
                    found = true;
                    break;
                }
            }
        }

        if (!found)
            continue;

        printf("  --%s", config_parameters[i].name);

        for (unsigned j = 0; config_parameters[i].alt_names[j]; j++) {
            printf(", %s", config_parameters[i].alt_names[j]);
        }

        printf("\n    %s", config_parameters[i].short_hint
                               ? config_parameters[i].short_hint
                               : config_parameters[i].help_text);
        printf("\n\n");
    }
}

void xconf_search_module(const char *module) {
    if (!module || !module[0]) {
        LOG(LEVEL_ERROR, "(search module) invalid module name.\n");
        return;
    }

    printf("SCAN MODULES:\n");
    list_searched_scan_modules(module);
    printf("PROBE MODULES:\n");
    list_searched_probe_modules(module);
    printf("OUTPUT MODULES:\n");
    list_searched_output_modules(module);
    printf("GENERATE MODULES:\n");
    list_searched_generate_modules(module);
}

void xconf_global_refresh(XConf *xconf) {
    uint64_t seed = xconf->seed;

    /**
     * Clear by provided func
     */
    targetset_rm_all(&xconf->targets);
    targetset_rm_all(&xconf->exclude);
    as_query_destroy(xconf->as_query);
    if (xconf->echo && xconf->echo != stdout)
        fclose(xconf->echo);

    /**
     * Free dynamic memory
     */
    FREE(xconf->probe_args);
    FREE(xconf->scanner_args);
    FREE(xconf->generator_args);
    FREE(xconf->out_conf.output_args);
    FREE(xconf->as_query);
    FREE(xconf->ip2asn_v4_filename);
    FREE(xconf->ip2asn_v6_filename);
    FREE(xconf->target_asn_v4);
    FREE(xconf->target_asn_v6);
    FREE(xconf->exclude_asn_v4);
    FREE(xconf->exclude_asn_v6);
    FREE(xconf->help_param);
    FREE(xconf->search_param);
    FREE(xconf->search_module);
#ifndef NOT_FOUND_BSON
    FREE(xconf->parse_bson_file);
#endif
#ifndef NOT_FOUND_MONGOC
    FREE(xconf->store_json_file);
    FREE(xconf->store_bson_file);
    FREE(xconf->mongodb_uri);
    FREE(xconf->mongodb_db);
    FREE(xconf->mongodb_col);
    FREE(xconf->mongodb_app);
#endif
#ifndef NOT_FOUND_PCRE2
    FREE(xconf->nmap_file);
#endif

    /**
     * Clear static memory
     */
    memset(xconf, 0, sizeof(XConf));

    /**
     * Set param in default
     */
    xconf->seed               = seed;
    xconf->tx_thread_count    = XCONF_DFT_TX_THD_COUNT;
    xconf->rx_handler_count   = XCONF_DFT_RX_HDL_COUNT;
    xconf->stack_buf_count    = XCONF_DFT_STACK_BUF_COUNT;
    xconf->dispatch_buf_count = XCONF_DFT_DISPATCH_BUF_COUNT;
    xconf->max_rate           = XCONF_DFT_MAX_RATE;
    xconf->dedup_win          = XCONF_DFT_DEDUP_WIN;
    xconf->shard.one          = XCONF_DFT_SHARD_ONE;
    xconf->shard.of           = XCONF_DFT_SHARD_OF;
    xconf->wait               = XCONF_DFT_WAIT;
    xconf->nic.snaplen        = XCONF_DFT_SNAPLEN;
    xconf->max_packet_len     = XCONF_DFT_MAX_PKT_LEN;
    xconf->packet_ttl         = XCONF_DFT_PACKET_TTL;
    xconf->tcp_init_window    = XCONF_DFT_TCP_SYN_WINSIZE;
    xconf->tcp_window         = XCONF_DFT_TCP_OTHER_WINSIZE;
    xconf->sendmmsg_batch     = XCONF_DFT_SENDMMSG_BATCH;
    xconf->sendmmsg_retries   = XCONF_DFT_SENDMMSG_RETRIES;
    xconf->sendq_size         = XCONF_DFT_SENDQUEUE_SIZE;
}

void xconf_benchmark(unsigned blackrock_rounds) {
    printf("=== benchmarking (%u-bits) ===\n\n", (unsigned)sizeof(void *) * 8);
    blackrock1_benchmark(blackrock_rounds);
    blackrock2_benchmark(blackrock_rounds);
    smack_benchmark();
}

/***************************************************************************
 ***************************************************************************/
static int xconf_self_selftest() {
    char test[] = " test 1 ";

    safe_trim(test, sizeof(test));
    if (strcmp(test, "test 1") != 0) {
        goto failure;
    }

    /* */
    {
        int   argc   = 6;
        char *argv[] = {"foo",        "bar", "-ddd",
                        "--readscan", "xxx", "--something"};

        if (xconf_contains("--nothing", argc, argv))
            goto failure;

        if (!xconf_contains("--readscan", argc, argv))
            goto failure;
    }

    return 0;
failure:
    LOG(LEVEL_ERROR, "(xconf) selftest failed\n");
    return 1;
}

int xconf_selftest(void) {
    puts("Regression test: start...");

    int x = 0;

    //! Add new regression test here
    {
        x += targetset_selftest();
        x += target_parse_selftest();
        x += ipv4address_selftest();
        x += ipv6address_selftest();
        x += ranges_selftest();
        x += ranges6_selftest();
        x += rangesport_selftest();
        x += dedup_selftest();
        x += checksum_selftest();
        x += smack_selftest();
        x += blackrock1_selftest();
        x += blackrock2_selftest();
#ifndef NOT_FOUND_PCRE2
        x += nmapservice_selftest();
#endif
        x += siphash24_selftest();
        x += lcg_selftest();
        x += pixie_time_selftest();
        x += rte_ring_selftest();
        x += xconf_self_selftest();
        x += rstfilter_selftest();
        x += base64_selftest();
        x += datachain_selftest();
        x += proto_http_maker_selftest();
        x += template_selftest();
        x += tcp_seg_ack_selftest();
    }

    if (x != 0)
        puts("Regression test: failed :(");
    else
        puts("Regression test: success!");

    return x;
}
