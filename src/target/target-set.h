/**
 * Born and updated from Masscan
 * Modified and Created by Alvin Chen 2024
 */
#ifndef TARGET_SET_H
#define TARGET_SET_H

#include <stddef.h>

#include "target-rangev4.h"
#include "target-rangev6.h"
struct AS_Query;

typedef struct TargetRangeSet {
    struct RangeList  ipv4;
    struct Range6List ipv6;

    /**
     * The ports we are scanning for. The user can specify repeated ports
     * and overlapping ranges, but we'll deduplicate them, scanning ports
     * only once.
     * NOTE: TCP ports are stored 0-64k, but UDP ports are stored in the
     * range 64k-128k, thus, allowing us to scan both at the same time.
     */
    struct RangeList ports;

    /**
     * Used internally to differentiate between indexes selecting an
     * IPv4 address and higher ones selecting an IPv6 address.
     * NOTE:Should be update manually or by targetset_optimize
     */
    uint64_t ipv4_threshold;
    /**
     * NOTE:Should be update manually or by targetset_optimize
     */
    uint64_t count_ports;
    uint64_t count_ipv4s;
    int128_t count_ipv6s;
} TargetSet;

/**
 * Count the total number of targets in a scan. This is calculated
 * the (IPv6 addresses + IPv4 addresses) * ports. This can produce
 * a 128-bit number (larger, actually).
 */
int128_t targetset_count(const TargetSet *targetset);

/**
 * Remove everything in "targets" that's listed in the "exclude"
 * list. The reason for this is that we'll have a single policy
 * file of those address ranges which we are forbidden to scan.
 * Then, each time we run a scan with different targets, we
 * apply this policy file.
 */
void targetset_apply_excludes(TargetSet *targets, TargetSet *exclude);

/**
 * The last step after processing the configuration, setting up the
 * state to be used for scanning. This sorts the address, removes
 * duplicates, and creates an optimized 'picker' system to easily
 * find an address given an index, or find an index given an address.
 */
void targetset_optimize(TargetSet *targets);

/**
 * This selects an IP+port combination given an index whose value
 * is [0..range], where 'range' is the value returned by the function
 * `targetset_range()`. Since the optimization step (`targetset_optimized()`)
 * sorted all addresses/ports, a monotonically increasing index will
 * list everything in sorted order. The intent, however, is to use the
 * "blackrock" algorithm to randomize the index before calling this function.
 *
 * It is this function, plus the 'blackrock' randomization algorithm, that
 * is at the heart of Xconf.
 */
void targetset_pick(const TargetSet *targetset, uint64_t index, ipaddress *addr,
                    unsigned *port);

bool targetset_has_ip(const TargetSet *targetset, ipaddress ip);

bool targetset_has_port(const TargetSet *targetset, unsigned port);

int targetset_add_ip_str(TargetSet *targetset, const char *string);

/**
 * Parse the string contain port specifier.
 * NOTE: this func may add no port in final.
 */
int targetset_add_port_str(TargetSet *targetset, const char *string,
                           unsigned proto_offset);

/**
 * add ipv4 addr to targetset by ASN
 */
int targetset_add_asn4_str(TargetSet             *targetset,
                           const struct AS_Query *as_query,
                           const char            *asn_str);

/**
 * add ipv6 addr to targetset by ASN
 */
int targetset_add_asn6_str(TargetSet             *targetset,
                           const struct AS_Query *as_query,
                           const char            *asn_str);

/**
 * Indicates whether there are IPv4 targets. If so, we'll have to
 * initialize the IPv4 portion of the stack.
 * @return true if there are IPv4 targets to be scanned, false
 * otherwise
 */
bool targetset_has_any_ipv4(const TargetSet *targetset);

/**
 * Indicates whether there are IPv6 targets. If so, we'll have to
 * initialize the IPv6 portion of the stack.
 * @return true if there are IPv6 targets to be scanned, false
 * otherwise
 */
bool targetset_has_any_ipv6(const TargetSet *targetset);

bool targetset_has_any_ports(const TargetSet *targetset);

void targetset_rm_all(TargetSet *targets);
void targetset_rm_ip(TargetSet *targets);
void targetset_rm_port(TargetSet *targets);

int targetset_selftest();

#endif
