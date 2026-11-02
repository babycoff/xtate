/*
    for tracking IP/port ranges
*/
#include "target-rangev6.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../xcmd.h"
#include "target-set.h"
#include "target-parse.h"
#include "target-rangev4.h"
#include "../util-out/logger.h"
#include "../util-data/fine-malloc.h"

#define REGRESS(i, x)                                                          \
    if (!(x)) {                                                                \
        LOG(LEVEL_ERROR, "%u: regression failed %s:%d\n", (unsigned)(i),       \
            __FILE__, __LINE__);                                               \
        return 1;                                                              \
    }

#define EQUAL(x, y) ipv6address_is_equal(x, y)

static inline ipv6address _int128_add(ipv6address x, ipv6address y) {
    ipv6address result;
    result.lo = x.lo + y.lo;
    result.hi = x.hi + y.hi + (result.lo < x.lo);
    return result;
}

static inline ipv6address _int128_sub(ipv6address x, ipv6address y) {
    ipv6address result;
    result.lo = x.lo - y.lo;
    result.hi = x.hi - y.hi - (result.lo > x.lo);
    return result;
}

static ipv6address _int128_add64(const ipv6address lhs, uint64_t rhs) {
    ipv6address result = lhs;
    result.lo += rhs;
    if (result.lo < lhs.lo)
        result.hi++;
    return result;
}

static inline int128_t _int128_mult64(int128_t lhs, uint64_t rhs) {
    int128_t result = {0, 0};
    uint64_t x;
    uint64_t b;
    uint64_t a;

    /* low-order 32 */
    a = (rhs >> 0) & 0xFFFFFFFFULL;
    b = (lhs.lo >> 0) & 0xFFFFFFFFULL;
    x = (a * b);
    result.lo += x;

    b = (lhs.lo >> 32ULL) & 0xFFFFFFFFULL;
    x = (a * b);
    result.lo += x << 32ULL;
    result.hi += x >> 32ULL;

    b = lhs.hi;
    x = (a * b);
    result.hi += x;

    /* next 32 */
    a = (rhs >> 32ULL) & 0xFFFFFFFFULL;
    b = (lhs.lo >> 0ULL) & 0xFFFFFFFFULL;
    x = (a * b);
    result.lo += x << 32ULL;
    result.hi += (x >> 32ULL) + (result.lo < (x << 32ULL));

    b = (lhs.lo >> 32ULL) & 0xFFFFFFFFULL;
    x = (a * b);
    result.hi += x;

    b = lhs.hi;
    x = (a * b);
    result.hi += x << 32ULL;

    return result;
}

static bool _int128_is_lt(const ipv6address lhs, const ipv6address rhs) {
    if (lhs.hi < rhs.hi)
        return true;
    else if (lhs.hi == rhs.hi && lhs.lo < rhs.lo)
        return true;
    else
        return false;
}
#define _int128_is_gte(x, y) (!_int128_is_lt((x), (y)))

static bool _int128_is_lte(const ipv6address lhs, const ipv6address rhs) {
    if (lhs.hi < rhs.hi)
        return true;
    if (lhs.hi > rhs.hi)
        return false;

    if (lhs.lo <= rhs.lo)
        return true;
    else
        return false;
}

bool range6_is_bad_address(const struct Range6 *range) {
    return _int128_is_lt(range->end, range->begin);
}

static bool _int128_is_eq(const ipv6address lhs, const ipv6address rhs) {
    return lhs.hi == rhs.hi && lhs.lo == rhs.lo;
}

static ipv6address _int128_dec(const ipv6address ip) {
    ipv6address result;

    if (ip.lo == 0) {
        result.hi = ip.hi - 1;
        result.lo = ~0ULL;
    } else {
        result.hi = ip.hi;
        result.lo = ip.lo - 1;
    }

    return result;
}

static ipv6address _int128_inc(const ipv6address ip) {
    ipv6address result;

    if (ip.lo == ~0) {
        result.hi = ip.hi + 1;
        result.lo = 0;
    } else {
        result.hi = ip.hi;
        result.lo = ip.lo + 1;
    }

    return result;
}

/***************************************************************************
 ***************************************************************************/
int128_t targetset_count(const TargetSet *targetset) {
    int128_t result;

    result = range6list_count(&targetset->ipv6);
    result = _int128_add64(result, rangelist_count(&targetset->ipv4));
    result = _int128_mult64(result, rangelist_count(&targetset->ports));

    return result;
}

/***************************************************************************
 * Does a linear/binary search to see if the list contains the ipv6 address
 ***************************************************************************/
bool range6list_is_contains(const struct Range6List *targets,
                            const ipv6address        ip) {
    size_t maxmax = targets->list_len;
    size_t min    = 0;
    size_t max    = targets->list_len;
    size_t mid;

    /**
     * Do linear search if not sorted
     */
    if (!targets->is_sorted) {
        LOG(LEVEL_DETAIL, "(%s) non-sorted range6list", __func__);
        size_t i;

        for (i = 0; i < targets->list_len; i++) {
            struct Range6 *range = &targets->list[i];

            if (_int128_is_lte(range->begin, ip) &&
                _int128_is_lte(ip, range->end))
                return true;
        }
        return false;
    }

    /**
     * Do binary search
     */
    for (;;) {
        mid = min + (max - min) / 2;
        if (_int128_is_lt(ip, targets->list[mid].begin)) {
            if (max == mid)
                break;
            max = mid;
            continue;
        } else if (_int128_is_lt(targets->list[mid].end, ip)) {
            if (mid + 1 == maxmax)
                break;
            else if (_int128_is_lt(ip, targets->list[mid + 1].begin))
                break;
            else
                min = mid + 1;
        } else {
            return true;
        }
    }

    return false;
}

/***************************************************************************
 * ???
 ***************************************************************************/
static void todo_remove_at(struct Range6List *targets, unsigned index) {
    memmove(&targets->list[index], &targets->list[index + 1],
            (targets->list_len - index) * sizeof(targets->list[index]));
    targets->list_len--;
}

/***************************************************************************
 * Test if two ranges overlap.
 * This is easiest done by testing that they don't overlap, and inverting
 * the result.
 * Note that adjacent addresses overlap.
 ***************************************************************************/
static int range6_is_overlap(const struct Range6 lhs, const struct Range6 rhs) {
    static const ipv6address FFFF = {~0ULL, ~0ULL};

    if (_int128_is_lt(lhs.begin, rhs.begin)) {
        if (EQUAL(lhs.end, FFFF) ||
            _int128_is_gte(_int128_inc(lhs.end), rhs.begin))
            return 1;
    }
    if (_int128_is_gte(lhs.begin, rhs.begin)) {
        if (_int128_is_lte(lhs.end, rhs.end))
            return 1;
    }

    if (_int128_is_lt(rhs.begin, lhs.begin)) {
        if (EQUAL(rhs.end, FFFF) ||
            _int128_is_gte(_int128_inc(rhs.end), lhs.begin))
            return 1;
    }
    if (_int128_is_gte(rhs.begin, lhs.begin)) {
        if (_int128_is_lte(rhs.end, lhs.end))
            return 1;
    }

    return 0;
#if 0
    static const ipv6address zero = {0, 0};
    ipv6address lhs_endm = _int128_dec(lhs.end);
    ipv6address rhs_endm = _int128_dec(rhs.end);

    /* llll rrrr */
    if (_int128_is_lt(zero, lhs.end) && _int128_is_lt(lhs_endm, rhs.begin))
        return 0;

    /* rrrr llll */
    if (_int128_is_lt(zero, rhs.end) && _int128_is_lt(rhs_endm, lhs.begin))
        return 0;

    return 1;
#endif
}

/***************************************************************************
 * Combine two ranges, such as when they overlap.
 ***************************************************************************/
static void range6_combine(struct Range6 *lhs, const struct Range6 rhs) {
    if (_int128_is_lte(rhs.begin, lhs->begin))
        lhs->begin = rhs.begin;
    if (_int128_is_lte(lhs->end, rhs.end))
        lhs->end = rhs.end;
}

/***************************************************************************
 * Callback for qsort() for comparing two ranges
 ***************************************************************************/
static int range6_compare(const void *lhs, const void *rhs) {
    struct Range6 *left  = (struct Range6 *)lhs;
    struct Range6 *right = (struct Range6 *)rhs;

    if (ipv6address_is_equal(left->begin, right->begin))
        return 0;
    else if (_int128_is_lt(left->begin, right->begin))
        return -1;
    else
        return 1;
}

/***************************************************************************
 ***************************************************************************/
void range6list_sort(struct Range6List *targets) {
    size_t            i;
    struct Range6List newlist        = {0};
    size_t            original_count = targets->list_len;

    /* Empty lists are, of course, sorted. We need to set this
     * to avoid an error later on in the code which asserts that
     * the lists are sorted */
    if (targets->list_len == 0) {
        targets->is_sorted = 1;
        return;
    }

    /* If it's already sorted, then skip this */
    if (targets->is_sorted) {
        return;
    }

    /* First, sort the list */
    LOG(LEVEL_DETAIL, "(range6list_sort) sorting...\n");
    qsort(targets->list,            /* the array to sort */
          targets->list_len,        /* number of elements to sort */
          sizeof(targets->list[0]), /* size of element */
          range6_compare);

    /* Second, combine all overlapping ranges. We do this by simply creating
     * a new list from a sorted list, so we don't have to remove things in the
     * middle when collapsing overlapping entries together, which is painfully
     * slow. */
    LOG(LEVEL_DETAIL, "(range6list_sort) combining...\n");
    for (i = 0; i < targets->list_len; i++) {
        range6list_add_range(&newlist, targets->list[i].begin,
                             targets->list[i].end);
    }

    LOG(LEVEL_DEBUG,
        "(range6list_sort) combined from %u elements to %u elements\n",
        original_count, newlist.list_len);
    FREE(targets->list);
    targets->list     = newlist.list;
    targets->list_len = newlist.list_len;
    newlist.list      = 0;

    LOG(LEVEL_DETAIL, "(range6list_sort) done...\n");

    targets->is_sorted = 1;
}

void range6list_add_range(struct Range6List *targets, ipv6address begin,
                          ipv6address end) {
    struct Range6 range;

    range.begin = begin;
    range.end   = end;

    /* auto-expand the list if necessary */
    if (targets->list_len + 1 >= targets->list_size) {
        targets->list_size = targets->list_size * 2 + 1;
        targets->list      = REALLOCARRAY(targets->list, targets->list_size,
                                          sizeof(targets->list[0]));
    }

    /* If empty list, then add this one */
    if (targets->list_len == 0) {
        targets->list[0] = range;
        targets->list_len++;
        targets->is_sorted = 1;
        return;
    }

    /* If new range overlaps the last range in the list, then combine it
     * rather than appending it. This is an optimization for the fact that
     * we often read in sequential addresses */
    if (range6_is_overlap(targets->list[targets->list_len - 1], range)) {
        range6_combine(&targets->list[targets->list_len - 1], range);
        targets->is_sorted = 0;
        return;
    }

    /* append to the end of our list */
    targets->list[targets->list_len] = range;
    targets->list_len++;
    targets->is_sorted = 0;
}

/***************************************************************************
 ***************************************************************************/
void range6list_rm_all(struct Range6List *targets) {
    FREE(targets->list);
    FREE(targets->picker);
    memset(targets, 0, sizeof(*targets));
}

/***************************************************************************
 ***************************************************************************/
void range6list_merge(struct Range6List       *list1,
                      const struct Range6List *list2) {
    size_t i;

    for (i = 0; i < list2->list_len; i++) {
        range6list_add_range(list1, list2->list[i].begin, list2->list[i].end);
    }
}

/***************************************************************************
 ***************************************************************************/
void range6list_remove_range(struct Range6List *targets,
                             const ipv6address begin, const ipv6address end) {
    size_t        i;
    struct Range6 x;

    x.begin = begin;
    x.end   = end;

    /* See if the range overlaps any exist range already in the
     * list */
    for (i = 0; i < targets->list_len; i++) {
        if (!range6_is_overlap(targets->list[i], x))
            continue;

        /* If the removal-range wholly covers the range, delete
         * it completely */
        if (_int128_is_lte(begin, targets->list[i].begin) &&
            _int128_is_lte(targets->list[i].end, end)) {
            todo_remove_at(targets, i);
            i--;
            continue;
        }

        /* If the removal-range bisects the target-rage, truncate
         * the lower end and add a new high-end */
        if (_int128_is_lte(targets->list[i].begin, begin) &&
            _int128_is_lte(end, targets->list[i].end)) {
            struct Range6 newrange;

            newrange.begin = _int128_inc(end);
            newrange.end   = targets->list[i].end;

            targets->list[i].end = _int128_dec(begin);

            range6list_add_range(targets, newrange.begin, newrange.end);
            i--;
            continue;
        }

        /* If overlap on the lower side */
        if (_int128_is_lte(targets->list[i].begin, end) &&
            _int128_is_lte(end, targets->list[i].end)) {
            targets->list[i].begin = _int128_inc(end);
        }

        /* If overlap on the upper side */
        if (_int128_is_lte(targets->list[i].begin, begin) &&
            _int128_is_lte(begin, targets->list[i].end)) {
            targets->list[i].end = _int128_dec(begin);
        }
    }
}

void range6list_remove_range2(struct Range6List *targets, struct Range6 range) {
    range6list_remove_range(targets, range.begin, range.end);
}

/***************************************************************************
 ***************************************************************************/
ipv6address range6list_exclude(struct Range6List       *targets,
                               const struct Range6List *excludes) {
    ipv6address count = {0, 0};
    size_t      i;

    for (i = 0; i < excludes->list_len; i++) {
        struct Range6 range = excludes->list[i];
        ipv6address   x;

        x = _int128_sub(range.end, range.begin);
        x = _int128_add64(x, 1);

        count = _int128_add(count, x);
        range6list_remove_range(targets, range.begin, range.end);
    }

    return count;
}

/***************************************************************************
 ***************************************************************************/
int128_t range6list_count(const struct Range6List *targets) {
    size_t      i;
    ipv6address result = {0, 0};

    for (i = 0; i < targets->list_len; i++) {
        ipv6address x;

        x = _int128_sub(targets->list[i].end, targets->list[i].begin);
        if (x.hi == ~0ULL && x.lo == ~0ULL)
            return x; /* overflow */
        x      = _int128_add64(x, 1);
        result = _int128_add(result, x);
    }

    return result;
}

/***************************************************************************
 ***************************************************************************/
ipv6address range6list_pick(const struct Range6List *targets, uint64_t index) {
    size_t        maxmax = targets->list_len;
    size_t        min    = 0;
    size_t        max    = targets->list_len;
    size_t        mid;
    const size_t *picker = targets->picker;

    if (!targets->is_sorted || !picker) {
        LOG(LEVEL_ERROR, "(%s) pick non-optimized range6list", __func__);
        xcmd_try_reboot();
        exit(1);
    }

    for (;;) {
        mid = min + (max - min) / 2;
        if (index < picker[mid]) {
            max = mid;
            continue;
        }
        if (index >= picker[mid]) {
            if (mid + 1 == maxmax)
                break;
            else if (index < picker[mid + 1])
                break;
            else
                min = mid + 1;
        }
    }

    return _int128_add64(targets->list[mid].begin, (index - picker[mid]));
}

/***************************************************************************
 * The normal "pick" function is a linear search, which is slow when there
 * are a lot of ranges. Therefore, the "pick2" creates sort of binary
 * search that'll be a lot faster. We choose "binary search" because
 * it's the most cache-efficient, having the least overhead to fit within
 * the cache.
 ***************************************************************************/
void range6list_optimize(struct Range6List *targets) {
    size_t     *picker;
    size_t      i;
    ipv6address total = {0, 0};

    if (targets->list_len == 0)
        return;

    /* This technique only works when the targets are in
     * ascending order */
    if (!targets->is_sorted)
        range6list_sort(targets);

    FREE(targets->picker);

    picker = REALLOCARRAY(NULL, targets->list_len, sizeof(*picker));

    for (i = 0; i < targets->list_len; i++) {
        ipv6address x;
        picker[i] = (size_t)total.lo;
        x         = _int128_sub(targets->list[i].end, targets->list[i].begin);
        x         = _int128_add64(x, 1);
        total     = _int128_add(total, x);
    }

    targets->picker = picker;
}

unsigned range6list_cidr_bits(struct Range6 *range, bool *exact) {
    uint64_t i;

    /* for the comments of this function, see  count_cidr_bits */
    *exact = false;

    for (i = 0; i < 128; i++) {
        int128_t mask;
        if (i < 64) {
            mask.hi = 0xFFFFFFFFffffffffull >> i;
            mask.lo = 0xFFFFFFFFffffffffull;
        } else {
            mask.hi = 0;
            mask.lo = 0xFFFFFFFFffffffffull >> (i - 64);
        }
        /*let begin's value in low mask is all-zero*/
        if ((range->begin.hi & mask.hi) != 0 ||
            (range->begin.lo & mask.lo) != 0) {
            continue;
        }
        /*high mask of begin & end must be same*/
        if ((range->begin.hi & ~mask.hi) == (range->end.hi & ~mask.hi) &&
            (range->begin.lo & ~mask.lo) == (range->end.lo & ~mask.lo)) {
            /*if end's value in low mask is all-one, range is an exactly CIDR*/
            if ((range->end.hi & mask.hi) == mask.hi &&
                (range->end.lo & mask.lo) == mask.lo) {
                *exact = true;
                return (unsigned)i;
            }
        } else {
            /*return the bits of first CIDR and adjust the range*/
            *exact       = false;
            range->begin = _int128_add(range->begin, mask);
            range->begin = _int128_inc(range->begin);

            return (unsigned)i;
        }
    }

    range->begin = _int128_inc(range->begin);

    return 128;
}

/***************************************************************************
 * Provide my own rand() simply to avoid static-analysis warning me that
 * 'rand()' is unrandom, when in fact we want the non-random properties of
 * rand() for regression testing.
 ***************************************************************************/
static unsigned r_rand(unsigned *seed) {
    static const unsigned a = 214013;
    static const unsigned c = 2531011;

    *seed = (*seed) * a + c;
    return (*seed) >> 16 & 0x7fff;
}

/***************************************************************************
 ***************************************************************************/
static int regress_pick2() {
    unsigned i;
    unsigned seed = 0;

    /*
     */
    for (i = 0; i < 65536; i++) {
        ipv6address a;
        ipv6address b;
        ipv6address c;
        ipv6address d;

        a.hi = r_rand(&seed);
        a.lo = (unsigned long long)r_rand(&seed) << 49ULL;
        b.hi = r_rand(&seed);
        b.lo = 0x8765432100000000ULL;

        c = _int128_add(a, b);
        d = _int128_sub(c, b);

        if (!_int128_is_eq(a, d)) {
            LOG(LEVEL_ERROR, "%s:%d: test failed (%u)\n", __FILE__, __LINE__,
                (unsigned)i);
            return 1;
        }
    }

    /*
     * Run 100 randomized regression tests
     */
    for (i = 3; i < 100; i++) {
        unsigned          j;
        unsigned          num_targets;
        ipv6address       begin        = {0};
        ipv6address       end          = {0};
        struct Range6List targets[1]   = {{0}};
        struct Range6List duplicate[1] = {{0}};
        uint64_t          range;
        ipv6address       x;

        seed = i;

        /* fill the target list with random ranges */
        num_targets = r_rand(&seed) % 5 + 1;
        for (j = 0; j < num_targets; j++) {
            begin.lo += r_rand(&seed) % 10;
            end.lo = begin.lo + r_rand(&seed) % 10;

            range6list_add_range(targets, begin, end);
        }

        /* Optimize for faster 'picking' addresses from an index */
        range6list_optimize(targets);

        /* Duplicate the targetlist using the picker */
        x = range6list_count(targets);
        if (x.hi) {
            LOG(LEVEL_ERROR, "(range6) range too big\n");
            return 1;
        }
        range = x.lo;
        for (j = 0; j < range; j++) {
            ipv6address addr;

            addr = range6list_pick(targets, j);
            range6list_add_range(duplicate, addr, addr);
        }

        /* at this point, the two range lists should be identical */
        REGRESS(i, targets->list_len == duplicate->list_len);
        REGRESS(i, memcmp(targets->list, duplicate->list,
                          targets->list_len * sizeof(targets->list[0])) == 0);

        range6list_rm_all(targets);
        range6list_rm_all(duplicate);
    }

    return 0;
}

int ranges6_selftest() {
    struct Range6 r;
    int           err;

    REGRESS(0, regress_pick2() == 0);

#define ERROR()                                                                \
    LOG(LEVEL_ERROR, "(%s) selftest failed %s:%u\n", __func__, __FILE__,       \
        __LINE__);

    err = target_parse_range("2001:0db8:85a3:0000:0000:8a2e:0370:7334", 0, 0, 0,
                             &r);
    if (err != Ipv6_Address)
        ERROR();

    /* test for the /0 CIDR block, since we'll be using that a lot to scan the
     * entire Internet */
    if (r.begin.hi != 0x20010db885a30000ULL)
        return 1;
    if (r.begin.lo != 0x00008a2e03707334ULL)
        return 1;

    /* Boundary prefixes: /0, /128, /32 and an explicit range. */
    if (target_parse_range("::/0", 0, 0, 0, &r) != Ipv6_Address)
        ERROR();
    if (r.begin.hi != 0 || r.begin.lo != 0 || r.end.hi != UINT64_MAX ||
        r.end.lo != UINT64_MAX)
        ERROR();

    if (target_parse_range("::1/128", 0, 0, 0, &r) != Ipv6_Address)
        ERROR();
    if (r.begin.hi != 0 || r.begin.lo != 1 || r.end.hi != 0 ||
        r.end.lo != 1)
        ERROR();

    if (target_parse_range("2001:db8::/32", 0, 0, 0, &r) != Ipv6_Address)
        ERROR();
    if (r.begin.hi != 0x20010db800000000ULL || r.begin.lo != 0 ||
        r.end.hi != 0x20010db8ffffffffULL || r.end.lo != UINT64_MAX)
        ERROR();

    if (target_parse_range("2001:db8::1-2001:db8::5", 0, 0, 0, &r) !=
        Ipv6_Address)
        ERROR();
    if (r.begin.hi != r.end.hi || r.begin.lo != 1 || r.end.lo != 5)
        ERROR();

    return 0;
}