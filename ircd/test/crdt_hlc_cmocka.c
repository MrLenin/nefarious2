/*
 * crdt_hlc_cmocka.c - CMocka tests for the Hybrid Logical Clock primitive
 *                     (crdt_hlc.c) and the INVARIANT-4 digest padding rule.
 *
 * Batch P3-5c, Suite 1.  No standalone HLC suite existed; the engine suite
 * only used HLCs incidentally.  This pins the primitive directly:
 *
 *   - hlc_local_event  is STRICTLY MONOTONIC (logical bumps when physical_ms
 *     does not advance; physical advance resets logical).
 *   - hlc_receive      advances past a remote HLC and NEVER regresses (a stale
 *     remote can't pull the local clock backwards).
 *   - hlc_compare      is a TOTAL ORDER (reflexive/antisymmetric/transitive),
 *     ordered physical_ms -> logical -> node_id (the tiebreak chain).
 *   - INVARIANT 4      sizeof(HLC)=16, 12 used -> 4 trailing pad bytes.  Two
 *     HLCs with IDENTICAL fields but DIFFERENT padding compare EQUAL and
 *     contribute an IDENTICAL crdt_state_digest.  This is the regression guard
 *     for "hash HLC fields, never memcpy the raw struct onto the wire / into
 *     the digest" (crdt_state.c hash_hlc).
 *
 * DETERMINISM: hlc_local_event / hlc_receive read the wall clock internally.
 * To keep the branch under test deterministic (and independent of the actual
 * wall-clock value), the local/remote physical_ms is seeded FAR in the future
 * so `now > physical_ms` is always false and the logical/adopt branches are
 * exercised.  No test asserts an absolute wall-clock value.
 *
 * The primitive is dependency-light; the invariant-4 digest half needs the
 * state/types engine, so this links the same object set as crdt_cmocka.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cmocka.h>

#include "crdt_hlc.h"
#include "crdt_types.h"
#include "crdt_state.h"

/* A physical_ms comfortably beyond any plausible test-host wall clock
 * (~year 33658).  Seeding the clock here forces hlc_local_event/hlc_receive
 * down the logical-counter / adopt-remote branches deterministically. */
#define HLC_FAR_FUTURE_MS  1000000000000000ULL

static struct HLC H(uint64_t ms, uint16_t logical, uint16_t node)
{
  struct HLC h;
  memset(&h, 0, sizeof h);
  h.physical_ms = ms;
  h.logical = logical;
  h.node_id = node;
  return h;
}

/* ================================================================== */
/* hlc_local_event — strict monotonicity                              */
/* ================================================================== */

/* When physical_ms does NOT advance (clock seeded to the future), successive
 * local events strictly increase in total order via the logical counter, and
 * the physical component stays put. */
static void test_hlc_local_event_monotonic(void **state)
{
  (void)state;
  struct HLC c, prev, cur;
  int i;

  /* precondition: the seed really is in the future (else the branch differs) */
  assert_true(hlc_wall_clock_ms() < HLC_FAR_FUTURE_MS);

  c = H(HLC_FAR_FUTURE_MS, 0, 1);
  prev = hlc_local_event(&c);            /* logical 0 -> 1 (physical frozen) */
  assert_int_equal(HLC_FAR_FUTURE_MS, (unsigned long long)prev.physical_ms);
  assert_int_equal(1, prev.logical);

  for (i = 0; i < 1000; i++) {
    cur = hlc_local_event(&c);
    assert_true(hlc_compare(&prev, &cur) < 0);            /* strictly increasing */
    assert_int_equal(HLC_FAR_FUTURE_MS, (unsigned long long)cur.physical_ms);
    assert_int_equal(prev.logical + 1, cur.logical);      /* logical bumps by one */
    assert_int_equal(1, cur.node_id);                     /* node_id preserved */
    prev = cur;
  }
  /* the in-place clock reflects the last returned value */
  assert_int_equal(cur.logical, c.logical);
  assert_int_equal(0, hlc_compare(&cur, &c));
}

/* When the wall clock HAS advanced past the stored physical_ms, the event
 * adopts the new physical time and RESETS the logical counter to 0 — and the
 * result is still strictly greater than the pre-call value (monotonic across
 * the advance branch). */
static void test_hlc_local_event_advances_physical(void **state)
{
  (void)state;
  struct HLC c, before, after;

  c = H(1 /* 1ms past epoch: wall clock is far ahead */, 55, 7);
  before = c;
  after = hlc_local_event(&c);
  assert_true(after.physical_ms > 1);        /* advanced to wall clock */
  assert_int_equal(0, after.logical);        /* reset on physical advance */
  assert_int_equal(7, after.node_id);
  assert_true(hlc_compare(&before, &after) < 0);   /* still monotonic */
}

/* ================================================================== */
/* hlc_receive — advance + never-regress                              */
/* ================================================================== */

static void test_hlc_receive_advances_and_never_regresses(void **state)
{
  (void)state;
  struct HLC local, remote, before, after;

  assert_true(hlc_wall_clock_ms() < HLC_FAR_FUTURE_MS);

  /* (1) remote AHEAD in physical -> adopt remote physical, logical=remote+1 */
  local  = H(HLC_FAR_FUTURE_MS,        3, 1);
  remote = H(HLC_FAR_FUTURE_MS + 100,  9, 2);
  before = local;
  after = hlc_receive(&local, &remote);
  assert_int_equal(HLC_FAR_FUTURE_MS + 100, (unsigned long long)after.physical_ms);
  assert_int_equal(10, after.logical);                 /* remote.logical + 1 */
  assert_true(hlc_compare(&before, &after) < 0);       /* advanced, never back */

  /* (2) SAME physical -> logical = max(local,remote) + 1 */
  local  = H(HLC_FAR_FUTURE_MS,  4, 1);
  remote = H(HLC_FAR_FUTURE_MS, 12, 2);
  before = local;
  after = hlc_receive(&local, &remote);
  assert_int_equal(HLC_FAR_FUTURE_MS, (unsigned long long)after.physical_ms);
  assert_int_equal(13, after.logical);                 /* max(4,12) + 1 */
  assert_true(hlc_compare(&before, &after) < 0);

  /* (3) local AHEAD in physical -> physical stays, logical++ ; remote does NOT
   *     pull us back even though its logical is huge. */
  local  = H(HLC_FAR_FUTURE_MS + 500,     7, 1);
  remote = H(HLC_FAR_FUTURE_MS,       60000, 2);
  before = local;
  after = hlc_receive(&local, &remote);
  assert_int_equal(HLC_FAR_FUTURE_MS + 500, (unsigned long long)after.physical_ms);
  assert_int_equal(8, after.logical);                  /* local logical + 1 */
  assert_true(hlc_compare(&before, &after) < 0);

  /* (4) ANCIENT remote (way in the past) must NEVER regress the local clock */
  local  = H(HLC_FAR_FUTURE_MS + 500, 7, 1);
  remote = H(1000,                    0, 2);
  before = local;
  after = hlc_receive(&local, &remote);
  assert_true(hlc_compare(&before, &after) < 0);       /* strictly forward */
  assert_true(after.physical_ms >= before.physical_ms);/* physical never drops */
}

/* ================================================================== */
/* hlc_compare — total order (physical -> logical -> node_id)         */
/* ================================================================== */

static void test_hlc_compare_total_order(void **state)
{
  (void)state;
  /* strictly ASCENDING in the (physical_ms, logical, node_id) lexicographic order,
   * exercising each tiebreak level: node breaks a logical tie, logical breaks a
   * physical tie, physical dominates both. */
  struct HLC v[6];
  int i, j, n = 6;
  v[0] = H(100, 0, 1);
  v[1] = H(100, 0, 2);   /* node_id breaks the tie (same ms + logical) */
  v[2] = H(100, 5, 0);   /* higher logical beats any node_id at a lower logical */
  v[3] = H(100, 5, 9);   /* node_id breaks the tie again */
  v[4] = H(200, 0, 0);   /* higher physical dominates a higher logical/node */
  v[5] = H(200, 0, 1);

  /* reflexive: compare(x,x) == 0 */
  for (i = 0; i < n; i++)
    assert_int_equal(0, hlc_compare(&v[i], &v[i]));

  /* strict order + antisymmetry across every ordered pair */
  for (i = 0; i < n; i++)
    for (j = 0; j < n; j++) {
      int c = hlc_compare(&v[i], &v[j]);
      if (i < j) {
        assert_true(c < 0);
        assert_true(hlc_compare(&v[j], &v[i]) > 0);      /* antisymmetric */
      } else if (i > j) {
        assert_true(c > 0);
      } else {
        assert_int_equal(0, c);
      }
    }

  /* transitivity across a representative chain (a<b, b<c => a<c) */
  assert_true(hlc_compare(&v[0], &v[2]) < 0);
  assert_true(hlc_compare(&v[2], &v[4]) < 0);
  assert_true(hlc_compare(&v[0], &v[4]) < 0);

  /* two independently-built structs with equal fields compare equal */
  {
    struct HLC a = H(123, 4, 5), b = H(123, 4, 5);
    assert_int_equal(0, hlc_compare(&a, &b));
  }
}

/* ================================================================== */
/* INVARIANT 4 — HLC padding independence                             */
/* ================================================================== */

/* Two HLCs with IDENTICAL fields but DIFFERENT trailing padding compare EQUAL,
 * and their raw byte representations really differ (so the test is not vacuous). */
static void test_hlc_invariant4_padding_compare_equal(void **state)
{
  (void)state;
  struct HLC ff, zz;

  /* Layout pin: 8 (physical_ms) + 2 (logical) + 2 (node_id) = 12 used, padded to
   * 16 -> 4 trailing pad bytes.  INVARIANT 4 is only meaningful because pad exists. */
  assert_int_equal(16, (int)sizeof(struct HLC));

  memset(&ff, 0xFF, sizeof ff);            /* pad bytes = 0xFF */
  ff.physical_ms = 1719000000000ULL; ff.logical = 7; ff.node_id = 42;
  memset(&zz, 0x00, sizeof zz);            /* pad bytes = 0x00 */
  zz.physical_ms = 1719000000000ULL; zz.logical = 7; zz.node_id = 42;

  /* the raw 16-byte representations differ (in the pad) ... */
  assert_true(memcmp(&ff, &zz, sizeof(struct HLC)) != 0);
  /* ... yet the fields-only comparator reports EQUAL, both directions */
  assert_int_equal(0, hlc_compare(&ff, &zz));
  assert_int_equal(0, hlc_compare(&zz, &ff));
}

/* The load-bearing guard: an HLC's contribution to crdt_state_digest is
 * padding-INDEPENDENT.  crdt_lwwmap_set takes the HLC BY VALUE, so the pad bytes
 * ride into the stored value.ts.  If the digest hashed the raw struct, the two
 * differently-padded states would diverge; because crdt_state.c's hash_hlc hashes
 * the three FIELDS, they converge.  (Fails RED if anyone switches the digest to
 * memcpy/hash the raw HLC struct.) */
static void test_hlc_invariant4_digest_padding_independent(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  struct HLC ff, zz;
  const char *key = "alice";               /* opaque metadata key blob */
  uint32_t klen = (uint32_t)strlen(key);

  /* SAME numeric on both: the ONLY difference between the two states will be the
   * padding of the write-HLC injected below. */
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 1);

  memset(&ff, 0xFF, sizeof ff);
  ff.physical_ms = 1719000000000ULL; ff.logical = 7; ff.node_id = 42;
  memset(&zz, 0x00, sizeof zz);
  zz.physical_ms = 1719000000000ULL; zz.logical = 7; zz.node_id = 42;
  assert_true(memcmp(&ff, &zz, sizeof(struct HLC)) != 0);   /* padding really differs */

  /* identical key + value + writer; differ ONLY in the write-HLC's padding */
  crdt_lwwmap_set(&s1.metadata, key, klen, "v", 1, ff, 5);
  crdt_lwwmap_set(&s2.metadata, key, klen, "v", 1, zz, 5);

  /* both digests hash the HLC field-by-field -> identical despite the pad */
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_true(crdt_state_digest_materialized(&s1) ==
              crdt_state_digest_materialized(&s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_hlc_local_event_monotonic),
    cmocka_unit_test(test_hlc_local_event_advances_physical),
    cmocka_unit_test(test_hlc_receive_advances_and_never_regresses),
    cmocka_unit_test(test_hlc_compare_total_order),
    cmocka_unit_test(test_hlc_invariant4_padding_compare_equal),
    cmocka_unit_test(test_hlc_invariant4_digest_padding_independent),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
