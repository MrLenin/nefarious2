/*
 * crdt_cmocka.c - CMocka tests for the custom-C CRDT engine (Phase 0 PoC)
 *
 * Encodes the proposal §16.6 success criteria as assertions, written
 * test-first (TDD). Scenarios:
 *   A - basic convergence after a simulated partition (+ idempotency)
 *   B - nick-collision resolution: deterministic, force-rename NOT kill
 *   C - concurrent KICK+JOIN: priority OR-Set (KICK wins; PART+JOIN add-wins)
 *   E - SQUIT as server-state transition: zero membership tombstones
 *
 * (Scenario D, the long-running tombstone-growth stress, lives in the
 *  standalone crdt_sim.c, not in the CI unit suite.)
 *
 * The engine (crdt_types.c / crdt_state.c) is dependency-light, so this links
 * against just those objects + crdt_hlc.o + test_stub.o (for log_write).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "crdt_hlc.h"
#include "crdt_types.h"
#include "crdt_state.h"
#include "crdt_wire.h"
#include "s2s_chunk.h"

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static struct HLC mkhlc(uint64_t ms, uint16_t logical, uint16_t node)
{
  struct HLC h;
  h.physical_ms = ms;
  h.logical = logical;
  h.node_id = node;
  return h;
}

static struct CrdtUserRecord mkuser(const char *nick, uint16_t srv,
                                    const char *ident, uint32_t ip)
{
  struct CrdtUserRecord u;
  memset(&u, 0, sizeof u);
  strncpy(u.nick, nick, sizeof u.nick - 1);
  strncpy(u.ident, ident, sizeof u.ident - 1);
  u.server = srv;
  u.ip = ip;
  return u;
}

static struct CrdtNickClaim mkclaim(const char *numeric, struct HLC at,
                                    const char *ident, uint32_t ip,
                                    const char *account)
{
  struct CrdtNickClaim c;
  memset(&c, 0, sizeof c);
  strncpy(c.numeric, numeric, sizeof c.numeric - 1);
  strncpy(c.ident, ident, sizeof c.ident - 1);
  if (account) strncpy(c.account, account, sizeof c.account - 1);
  c.ip = ip;
  c.claimed_at = at;
  return c;
}

/* ================================================================== */
/* Scenario A — basic convergence + idempotency                       */
/* ================================================================== */

static void test_A_convergence(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* Shared baseline created on s1, then synced to s2. */
  struct CrdtUserRecord ua = mkuser("alice", 1, "alice", 0x01010101);
  crdt_user_set(&s1, "AAAAA", &ua);
  crdt_chan_join(&s1, "#chan", "AAAAA");
  assert_int_equal(2, crdt_state_sync(&s2, &s1)); /* SET user + ADD member */
  assert_true(crdt_state_equal(&s1, &s2));

  /* --- partition: independent, non-conflicting ops on each side --- */
  struct CrdtUserRecord ub = mkuser("bob", 2, "bob", 0x02020202);
  crdt_user_set(&s2, "BBBBB", &ub);          /* s2-only */
  crdt_chan_join(&s2, "#chan", "BBBBB");

  struct CrdtUserRecord uc = mkuser("carol", 1, "carol", 0x03030303);
  crdt_user_set(&s1, "CCCCC", &uc);          /* s1-only */
  crdt_chan_join(&s1, "#chan", "CCCCC");

  /* --- rejoin: exchange deltas both ways --- */
  crdt_state_sync(&s1, &s2);
  crdt_state_sync(&s2, &s1);

  /* converged + complete */
  assert_true(crdt_state_equal(&s1, &s2));
  assert_non_null(crdt_user_get(&s1, "BBBBB"));
  assert_non_null(crdt_user_get(&s2, "CCCCC"));
  assert_int_equal(3, crdt_chan_visible_members(&s1, "#chan"));
  assert_int_equal(3, crdt_chan_visible_members(&s2, "#chan"));

  /* --- idempotency: re-syncing applies nothing and changes nothing --- */
  assert_int_equal(0, crdt_state_sync(&s1, &s2));
  assert_int_equal(0, crdt_state_sync(&s2, &s1));
  assert_true(crdt_state_equal(&s1, &s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */
/* Scenario B — nick collision: deterministic, no kill                */
/* ================================================================== */

static void test_B_collision_different_user_oldest_wins(void **state)
{
  (void)state;
  /* alice claimed on two sides by DIFFERENT users (differing ip/ident). */
  struct CrdtNickClaim a = mkclaim("AAAAA", mkhlc(100, 0, 1), "alice",
                                   0x0A0A0A0A, NULL);
  struct CrdtNickClaim b = mkclaim("BBBBB", mkhlc(200, 0, 2), "bob",
                                   0x0B0B0B0B, NULL);
  /* different user@host -> OLDER timestamp wins (keep established user) */
  assert_ptr_equal(&a, crdt_resolve_nick_collision(&a, &b, NULL));
  assert_ptr_equal(&a, crdt_resolve_nick_collision(&b, &a, NULL)); /* symmetric */
}

static void test_B_collision_same_user_newest_wins(void **state)
{
  (void)state;
  /* same user@host (same ip+ident) reconnecting -> NEWER wins */
  struct CrdtNickClaim old = mkclaim("AAAAA", mkhlc(100, 0, 1), "alice",
                                     0x0A0A0A0A, NULL);
  struct CrdtNickClaim new = mkclaim("CCCCC", mkhlc(300, 0, 3), "alice",
                                     0x0A0A0A0A, NULL);
  assert_ptr_equal(&new, crdt_resolve_nick_collision(&old, &new, NULL));
}

static void test_B_collision_account_owner_wins(void **state)
{
  (void)state;
  /* registered nick: the account owner wins regardless of timestamp.
   * Here the YOUNGER claim (b, T=200) is the owner and must still win. */
  struct CrdtNickClaim a = mkclaim("AAAAA", mkhlc(100, 0, 1), "alice",
                                   0x0A0A0A0A, "");
  struct CrdtNickClaim b = mkclaim("BBBBB", mkhlc(200, 0, 2), "bob",
                                   0x0B0B0B0B, "bob_acct");
  assert_ptr_equal(&b, crdt_resolve_nick_collision(&a, &b, "bob_acct"));
}

static void test_B_collision_tie_breaks_on_node(void **state)
{
  (void)state;
  /* identical timestamps, different users -> lower node_id wins */
  struct CrdtNickClaim a = mkclaim("AAAAA", mkhlc(100, 0, 1), "alice",
                                   0x0A0A0A0A, NULL);
  struct CrdtNickClaim b = mkclaim("BBBBB", mkhlc(100, 0, 2), "bob",
                                   0x0B0B0B0B, NULL);
  assert_ptr_equal(&a, crdt_resolve_nick_collision(&a, &b, NULL));
}

static void test_B_force_rename_preserves_both(void **state)
{
  (void)state;
  /* The loser is force-renamed to its numeric, NOT killed:
   * both users survive, contested nick goes to the winner. */
  struct CrdtNetworkState st;
  crdt_state_init(&st, 1);

  struct CrdtUserRecord ua = mkuser("alice", 1, "alice", 0x0A0A0A0A);
  struct CrdtUserRecord ub = mkuser("alice", 1, "bob", 0x0B0B0B0B);
  crdt_user_set(&st, "AAAAA", &ua);
  crdt_user_set(&st, "BBBBB", &ub);

  struct CrdtNickClaim a = mkclaim("AAAAA", mkhlc(100, 0, 1), "alice",
                                   0x0A0A0A0A, NULL);
  struct CrdtNickClaim b = mkclaim("BBBBB", mkhlc(200, 0, 2), "bob",
                                   0x0B0B0B0B, NULL);
  crdt_nick_claim(&st, "alice", &a);   /* winner established */

  /* b loses (younger, different user) -> force-rename b to its numeric.
   * "now" must come from this server's clock so it beats the record's
   * write HLC (which crdt_user_set stamped off the same clock). */
  const struct CrdtNickClaim *winner = crdt_resolve_nick_collision(&a, &b, NULL);
  assert_ptr_equal(&a, winner);
  struct HLC now = hlc_local_event(&st.clock);
  crdt_nick_force_rename(&st, &b, now);

  /* both users still exist (no kill) */
  assert_non_null(crdt_user_get(&st, "AAAAA"));
  assert_non_null(crdt_user_get(&st, "BBBBB"));
  /* loser now wears its numeric as nick */
  assert_string_equal("BBBBB", crdt_user_get(&st, "BBBBB")->nick);
  /* contested nick still resolves to the winner */
  const struct CrdtNickClaim *cur =
    (const struct CrdtNickClaim *)crdt_lwwmap_get(&st.nicks, "alice", 5)->data;
  assert_string_equal("AAAAA", cur->numeric);

  crdt_state_clear(&st);
}

/* ================================================================== */
/* Scenario C — concurrent KICK+JOIN: priority OR-Set                 */
/* ================================================================== */

static void test_C_kick_beats_concurrent_join(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* baseline: X is a member, known on both sides */
  crdt_chan_join(&s1, "#c", "XXXXX");
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_orset_contains(&crdt_state_channel(&s1, "#c", 0)->members,
                                          "XXXXX", 5));

  /* --- partition --- */
  crdt_chan_remove(&s1, "#c", "XXXXX", CRDT_PRIORITY_CHANOP); /* A: KICK */
  crdt_chan_join(&s2, "#c", "XXXXX");                          /* B: re-JOIN (new tag) */

  /* --- rejoin --- */
  crdt_state_sync(&s1, &s2);
  crdt_state_sync(&s2, &s1);

  /* KICK (priority) beats the concurrent JOIN; both converge to absent */
  assert_int_equal(0, crdt_orset_contains(&crdt_state_channel(&s1, "#c", 0)->members,
                                          "XXXXX", 5));
  assert_int_equal(0, crdt_orset_contains(&crdt_state_channel(&s2, "#c", 0)->members,
                                          "XXXXX", 5));
  assert_true(crdt_state_equal(&s1, &s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

static void test_C_part_yields_to_concurrent_join(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  crdt_chan_join(&s1, "#c", "XXXXX");
  crdt_state_sync(&s2, &s1);

  /* --- partition: voluntary PART vs concurrent re-JOIN --- */
  crdt_chan_remove(&s1, "#c", "XXXXX", CRDT_PRIORITY_USER);  /* A: PART */
  crdt_chan_join(&s2, "#c", "XXXXX");                         /* B: re-JOIN */

  crdt_state_sync(&s1, &s2);
  crdt_state_sync(&s2, &s1);

  /* PART is priority-0: the concurrent JOIN survives (add-wins) */
  assert_int_equal(1, crdt_orset_contains(&crdt_state_channel(&s1, "#c", 0)->members,
                                          "XXXXX", 5));
  assert_true(crdt_state_equal(&s1, &s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */
/* Scenario E — SQUIT as server-state transition (no tombstone storm) */
/* ================================================================== */

static void test_E_squit_creates_no_membership_tombstones(void **state)
{
  (void)state;
  struct CrdtNetworkState st;
  crdt_state_init(&st, 1);

  const int N = 50;
  crdt_server_set(&st, 7, CRDT_SRV_ACTIVE);
  for (int i = 0; i < N; i++) {
    char num[CRDT_NUMERICLEN];
    snprintf(num, sizeof num, "U%03d", i);   /* fits in 5 chars */
    struct CrdtUserRecord u = mkuser("user", 7, "id", 0x07070707u + i);
    crdt_user_set(&st, num, &u);
    crdt_chan_join(&st, "#big", num);
  }
  struct CrdtChannel *c = crdt_state_channel(&st, "#big", 0);
  assert_int_equal((uint32_t)N, crdt_orset_size(&c->members));
  assert_int_equal(0, crdt_orset_tomb_count(&c->members));

  /* SQUIT server 7 — a single LWW write, NOT N removals */
  crdt_server_squit(&st, 7);

  /* users are hidden but NOT tombstoned: zero membership tombstones */
  assert_int_equal(0, crdt_orset_tomb_count(&c->members));
  assert_int_equal((uint32_t)N, crdt_orset_size(&c->members)); /* still in set */
  assert_int_equal(0, crdt_chan_visible_members(&st, "#big"));  /* but invisible */

  /* user records still present (hidden, not removed) */
  assert_non_null(crdt_user_get(&st, "U000"));
  assert_int_equal(0, crdt_user_visible(&st, "U000"));

  /* relink restores visibility instantly, still no tombstones */
  crdt_server_relink(&st, 7);
  assert_int_equal((uint32_t)N, crdt_chan_visible_members(&st, "#big"));
  assert_int_equal(0, crdt_orset_tomb_count(&c->members));

  crdt_state_clear(&st);
}

/* ================================================================== */
/* Phase 2 — wire serialization round-trip                            */
/* ================================================================== */

static void test_wire_sv_roundtrip(void **state)
{
  (void)state;
  struct CrdtStateVector a, b;
  uint8_t buf[512];
  int n;
  crdt_sv_init(&a);
  crdt_sv_init(&b);
  crdt_sv_update(&a, 1, 100);
  crdt_sv_update(&a, 5, 42);
  crdt_sv_update(&a, 4000, 7);
  n = crdt_sv_encode(&a, buf, sizeof buf);
  assert_true(n > 0);
  assert_true(crdt_sv_decode(&b, buf, (size_t)n) >= 0);
  assert_int_equal(100, b.seq[1]);
  assert_int_equal(42, b.seq[5]);
  assert_int_equal(7, b.seq[4000]);
  assert_int_equal(0, b.seq[2]);   /* unset stays zero */
}

/* The payoff: encode a server's oplog as a delta vs an empty peer SV, apply it
 * to a fresh replica, and the two converge — the wire form of crdt_state_sync. */
static void test_wire_delta_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[8192];
  int n, applied;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  struct CrdtUserRecord u = mkuser("alice", 1, "alice", 0x01010101);
  crdt_user_set(&s1, "AAAAA", &u);
  crdt_chan_join(&s1, "#wire", "AAAAA");
  crdt_chan_join(&s1, "#wire", "BBBBB");
  crdt_chan_remove(&s1, "#wire", "BBBBB", CRDT_PRIORITY_CHANOP); /* KICK */
  struct CrdtNickClaim c = mkclaim("AAAAA", mkhlc(100, 0, 1), "alice",
                                   0x01010101, NULL);
  crdt_nick_claim(&s1, "alice", &c);

  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  assert_true(n > 0);
  applied = crdt_delta_apply(&s2, buf, (size_t)n);
  assert_true(applied > 0);
  assert_true(crdt_state_equal(&s1, &s2));

  /* idempotent: re-applying the same delta changes nothing */
  applied = crdt_delta_apply(&s2, buf, (size_t)n);
  assert_int_equal(0, applied);
  assert_true(crdt_state_equal(&s1, &s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* digest differs under tag divergence, converges after bidirectional sync —
 * this is the cross-server convergence proof in miniature. */
static void test_wire_digest_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[8192];
  int n;
  struct CrdtUserRecord u = mkuser("a", 1, "a", 0x01010101);
  uint8_t msnap[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  /* same logical content, but each server tags it with its own origin. Topic
   * and modes are included on purpose: they must be op-backed to converge
   * (regression guard for the bug where they bypassed the oplog). */
  crdt_user_set(&s1, "AAAAA", &u);  crdt_chan_join(&s1, "#d", "AAAAA");
  crdt_topic_set(&s1, "#d", "hello");  crdt_modes_set(&s1, "#d", msnap, sizeof msnap);
  crdt_user_set(&s2, "AAAAA", &u);  crdt_chan_join(&s2, "#d", "AAAAA");
  crdt_topic_set(&s2, "#d", "hello");  crdt_modes_set(&s2, "#d", msnap, sizeof msnap);
  assert_true(crdt_state_digest(&s1) != crdt_state_digest(&s2));  /* tags differ */
  /* exchange deltas both ways -> tag union -> converge */
  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s2, buf, (size_t)n);
  n = crdt_delta_encode(&s2.oplog, &s1.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s1, buf, (size_t)n);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));  /* converged */
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* Two replicas make CONCURRENT, CONFLICTING changes to the same entities with
 * no coordination, then sync. They must still converge to the same digest --
 * the core CRDT guarantee under contention (concurrent LWW conflict on a key,
 * concurrent part-vs-keep on a member, conflicting topic + modes). */
static void test_wire_concurrent_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[8192];
  int n, r;
  struct CrdtUserRecord ua = mkuser("alice", 1, "a", 0x0A);
  struct CrdtUserRecord ub = mkuser("bob", 1, "b", 0x0B);
  struct CrdtUserRecord aX = mkuser("aliceX", 1, "a", 0x0A);
  struct CrdtUserRecord aY = mkuser("aliceY", 1, "a", 0x0A);
  uint8_t m1[2] = { 0x10, 0 }, m2[2] = { 0x20, 0 };
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* shared baseline, mirrored independently on each side (own origin tags) */
  crdt_user_set(&s1, "AAAAA", &ua); crdt_chan_join(&s1, "#x", "AAAAA");
  crdt_user_set(&s2, "AAAAA", &ua); crdt_chan_join(&s2, "#x", "AAAAA");
  crdt_user_set(&s1, "BBBBB", &ub); crdt_chan_join(&s1, "#x", "BBBBB");
  crdt_user_set(&s2, "BBBBB", &ub); crdt_chan_join(&s2, "#x", "BBBBB");

  /* --- concurrent, conflicting ops (no sync between them) --- */
  crdt_user_set(&s1, "AAAAA", &aX);                 /* A's record two ways  */
  crdt_user_set(&s2, "AAAAA", &aY);
  crdt_chan_remove(&s1, "#x", "BBBBB", CRDT_PRIORITY_USER); /* s1 parts B    */
  crdt_user_set(&s2, "CCCCC", &ub); crdt_chan_join(&s2, "#x", "CCCCC"); /* s2 adds C */
  crdt_topic_set(&s1, "#x", "topic-one");           /* conflicting topic    */
  crdt_topic_set(&s2, "#x", "topic-two");
  crdt_modes_set(&s1, "#x", m1, sizeof m1);         /* conflicting modes    */
  crdt_modes_set(&s2, "#x", m2, sizeof m2);

  assert_true(crdt_state_digest(&s1) != crdt_state_digest(&s2));  /* diverged */

  /* exchange deltas both ways (two rounds to flush relayed ops) */
  for (r = 0; r < 2; r++) {
    n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
    crdt_delta_apply(&s2, buf, (size_t)n);
    n = crdt_delta_encode(&s2.oplog, &s1.local_sv, buf, sizeof buf);
    crdt_delta_apply(&s1, buf, (size_t)n);
  }

  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));  /* converged */
  /* idempotent: nothing left to apply either way */
  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  assert_int_equal(0, crdt_delta_apply(&s2, buf, (size_t)n));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* A full-state snapshot reconstructs a byte-identical document on a fresh peer
 * (CR F: the fallback when delta sync can't, because the ops were GC'd). */
static void test_snapshot_roundtrip(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[16384];
  int n;
  struct CrdtUserRecord u = mkuser("alice", 1, "a", 0x01020304);
  uint8_t modesnap[3] = { 0x10, 0x20, 0x30 };
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  crdt_user_set(&s1, "AAAAA", &u);
  crdt_chan_join(&s1, "#r", "AAAAA");
  crdt_chan_join(&s1, "#r", "BBBBB");
  crdt_chan_remove(&s1, "#r", "BBBBB", CRDT_PRIORITY_USER);  /* leaves a tombstone */
  crdt_topic_set(&s1, "#r", "hello world");
  crdt_modes_set(&s1, "#r", modesnap, sizeof modesnap);

  n = crdt_snapshot_encode(&s1, buf, sizeof buf);
  assert_true(n > 0);
  assert_true(crdt_snapshot_apply(&s2, buf, (size_t)n) >= 0);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* crdt_state_gc advances gc_floor to the stable cut it reclaimed against. */
static void test_gc_advances_floor(void **state)
{
  (void)state;
  struct CrdtNetworkState s1;
  struct CrdtUserRecord u = mkuser("alice", 1, "a", 1);
  crdt_state_init(&s1, 1);
  crdt_user_set(&s1, "AAAAA", &u);
  crdt_chan_join(&s1, "#g", "AAAAA");
  crdt_topic_set(&s1, "#g", "t");
  assert_int_equal(0, (int)s1.gc_floor.seq[1]);
  crdt_state_gc(&s1, &s1.local_sv);
  assert_int_equal((int)s1.local_sv.seq[1], (int)s1.gc_floor.seq[1]);
  assert_true(s1.gc_floor.seq[1] > 0);
  crdt_state_clear(&s1);
}

/* The real CR F scenario: a peer falls so far behind that the ops it needs have
 * been GC'd from the oplog -> a delta can't catch it up, but a snapshot can. */
static void test_snapshot_recovers_gc_gap(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[16384];
  int n;
  struct CrdtUserRecord u = mkuser("alice", 1, "a", 1);
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  crdt_user_set(&s1, "AAAAA", &u);
  crdt_chan_join(&s1, "#g", "AAAAA");
  crdt_topic_set(&s1, "#g", "t");

  /* s1 GCs against its own SV (every other peer caught up; s2 was split) ->
   * oplog emptied, gc_floor now past s2's (empty) SV. */
  crdt_state_gc(&s1, &s1.local_sv);

  /* a delta for the far-behind s2 is empty (the ops are gone) -> still diverged */
  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s2, buf, (size_t)n);
  assert_true(crdt_state_digest(&s1) != crdt_state_digest(&s2));

  /* a snapshot catches it up regardless of the GC gap */
  n = crdt_snapshot_encode(&s1, buf, sizeof buf);
  assert_true(crdt_snapshot_apply(&s2, buf, (size_t)n) >= 0);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* The materialized digest is invariant under GC (it hashes only present
 * elements), while the full digest is not (it hashes reclaimable tombstones).
 * This is why two replicas with identical live state but different GC progress
 * agree on mdigest but not digest -- mdigest is the real convergence metric. */
static void test_materialized_digest_gc_invariant(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  uint64_t m_before, m_after, full_before, full_after;
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#g", "AAAAA");
  crdt_chan_join(&s, "#g", "BBBBB");
  crdt_chan_remove(&s, "#g", "BBBBB", CRDT_PRIORITY_USER);  /* leaves a tombstone */
  m_before = crdt_state_digest_materialized(&s);
  full_before = crdt_state_digest(&s);
  crdt_state_gc(&s, &s.local_sv);             /* reclaim the stable tombstone */
  m_after = crdt_state_digest_materialized(&s);
  full_after = crdt_state_digest(&s);
  assert_int_equal(m_before, m_after);        /* materialized: unchanged by GC */
  assert_int_not_equal(full_before, full_after); /* full: tombstone reclaimed */
  crdt_state_clear(&s);
}

static void test_wire_b64_roundtrip(void **state)
{
  (void)state;
  const uint8_t in[] = { 0, 1, 2, 253, 254, 255, 0x10, 0x20, 'h', 'i' };
  char enc[64];
  uint8_t dec[64];
  size_t L;
  int n = crdt_b64_encode(in, sizeof in, enc, sizeof enc);
  assert_true(n > 0);
  assert_int_equal((int)sizeof in, crdt_b64_decode(enc, dec, sizeof dec));
  assert_memory_equal(in, dec, sizeof in);
  /* exercise all three padding cases */
  for (L = 1; L <= 3; L++) {
    assert_true(crdt_b64_encode(in, L, enc, sizeof enc) > 0);
    assert_int_equal((int)L, crdt_b64_decode(enc, dec, sizeof dec));
    assert_memory_equal(in, dec, L);
  }
}

/* ================================================================== */
/* Phase 2 — shared S2S chunk reassembly                              */
/* ================================================================== */

static void test_chunk_reassembles(void **state)
{
  (void)state;
  char *out = NULL; size_t len = 0;
  assert_int_equal(0, s2s_chunk_feed((void *)1, "id1", "AAAA", 1, &out, &len));
  assert_int_equal(0, s2s_chunk_feed((void *)1, "id1", "BBBB", 1, &out, &len));
  assert_int_equal(1, s2s_chunk_feed((void *)1, "id1", "CC", 0, &out, &len));
  assert_non_null(out);
  assert_int_equal(10, (int)len);
  assert_string_equal("AAAABBBBCC", out);
  free(out);
}

static void test_chunk_isolation(void **state)
{
  (void)state;
  char *out = NULL; size_t len = 0;
  /* same id over two different links must not collide */
  s2s_chunk_feed((void *)1, "x", "L1", 1, &out, &len);
  s2s_chunk_feed((void *)2, "x", "L2", 1, &out, &len);
  assert_int_equal(1, s2s_chunk_feed((void *)1, "x", "a", 0, &out, &len));
  assert_string_equal("L1a", out); free(out);
  assert_int_equal(1, s2s_chunk_feed((void *)2, "x", "b", 0, &out, &len));
  assert_string_equal("L2b", out); free(out);
}

static void test_chunk_cleanup_link(void **state)
{
  (void)state;
  char *out = NULL; size_t len = 0;
  s2s_chunk_feed((void *)1, "id", "XYZ", 1, &out, &len);  /* buffered */
  s2s_chunk_cleanup_link((void *)1);                       /* peer SQUIT */
  /* a fresh feed for the same (link,id) starts clean, not "XYZ..." */
  assert_int_equal(1, s2s_chunk_feed((void *)1, "id", "Q", 0, &out, &len));
  assert_string_equal("Q", out);
  free(out);
}

/* ================================================================== */

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_A_convergence),
    cmocka_unit_test(test_B_collision_different_user_oldest_wins),
    cmocka_unit_test(test_B_collision_same_user_newest_wins),
    cmocka_unit_test(test_B_collision_account_owner_wins),
    cmocka_unit_test(test_B_collision_tie_breaks_on_node),
    cmocka_unit_test(test_B_force_rename_preserves_both),
    cmocka_unit_test(test_C_kick_beats_concurrent_join),
    cmocka_unit_test(test_C_part_yields_to_concurrent_join),
    cmocka_unit_test(test_E_squit_creates_no_membership_tombstones),
    cmocka_unit_test(test_wire_sv_roundtrip),
    cmocka_unit_test(test_wire_delta_converges),
    cmocka_unit_test(test_wire_digest_converges),
    cmocka_unit_test(test_wire_concurrent_converges),
    cmocka_unit_test(test_snapshot_roundtrip),
    cmocka_unit_test(test_gc_advances_floor),
    cmocka_unit_test(test_snapshot_recovers_gc_gap),
    cmocka_unit_test(test_materialized_digest_gc_invariant),
    cmocka_unit_test(test_wire_b64_roundtrip),
    cmocka_unit_test(test_chunk_reassembles),
    cmocka_unit_test(test_chunk_isolation),
    cmocka_unit_test(test_chunk_cleanup_link),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
