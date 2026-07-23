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
#include "crdt_shadow.h"    /* M12: force_lastmod (static inline, pure) */

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
  memcpy(u.ip6, &ip, sizeof ip);   /* Phase 3b: ip is now ip6[16]; stash the
                                      test's u32 in the first 4 bytes */
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

/* Phase 3g gate: crdt_orset_is_explicitly_removed distinguishes a tombstoned
 * member (a real remove happened → safe to reconcile-remove live) from a merely
 * absent one (never added / sync lag → must NOT remove a live member). */
static void test_orset_explicit_removal_gate(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  struct CrdtORSet *m;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* present (joined, not removed): contained, NOT explicitly removed */
  crdt_chan_join(&s1, "#c", "PPPPP");
  m = &crdt_state_channel(&s1, "#c", 0)->members;
  assert_int_equal(1, crdt_orset_contains(m, "PPPPP", 5));
  assert_int_equal(0, crdt_orset_is_explicitly_removed(m, "PPPPP", 5));

  /* absent (never added): neither contained nor explicitly removed (the guard) */
  assert_int_equal(0, crdt_orset_contains(m, "ABSEN", 5));
  assert_int_equal(0, crdt_orset_is_explicitly_removed(m, "ABSEN", 5));

  /* fully tombstoned (joined then PART): NOT contained, IS explicitly removed */
  crdt_chan_join(&s1, "#c", "RRRRR");
  crdt_chan_remove(&s1, "#c", "RRRRR", CRDT_PRIORITY_USER);
  m = &crdt_state_channel(&s1, "#c", 0)->members;
  assert_int_equal(0, crdt_orset_contains(m, "RRRRR", 5));
  assert_int_equal(1, crdt_orset_is_explicitly_removed(m, "RRRRR", 5));

  /* partial tombstone (PART vs concurrent re-JOIN → one tag tombstoned, one live):
   * contained, NOT explicitly removed (the live add-tag keeps the member present) */
  crdt_chan_join(&s1, "#c", "QQQQQ");
  crdt_state_sync(&s2, &s1);                                 /* s2 learns tag1 */
  crdt_chan_remove(&s1, "#c", "QQQQQ", CRDT_PRIORITY_USER);  /* s1 tombstones tag1 */
  crdt_chan_join(&s2, "#c", "QQQQQ");                        /* s2 re-joins → tag2 */
  crdt_state_sync(&s1, &s2);                                 /* s1: tag1(tomb) + tag2(live) */
  m = &crdt_state_channel(&s1, "#c", 0)->members;
  assert_int_equal(1, crdt_orset_contains(m, "QQQQQ", 5));
  assert_int_equal(0, crdt_orset_is_explicitly_removed(m, "QQQQQ", 5));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */
/* Phase 3i: ban/except OR-Set ops replicate via DELTA sync (not just snapshot).
 * Guards against the regression where crdt_shadow_lists used a direct
 * crdt_orset_add (no op) so steady-state +b/-b never reached peers. */
static void test_chan_ban_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  const char *B = "bad!*@*.evil", *E = "ok!*@*.good";
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* +b on s1 -> delta sync -> s2 has it in bans */
  crdt_chan_ban_add(&s1, "#c", B, 0);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_orset_contains(&crdt_state_channel(&s2, "#c", 0)->bans,
                                          B, (uint32_t)strlen(B)));
  /* +e on s1 -> goes to excepts, NOT bans */
  crdt_chan_ban_add(&s1, "#c", E, 1);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_orset_contains(&crdt_state_channel(&s2, "#c", 0)->excepts,
                                          E, (uint32_t)strlen(E)));
  assert_int_equal(0, crdt_orset_contains(&crdt_state_channel(&s2, "#c", 0)->bans,
                                          E, (uint32_t)strlen(E)));
  /* -b on s1 -> delta sync -> s2 removes it */
  crdt_chan_ban_remove(&s1, "#c", B, CRDT_PRIORITY_USER, 0);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(0, crdt_orset_contains(&crdt_state_channel(&s2, "#c", 0)->bans,
                                          B, (uint32_t)strlen(B)));
  /* the except is untouched */
  assert_int_equal(1, crdt_orset_contains(&crdt_state_channel(&s2, "#c", 0)->excepts,
                                          E, (uint32_t)strlen(E)));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* F1-c: per-user SILENCE OR-Set — a GLOBAL collection keyed usernumeric\0mask.
 * Ops replicate via DELTA sync (not just snapshot), removes tombstone, a second
 * mask for the same user coexists, digests converge each step, and the surviving
 * state round-trips through a CR-F snapshot (the cold-join path). Mirrors
 * test_chan_ban_op_replicates but on the global st->silences OR-Set. */
static void test_silence_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2, s3;
  const char *U = "AAAAB";                 /* a 5-char client numeric */
  const char *M1 = "spammer!*@*.evil";
  const char *M2 = "flooder!*@*.bad";
  char k1[64], k2[64];
  uint32_t ul = (uint32_t)strlen(U);
  uint32_t k1l, k2l;
  uint8_t buf[8192];
  int n;

  /* composite keys: usernumeric\0mask (NUL-separated, mask may not contain NUL) */
  memcpy(k1, U, ul); k1[ul] = '\0'; memcpy(k1 + ul + 1, M1, strlen(M1));
  k1l = ul + 1 + (uint32_t)strlen(M1);
  memcpy(k2, U, ul); k2[ul] = '\0'; memcpy(k2 + ul + 1, M2, strlen(M2));
  k2l = ul + 1 + (uint32_t)strlen(M2);

  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* +silence on s1 -> delta sync -> s2 has it */
  crdt_silence_add(&s1, U, M1);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_orset_contains(&s2.silences, k1, k1l));
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* a second mask for the same user coexists (OR-Set, distinct keys) */
  crdt_silence_add(&s1, U, M2);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_orset_contains(&s2.silences, k2, k2l));
  assert_int_equal(1, crdt_orset_contains(&s2.silences, k1, k1l));

  /* -silence M1 -> delta sync -> s2 removes M1, keeps M2 */
  crdt_silence_remove(&s1, U, M1, CRDT_PRIORITY_USER);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(0, crdt_orset_contains(&s2.silences, k1, k1l));
  assert_int_equal(1, crdt_orset_contains(&s2.silences, k2, k2l));
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* snapshot roundtrip (CR-F cold join) preserves the surviving silence */
  crdt_state_init(&s3, 3);
  n = crdt_snapshot_encode(&s1, buf, sizeof buf);
  assert_true(n > 0);
  assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
  assert_int_equal(1, crdt_orset_contains(&s3.silences, k2, k2l));
  assert_int_equal(0, crdt_orset_contains(&s3.silences, k1, k1l));
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s3));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
  crdt_state_clear(&s3);
}

/* F2-a: read-marker MAX-register — delta replicates, multi-writer advance converges,
 * the merge keeps the MAX timestamp and NEVER regresses (a lower value set later, or
 * carried by a snapshot, must not overwrite a higher one — the regression guard that
 * is the whole reason for a comparator register vs plain HLC-LWW), digest converges. */
static void test_marker_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2, s3;
  char key[32], got[64];
  uint32_t klen;
  uint8_t buf[8192];
  int n;
  /* key = account\0target (opaque composite, NUL-separated); values are fixed-width
   * "seconds.milliseconds" strings (lexical compare == numeric for equal width). */
  memcpy(key, "alice", 5); key[5] = '\0'; memcpy(key + 6, "#chan", 5);
  klen = 5 + 1 + 5;

  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* set on s1 -> delta -> s2 */
  crdt_marker_set(&s1, key, klen, "1719630000.100");
  crdt_state_sync(&s2, &s1);
  assert_true(crdt_marker_get(&s2, key, klen, got, sizeof got) > 0);
  assert_string_equal("1719630000.100", got);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* multi-writer: advance on s2 -> delta -> s1 converges up */
  crdt_marker_set(&s2, key, klen, "1719630000.200");
  crdt_state_sync(&s1, &s2);
  assert_true(crdt_marker_get(&s1, key, klen, got, sizeof got) > 0);
  assert_string_equal("1719630000.200", got);

  /* ★ MAX guard: a LOWER value set LATER must NOT regress the marker */
  crdt_marker_set(&s1, key, klen, "1719630000.150");   /* < .200 -> local no-op */
  crdt_marker_get(&s1, key, klen, got, sizeof got);
  assert_string_equal("1719630000.200", got);
  crdt_state_sync(&s2, &s1);
  crdt_marker_get(&s2, key, klen, got, sizeof got);
  assert_string_equal("1719630000.200", got);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* snapshot roundtrip: a snapshot carrying a LOWER marker (.200) must NOT regress a
   * higher local one (.300) — guards the lexical-max snapshot special-case vs lww_set */
  crdt_state_init(&s3, 3);
  crdt_marker_set(&s3, key, klen, "1719630000.300");
  n = crdt_snapshot_encode(&s1, buf, sizeof buf);   /* s1 holds .200 */
  assert_true(n > 0);
  assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
  crdt_marker_get(&s3, key, klen, got, sizeof got);
  assert_string_equal("1719630000.300", got);

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
  crdt_state_clear(&s3);
}

/* ================================================================== */
/* Global-state track: a G-line set/update/delete replicates via DELTA and the
 * record round-trips with field fidelity; digests converge each step; the
 * collection survives a snapshot roundtrip (the CR-F cold-join path). */
static void test_gline_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  const char *M = "*!*@*.evil.example";
  struct CrdtGlineRecord rec;
  const struct CrdtLWWValue *v;
  uint32_t ml = (uint32_t)strlen(M);
  uint8_t buf[8192];
  int n;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  memset(&rec, 0, sizeof rec);
  rec.expire = 1000; rec.lastmod = 500; rec.lifetime = 9999; rec.flags = 1; rec.bits = 24;
  strcpy(rec.reason, "spam");
  crdt_gline_set(&s1, M, &rec);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.glines, M, ml);
  assert_non_null(v);
  assert_non_null(v->data);
  assert_int_equal((int)sizeof(struct CrdtGlineRecord), (int)v->data_len);
  assert_int_equal(1000, (int)((const struct CrdtGlineRecord *)v->data)->expire);
  assert_int_equal(24,   ((const struct CrdtGlineRecord *)v->data)->bits);
  assert_string_equal("spam", ((const struct CrdtGlineRecord *)v->data)->reason);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  /* step 3 removal gate: a PRESENT gline is not "explicitly removed" on either replica */
  assert_int_equal(0, crdt_gline_is_explicitly_removed(&s1, M));
  assert_int_equal(0, crdt_gline_is_explicitly_removed(&s2, M));

  /* update (newer ts) replicates + wins */
  rec.expire = 2000; strcpy(rec.reason, "spam-updated");
  crdt_gline_set(&s1, M, &rec);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.glines, M, ml);
  assert_non_null(v); assert_non_null(v->data);
  assert_int_equal(2000, (int)((const struct CrdtGlineRecord *)v->data)->expire);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* snapshot roundtrip preserves the gline (pins the snap_put_lww serialize line) */
  {
    struct CrdtNetworkState s3;
    crdt_state_init(&s3, 3);
    n = crdt_snapshot_encode(&s1, buf, sizeof buf);
    assert_true(n > 0);
    assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
    v = crdt_lwwmap_get(&s3.glines, M, ml);
    assert_non_null(v); assert_non_null(v->data);
    assert_int_equal(2000, (int)((const struct CrdtGlineRecord *)v->data)->expire);
    crdt_state_clear(&s3);
  }

  /* delete (tombstone) replicates -> gone, digests still converge */
  crdt_gline_del(&s1, M);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.glines, M, ml);
  assert_true(v == NULL || v->data == NULL);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  /* step 3 removal gate: the tombstone makes the mask "explicitly removed" on BOTH
   * replicas (the doc->live remove driver gates on this, never on mere absence) */
  assert_int_equal(1, crdt_gline_is_explicitly_removed(&s1, M));
  assert_int_equal(1, crdt_gline_is_explicitly_removed(&s2, M));
  /* a mask that was NEVER set is absent, NOT explicitly removed (sync-lag safety) */
  assert_int_equal(0, crdt_gline_is_explicitly_removed(&s2, "*!*@never.set.example"));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */
/* Tier C F2-b: account metadata as a plain HLC-LWW doc collection keyed by the
 * opaque account\0key composite (variable-length blob value). SET replicates via
 * DELTA + round-trips byte-exact; a newer-HLC SET wins (last-write-wins, NOT a
 * max-register like markers); DELETE tombstones + flips the explicit-removal gate
 * (the doc->store remove driver gates on it, never on mere absence); a snapshot
 * round-trip preserves a present entry and a tombstone (the CR-F cold-join path). */
static void test_metadata_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2, s3;
  char key[96];
  const struct CrdtLWWValue *v;
  uint32_t klen;
  uint8_t buf[8192];
  int n;
  /* key = account\0metakey (opaque composite, NUL-separated — metadata keys are
   * validated to [a-z0-9_./-] so the only NUL is our separator). */
  memcpy(key, "alice", 5); key[5] = '\0'; memcpy(key + 6, "avatar", 6);
  klen = 5 + 1 + 6;

  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* set on s1 -> delta -> s2; value blob round-trips byte-exact */
  crdt_metadata_set(&s1, key, klen, "https://x/a.png", 15);
  crdt_state_sync(&s2, &s1);
  v = crdt_metadata_get(&s2, key, klen);
  assert_non_null(v); assert_non_null(v->data);
  assert_int_equal(15, (int)v->data_len);
  assert_memory_equal("https://x/a.png", v->data, 15);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(0, crdt_metadata_is_explicitly_removed(&s1, key, klen));
  assert_int_equal(0, crdt_metadata_is_explicitly_removed(&s2, key, klen));

  /* update (newer HLC) wins — plain LWW, no max/lexical constraint */
  crdt_metadata_set(&s1, key, klen, "v2", 2);
  crdt_state_sync(&s2, &s1);
  v = crdt_metadata_get(&s2, key, klen);
  assert_non_null(v); assert_non_null(v->data);
  assert_int_equal(2, (int)v->data_len);
  assert_memory_equal("v2", v->data, 2);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* snapshot roundtrip preserves a present entry (pins the snap_put_lww line) */
  crdt_state_init(&s3, 3);
  n = crdt_snapshot_encode(&s1, buf, sizeof buf);
  assert_true(n > 0);
  assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
  v = crdt_metadata_get(&s3, key, klen);
  assert_non_null(v); assert_non_null(v->data);
  assert_int_equal(2, (int)v->data_len);
  assert_memory_equal("v2", v->data, 2);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s3));

  /* delete (tombstone) replicates -> gone; explicit-removal gate flips on BOTH */
  crdt_metadata_del(&s1, key, klen);
  crdt_state_sync(&s2, &s1);
  v = crdt_metadata_get(&s2, key, klen);
  assert_true(v == NULL || v->data == NULL);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(1, crdt_metadata_is_explicitly_removed(&s1, key, klen));
  assert_int_equal(1, crdt_metadata_is_explicitly_removed(&s2, key, klen));
  /* a key NEVER set is absent, NOT explicitly removed (sync-lag safety) */
  {
    char nk[16]; memcpy(nk, "bob", 3); nk[3] = '\0'; memcpy(nk + 4, "x", 1);
    assert_int_equal(0, crdt_metadata_is_explicitly_removed(&s2, nk, 3 + 1 + 1));
  }

  /* snapshot carrying the tombstone reconstructs it as explicitly-removed on a
   * fresh replica (backfill-on-link: the leaf learns the CLEAR via snapshot) */
  {
    struct CrdtNetworkState s4;
    crdt_state_init(&s4, 4);
    n = crdt_snapshot_encode(&s1, buf, sizeof buf);
    assert_true(n > 0);
    assert_true(crdt_snapshot_apply(&s4, buf, (size_t)n) >= 0);
    assert_int_equal(1, crdt_metadata_is_explicitly_removed(&s4, key, klen));
    crdt_state_clear(&s4);
  }

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
  crdt_state_clear(&s3);
}

/* 5-5e M2: bouncer-session doc collection (account\0sessid -> CrdtBouncerSession LWW):
 * field-by-field pack round-trips, replicates via delta, digest converges, update wins,
 * the explicit-removal gate distinguishes delete-tombstone from absent, and a snapshot
 * round-trip preserves it (pins the snap_put_lww + embedded-NUL key path). */
static void test_bsess_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  const char *ACC = "alice", *SID = "AZ7cJWoJ-uuid-v7-22ch";
  struct CrdtBouncerSession rec;
  const struct CrdtBouncerSession *g;
  uint8_t buf[8192];
  int n;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* Layout pin (M6b-2 BS O): catch an accidental interior hole / wrong pad
   * when fields are added — the digest hashes the whole record incl. pad, so
   * the size must stay a stable 8-byte multiple (memset-before-fill keeps the
   * pad deterministic across replicas). */
  assert_int_equal(192, (int)sizeof(struct CrdtBouncerSession));

  memset(&rec, 0, sizeof rec);
  rec.state = 1 /* BOUNCE_HOLDING */; rec.hold_override = 1;
  rec.created = 1000; rec.last_active = 1500; rec.total_active = 42;
  rec.attach_count = 3; rec.connect_count = 7;
  strcpy(rec.name, "laptop");
  strcpy(rec.token, "tok-abc-123");
  strcpy(rec.oper_name, "shmoo");          /* M6b-2 BS O: doc-native oper grant */
  rec.oper_granted_at = 1234567;
  crdt_bsess_set(&s1, ACC, SID, &rec);
  crdt_state_sync(&s2, &s1);

  g = crdt_bsess_get(&s2, ACC, SID);
  assert_non_null(g);
  assert_int_equal(1, g->state);
  assert_int_equal(1, g->hold_override);
  assert_int_equal(1000, (int)g->created);
  assert_int_equal(3, (int)g->attach_count);
  assert_int_equal(7, (int)g->connect_count);
  assert_string_equal("laptop", g->name);
  assert_string_equal("tok-abc-123", g->token);
  assert_string_equal("shmoo", g->oper_name);
  assert_int_equal(1234567, (int)g->oper_granted_at);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  /* present -> not "explicitly removed" on either replica */
  assert_int_equal(0, crdt_bsess_is_explicitly_removed(&s1, ACC, SID));
  assert_int_equal(0, crdt_bsess_is_explicitly_removed(&s2, ACC, SID));
  /* a sessid never set is absent, NOT explicitly removed (sync-lag safety) */
  assert_int_equal(0, crdt_bsess_is_explicitly_removed(&s2, ACC, "never-existed"));

  /* update (newer ts) replicates + wins */
  rec.state = 0 /* ACTIVE */; rec.attach_count = 4; strcpy(rec.name, "phone");
  crdt_bsess_set(&s1, ACC, SID, &rec);
  crdt_state_sync(&s2, &s1);
  g = crdt_bsess_get(&s2, ACC, SID);
  assert_non_null(g);
  assert_int_equal(0, g->state);
  assert_int_equal(4, (int)g->attach_count);
  assert_string_equal("phone", g->name);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* snapshot roundtrip preserves the session (embedded-NUL key survives) */
  {
    struct CrdtNetworkState s3;
    crdt_state_init(&s3, 3);
    n = crdt_snapshot_encode(&s1, buf, sizeof buf);
    assert_true(n > 0);
    assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
    g = crdt_bsess_get(&s3, ACC, SID);
    assert_non_null(g);
    assert_int_equal(4, (int)g->attach_count);
    assert_string_equal("phone", g->name);
    crdt_state_clear(&s3);
  }

  /* delete-tombstone: explicit-removal gate flips, absent stays absent */
  crdt_bsess_del(&s1, ACC, SID);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_bsess_is_explicitly_removed(&s2, ACC, SID));
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* 5-5e M3: crdt_bsess_winner derives the cross-sessid election winner (strcmp-lowest
 * sessid among an account's LIVE records) — must match the live election + exclude a
 * tombstoned (collapsed) loser, scoped per-account. */
static void test_bsess_winner(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtBouncerSession rec;
  char w[64];
  crdt_state_init(&s, 1);
  memset(&rec, 0, sizeof rec);
  /* account "alice": two sessids, strcmp-min "Axxx" wins over "Bxxx" */
  crdt_bsess_set(&s, "alice", "Bxxx", &rec);
  crdt_bsess_set(&s, "alice", "Axxx", &rec);
  crdt_bsess_set(&s, "bob",   "Czzz", &rec);   /* different account, must be ignored */

  assert_non_null(crdt_bsess_winner(&s, "alice", w, sizeof w));
  assert_string_equal("Axxx", w);              /* lex-min == the strcmp(<0) election */
  assert_non_null(crdt_bsess_winner(&s, "bob", w, sizeof w));
  assert_string_equal("Czzz", w);              /* per-account scoping */
  assert_null(crdt_bsess_winner(&s, "nobody", w, sizeof w));

  /* tombstone the winner -> the next-lowest LIVE sessid wins (collapsed loser excluded) */
  crdt_bsess_del(&s, "alice", "Axxx");
  assert_non_null(crdt_bsess_winner(&s, "alice", w, sizeof w));
  assert_string_equal("Bxxx", w);
  /* tombstone the last one -> no live session -> NULL */
  crdt_bsess_del(&s, "alice", "Bxxx");
  assert_null(crdt_bsess_winner(&s, "alice", w, sizeof w));

  crdt_state_clear(&s);
}

/* 5-5e M4: per-connection bconns collection + roster count. Connections (primary +
 * aliases) replicate via delta, the roster = live entries per (account,sessid), a
 * removed connection drops the roster + flips the tombstone gate, digest converges. */
static void test_bconn_roster(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  struct CrdtBouncerConn rec;
  const struct CrdtBouncerConn *g;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  memset(&rec, 0, sizeof rec);
  rec.host = 1; rec.is_primary = 1; rec.caps = 0x5; rec.caps_known = 1;
  crdt_bconn_set(&s1, "alice", "S1", "AAAAA", &rec);   /* primary */
  rec.host = 2; rec.is_primary = 0; rec.caps = 0; rec.caps_known = 0;
  crdt_bconn_set(&s1, "alice", "S1", "BBBBB", &rec);   /* alias */
  crdt_bconn_set(&s1, "bob",   "S9", "CCCCC", &rec);   /* other account/session */
  crdt_state_sync(&s2, &s1);

  assert_int_equal(2, crdt_bconn_roster_count(&s2, "alice", "S1"));
  assert_int_equal(1, crdt_bconn_roster_count(&s2, "bob", "S9"));
  assert_int_equal(0, crdt_bconn_roster_count(&s2, "alice", "S2"));   /* no such session */
  g = crdt_bconn_get(&s2, "alice", "S1", "AAAAA");
  assert_non_null(g);
  assert_int_equal(1, g->is_primary);
  assert_int_equal(5, (int)g->caps);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* M6a-2: the primary connnum is derivable from the roster (is_primary entry) */
  {
    char pn[16];
    assert_non_null(crdt_bconn_primary(&s2, "alice", "S1", pn, sizeof pn));
    assert_string_equal("AAAAA", pn);             /* the is_primary=1 entry */
    assert_null(crdt_bconn_primary(&s2, "bob", "S9", pn, sizeof pn)); /* all aliases -> none */
  }

  /* alias disconnects -> roster drops to 1, tombstone gate flips, primary unaffected */
  crdt_bconn_del(&s1, "alice", "S1", "BBBBB");
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_bconn_roster_count(&s2, "alice", "S1"));
  assert_int_equal(1, crdt_bconn_is_explicitly_removed(&s2, "alice", "S1", "BBBBB"));
  assert_int_equal(0, crdt_bconn_is_explicitly_removed(&s2, "alice", "S1", "AAAAA"));
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* 5-5e M5: the liveness-lease comparator (PURE) — the riskiest single piece of logic.
 * Total order: higher generation wins; tie -> lower host numeric. Antisymmetric; identical
 * authority -> 0 (so the register merge no-ops on a re-affirm = idempotent). */
static void test_blease_compare(void **state)
{
  (void)state;
  struct CrdtBouncerLease a, b;
  memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);

  /* higher generation wins regardless of host */
  a.host = 9; a.generation = 2;
  b.host = 1; b.generation = 1;
  assert_true(crdt_blease_compare(&a, &b) > 0);
  assert_true(crdt_blease_compare(&b, &a) < 0);   /* antisymmetric */

  /* same generation -> LOWER host numeric wins (symmetric-dual-revive collapse) */
  a.host = 7; a.generation = 5;
  b.host = 3; b.generation = 5;
  assert_true(crdt_blease_compare(&a, &b) < 0);    /* host 7 loses to host 3 */
  assert_true(crdt_blease_compare(&b, &a) > 0);

  /* identical authority (host+gen) -> 0, even if claim_ms differs (not consulted) */
  a.host = 4; a.generation = 8; a.claim_ms = 1000;
  b.host = 4; b.generation = 8; b.claim_ms = 9999;
  assert_int_equal(0, crdt_blease_compare(&a, &b));
}

/* 5-5e M5: the beacon-gated claim DECISION (PURE) truth table:
 *   no lease            -> claim gen 0
 *   I already hold       -> re-affirm my generation (idempotent)
 *   other holds, FRESH   -> stand down (-1)
 *   other holds, STALE   -> revive at generation+1 (supersede) */
static void test_blease_decide(void **state)
{
  (void)state;
  struct CrdtBouncerLease cur;
  memset(&cur, 0, sizeof cur);

  assert_int_equal(0, (int)crdt_blease_decide(NULL, 0, 5));   /* fresh session */

  cur.host = 5; cur.generation = 3;
  assert_int_equal(3, (int)crdt_blease_decide(&cur, 1, 5));   /* my own claim -> re-affirm */
  assert_int_equal(3, (int)crdt_blease_decide(&cur, 0, 5));   /* (freshness irrelevant when mine) */

  cur.host = 9; cur.generation = 3;
  assert_int_equal(-1, (int)crdt_blease_decide(&cur, 1, 5));  /* other fresh -> stand down */
  assert_int_equal(4, (int)crdt_blease_decide(&cur, 0, 5));   /* other stale -> revive gen+1 */
}

/* 5-5e M6d: the authoritative lease ACTION truth table — NOOP / REVIVE_LOCAL / DEMOTE_TO_ALIAS.
 * Args: (lease, me, holder_beacon_fresh, have_local_primary, want_revive). */
static void test_blease_action(void **state)
{
  (void)state;
  struct CrdtBouncerLease cur;
  memset(&cur, 0, sizeof cur);

  /* no lease -> always NOOP (the claim path owns a fresh session) */
  assert_int_equal(CRDT_BLEASE_NOOP, crdt_blease_action(NULL, 5, 0, 1, 1));

  /* lease held by me -> NOOP regardless of the rest */
  cur.host = 5; cur.generation = 2;
  assert_int_equal(CRDT_BLEASE_NOOP, crdt_blease_action(&cur, 5, 1, 1, 1));
  assert_int_equal(CRDT_BLEASE_NOOP, crdt_blease_action(&cur, 5, 0, 1, 1));

  /* another holder, beacon FRESH (live elsewhere) */
  cur.host = 9;
  assert_int_equal(CRDT_BLEASE_DEMOTE_TO_ALIAS,            /* my live primary is the loser */
                   crdt_blease_action(&cur, 5, 1, 1, 0));
  assert_int_equal(CRDT_BLEASE_NOOP,                       /* bare replica: nothing to do */
                   crdt_blease_action(&cur, 5, 1, 0, 0));
  assert_int_equal(CRDT_BLEASE_NOOP,                       /* fresh holder beats want_revive */
                   crdt_blease_action(&cur, 5, 1, 0, 1));
  assert_int_equal(CRDT_BLEASE_DEMOTE_TO_ALIAS,            /* fresh holder: still demote, never revive */
                   crdt_blease_action(&cur, 5, 1, 1, 1));

  /* another holder, beacon STALE (split-away / dead) */
  assert_int_equal(CRDT_BLEASE_REVIVE_LOCAL,              /* revive site takes over */
                   crdt_blease_action(&cur, 5, 0, 0, 1));
  assert_int_equal(CRDT_BLEASE_REVIVE_LOCAL,
                   crdt_blease_action(&cur, 5, 0, 1, 1));
  assert_int_equal(CRDT_BLEASE_NOOP,                      /* not a revive site: claim supersedes */
                   crdt_blease_action(&cur, 5, 0, 1, 0));
  assert_int_equal(CRDT_BLEASE_NOOP,
                   crdt_blease_action(&cur, 5, 0, 0, 0));
}

/* 5-5e M5: the lease register converges to the comparator-winner regardless of order, the
 * revive (gen+1) supersedes a stale predecessor on heal, re-apply is idempotent, the
 * value-only digest agrees, and a tombstone is never resurrected. */
static void test_blease_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  const char *ACC = "alice", *SID = "AZ7cJWoJ-uuid-v7-22ch";
  const struct CrdtBouncerLease *g;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* node 1 is the original holder (gen 0) */
  crdt_blease_claim(&s1, ACC, SID, 1, 0, 1000);
  crdt_state_sync(&s2, &s1);
  g = crdt_blease_get(&s2, ACC, SID);
  assert_non_null(g);
  assert_int_equal(1, g->host);
  assert_int_equal(0, (int)g->generation);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* re-affirm on the holder is a no-op (no op storm) -> still converged, no change */
  crdt_blease_claim(&s1, ACC, SID, 1, 0, 2000);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_blease_get(&s2, ACC, SID)->host);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* PARTITION + REVIVE: node 2 sees node-1 stale, revives at gen+1 (decide -> 1) */
  {
    const struct CrdtBouncerLease *cur = crdt_blease_get(&s2, ACC, SID);
    long gen = crdt_blease_decide(cur, 0 /*node1 beacon STALE*/, 2);
    assert_int_equal(1, (int)gen);
    crdt_blease_claim(&s2, ACC, SID, 2, (uint32_t)gen, 3000);
  }
  /* HEAL: exchange both ways -> both converge to host=2 gen=1 (the reviver supersedes) */
  crdt_state_sync(&s1, &s2);
  crdt_state_sync(&s2, &s1);
  g = crdt_blease_get(&s1, ACC, SID);
  assert_non_null(g);
  assert_int_equal(2, g->host);
  assert_int_equal(1, (int)g->generation);
  assert_int_equal(2, crdt_blease_get(&s2, ACC, SID)->host);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* node-1 (the OLD holder) on return decides to stand down (other fresh, higher gen) */
  assert_int_equal(-1, (int)crdt_blease_decide(crdt_blease_get(&s1, ACC, SID), 1, 1));

  /* idempotent: re-syncing applies nothing new, digest stable */
  crdt_state_sync(&s1, &s2);
  assert_int_equal(2, crdt_blease_get(&s1, ACC, SID)->host);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* destroy -> tombstone; a stale lower-gen re-delivery must NOT resurrect it */
  crdt_blease_del(&s1, ACC, SID);
  crdt_state_sync(&s2, &s1);
  assert_null(crdt_blease_get(&s2, ACC, SID));
  {
    struct CrdtNetworkState s3;          /* a node that still has the old gen-0 claim */
    crdt_state_init(&s3, 3);
    crdt_blease_claim(&s3, ACC, SID, 3, 0, 500);
    crdt_state_sync(&s2, &s3);            /* deliver the stale claim to the tombstoned node */
    assert_null(crdt_blease_get(&s2, ACC, SID));   /* tombstone holds (single-use sessid) */
    crdt_state_clear(&s3);
  }

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* 5-5e M5: order-independence + symmetric dual-revive. Two nodes both revive the SAME
 * session at gen 1 during a mesh split (hosts 4 and 6); on heal the merge collapses to the
 * LOWER host (4) on EVERY replica, regardless of which claim each saw first. */
static void test_blease_symmetric_dual_revive(void **state)
{
  (void)state;
  struct CrdtNetworkState s4, s6, obs;
  const char *ACC = "bob", *SID = "S-dual";
  crdt_state_init(&s4, 4);
  crdt_state_init(&s6, 6);
  crdt_state_init(&obs, 9);

  /* both independently revive at gen 1 (each saw the original gen-0 holder go stale) */
  crdt_blease_claim(&s4, ACC, SID, 4, 1, 100);
  crdt_blease_claim(&s6, ACC, SID, 6, 1, 100);

  /* observer sees host 6 FIRST, then host 4 -> must still end on host 4 (lower wins) */
  crdt_state_sync(&obs, &s6);
  assert_int_equal(6, crdt_blease_get(&obs, ACC, SID)->host);
  crdt_state_sync(&obs, &s4);
  assert_int_equal(4, crdt_blease_get(&obs, ACC, SID)->host);   /* comparator-max */

  /* the reverse arrival order on s4/s6 themselves converges identically */
  crdt_state_sync(&s4, &s6);   /* s4 sees host-6 claim -> 6 loses to its own 4 */
  crdt_state_sync(&s6, &s4);   /* s6 sees host-4 claim -> supersedes its own 6 */
  assert_int_equal(4, crdt_blease_get(&s4, ACC, SID)->host);
  assert_int_equal(4, crdt_blease_get(&s6, ACC, SID)->host);
  assert_true(crdt_state_digest(&s4) == crdt_state_digest(&s6));
  assert_true(crdt_state_digest(&s4) == crdt_state_digest(&obs));

  crdt_state_clear(&s4);
  crdt_state_clear(&s6);
  crdt_state_clear(&obs);
}

/* SHUN doc collection (global-state track sibling of GLINE): set/update/delete via
 * delta + digest converge + snapshot roundtrip + the explicit-removal gate. */
static void test_shun_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  const char *M = "*!*@*.silence.example";
  struct CrdtShunRecord rec;
  const struct CrdtLWWValue *v;
  uint32_t ml = (uint32_t)strlen(M);
  uint8_t buf[8192];
  int n;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  memset(&rec, 0, sizeof rec);
  rec.expire = 1000; rec.lastmod = 500; rec.lifetime = 9999; rec.flags = 1; rec.bits = 24;
  strcpy(rec.reason, "noise");
  crdt_shun_set(&s1, M, &rec);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.shuns, M, ml);
  assert_non_null(v);
  assert_non_null(v->data);
  assert_int_equal((int)sizeof(struct CrdtShunRecord), (int)v->data_len);
  assert_int_equal(1000, (int)((const struct CrdtShunRecord *)v->data)->expire);
  assert_string_equal("noise", ((const struct CrdtShunRecord *)v->data)->reason);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(0, crdt_shun_is_explicitly_removed(&s1, M));
  assert_int_equal(0, crdt_shun_is_explicitly_removed(&s2, M));

  /* update (newer ts) replicates + wins */
  rec.expire = 2000; strcpy(rec.reason, "noise-updated");
  crdt_shun_set(&s1, M, &rec);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.shuns, M, ml);
  assert_non_null(v); assert_non_null(v->data);
  assert_int_equal(2000, (int)((const struct CrdtShunRecord *)v->data)->expire);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* snapshot roundtrip (pins the snap_put_lww shuns serialize line) */
  {
    struct CrdtNetworkState s3;
    crdt_state_init(&s3, 3);
    n = crdt_snapshot_encode(&s1, buf, sizeof buf);
    assert_true(n > 0);
    assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
    v = crdt_lwwmap_get(&s3.shuns, M, ml);
    assert_non_null(v); assert_non_null(v->data);
    assert_int_equal(2000, (int)((const struct CrdtShunRecord *)v->data)->expire);
    crdt_state_clear(&s3);
  }

  /* delete (tombstone) replicates -> gone + explicit-removal gate */
  crdt_shun_del(&s1, M);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.shuns, M, ml);
  assert_true(v == NULL || v->data == NULL);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(1, crdt_shun_is_explicitly_removed(&s1, M));
  assert_int_equal(1, crdt_shun_is_explicitly_removed(&s2, M));
  assert_int_equal(0, crdt_shun_is_explicitly_removed(&s2, "*!*@never.set.example"));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ZLINE doc collection (global-state track, single IP mask): set/update/delete via
 * delta + digest converge + snapshot roundtrip + the explicit-removal gate. */
static void test_zline_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  const char *M = "203.0.113.0/24";
  struct CrdtZlineRecord rec;
  const struct CrdtLWWValue *v;
  uint32_t ml = (uint32_t)strlen(M);
  uint8_t buf[8192];
  int n;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  memset(&rec, 0, sizeof rec);
  rec.expire = 1000; rec.lastmod = 500; rec.lifetime = 9999; rec.flags = 3; rec.bits = 24;
  strcpy(rec.reason, "drone");
  crdt_zline_set(&s1, M, &rec);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.zlines, M, ml);
  assert_non_null(v);
  assert_non_null(v->data);
  assert_int_equal((int)sizeof(struct CrdtZlineRecord), (int)v->data_len);
  assert_int_equal(1000, (int)((const struct CrdtZlineRecord *)v->data)->expire);
  assert_string_equal("drone", ((const struct CrdtZlineRecord *)v->data)->reason);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(0, crdt_zline_is_explicitly_removed(&s1, M));

  /* update (newer ts) replicates + wins */
  rec.expire = 2000; strcpy(rec.reason, "drone-updated");
  crdt_zline_set(&s1, M, &rec);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.zlines, M, ml);
  assert_non_null(v); assert_non_null(v->data);
  assert_int_equal(2000, (int)((const struct CrdtZlineRecord *)v->data)->expire);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* snapshot roundtrip (pins the snap_put_lww zlines serialize line) */
  {
    struct CrdtNetworkState s3;
    crdt_state_init(&s3, 3);
    n = crdt_snapshot_encode(&s1, buf, sizeof buf);
    assert_true(n > 0);
    assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
    v = crdt_lwwmap_get(&s3.zlines, M, ml);
    assert_non_null(v); assert_non_null(v->data);
    assert_int_equal(2000, (int)((const struct CrdtZlineRecord *)v->data)->expire);
    crdt_state_clear(&s3);
  }

  /* delete (tombstone) replicates -> gone + explicit-removal gate */
  crdt_zline_del(&s1, M);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.zlines, M, ml);
  assert_true(v == NULL || v->data == NULL);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(1, crdt_zline_is_explicitly_removed(&s1, M));
  assert_int_equal(1, crdt_zline_is_explicitly_removed(&s2, M));
  assert_int_equal(0, crdt_zline_is_explicitly_removed(&s2, "198.51.100.0/24"));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* JUPE doc collection (global-state track, server-name key, no lifetime/addr): set/
 * update/delete via delta + digest converge + snapshot roundtrip + removal gate. */
static void test_jupe_op_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  const char *M = "evil.example.net";
  struct CrdtJupeRecord rec;
  const struct CrdtLWWValue *v;
  uint32_t ml = (uint32_t)strlen(M);
  uint8_t buf[8192];
  int n;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  memset(&rec, 0, sizeof rec);
  rec.expire = 1000; rec.lastmod = 500; rec.flags = 1;
  strcpy(rec.reason, "rogue");
  crdt_jupe_set(&s1, M, &rec);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.jupes, M, ml);
  assert_non_null(v);
  assert_non_null(v->data);
  assert_int_equal((int)sizeof(struct CrdtJupeRecord), (int)v->data_len);
  assert_int_equal(1000, (int)((const struct CrdtJupeRecord *)v->data)->expire);
  assert_string_equal("rogue", ((const struct CrdtJupeRecord *)v->data)->reason);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(0, crdt_jupe_is_explicitly_removed(&s1, M));

  /* update (newer ts) replicates + wins */
  rec.expire = 2000; strcpy(rec.reason, "rogue-updated");
  crdt_jupe_set(&s1, M, &rec);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.jupes, M, ml);
  assert_non_null(v); assert_non_null(v->data);
  assert_int_equal(2000, (int)((const struct CrdtJupeRecord *)v->data)->expire);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  /* snapshot roundtrip (pins the snap_put_lww jupes serialize line) */
  {
    struct CrdtNetworkState s3;
    crdt_state_init(&s3, 3);
    n = crdt_snapshot_encode(&s1, buf, sizeof buf);
    assert_true(n > 0);
    assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
    v = crdt_lwwmap_get(&s3.jupes, M, ml);
    assert_non_null(v); assert_non_null(v->data);
    assert_int_equal(2000, (int)((const struct CrdtJupeRecord *)v->data)->expire);
    crdt_state_clear(&s3);
  }

  /* delete (tombstone) replicates -> gone + explicit-removal gate */
  crdt_jupe_del(&s1, M);
  crdt_state_sync(&s2, &s1);
  v = crdt_lwwmap_get(&s2.jupes, M, ml);
  assert_true(v == NULL || v->data == NULL);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(1, crdt_jupe_is_explicitly_removed(&s1, M));
  assert_int_equal(1, crdt_jupe_is_explicitly_removed(&s2, M));
  assert_int_equal(0, crdt_jupe_is_explicitly_removed(&s2, "other.example.net"));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */
/* Phase 3j: per-channel creationtime is an incarnation MIN-register.
 * Concurrent creates converge to the LOWER TS (IRC lower-TS-wins, the safe
 * direction); a destroy (clear, a LOCAL incarnation bump) + recreate to a
 * HIGHER TS is NOT resurrected to the stale lower value — the set-op carries
 * its del_hlc so the boundary rides to every peer. Also covers the snapshot
 * roundtrip of the register. */
static void test_chan_ctime_min_incarnation(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[8192];
  int n;

  /* --- concurrent create: s1=400, s2=407, both incarnation-0 -> min wins --- */
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  crdt_chan_ctime_set(&s1, "#c", 400);
  crdt_chan_ctime_set(&s2, "#c", 407);
  crdt_state_sync(&s1, &s2);
  crdt_state_sync(&s2, &s1);
  assert_int_equal(400, (int)crdt_chan_ctime_get(&s1, "#c"));  /* not 407 (LWW would pick 407) */
  assert_int_equal(400, (int)crdt_chan_ctime_get(&s2, "#c"));
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);

  /* --- destroy + recreate to a HIGHER TS: no resurrection to 400 --- */
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  crdt_chan_ctime_set(&s1, "#c", 400);          /* incarnation 1 */
  crdt_state_sync(&s2, &s1);
  assert_int_equal(400, (int)crdt_chan_ctime_get(&s2, "#c"));
  crdt_chan_ctime_clear(&s1, "#c");             /* destroy (local incarnation bump) */
  assert_int_equal(0, (int)crdt_chan_ctime_get(&s1, "#c"));    /* deleted -> 0 */
  crdt_chan_ctime_set(&s1, "#c", 500);          /* recreate, HIGHER TS, incarnation 2 */
  crdt_state_sync(&s2, &s1);                     /* the set-op carries del_hlc */
  assert_int_equal(500, (int)crdt_chan_ctime_get(&s1, "#c"));
  assert_int_equal(500, (int)crdt_chan_ctime_get(&s2, "#c"));  /* NOT 400 */

  /* --- snapshot roundtrip preserves the register --- */
  {
    struct CrdtNetworkState s3;
    crdt_state_init(&s3, 3);
    n = crdt_snapshot_encode(&s1, buf, sizeof buf);
    assert_true(n > 0);
    assert_true(crdt_snapshot_apply(&s3, buf, (size_t)n) >= 0);
    assert_int_equal(500, (int)crdt_chan_ctime_get(&s3, "#c"));
    crdt_state_clear(&s3);
  }
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */
/* Phase 3k: kick_info LWW replicates via DELTA, and its HLC gates KICK-vs-PART.
 * A member kicked (kick_info written AFTER the join's members_status) -> kick_info
 * is the newer write -> reconcile emits KICK. After a rejoin (members_status
 * rewritten, newer than the stale kick_info) -> reconcile emits PART. */
static void test_kick_info_replicates_and_hlc_gates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  struct CrdtKickInfo ki;
  struct CrdtMemberRecord mr;
  const struct CrdtLWWValue *kv, *mv;
  char key[16]; uint32_t klen;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  memset(&mr, 0, sizeof mr);
  memset(&ki, 0, sizeof ki);
  strcpy(ki.kicker, "AAAAA"); strcpy(ki.reason, "spam");
  memcpy(key, "#c", 2); key[2]='\0'; memcpy(key+3, "BBBBB", 5); klen = 2+1+5;

  crdt_member_status_set(&s1, "#c", "BBBBB", &mr);   /* join  (HLC j1) */
  crdt_kick_info_set(&s1, "#c", "BBBBB", &ki);       /* kick  (HLC k1 > j1) */
  crdt_state_sync(&s2, &s1);

  kv = crdt_kick_info_get(&s2, "#c", "BBBBB");       /* replicated via delta */
  assert_non_null(kv);
  assert_int_equal(0, strcmp(((const struct CrdtKickInfo*)kv->data)->kicker, "AAAAA"));
  assert_int_equal(0, strcmp(((const struct CrdtKickInfo*)kv->data)->reason, "spam"));
  mv = crdt_lwwmap_get(&s2.members_status, key, klen);
  assert_non_null(mv);
  assert_true(hlc_compare(&kv->ts, &mv->ts) > 0);    /* kick fresh -> KICK */

  /* rejoin: members_status rewritten (HLC j2 > k1) -> stale kick -> PART */
  crdt_member_status_set(&s1, "#c", "BBBBB", &mr);
  crdt_state_sync(&s2, &s1);
  kv = crdt_kick_info_get(&s2, "#c", "BBBBB");
  mv = crdt_lwwmap_get(&s2.members_status, key, klen);
  assert_true(hlc_compare(&mv->ts, &kv->ts) > 0);    /* join newer -> kick stale */

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

/* Phase 4a: the servers LWW-map is a NEW convergence surface — it is multi-writer
 * (the squitted server can't write its own state, so whichever server OBSERVES the
 * transition writes it), resolved by LWW+HLC.  Two replicas writing divergent
 * server-state concurrently MUST converge, and a later relink (causally after a
 * received SQUIT) MUST win network-wide (§17.3.5 quick-reconnect across replicas). */
static void test_server_state_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[8192];
  int n;
  struct CrdtUserRecord u = mkuser("x", 7, "id", 0x07070707u);
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* a user on server 7 exists on both (same content, each tags with own origin) */
  crdt_user_set(&s1, "U000", &u);
  crdt_user_set(&s2, "U000", &u);

  /* concurrent divergent server-state: s1 observes server 7 SPLIT, s2 ACTIVE */
  crdt_server_squit(&s1, 7);
  crdt_server_set(&s2, 7, CRDT_SRV_ACTIVE);
  assert_true(crdt_state_digest(&s1) != crdt_state_digest(&s2));

  /* exchange both ways -> LWW(servers) by HLC -> converge to ONE state */
  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s2, buf, (size_t)n);
  n = crdt_delta_encode(&s2.oplog, &s1.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s1, buf, (size_t)n);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  /* both replicas agree on the user's visibility (whichever HLC won) */
  assert_int_equal(crdt_user_visible(&s1, "U000"), crdt_user_visible(&s2, "U000"));

  /* quick-reconnect: s2 (having received s1's SQUIT, so its clock is causally
   * past it) relinks server 7 -> a strictly-later HLC -> ACTIVE wins everywhere */
  crdt_server_relink(&s2, 7);
  n = crdt_delta_encode(&s2.oplog, &s1.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s1, buf, (size_t)n);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  assert_int_equal(1, crdt_user_visible(&s1, "U000"));
  assert_int_equal(1, crdt_user_visible(&s2, "U000"));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* Phase 4a follow-up: a process restart resets next_seq to 1, but peers still
 * remember the restarted server's pre-restart state vector.  When the restarted
 * server adopts a peer snapshot (raising its local_sv to the peer's view of its
 * OLD seq), it must RESUME minting above that floor — else its post-restart ops
 * carry already-seen seqs and peers dedup them via crdt_sv_has_seen, dropping
 * them forever (a persistent post-restart divergence). */
static void test_restart_resumes_seq_past_adopted_sv(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[16384];
  int n, applied, i;
  struct CrdtUserRecord u = mkuser("a", 1, "a", 0x01010101);

  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* s1 makes 5 ops; s2 receives them -> s2.local_sv[1] = 5 */
  for (i = 0; i < 5; i++) {
    char num[CRDT_NUMERICLEN];
    snprintf(num, sizeof num, "U%03d", i);
    crdt_user_set(&s1, num, &u);
  }
  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s2, buf, (size_t)n);

  /* s1 "restarts": fresh state (next_seq back to 1), then adopts s2's snapshot
   * (whose SV carries s1's OLD seq=5). */
  crdt_state_clear(&s1);
  crdt_state_init(&s1, 1);
  n = crdt_snapshot_encode(&s2, buf, sizeof buf);
  assert_true(crdt_snapshot_apply(&s1, buf, (size_t)n) >= 0);

  /* A NEW post-restart op MUST carry a seq above s2's view of s1 (5), so s2
   * applies it instead of deduping it. */
  crdt_user_set(&s1, "NEW1", &u);
  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  applied = crdt_delta_apply(&s2, buf, (size_t)n);
  assert_true(applied >= 1);                     /* RED without crdt_state_resume_seq */
  assert_non_null(crdt_user_get(&s2, "NEW1"));
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* Phase 4c: server-state convergence in a MESH (triangle), not just the star.
 *
 * The 2-node test_server_state_converges passes because a single bidirectional
 * exchange reconciles the LWW(servers) map.  In a TRIANGLE with a redundant edge
 * (A-B, A-C P10 + B-C overlay) the live single-writer model does NOT converge:
 *
 *   1. cut A-C -> A (C's direct uplink) writes C=SPLIT; C (A's uplink) writes
 *      A=SPLIT  (crdt_shadow_server_squit, single observer-writer).
 *   2. each node self-asserts self=ACTIVE only when it SEES itself !=ACTIVE
 *      (crdt_assert_self_active) -- a heal that depends on the SPLIT-about-self
 *      reaching the originating node across the mesh.
 *   3. per-round GC against DIRECT peers reclaims the racing servers ops before
 *      the heal has propagated everywhere.
 *   4. on relink A-C exchanges a snapshot A<->C -- but B's links never dropped,
 *      so B gets NO refreshing snapshot and the reconciling ops are gone.
 *
 * Live, nef4 was left permanently stale; crdt_state_digest (which hashes LWW
 * value+HLC+writer for the servers map and is NOT GC-invariant) never reconverged.
 *
 * This test PASSES: the pure ENGINE (LWW + delta + snapshot + causal GC) DOES
 * converge a triangle partition+relink given full anti-entropy.  That is the
 * point — it localizes the live non-convergence to the WIRE/integration layer
 * (eager-relay-once + GC reclaiming reconciling ops before the heal lands +
 * relink snapshotting only the relinked peer), which the engine harness cannot
 * model.  The Phase 4c fix therefore does NOT try to make a per-viewpoint value
 * survive that wire layer: production stops writing the servers map entirely and
 * derives reachability LOCALLY (FindNServer at the materialize gate = SPLIT iff
 * unreachable via all transports).  This test is retained as the proof the engine
 * primitive is sound and a guard for any future convergent Tier-2 liveness design. */
static void tri_xchg(struct CrdtNetworkState *x, struct CrdtNetworkState *y,
                     uint8_t *buf, size_t bufsz)
{
  int n;
  n = crdt_delta_encode(&x->oplog, &y->local_sv, buf, bufsz);
  crdt_delta_apply(y, buf, (size_t)n);
  n = crdt_delta_encode(&y->oplog, &x->local_sv, buf, bufsz);
  crdt_delta_apply(x, buf, (size_t)n);
}
static void tri_self_assert(struct CrdtNetworkState *s)
{
  if (crdt_server_state(s, s->my_numeric) != CRDT_SRV_ACTIVE)
    crdt_server_set(s, s->my_numeric, CRDT_SRV_ACTIVE);
}
static void test_server_state_converges_mesh(void **state)
{
  (void)state;
  struct CrdtNetworkState A, B, C;          /* A=hub(1) B=leaf2(2) C=leaf3(3) */
  struct CrdtStateVector st;
  uint8_t buf[16384];
  int r;
  struct CrdtUserRecord ua = mkuser("a", 1, "a", 0x01010101u);
  struct CrdtUserRecord ub = mkuser("b", 2, "b", 0x02020202u);
  struct CrdtUserRecord uc = mkuser("c", 3, "c", 0x03030303u);

  crdt_state_init(&A, 1);
  crdt_state_init(&B, 2);
  crdt_state_init(&C, 3);

  /* boot: a user on each server + each asserts itself ACTIVE (peer-link trigger) */
  crdt_user_set(&A, "U001", &ua); tri_self_assert(&A);
  crdt_user_set(&B, "U002", &ub); tri_self_assert(&B);
  crdt_user_set(&C, "U003", &uc); tri_self_assert(&C);

  /* converge the full triangle (A-B, A-C, B-C) */
  for (r = 0; r < 4; r++) {
    tri_xchg(&A, &B, buf, sizeof buf);
    tri_xchg(&A, &C, buf, sizeof buf);
    tri_xchg(&B, &C, buf, sizeof buf);
  }
  assert_true(crdt_state_digest(&A) == crdt_state_digest(&B));
  assert_true(crdt_state_digest(&B) == crdt_state_digest(&C));

  /* ---- partition: cut A-C.  Live edges: A-B, B-C (a line). ---- */
  crdt_server_squit(&A, 3);   /* A: its direct downlink C is gone */
  crdt_server_squit(&C, 1);   /* C: its direct uplink A is gone   */

  for (r = 0; r < 6; r++) {
    tri_self_assert(&A); tri_self_assert(&B); tri_self_assert(&C);
    tri_xchg(&A, &B, buf, sizeof buf);
    tri_xchg(&B, &C, buf, sizeof buf);
    /* per-node GC against DIRECT peers only (as live) */
    { const struct CrdtStateVector *v[2] = { &A.local_sv, &B.local_sv };
      crdt_sv_global_min(&st, v, 2); crdt_state_gc(&A, &st); }
    { const struct CrdtStateVector *v[3] = { &B.local_sv, &A.local_sv, &C.local_sv };
      crdt_sv_global_min(&st, v, 3); crdt_state_gc(&B, &st); }
    { const struct CrdtStateVector *v[2] = { &C.local_sv, &B.local_sv };
      crdt_sv_global_min(&st, v, 2); crdt_state_gc(&C, &st); }
  }

  /* ---- relink A-C: snapshot exchange A<->C only (B's links never dropped) ---- */
  { int n = crdt_snapshot_encode(&A, buf, sizeof buf);
    assert_true(crdt_snapshot_apply(&C, buf, (size_t)n) >= 0);
    n = crdt_snapshot_encode(&C, buf, sizeof buf);
    assert_true(crdt_snapshot_apply(&A, buf, (size_t)n) >= 0); }

  /* full triangle anti-entropy resumes */
  for (r = 0; r < 6; r++) {
    tri_self_assert(&A); tri_self_assert(&B); tri_self_assert(&C);
    tri_xchg(&A, &B, buf, sizeof buf);
    tri_xchg(&A, &C, buf, sizeof buf);
    tri_xchg(&B, &C, buf, sizeof buf);
    { const struct CrdtStateVector *v[3] = { &A.local_sv, &B.local_sv, &C.local_sv };
      crdt_sv_global_min(&st, v, 3); crdt_state_gc(&A, &st);
      crdt_state_gc(&B, &st); crdt_state_gc(&C, &st); }
  }

  /* the whole point: the convergent doc must reconverge across the triangle */
  assert_true(crdt_state_digest(&A) == crdt_state_digest(&B));
  assert_true(crdt_state_digest(&B) == crdt_state_digest(&C));
  /* and the users are visible everywhere again (relink healed materialization) */
  assert_int_equal(1, crdt_user_visible(&A, "U003"));
  assert_int_equal(1, crdt_user_visible(&B, "U003"));
  assert_int_equal(1, crdt_user_visible(&C, "U003"));

  crdt_state_clear(&A);
  crdt_state_clear(&B);
  crdt_state_clear(&C);
}

/* Phase 4c: snapshot-apply must raise gc_floor so snapshot-acquired state can
 * RE-PROPAGATE to a third node.
 *
 * Live finding (partition/merge demo): on relink, a node (nef3) acquires a
 * partitioned peer's (nef5's) state via a CR F full snapshot.  A snapshot
 * delivers STATE but NO ops -- so nef3 has nef5's users with nothing in its
 * oplog for them (oplog=0).  A third node (nef4) whose link never dropped is
 * only slightly behind on nef5's seq; the sync responder serves it a DELTA, but
 * nef3 has no ops in that range -> empty delta -> nef4 stays permanently stale.
 *
 * The responder already has a snapshot-fallback for peers "behind the GC floor"
 * (crdt_shadow_peer_behind_floor -> send_crdt_snapshot).  It never fires here
 * because crdt_snapshot_apply raised local_sv but NOT gc_floor.  The fix: a
 * snapshot reclaims the oplog below its SV (we hold state, not ops), so
 * gc_floor must rise to the adopted SV -- the op-level analog of resume_seq.
 *
 * This test models the responder's serve decision (delta vs snapshot-fallback)
 * with the engine's gc_floor and asserts the third node converges.  RED before
 * the gc_floor lift (empty delta -> B stale); GREEN after. */
static int tri_behind_floor(const struct CrdtNetworkState *server,
                            const struct CrdtNetworkState *peer)
{
  int i;
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    if (peer->local_sv.seq[i] < server->gc_floor.seq[i])
      return 1;
  return 0;
}
static void tri_serve(struct CrdtNetworkState *server, struct CrdtNetworkState *peer,
                      uint8_t *buf, size_t bufsz)
{
  int n;
  if (tri_behind_floor(server, peer)) {        /* ops gone -> snapshot-fallback */
    n = crdt_snapshot_encode(server, buf, bufsz);
    crdt_snapshot_apply(peer, buf, (size_t)n);
  } else {                                      /* serve a delta from the oplog */
    n = crdt_delta_encode(&server->oplog, &peer->local_sv, buf, bufsz);
    crdt_delta_apply(peer, buf, (size_t)n);
  }
}
static void test_snapshot_apply_raises_gc_floor(void **state)
{
  (void)state;
  struct CrdtNetworkState A, B, C;          /* A=hub(1) B=leaf(2) C=partitioned(3) */
  uint8_t buf[16384];
  int n;
  struct CrdtUserRecord uc = mkuser("c", 3, "c", 0x03030303u);

  crdt_state_init(&A, 1);
  crdt_state_init(&B, 2);
  crdt_state_init(&C, 3);

  /* C (origin 3) creates state while partitioned -> ops in C's oplog only */
  crdt_user_set(&C, "U030", &uc);
  crdt_user_set(&C, "U031", &uc);
  crdt_user_set(&C, "U032", &uc);

  /* A acquires C's state via SNAPSHOT (the relink CR F path): state, no ops */
  n = crdt_snapshot_encode(&C, buf, sizeof buf);
  assert_true(crdt_snapshot_apply(&A, buf, (size_t)n) >= 0);
  assert_non_null(crdt_user_get(&A, "U030"));        /* A has the state ... */
  assert_int_equal(0, (int)A.oplog.count);            /* ... but holds NO ops for it */

  /* THE FIX: snapshot-apply raised gc_floor to the adopted SV, so a peer still
   * behind C's seq is detected as below-floor (and will be sent a snapshot). */
  assert_true(A.gc_floor.seq[3] >= C.local_sv.seq[3]);   /* RED without the fix */

  /* B is behind (none of C's state). A serves B by the floor decision. Without
   * the fix A serves an empty delta (no C-ops) and B stays stale; with the fix A
   * snapshots B. */
  tri_serve(&A, &B, buf, sizeof buf);
  assert_non_null(crdt_user_get(&B, "U030"));            /* RED: stale without fix */
  assert_non_null(crdt_user_get(&B, "U032"));
  assert_true(crdt_state_digest_materialized(&A) ==
              crdt_state_digest_materialized(&B));

  crdt_state_clear(&A);
  crdt_state_clear(&B);
  crdt_state_clear(&C);
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

/* Phase 3a single-writer invariant: when exactly ONE replica writes an entity
 * and the other only RECEIVES it (the gated, non-re-mirroring case), the FULL
 * digest (OR-Set add-tags + tombstones included) converges after a single
 * ONE-WAY sync -- there is one origin tag per entity, so no bidirectional tag
 * union is needed. The control half then re-introduces the re-mirror artifact
 * (B also writes the same entity with its own origin) and shows the full digest
 * diverging while the materialized digest still agrees -- exactly the cosmetic
 * divergence Phase 3a's gating removes. Contrast test_wire_digest_converges,
 * where BOTH sides write and full convergence needs a round-trip. */
static void test_single_writer_full_digest_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState A, B;
  uint8_t buf[8192];
  int n, applied;
  struct CrdtUserRecord u = mkuser("alice", 4, "a", 0x04040404);
  uint8_t msnap[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
  crdt_state_init(&A, 4);   /* A (numeric 4) is the SOLE writer */
  crdt_state_init(&B, 3);   /* B (numeric 3) only receives -- writes nothing */

  crdt_user_set(&A, "AAAAA", &u);
  crdt_chan_join(&A, "#c", "AAAAA");
  crdt_topic_set(&A, "#c", "hi");
  crdt_modes_set(&A, "#c", msnap, sizeof msnap);

  /* one-way sync B<-A (B is the single-writer-gated peer: it mirrors nothing) */
  n = crdt_delta_encode(&A.oplog, &B.local_sv, buf, sizeof buf);
  assert_true(n > 0);
  applied = crdt_delta_apply(&B, buf, (size_t)n);
  assert_true(applied > 0);

  /* FULL digest matches after ONE one-way sync (single origin tag per entity);
   * materialized matches too. No bidirectional round-trip was needed. */
  assert_true(crdt_state_digest(&A) == crdt_state_digest(&B));
  assert_true(crdt_state_digest_materialized(&A) ==
              crdt_state_digest_materialized(&B));

  /* control: if B ALSO writes the same entities (the re-mirror artifact), the
   * single one-way sync above is no longer sufficient -- A has never seen B's
   * origin-3 ops, so the full digest diverges (and so does materialized: each
   * side's winning user-LWW is its own origin's write, same value bytes but a
   * different ts/writer). Convergence now requires a round-trip. This is the
   * cost single-writer gating removes. */
  crdt_user_set(&B, "AAAAA", &u);
  crdt_chan_join(&B, "#c", "AAAAA");
  assert_true(crdt_state_digest(&A) != crdt_state_digest(&B));   /* one-way insufficient */
  n = crdt_delta_encode(&B.oplog, &A.local_sv, buf, sizeof buf);
  assert_true(n > 0);
  crdt_delta_apply(&A, buf, (size_t)n);                          /* the round-trip */
  assert_true(crdt_state_digest(&A) == crdt_state_digest(&B));   /* now converged */
  assert_true(crdt_state_digest_materialized(&A) ==
              crdt_state_digest_materialized(&B));

  crdt_state_clear(&A);
  crdt_state_clear(&B);
}

/* Phase 3b: the EXPANDED user record (host/realname/account/umodes/ip6/TS/...)
 * round-trips byte-for-byte through delta encode+apply. assert_memory_equal over
 * the whole record catches any wire field that wasn't serialized. The record is
 * memset to 0 first so padding bytes are deterministic. */
static void test_user_record_full_roundtrip(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[8192];
  int n;
  struct CrdtUserRecord u;
  const struct CrdtUserRecord *r;
  unsigned char ip[16] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4 };
  memset(&u, 0, sizeof u);
  strcpy(u.nick, "alice"); strcpy(u.ident, "al");
  strcpy(u.host, "host.example.net"); strcpy(u.realhost, "real.example.net");
  strcpy(u.realname, "Alice Roberts");
  strcpy(u.account, "alice_acct"); strcpy(u.umodes, "+rix");
  memcpy(u.ip6, ip, 16);
  u.nick_ts = 1780000000ULL; u.acc_create = 1779000000ULL;
  u.server = 4;
  crdt_state_init(&s1, 4);
  crdt_state_init(&s2, 3);
  crdt_user_set(&s1, "DAAAB", &u);
  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  assert_true(n > 0);
  assert_true(crdt_delta_apply(&s2, buf, (size_t)n) > 0);
  r = crdt_user_get(&s2, "DAAAB");
  assert_non_null(r);
  assert_memory_equal(r, &u, sizeof u);   /* whole-record byte fidelity */
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* Phase 3b: per-member status LWW (keyed chan\0numeric) round-trips through
 * delta, and a later deop (higher HLC) wins after a one-way exchange — the LWW
 * conflict semantics that make op/deop a value change, not a membership churn. */
static void test_member_status_roundtrip_and_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[8192];
  int n;
  char key[64];
  uint32_t klen;
  struct CrdtMemberRecord op_rec, deop_rec;
  const struct CrdtLWWValue *v;
  memset(&op_rec, 0, sizeof op_rec);
  op_rec.status = CRDT_MEMBER_OP | CRDT_MEMBER_VOICE; op_rec.oplevel = 5;
  memset(&deop_rec, 0, sizeof deop_rec);
  deop_rec.status = CRDT_MEMBER_VOICE; deop_rec.oplevel = 0;
  /* composite key "#c\0DAAAB" */
  memcpy(key, "#c", 2); key[2] = '\0'; memcpy(key + 3, "DAAAB", 5);
  klen = 2 + 1 + 5;
  crdt_state_init(&s1, 4);
  crdt_state_init(&s2, 3);
  crdt_member_status_set(&s1, "#c", "DAAAB", &op_rec);
  n = crdt_delta_encode(&s1.oplog, &s2.local_sv, buf, sizeof buf);
  assert_true(n > 0);
  assert_true(crdt_delta_apply(&s2, buf, (size_t)n) > 0);
  v = crdt_lwwmap_get(&s2.members_status, key, klen);
  assert_non_null(v);
  assert_int_equal((int)v->data_len, (int)sizeof op_rec);
  assert_memory_equal(v->data, &op_rec, sizeof op_rec);
  /* s2 deops later (higher HLC) -> wins; sync back to s1 -> both converge */
  crdt_member_status_set(&s2, "#c", "DAAAB", &deop_rec);
  n = crdt_delta_encode(&s2.oplog, &s1.local_sv, buf, sizeof buf);
  assert_true(n > 0);
  assert_true(crdt_delta_apply(&s1, buf, (size_t)n) > 0);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  v = crdt_lwwmap_get(&s1.members_status, key, klen);
  assert_non_null(v);
  assert_memory_equal(v->data, &deop_rec, sizeof deop_rec);
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* Phase 3b: a full snapshot carries the new chanmeta + members_status maps
 * (guards the snapshot-encoder wiring — a forgotten snap_put_lww would diverge
 * the digest). */
static void test_snapshot_chanmeta_members_roundtrip(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  uint8_t buf[16384];
  int n;
  struct CrdtChanMeta meta;
  struct CrdtMemberRecord mr;
  const struct CrdtLWWValue *v;
  memset(&meta, 0, sizeof meta);
  meta.creationtime = 1780000123ULL; meta.topic_time = 1780000200ULL;
  strcpy(meta.topic_nick, "alice!al@host.example.net");
  memset(&mr, 0, sizeof mr);
  mr.status = CRDT_MEMBER_OP; mr.oplevel = 1;
  crdt_state_init(&s1, 4);
  crdt_state_init(&s2, 3);
  crdt_chan_join(&s1, "#c", "DAAAB");
  crdt_chanmeta_set(&s1, "#c", &meta);
  crdt_member_status_set(&s1, "#c", "DAAAB", &mr);
  n = crdt_snapshot_encode(&s1, buf, sizeof buf);
  assert_true(n > 0);
  assert_int_equal(0, crdt_snapshot_apply(&s2, buf, (size_t)n));
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  v = crdt_lwwmap_get(&s2.chanmeta, "#c", 2);
  assert_non_null(v);
  assert_memory_equal(v->data, &meta, sizeof meta);
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

/* Reproduces the live 3-peer scenario that left a fresh peer mdigest-divergent:
 * a peer (leaf) independently re-mirrors the SAME logical state with its OWN
 * origin/HLC (as P10-burst mirroring does), the other peer (hub) has already
 * GC'd its own ops (so it can only serve a CR F snapshot, not a delta), leaf
 * applies the snapshot, then bidirectional anti-entropy runs. The materialized
 * state MUST converge -- both must agree on the LWW winner (value, ts, writer)
 * for every key, not just the value. */
static void test_fresh_mirror_snapshot_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState hub, leaf;
  uint8_t buf[16384];
  int n, r;
  struct CrdtUserRecord u = mkuser("alice", 1, "a", 0x01020304);
  crdt_state_init(&hub, 1);
  crdt_state_init(&leaf, 2);

  /* hub's original writes, then GC -> its own ops leave the oplog (only the
   * materialized state survives, reachable solely via a snapshot) */
  crdt_user_set(&hub, "AAAAA", &u);
  crdt_chan_join(&hub, "#c", "AAAAA");
  crdt_topic_set(&hub, "#c", "hi");
  crdt_state_gc(&hub, &hub.local_sv);

  /* leaf independently re-mirrors the same logical state (its own origin/HLC) */
  crdt_user_set(&leaf, "AAAAA", &u);
  crdt_chan_join(&leaf, "#c", "AAAAA");
  crdt_topic_set(&leaf, "#c", "hi");

  /* leaf is behind hub's GC floor -> CR F snapshot */
  n = crdt_snapshot_encode(&hub, buf, sizeof buf);
  assert_true(crdt_snapshot_apply(&leaf, buf, (size_t)n) >= 0);

  /* bidirectional anti-entropy */
  for (r = 0; r < 3; r++) {
    n = crdt_delta_encode(&hub.oplog, &leaf.local_sv, buf, sizeof buf);
    crdt_delta_apply(&leaf, buf, (size_t)n);
    n = crdt_delta_encode(&leaf.oplog, &hub.local_sv, buf, sizeof buf);
    crdt_delta_apply(&hub, buf, (size_t)n);
  }

  assert_true(crdt_state_digest_materialized(&hub) ==
              crdt_state_digest_materialized(&leaf));
  crdt_state_clear(&hub);
  crdt_state_clear(&leaf);
}

/* Multi-hop topology A -- B -- C (B relays; A and C are NOT direct peers). Each
 * node runs anti-entropy with ONLY its direct peers and GCs against ONLY its
 * direct peers' SVs -- exactly what crdt_shadow_gc does live. With ongoing churn
 * on A and C, all three must still converge: the claim is that "retain an op
 * until every direct peer has it" + hop-by-hop relay is sufficient for GC safety
 * in any connected topology, so no transitive (CR V) SV propagation is needed. */
static void test_multihop_relay_gc_converges(void **state)
{
  (void)state;
  struct CrdtNetworkState A, B, C;
  struct CrdtStateVector st;
  uint8_t buf[16384];
  int n, r;
  char key[8];
  crdt_state_init(&A, 1);
  crdt_state_init(&B, 2);
  crdt_state_init(&C, 3);

  for (r = 0; r < 6; r++) {
    struct CrdtUserRecord ua = mkuser("a", 1, "a", (uint32_t)(0x100 + r));
    struct CrdtUserRecord uc = mkuser("c", 3, "c", (uint32_t)(0x300 + r));
    snprintf(key, sizeof key, "A%04d", r);
    crdt_user_set(&A, key, &ua);  crdt_chan_join(&A, "#x", key);
    snprintf(key, sizeof key, "C%04d", r);
    crdt_user_set(&C, key, &uc);  crdt_chan_join(&C, "#x", key);

    /* direct-peer anti-entropy only: A<->B, then B<->C */
    n = crdt_delta_encode(&A.oplog, &B.local_sv, buf, sizeof buf); crdt_delta_apply(&B, buf, (size_t)n);
    n = crdt_delta_encode(&B.oplog, &A.local_sv, buf, sizeof buf); crdt_delta_apply(&A, buf, (size_t)n);
    n = crdt_delta_encode(&B.oplog, &C.local_sv, buf, sizeof buf); crdt_delta_apply(&C, buf, (size_t)n);
    n = crdt_delta_encode(&C.oplog, &B.local_sv, buf, sizeof buf); crdt_delta_apply(&B, buf, (size_t)n);

    /* per-node GC against DIRECT peers only (the crux of the claim) */
    { const struct CrdtStateVector *v[2] = { &A.local_sv, &B.local_sv };
      crdt_sv_global_min(&st, v, 2); crdt_state_gc(&A, &st); }
    { const struct CrdtStateVector *v[3] = { &B.local_sv, &A.local_sv, &C.local_sv };
      crdt_sv_global_min(&st, v, 3); crdt_state_gc(&B, &st); }
    { const struct CrdtStateVector *v[2] = { &C.local_sv, &B.local_sv };
      crdt_sv_global_min(&st, v, 2); crdt_state_gc(&C, &st); }
  }

  /* flush: keep relaying (no new ops) until everything propagates end to end */
  for (r = 0; r < 5; r++) {
    n = crdt_delta_encode(&A.oplog, &B.local_sv, buf, sizeof buf); crdt_delta_apply(&B, buf, (size_t)n);
    n = crdt_delta_encode(&B.oplog, &A.local_sv, buf, sizeof buf); crdt_delta_apply(&A, buf, (size_t)n);
    n = crdt_delta_encode(&B.oplog, &C.local_sv, buf, sizeof buf); crdt_delta_apply(&C, buf, (size_t)n);
    n = crdt_delta_encode(&C.oplog, &B.local_sv, buf, sizeof buf); crdt_delta_apply(&B, buf, (size_t)n);
  }

  /* A and C never exchanged directly, B GC'd against only its direct peers --
   * yet all three converge materially */
  assert_true(crdt_state_digest_materialized(&A) == crdt_state_digest_materialized(&B));
  assert_true(crdt_state_digest_materialized(&B) == crdt_state_digest_materialized(&C));

  crdt_state_clear(&A);
  crdt_state_clear(&B);
  crdt_state_clear(&C);
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

/* Phase 3m: user delete-tombstone gate (the doc->live delete-on-leave guard).
 * absent->0, present->0, deleted->1, reconnect(newer set)->0; and it replicates. */
static void test_user_explicit_removal_gate(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  struct CrdtUserRecord u;
  unsigned char ip[16] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4 };
  memset(&u, 0, sizeof u);
  strcpy(u.nick, "bob"); strcpy(u.ident, "bo"); strcpy(u.host, "h.example");
  strcpy(u.realname, "Bob"); strcpy(u.umodes, "+i");
  memcpy(u.ip6, ip, 16); u.nick_ts = 1780000000ULL; u.server = 4;
  crdt_state_init(&s1, 4);
  crdt_state_init(&s2, 3);

  /* absent: NOT explicitly removed (the sync-lag guard) */
  assert_int_equal(0, crdt_user_is_explicitly_removed(&s1, "DAAAB"));
  /* present: NOT explicitly removed */
  crdt_user_set(&s1, "DAAAB", &u);
  assert_int_equal(0, crdt_user_is_explicitly_removed(&s1, "DAAAB"));
  assert_non_null(crdt_user_get(&s1, "DAAAB"));
  /* deleted: IS explicitly removed; get() now NULL (deleted == absent for get) */
  crdt_user_remove(&s1, "DAAAB");
  assert_int_equal(1, crdt_user_is_explicitly_removed(&s1, "DAAAB"));
  assert_null(crdt_user_get(&s1, "DAAAB"));
  /* the tombstone replicates: s2 learns the delete via the oplog and sees it */
  assert_true(crdt_state_sync(&s2, &s1) >= 0);
  assert_int_equal(1, crdt_user_is_explicitly_removed(&s2, "DAAAB"));
  /* reconnect on the same numeric (newer-HLC set) clears the tombstone */
  crdt_user_set(&s1, "DAAAB", &u);
  assert_int_equal(0, crdt_user_is_explicitly_removed(&s1, "DAAAB"));
  assert_non_null(crdt_user_get(&s1, "DAAAB"));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* LWW delete-tombstone GC: a user-remove tombstone is reclaimed only once its DELETE
 * op is causally stable (all peers saw it); kept while unstable (no resurrection). */
static void test_lww_tombstone_gc(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtUserRecord u;
  struct CrdtStateVector stable;
  memset(&u, 0, sizeof u);
  strcpy(u.nick, "ghost"); u.server = 4;
  crdt_state_init(&s, 4);
  crdt_user_set(&s, "DAAAB", &u);
  crdt_user_remove(&s, "DAAAB");
  assert_int_equal(1, crdt_user_is_explicitly_removed(&s, "DAAAB"));

  /* unstable (nothing acked past the delete): tombstone KEPT */
  crdt_sv_init(&stable);
  crdt_state_gc(&s, &stable);
  assert_int_equal(1, crdt_user_is_explicitly_removed(&s, "DAAAB"));

  /* stable (peer 4 acked well past the delete): tombstone RECLAIMED, no resurrection */
  crdt_sv_update(&stable, 4, 1000);
  crdt_state_gc(&s, &stable);
  assert_int_equal(0, crdt_user_is_explicitly_removed(&s, "DAAAB"));
  assert_null(crdt_user_get(&s, "DAAAB"));
  crdt_state_clear(&s);
}

/* ================================================================== */
/* M12 — same-second ban lastmod collision (Theme B).                        */
/* The glines/shuns/zlines docs are HLC-LWW and converge deterministically   */
/* even when two nodes set the same mask in the same wall-clock second       */
/* (equal `lastmod`); the defect is downstream, at the legacy *_modify        */
/* version gate the reconcile drives live (gline.c:812 & twins), which        */
/* rejects an equal-lastmod modify as "already have that version". That live  */
/* gate pulls in the whole gline subsystem + Client, so it is LIVE-only; here */
/* we gate (a) the pure force_lastmod tie-breaker the reconcile now applies,  */
/* and (b) that the doc itself converges (localizing the bug to the live      */
/* drive, exactly as the M12 design argues).                                  */

/* force_lastmod: doc ahead -> take the doc; tie or live-ahead -> one past live
 * (break the tie toward the doc-winner so the equal-lastmod gate can't reject it). */
static void test_force_lastmod_breaks_tie(void **state)
{
  (void)state;
  assert_int_equal(101, (int)force_lastmod(100, 100));   /* tie       -> live + 1 */
  assert_int_equal(200, (int)force_lastmod(100, 200));   /* doc ahead -> doc      */
  assert_int_equal(201, (int)force_lastmod(200, 100));   /* live ahead-> live + 1 */
}

/* Doc-convergence: two nodes set the SAME mask in the same second with EQUAL
 * lastmod but DIFFERENT reasons; after a cross-merge both replicas converge to one
 * winning record (identical digest, identical winning reason), and the tie-inducing
 * equal lastmod is preserved. Proves the doc is fine -> the churn the finding
 * describes lives purely in the live gline_modify gate, not in the CRDT. */
static void test_gline_doc_converges_same_lastmod(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  const char *M = "*!*@*.same-second.example";
  uint32_t ml = (uint32_t)strlen(M);
  struct CrdtGlineRecord ra, rb;
  const struct CrdtLWWValue *v1, *v2;
  const struct CrdtGlineRecord *w1, *w2;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  memset(&ra, 0, sizeof ra);
  ra.expire = 5000; ra.lastmod = 500; ra.lifetime = 9999; ra.flags = 1; ra.bits = 0;
  strcpy(ra.reason, "reason-from-node-1");
  memcpy(&rb, &ra, sizeof rb);          /* same mask, same lastmod, DIFFERENT reason */
  strcpy(rb.reason, "reason-from-node-2");
  crdt_gline_set(&s1, M, &ra);          /* node 1 sets its version */
  crdt_gline_set(&s2, M, &rb);          /* node 2 sets its version, same second */
  crdt_state_sync(&s2, &s1);            /* cross-merge both directions */
  crdt_state_sync(&s1, &s2);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));   /* converged */
  v1 = crdt_lwwmap_get(&s1.glines, M, ml);
  v2 = crdt_lwwmap_get(&s2.glines, M, ml);
  assert_non_null(v1); assert_non_null(v2);
  w1 = (const struct CrdtGlineRecord *)v1->data;
  w2 = (const struct CrdtGlineRecord *)v2->data;
  assert_string_equal(w1->reason, w2->reason);            /* same winner everywhere */
  assert_int_equal((int)w1->lastmod, (int)w2->lastmod);
  assert_int_equal(500, (int)w1->lastmod);                /* the tie-inducing lastmod */
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */
/* Orphan per-member metadata reclaim (members_status/kick_info for departed
 * members): the parallel LWW entries aren't tombstones, so the normal tombstone GC
 * never reclaims them — crdt_state_reclaim_orphan_member_meta mints DELETE ops for
 * members that have FULLY departed the OR-Set (removal causally stable). */

/* DONE: a fully-departed member's metadata is reclaimed (delete-op minted). */
static void test_orphan_member_meta_reclaimed(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtMemberRecord mr;
  struct CrdtKickInfo ki;
  struct CrdtStateVector stable;
  memset(&mr, 0, sizeof mr); mr.status = CRDT_MEMBER_OP; mr.oplevel = 3;
  memset(&ki, 0, sizeof ki); strcpy(ki.kicker, "AAAAA"); strcpy(ki.reason, "bye");
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_member_status_set(&s, "#c", "AAAAB", &mr);
  crdt_kick_info_set(&s, "#c", "AAAAB", &ki);
  assert_non_null(crdt_member_status_get(&s, "#c", "AAAAB"));
  assert_non_null(crdt_kick_info_get(&s, "#c", "AAAAB"));
  /* member departs + removal becomes causally stable -> OR-Set tombstone GC'd */
  crdt_chan_remove(&s, "#c", "AAAAB", CRDT_PRIORITY_USER);
  crdt_sv_init(&stable); crdt_sv_update(&stable, 1, 1000);
  crdt_state_gc(&s, &stable);
  /* now fully gone -> reclaim mints DELETE ops -> entries read back NULL */
  assert_true(crdt_state_reclaim_orphan_member_meta(&s) >= 2);
  assert_null(crdt_member_status_get(&s, "#c", "AAAAB"));
  assert_null(crdt_kick_info_get(&s, "#c", "AAAAB"));
  /* the delete tombstones themselves GC after stability (no unbounded growth) */
  crdt_sv_update(&stable, 1, 2000);
  crdt_state_gc(&s, &stable);
  crdt_state_clear(&s);
}

/* KEPT: a still-live member's metadata is NOT reclaimed. */
static void test_orphan_meta_kept_while_member_live(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtMemberRecord mr;
  memset(&mr, 0, sizeof mr); mr.status = CRDT_MEMBER_OP;
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_member_status_set(&s, "#c", "AAAAB", &mr);
  assert_int_equal(0, crdt_state_reclaim_orphan_member_meta(&s));
  assert_non_null(crdt_member_status_get(&s, "#c", "AAAAB"));
  crdt_state_clear(&s);
}

/* KEPT: while the OR-Set tombstone is still present (removal NOT yet causally
 * stable), kick_info is retained — reconcile-remove on lagging peers still needs it
 * for the KICK-vs-PART decision. */
static void test_orphan_meta_kept_while_tombstone_present(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtMemberRecord mr;
  struct CrdtKickInfo ki;
  struct CrdtStateVector stable;
  memset(&mr, 0, sizeof mr); mr.status = CRDT_MEMBER_OP;
  memset(&ki, 0, sizeof ki); strcpy(ki.kicker, "AAAAA"); strcpy(ki.reason, "k");
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_member_status_set(&s, "#c", "AAAAB", &mr);
  crdt_kick_info_set(&s, "#c", "AAAAB", &ki);
  crdt_chan_remove(&s, "#c", "AAAAB", CRDT_PRIORITY_USER);
  crdt_sv_init(&stable);                 /* nothing stable -> tombstone remains */
  crdt_state_gc(&s, &stable);
  /* tombstone present (member is_explicitly_removed) -> kick_info retained */
  assert_int_equal(0, crdt_state_reclaim_orphan_member_meta(&s));
  assert_non_null(crdt_kick_info_get(&s, "#c", "AAAAB"));
  crdt_state_clear(&s);
}

/* ================================================================== */
/* m15 — delete-on-leave for members_status (Theme B).                       */
/* members_status is a naked HLC-LWW register that was minted on join/mode but */
/* NEVER cleared on part/kick, so a departed member's stale +o lingered and    */
/* re-op'd them on rejoin (reconcile_mstatus_cb). crdt_member_status_remove    */
/* mints a members_status DELETE synchronously at the clean part/kick home hook */
/* (no stability gate — it is the real leave event), complementing the         */
/* Theme-A GC reap which backstops UNCLEAN departures (SQUIT/crash).           */

/* DELETE-ON-LEAVE: a clean leave clears the status; the delete moves both the SV
 * and the doc digest in one step (Fix-A safe — never SV-equal/digest-different). */
static void test_member_status_delete_on_leave(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtMemberRecord mr;
  uint64_t d_before, d_after, sv_before, sv_after;
  memset(&mr, 0, sizeof mr); mr.status = CRDT_MEMBER_OP; mr.oplevel = 3;
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_member_status_set(&s, "#c", "AAAAB", &mr);
  assert_non_null(crdt_member_status_get(&s, "#c", "AAAAB"));   /* +o present */
  d_before = crdt_state_digest(&s); sv_before = s.local_sv.seq[1];
  crdt_member_status_remove(&s, "#c", "AAAAB");                 /* clean leave */
  d_after = crdt_state_digest(&s); sv_after = s.local_sv.seq[1];
  assert_null(crdt_member_status_get(&s, "#c", "AAAAB"));       /* +o gone */
  assert_true(sv_after > sv_before);      /* a DELETE op was minted (SV moved) */
  assert_true(d_after != d_before);       /* digest moved in lockstep (Fix-A safe) */
  crdt_state_clear(&s);
}

/* REJOIN-NOT-CONTAMINATED (the important one): the member is op'd on node A whose
 * clock runs AHEAD, so the +o carries a HIGH HLC — naively that stale op would
 * out-rank a later normal-clock write. But the clean leave mints the DELETE on the
 * SAME node A, and A's HLC is monotone, so the delete's HLC strictly exceeds the +o's
 * and wins the LWW on every replica. The stale +o is therefore gone network-wide, so
 * reconcile_mstatus_cb finds no record and cannot re-op a plain rejoiner. (LWW is
 * arrival-order-independent: even if the stale +o reaches a peer AFTER the delete, the
 * higher-HLC delete still wins.) Pre-fix, with no delete, the +o lingered non-NULL and
 * contaminated the rejoin. NB: the residual pathological case — a fast-clock +o minted
 * on a DIFFERENT (far) node whose physical_ms exceeds the leaving home's delete — is
 * NOT closed by delete-on-leave; the complete fix is membership-incarnation anchoring
 * (Theme-B follow-up). */
static void test_member_status_rejoin_not_contaminated(void **state)
{
  (void)state;
  struct CrdtNetworkState sA, sB;
  struct CrdtMemberRecord op_rec;
  memset(&op_rec, 0, sizeof op_rec); op_rec.status = CRDT_MEMBER_OP; op_rec.oplevel = 5;
  crdt_state_init(&sA, 1);
  crdt_state_init(&sB, 2);
  crdt_chan_join(&sA, "#c", "BBBBB");
  sA.clock.physical_ms += 60000;          /* A's clock runs 60s ahead */
  crdt_member_status_set(&sA, "#c", "BBBBB", &op_rec);  /* +o at a HIGH HLC */
  crdt_state_sync(&sB, &sA);
  assert_non_null(crdt_member_status_get(&sB, "#c", "BBBBB"));  /* both hold the +o */
  /* clean leave on the SAME node that op'd -> monotone HLC makes the delete win */
  crdt_chan_remove(&sA, "#c", "BBBBB", CRDT_PRIORITY_USER);
  crdt_member_status_remove(&sA, "#c", "BBBBB");
  crdt_state_sync(&sB, &sA);
  assert_null(crdt_member_status_get(&sA, "#c", "BBBBB"));      /* stale +o gone... */
  assert_null(crdt_member_status_get(&sB, "#c", "BBBBB"));      /* ...on both replicas */
  assert_true(crdt_state_digest(&sA) == crdt_state_digest(&sB));/* converged */
  crdt_state_clear(&sA);
  crdt_state_clear(&sB);
}

/* NO-DOUBLE-MINT-WITH-REAP: after the synchronous delete tombstones the entry, the
 * Theme-A GC reap must not re-mint a second DELETE for the same key — crdt_lwwmap_
 * foreach skips the deleted entry (and once causally stable the tombstone GC frees it
 * outright). Either way the reap reclaims 0 for a member whose status was already
 * cleared on leave. The reap stays the backstop for UNCLEAN departures. */
static void test_member_status_remove_no_double_mint_with_reap(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtMemberRecord mr;
  struct CrdtStateVector stable;
  memset(&mr, 0, sizeof mr); mr.status = CRDT_MEMBER_OP;
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_member_status_set(&s, "#c", "AAAAB", &mr);
  /* clean leave: OR-Set remove + the synchronous members_status DELETE */
  crdt_chan_remove(&s, "#c", "AAAAB", CRDT_PRIORITY_USER);
  crdt_member_status_remove(&s, "#c", "AAAAB");
  assert_null(crdt_member_status_get(&s, "#c", "AAAAB"));
  /* make the removal causally stable so the reap WOULD consider the member gone */
  crdt_sv_init(&stable); crdt_sv_update(&stable, 1, 1000);
  crdt_state_gc(&s, &stable);
  /* no kick_info here + members_status already tombstoned -> reap re-mints nothing */
  assert_int_equal(0, crdt_state_reclaim_orphan_member_meta(&s));
  assert_null(crdt_member_status_get(&s, "#c", "AAAAB"));
  crdt_state_clear(&s);
}

/* ================================================================== */
/* M10: orphaned per-channel LWW meta (topics/modes/chanmeta) for FULLY-GONE
 * channels. Like member-meta these LWW entries are live registers, not tombstones,
 * so the normal GC never reclaims them; they leak forever for churned channels and
 * bloat every CR F snapshot. crdt_state_reclaim_orphan_chan_meta mints DELETE ops
 * once the channel is fully gone: members OR-Set empty AND causally stable
 * (tomb_count==0) AND the ctime incarnation dead. Reclaim = mint a DELETE (never a
 * local free — a peer's CR F would resurrect a local-free and flap the digest). */

/* RECLAIMED: a fully-gone channel's topic/modes/chanmeta are reclaimed, and the reap
 * moves local_sv AND the doc digest in lockstep (never an SV-equal/digest-different
 * state, which would trip Fix-A's anti-entropy into a spurious CR F snapshot). */
static void test_orphan_chan_meta_reclaimed(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtChanMeta cm;
  struct CrdtStateVector stable;
  uint64_t d_before, d_after, sv_before, sv_after;
  memset(&cm, 0, sizeof cm); cm.creationtime = 42;
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_topic_set(&s, "#c", "hello world");
  crdt_modes_set(&s, "#c", "ntk", 3);
  crdt_chanmeta_set(&s, "#c", &cm);
  assert_non_null(crdt_lwwmap_get(&s.topics, "#c", 2));
  assert_non_null(crdt_lwwmap_get(&s.modes, "#c", 2));
  assert_non_null(crdt_lwwmap_get(&s.chanmeta, "#c", 2));
  /* channel empties + removal becomes causally stable -> members OR-Set tombstone GC'd */
  crdt_chan_remove(&s, "#c", "AAAAB", CRDT_PRIORITY_USER);
  crdt_sv_init(&stable); crdt_sv_update(&stable, 1, 100000);
  crdt_state_gc(&s, &stable);
  /* fully gone -> reclaim mints 3 DELETE ops (topic/modes/chanmeta) */
  d_before = crdt_state_digest(&s); sv_before = s.local_sv.seq[1];
  assert_int_equal(3, crdt_state_reclaim_orphan_chan_meta(&s));
  d_after = crdt_state_digest(&s); sv_after = s.local_sv.seq[1];
  assert_true(sv_after > sv_before);     /* an op was minted (SV moved) */
  assert_true(d_after != d_before);      /* the doc digest moved with it (lockstep) */
  assert_null(crdt_lwwmap_get(&s.topics, "#c", 2));
  assert_null(crdt_lwwmap_get(&s.modes, "#c", 2));
  assert_null(crdt_lwwmap_get(&s.chanmeta, "#c", 2));
  /* the delete tombstones themselves GC after stability (no unbounded growth) */
  crdt_sv_update(&stable, 1, 200000);
  crdt_state_gc(&s, &stable);
  crdt_state_clear(&s);
}

/* KEPT: a live channel's meta is NOT reclaimed. */
static void test_orphan_chan_meta_kept_while_live(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtChanMeta cm;
  memset(&cm, 0, sizeof cm);
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_topic_set(&s, "#c", "hi");
  crdt_modes_set(&s, "#c", "nt", 2);
  crdt_chanmeta_set(&s, "#c", &cm);
  assert_int_equal(0, crdt_state_reclaim_orphan_chan_meta(&s));
  assert_non_null(crdt_lwwmap_get(&s.topics, "#c", 2));
  crdt_state_clear(&s);
}

/* KEPT: while the member OR-Set tombstone is still present (removal NOT yet causally
 * stable, tomb_count>0) the channel meta is retained -- lagging peers may still be
 * mid-departure, so the members-empty signal is not yet trustworthy. */
static void test_orphan_chan_meta_kept_while_tombstone_present(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtChanMeta cm;
  struct CrdtStateVector stable;
  memset(&cm, 0, sizeof cm);
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_topic_set(&s, "#c", "hi");
  crdt_modes_set(&s, "#c", "nt", 2);
  crdt_chanmeta_set(&s, "#c", &cm);
  crdt_chan_remove(&s, "#c", "AAAAB", CRDT_PRIORITY_USER);
  crdt_sv_init(&stable);                 /* nothing stable -> tombstone remains */
  crdt_state_gc(&s, &stable);
  assert_int_equal(0, crdt_state_reclaim_orphan_chan_meta(&s));
  assert_non_null(crdt_lwwmap_get(&s.topics, "#c", 2));
  crdt_state_clear(&s);
}

/* KEPT: an empty channel whose ctime incarnation is still LIVE (members drained but
 * the channel not destroyed) is NOT reclaimed -- a peer may hold it as a transient
 * 0-member live incarnation that can regain members / re-set its topic. The ctime
 * gate (not members alone) guards that M6-trap-1 resurrection. */
static void test_orphan_chan_meta_kept_while_ctime_live(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtStateVector stable;
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_chan_ctime_set(&s, "#c", 1234567890);   /* live incarnation */
  crdt_topic_set(&s, "#c", "hi");
  crdt_chan_remove(&s, "#c", "AAAAB", CRDT_PRIORITY_USER);
  crdt_sv_init(&stable); crdt_sv_update(&stable, 1, 100000);
  crdt_state_gc(&s, &stable);            /* members empty + stable, but ctime still live */
  assert_int_equal(0, crdt_state_reclaim_orphan_chan_meta(&s));
  assert_non_null(crdt_lwwmap_get(&s.topics, "#c", 2));
  crdt_state_clear(&s);
}

/* KEPT: a meta entry whose CrdtChannel struct has not been created on this node is
 * NOT reaped. A topic/modes/chanmeta SET op creates no struct (only member/ban/
 * except/ctime ops do), so under cross-origin delta lag a node can hold the meta
 * before the struct-creating ops arrive -- chan_find is NULL for a channel that is
 * forming, not gone. Reaping there would delete a live channel's meta network-wide.
 * (Would FAIL under the prior `!ch -> return 1` vacuous-fully-gone behavior.) */
static void test_orphan_chan_meta_kept_while_struct_absent(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  crdt_state_init(&s, 1);
  crdt_topic_set(&s, "#c", "hi");        /* meta present, NO struct-creating op */
  assert_int_equal(0, crdt_state_reclaim_orphan_chan_meta(&s));
  assert_non_null(crdt_lwwmap_get(&s.topics, "#c", 2));
  crdt_state_clear(&s);
}

/* RECLAIMED via the realistic destroy path: ctime is SET (live incarnation) then
 * CLEARED (crdt_chan_ctime_clear bumps ctime_del past ctime_set), so the channel is
 * dead by incarnation-compare, not merely by both-HLCs-unset. */
static void test_orphan_chan_meta_reclaimed_after_ctime_clear(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtStateVector stable;
  crdt_state_init(&s, 1);
  crdt_chan_join(&s, "#c", "AAAAB");
  crdt_chan_ctime_set(&s, "#c", 1234567890);   /* live incarnation */
  crdt_topic_set(&s, "#c", "hi");
  crdt_chan_remove(&s, "#c", "AAAAB", CRDT_PRIORITY_USER);
  crdt_chan_ctime_clear(&s, "#c");             /* destroy: ctime_del > ctime_set */
  crdt_sv_init(&stable); crdt_sv_update(&stable, 1, 100000);
  crdt_state_gc(&s, &stable);
  assert_true(crdt_state_reclaim_orphan_chan_meta(&s) >= 1);   /* topic reaped */
  assert_null(crdt_lwwmap_get(&s.topics, "#c", 2));
  crdt_state_clear(&s);
}

/* ================================================================== */
/* M9: per-user SILENCE masks (global silences OR-Set, keyed usernumeric\0mask). A
 * departed user's masks are never tombstoned by user_remove, so they persist as LIVE
 * OR-Set entries forever (growth) AND -- worse -- a reused P10 numeric inherits the
 * departed predecessor's masks (bleed: sync_user_silences keys purely on the numeric).
 * Two reaps mint crdt_silence_remove: a SYNCHRONOUS targeted reap inside
 * crdt_user_remove (closes the bleed via same-origin seq-ordering) and a backstop GC
 * sweep for the home-SQUIT-with-user-live case (crdt_user_remove never fires). */

/* build the composite silences key numeric\0mask (mirrors the engine's silence_key). */
static uint32_t mk_sil_key(char *out, const char *num, const char *mask)
{
  uint32_t ul = (uint32_t)strlen(num), ml = (uint32_t)strlen(mask);
  memcpy(out, num, ul); out[ul] = '\0'; memcpy(out + ul + 1, mask, ml);
  return ul + 1 + ml;
}

/* RECLAIMED (backstop sweep): a silence whose owning user is FULLY absent from the
 * users map (removal causally stable / tombstone GC'd) is reaped. Assert the reap
 * moves local_sv AND the doc digest in lockstep (never SV-equal/digest-different). */
static void test_orphan_silences_reclaimed(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  char key[64];
  uint32_t klen;
  uint64_t d_before, d_after, sv_before, sv_after;
  klen = mk_sil_key(key, "YAAAB", "*!*@x");
  crdt_state_init(&s, 1);
  /* silence present with NO user record -> the fully-gone state (user absent) */
  crdt_silence_add(&s, "YAAAB", "*!*@x");
  assert_true(crdt_orset_contains(&s.silences, key, klen));
  d_before = crdt_state_digest(&s); sv_before = s.local_sv.seq[1];
  assert_true(crdt_state_reclaim_orphan_silences(&s) >= 1);
  d_after = crdt_state_digest(&s); sv_after = s.local_sv.seq[1];
  assert_true(sv_after > sv_before);     /* a REMOVE op was minted (SV moved) */
  assert_true(d_after != d_before);      /* the doc digest moved with it (lockstep) */
  assert_false(crdt_orset_contains(&s.silences, key, klen));
  crdt_state_clear(&s);
}

/* KEPT: a live user's silence is NOT reaped by the sweep. */
static void test_orphan_silences_kept_while_user_live(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtUserRecord u;
  char key[64];
  uint32_t klen;
  memset(&u, 0, sizeof u);
  klen = mk_sil_key(key, "YAAAB", "*!*@x");
  crdt_state_init(&s, 1);
  crdt_user_set(&s, "YAAAB", &u);
  crdt_silence_add(&s, "YAAAB", "*!*@x");
  assert_int_equal(0, crdt_state_reclaim_orphan_silences(&s));
  assert_true(crdt_orset_contains(&s.silences, key, klen));
  crdt_state_clear(&s);
}

/* KEPT: while the user's delete-tombstone is still present (removal NOT yet causally
 * stable, is_deleted()==1) the sweep must not act -- a lagging peer may not have seen
 * the user yet; the LWW analog of the template's "kept while OR-Set tombstone present". */
static void test_orphan_silences_kept_while_user_tombstone(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtUserRecord u;
  char key[64];
  uint32_t klen;
  struct HLC hi = { 0xFFFFFFFFFFFFULL, 0, 1 };   /* far-future -> delete wins the set */
  memset(&u, 0, sizeof u);
  klen = mk_sil_key(key, "YAAAB", "*!*@x");
  crdt_state_init(&s, 1);
  crdt_user_set(&s, "YAAAB", &u);
  crdt_silence_add(&s, "YAAAB", "*!*@x");
  /* tombstone the user directly (op-less) so is_deleted()==1 but it is NOT GC'd */
  crdt_lwwmap_delete(&s.users, "YAAAB", 5, hi, 1);
  assert_true(crdt_lwwmap_is_deleted(&s.users, "YAAAB", 5));
  assert_int_equal(0, crdt_state_reclaim_orphan_silences(&s));
  assert_true(crdt_orset_contains(&s.silences, key, klen));
  crdt_state_clear(&s);
}

/* BLEED REGRESSION (the important one): a P10 numeric YYXXX is reused by the SAME
 * owning server after a client departs. Without the SYNCHRONOUS reap inside
 * crdt_user_remove, the reused numeric would inherit the departed predecessor's masks
 * (sync_user_silences keys purely on the numeric) and silently drop the new user's
 * senders. The reap mints the silence REMOVE ops with seqs BEFORE any future user_set
 * for the reused numeric (same origin, monotonic next_seq) -> every node applies the
 * REMOVE before the reuse's user-SET -> the new user never inherits the mask. This
 * case FAILS if the reap is moved out of crdt_user_remove to a sweep-only design. */
static void test_silence_numeric_reuse_no_bleed(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtUserRecord u;
  char key[64];
  uint32_t klen;
  memset(&u, 0, sizeof u);
  klen = mk_sil_key(key, "YAAAB", "*!*@bad.example");
  crdt_state_init(&s, 1);
  /* original client on numeric YAAAB adds a silence, then departs */
  crdt_user_set(&s, "YAAAB", &u);
  crdt_silence_add(&s, "YAAAB", "*!*@bad.example");
  assert_true(crdt_orset_contains(&s.silences, key, klen));   /* present while live */
  crdt_user_remove(&s, "YAAAB");         /* synchronous targeted reap fires here */
  /* the departed user's mask is tombstoned immediately -- BEFORE any reuse */
  assert_false(crdt_orset_contains(&s.silences, key, klen));
  /* the SAME server reuses the numeric for a fresh client */
  crdt_user_set(&s, "YAAAB", &u);
  /* the reused numeric does NOT inherit the predecessor's mask (bleed closed) */
  assert_false(crdt_orset_contains(&s.silences, key, klen));
  crdt_state_clear(&s);
}

/* MASK PARITY: an exception mask rides the doc in sil_docmask's '~'-prefixed form. The
 * reap copies the mask bytes VERBATIM from the doc key (never re-canonicalizing), so a
 * '~'-prefixed mask is tombstoned byte-identically -- crdt_silence_remove's
 * silence_key() rebuilds the exact present key. This guards the design's flagged
 * flip-flop risk: the reaped mask always matches the form the live mirror stored. */
static void test_orphan_silences_reap_exception_mask(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  char key[64];
  uint32_t klen;
  klen = mk_sil_key(key, "YAAAB", "~*!*@safe.example");   /* '~' = BAN_EXCEPTION docmask */
  crdt_state_init(&s, 1);
  crdt_silence_add(&s, "YAAAB", "~*!*@safe.example");     /* no user record -> absent */
  assert_true(crdt_orset_contains(&s.silences, key, klen));
  assert_true(crdt_state_reclaim_orphan_silences(&s) >= 1);
  assert_false(crdt_orset_contains(&s.silences, key, klen));
  crdt_state_clear(&s);
}

/* ================================================================== */
/* Fix A (digest-aware anti-entropy): the state vector counts ops per origin but
 * does NOT summarise content/HLC, so two replicas can share an SV yet hold
 * different content (e.g. a CR F snapshot HLC-merge or ctime incarnation change
 * that bypasses the oplog). SV-based anti-entropy emits an empty delta for such a
 * pair and never repairs it; only a CR F snapshot (which HLC-merges, bypassing SV
 * dedup) reconciles content. These two suites encode that invariant. */

/* DETECTION: equal SV is possible with different digest. */
static void test_equal_sv_can_differ_in_content(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2, src;
  uint8_t buf[8192];
  int n, i, sv_eq;
  struct CrdtUserRecord u  = mkuser("a", 1, "a", 0x01010101);
  struct CrdtUserRecord u2 = mkuser("a", 1, "a", 0x02020202);  /* different bytes */
  struct HLC hi = { 0xFFFFFFFFFFFFULL, 0, 1 };  /* far-future -> always wins merge */
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  crdt_state_init(&src, 3);
  /* shared op-backed content from a common origin (3): equal SV + equal digest */
  crdt_user_set(&src, "AAAAA", &u);
  n = crdt_delta_encode(&src.oplog, &s1.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s1, buf, (size_t)n);
  n = crdt_delta_encode(&src.oplog, &s2.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s2, buf, (size_t)n);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));
  /* diverge s1's CONTENT via a higher-HLC, NON-op-backed write (mimics the CR F
   * HLC-merge / ctime incarnation change that bypasses the oplog) */
  crdt_lwwmap_set(&s1.users, "AAAAA", 5, &u2, sizeof u2, hi, 1);
  /* SV is unchanged (no op) but the digest now differs: the SV-invisible case */
  sv_eq = 1;
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    if (s1.local_sv.seq[i] != s2.local_sv.seq[i]) { sv_eq = 0; break; }
  assert_true(sv_eq);
  assert_true(crdt_state_digest(&s1) != crdt_state_digest(&s2));
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
  crdt_state_clear(&src);
}

/* REPAIR: a CR F snapshot converges an equal-SV/different-content divergence. */
static void test_snapshot_converges_equal_sv_divergence(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2, src;
  uint8_t buf[8192];
  int n;
  struct CrdtUserRecord u  = mkuser("a", 1, "a", 0x01010101);
  struct CrdtUserRecord u2 = mkuser("a", 1, "a", 0x02020202);
  struct HLC hi = { 0xFFFFFFFFFFFFULL, 0, 1 };
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  crdt_state_init(&src, 3);
  crdt_user_set(&src, "AAAAA", &u);
  n = crdt_delta_encode(&src.oplog, &s1.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s1, buf, (size_t)n);
  n = crdt_delta_encode(&src.oplog, &s2.local_sv, buf, sizeof buf);
  crdt_delta_apply(&s2, buf, (size_t)n);
  crdt_lwwmap_set(&s1.users, "AAAAA", 5, &u2, sizeof u2, hi, 1);
  assert_true(crdt_state_digest(&s1) != crdt_state_digest(&s2));  /* diverged */
  /* the Fix A repair: a snapshot from the divergent peer HLC-merges content,
   * converging the digest even though the SVs were already equal (an empty delta
   * would never have repaired it). */
  n = crdt_snapshot_encode(&s1, buf, sizeof buf);
  assert_true(n > 0);
  crdt_snapshot_apply(&s2, buf, (size_t)n);
  assert_true(crdt_state_digest(&s1) == crdt_state_digest(&s2));  /* converged */
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
  crdt_state_clear(&src);
}

/* ================================================================== */
/* R3: time-windowed msgid dedup (crdt_dedup_*) — replaces the count-bounded ring. */

static void test_dedup_basic(void **state)
{
  (void)state;
  static struct CrdtMsgidDedup d; crdt_dedup_init(&d);
  assert_int_equal(0, crdt_dedup_check_add(&d, "a", 100, 60));  /* new */
  assert_int_equal(1, crdt_dedup_check_add(&d, "a", 110, 60));  /* dup within window */
  assert_int_equal(0, crdt_dedup_check_add(&d, "b", 110, 60));  /* different id */
}

static void test_dedup_window_expiry(void **state)
{
  (void)state;
  static struct CrdtMsgidDedup d; crdt_dedup_init(&d);
  assert_int_equal(0, crdt_dedup_check_add(&d, "a", 100, 60));
  assert_int_equal(0, crdt_dedup_check_add(&d, "a", 200, 60));  /* expired -> new */
  assert_int_equal(1, crdt_dedup_check_add(&d, "a", 210, 60));  /* fresh dup again */
}

static void test_dedup_no_msgid(void **state)
{
  (void)state;  /* "*"/empty/NULL are never dedupable (else distinct msgid-less msgs
                   would spuriously dedup against each other — the old ring's bug). */
  static struct CrdtMsgidDedup d; crdt_dedup_init(&d);
  assert_int_equal(0, crdt_dedup_check_add(&d, "*", 100, 60));
  assert_int_equal(0, crdt_dedup_check_add(&d, "*", 100, 60));
  assert_int_equal(0, crdt_dedup_check_add(&d, "", 100, 60));
  assert_int_equal(0, crdt_dedup_check_add(&d, NULL, 100, 60));
}

static void test_dedup_not_count_bounded(void **state)
{
  (void)state;  /* the scale fix: >256 distinct ids in the window, the FIRST is STILL
                   deduped — the old 256-ring would have count-evicted it. */
  static struct CrdtMsgidDedup d; crdt_dedup_init(&d);
  char id[32]; int i;
  for (i = 0; i < 300; i++) {
    snprintf(id, sizeof id, "m%d", i);
    assert_int_equal(0, crdt_dedup_check_add(&d, id, 100, 60));  /* all new */
  }
  assert_int_equal(1, crdt_dedup_check_add(&d, "m0", 100, 60));  /* m0 still seen */
}

/* ================================================================== */

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_user_explicit_removal_gate),
    cmocka_unit_test(test_lww_tombstone_gc),
    cmocka_unit_test(test_orphan_member_meta_reclaimed),
    cmocka_unit_test(test_orphan_meta_kept_while_member_live),
    cmocka_unit_test(test_orphan_meta_kept_while_tombstone_present),
    cmocka_unit_test(test_member_status_delete_on_leave),
    cmocka_unit_test(test_member_status_rejoin_not_contaminated),
    cmocka_unit_test(test_member_status_remove_no_double_mint_with_reap),
    cmocka_unit_test(test_orphan_chan_meta_reclaimed),
    cmocka_unit_test(test_orphan_chan_meta_reclaimed_after_ctime_clear),
    cmocka_unit_test(test_orphan_chan_meta_kept_while_struct_absent),
    cmocka_unit_test(test_orphan_chan_meta_kept_while_live),
    cmocka_unit_test(test_orphan_chan_meta_kept_while_tombstone_present),
    cmocka_unit_test(test_orphan_chan_meta_kept_while_ctime_live),
    cmocka_unit_test(test_orphan_silences_reclaimed),
    cmocka_unit_test(test_orphan_silences_kept_while_user_live),
    cmocka_unit_test(test_orphan_silences_kept_while_user_tombstone),
    cmocka_unit_test(test_silence_numeric_reuse_no_bleed),
    cmocka_unit_test(test_orphan_silences_reap_exception_mask),
    cmocka_unit_test(test_A_convergence),
    cmocka_unit_test(test_B_collision_different_user_oldest_wins),
    cmocka_unit_test(test_B_collision_same_user_newest_wins),
    cmocka_unit_test(test_B_collision_account_owner_wins),
    cmocka_unit_test(test_B_collision_tie_breaks_on_node),
    cmocka_unit_test(test_B_force_rename_preserves_both),
    cmocka_unit_test(test_C_kick_beats_concurrent_join),
    cmocka_unit_test(test_C_part_yields_to_concurrent_join),
    cmocka_unit_test(test_orset_explicit_removal_gate),
    cmocka_unit_test(test_chan_ban_op_replicates),
    cmocka_unit_test(test_silence_op_replicates),
    cmocka_unit_test(test_marker_op_replicates),
    cmocka_unit_test(test_gline_op_replicates),
    cmocka_unit_test(test_force_lastmod_breaks_tie),
    cmocka_unit_test(test_gline_doc_converges_same_lastmod),
    cmocka_unit_test(test_metadata_op_replicates),
    cmocka_unit_test(test_bsess_op_replicates),
    cmocka_unit_test(test_bsess_winner),
    cmocka_unit_test(test_bconn_roster),
    cmocka_unit_test(test_blease_compare),
    cmocka_unit_test(test_blease_decide),
    cmocka_unit_test(test_blease_action),
    cmocka_unit_test(test_blease_converges),
    cmocka_unit_test(test_blease_symmetric_dual_revive),
    cmocka_unit_test(test_shun_op_replicates),
    cmocka_unit_test(test_zline_op_replicates),
    cmocka_unit_test(test_jupe_op_replicates),
    cmocka_unit_test(test_chan_ctime_min_incarnation),
    cmocka_unit_test(test_kick_info_replicates_and_hlc_gates),
    cmocka_unit_test(test_E_squit_creates_no_membership_tombstones),
    cmocka_unit_test(test_server_state_converges),
    cmocka_unit_test(test_server_state_converges_mesh),
    cmocka_unit_test(test_restart_resumes_seq_past_adopted_sv),
    cmocka_unit_test(test_snapshot_apply_raises_gc_floor),
    cmocka_unit_test(test_equal_sv_can_differ_in_content),
    cmocka_unit_test(test_snapshot_converges_equal_sv_divergence),
    cmocka_unit_test(test_dedup_basic),
    cmocka_unit_test(test_dedup_window_expiry),
    cmocka_unit_test(test_dedup_no_msgid),
    cmocka_unit_test(test_dedup_not_count_bounded),
    cmocka_unit_test(test_wire_sv_roundtrip),
    cmocka_unit_test(test_wire_delta_converges),
    cmocka_unit_test(test_wire_digest_converges),
    cmocka_unit_test(test_single_writer_full_digest_converges),
    cmocka_unit_test(test_user_record_full_roundtrip),
    cmocka_unit_test(test_member_status_roundtrip_and_converges),
    cmocka_unit_test(test_snapshot_chanmeta_members_roundtrip),
    cmocka_unit_test(test_wire_concurrent_converges),
    cmocka_unit_test(test_snapshot_roundtrip),
    cmocka_unit_test(test_gc_advances_floor),
    cmocka_unit_test(test_snapshot_recovers_gc_gap),
    cmocka_unit_test(test_materialized_digest_gc_invariant),
    cmocka_unit_test(test_fresh_mirror_snapshot_converges),
    cmocka_unit_test(test_multihop_relay_gc_converges),
    cmocka_unit_test(test_wire_b64_roundtrip),
    cmocka_unit_test(test_chunk_reassembles),
    cmocka_unit_test(test_chunk_isolation),
    cmocka_unit_test(test_chunk_cleanup_link),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
