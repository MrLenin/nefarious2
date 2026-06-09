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
  strcpy(u.host, "host.example.net"); strcpy(u.realname, "Alice Roberts");
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
    cmocka_unit_test(test_orset_explicit_removal_gate),
    cmocka_unit_test(test_chan_ban_op_replicates),
    cmocka_unit_test(test_chan_ctime_min_incarnation),
    cmocka_unit_test(test_kick_info_replicates_and_hlc_gates),
    cmocka_unit_test(test_E_squit_creates_no_membership_tombstones),
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
