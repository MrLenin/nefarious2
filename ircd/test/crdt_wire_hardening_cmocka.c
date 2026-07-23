/*
 * crdt_wire_hardening_cmocka.c - malformed-wire trust-boundary tests
 *
 * The CR token family accepts raw byte streams from directly-linked peers, and
 * every decoded field that indexes fixed-size engine state must be validated at
 * that trust boundary.  These tests feed hostile / corrupt / truncated
 * encodings straight into the decode/apply/feed primitives and assert they are
 * rejected (or ignored) without touching state out of bounds:
 *
 *   - op origin / tag.origin >= CRDT_MAX_SERVERS (they index
 *     CrdtStateVector.seq[CRDT_MAX_SERVERS] in sv_has_seen / sv_update and the
 *     OR-Set GC) -> rejected at decode AND at apply
 *   - unknown collection byte (an op from a NEWER peer) -> ignored without a
 *     NULL-map deref, but still recorded so relay/dedup stay coherent
 *   - snapshot OR-Set add/tomb tags with OOB origins -> snapshot rejected
 *   - truncated op / delta / snapshot buffers at every cut -> clean failure
 *   - crdt_orset_remove reports at most max_out tags per call (the returned
 *     count NEVER exceeds the caller's buffer); callers loop until done, so a
 *     member with > max_out add-tags still fully removes AND replicates
 *   - s2s_chunk_feed aborts an unterminated stream at the reassembly cap and
 *     frees the slot (no unbounded growth on a peer that never sends '.')
 *
 * Engine-pure: links crdt_types.o crdt_state.o crdt_hlc.o crdt_wire.o
 * s2s_chunk.o + test_stub.o only, same as crdt_cmocka.
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

/* A syntactically-valid LWW SET op the encoder accepts; the test then poisons
 * individual fields.  Pointers reference static storage (encode only reads). */
static void mk_set_op(struct CrdtOp *op, uint16_t origin, uint64_t seq)
{
  memset(op, 0, sizeof *op);
  op->origin = origin;
  op->seq = seq;
  op->type = CRDT_OP_SET;
  op->coll = CRDT_COLL_USERS;
  op->key = (char *)"AAAAA";
  op->key_len = 5;
  op->val = (void *)"v";
  op->val_len = 1;
  op->ts = mkhlc(1000, 0, origin);
  op->writer = origin;
}

/* A syntactically-valid OR-Set ADD op (channel member). */
static void mk_add_op(struct CrdtOp *op, uint16_t origin, uint64_t seq,
                      uint16_t tag_origin, uint64_t tag_seq)
{
  memset(op, 0, sizeof *op);
  op->origin = origin;
  op->seq = seq;
  op->type = CRDT_OP_ADD;
  op->coll = CRDT_COLL_CHAN_MEMBERS;
  op->chan = (char *)"#c";
  op->chan_len = 2;
  op->key = (char *)"AAAAA";
  op->key_len = 5;
  op->tag.origin = tag_origin;
  op->tag.seq = tag_seq;
}

/* ================================================================== */
/* C1 — decoded origin / tag.origin must be < CRDT_MAX_SERVERS        */
/* ================================================================== */

static void test_op_decode_rejects_oob_origin(void **state)
{
  (void)state;
  struct CrdtOp op, dec;
  uint8_t buf[256];
  int n;

  /* first out-of-bounds slot */
  mk_set_op(&op, (uint16_t)CRDT_MAX_SERVERS, 1);
  n = crdt_op_encode(&op, buf, sizeof buf);
  assert_true(n > 0);
  assert_int_equal(-1, crdt_op_decode(&dec, buf, (size_t)n));

  /* the far end of the u16 range */
  mk_set_op(&op, 0xFFFF, 1);
  n = crdt_op_encode(&op, buf, sizeof buf);
  assert_true(n > 0);
  assert_int_equal(-1, crdt_op_decode(&dec, buf, (size_t)n));

  /* control: the last in-range origin still decodes */
  mk_set_op(&op, (uint16_t)(CRDT_MAX_SERVERS - 1), 1);
  n = crdt_op_encode(&op, buf, sizeof buf);
  assert_true(n > 0);
  assert_int_equal(n, crdt_op_decode(&dec, buf, (size_t)n));
  assert_int_equal(CRDT_MAX_SERVERS - 1, dec.origin);
  crdt_op_free_fields(&dec);
}

static void test_op_decode_rejects_oob_tag_origin(void **state)
{
  (void)state;
  struct CrdtOp op, dec;
  uint8_t buf[256];
  int n;

  mk_add_op(&op, 2, 1, (uint16_t)CRDT_MAX_SERVERS, 7);
  n = crdt_op_encode(&op, buf, sizeof buf);
  assert_true(n > 0);
  assert_int_equal(-1, crdt_op_decode(&dec, buf, (size_t)n));

  /* control: in-range tag origin decodes */
  mk_add_op(&op, 2, 1, (uint16_t)(CRDT_MAX_SERVERS - 1), 7);
  n = crdt_op_encode(&op, buf, sizeof buf);
  assert_true(n > 0);
  assert_int_equal(n, crdt_op_decode(&dec, buf, (size_t)n));
  assert_int_equal(CRDT_MAX_SERVERS - 1, dec.tag.origin);
  crdt_op_free_fields(&dec);
}

static void test_delta_apply_rejects_oob_origin(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtOp op;
  uint8_t buf[512];
  int n;

  crdt_state_init(&s, 1);
  /* delta = [count:4][one op with an OOB origin] */
  buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 1;
  mk_set_op(&op, 9999, 1);
  n = crdt_op_encode(&op, buf + 4, sizeof buf - 4);
  assert_true(n > 0);
  assert_int_equal(-1, crdt_delta_apply(&s, buf, (size_t)(4 + n)));
  assert_null(s.oplog.head);            /* nothing recorded */
  assert_int_equal(0, crdt_lwwmap_size(&s.users));
  crdt_state_clear(&s);
}

static void test_apply_op_rejects_oob_origin(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtOp op;

  crdt_state_init(&s, 1);

  /* an in-process op with an OOB ORIGIN must be skipped, not sv_update'd
   * (seq[CRDT_MAX_SERVERS] is one past the array) */
  mk_set_op(&op, (uint16_t)CRDT_MAX_SERVERS, 1);
  crdt_state_apply_op(&s, &op);
  assert_null(s.oplog.head);
  assert_int_equal(0, crdt_lwwmap_size(&s.users));

  /* an OOB TAG origin must be skipped too (it lands in the OR-Set and the
   * GC indexes stable->seq[t.origin]) */
  mk_add_op(&op, 2, 1, 0xFFFF, 3);
  crdt_state_apply_op(&s, &op);
  assert_null(s.oplog.head);

  crdt_state_clear(&s);
}

static void test_snapshot_rejects_oob_tag_origin(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  struct CrdtChannel *ch;
  struct CrdtTag bad;
  uint8_t *buf = malloc(65536);
  int n;

  assert_non_null(buf);

  /* OOB add-tag in a channel member OR-Set */
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  ch = crdt_state_channel(&s1, "#h", 1);
  assert_non_null(ch);
  bad.origin = (uint16_t)CRDT_MAX_SERVERS;
  bad.seq = 7;
  crdt_orset_merge_add(&ch->members, "AAAAA", 5, bad);
  n = crdt_snapshot_encode(&s1, buf, 65536);
  assert_true(n > 0);
  assert_int_equal(-1, crdt_snapshot_apply(&s2, buf, (size_t)n));
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);

  /* OOB tombstone tag in a ban OR-Set */
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  ch = crdt_state_channel(&s1, "#h", 1);
  assert_non_null(ch);
  bad.origin = 0xFFFF;
  bad.seq = 9;
  crdt_orset_merge_remove(&ch->bans, bad, 0);
  n = crdt_snapshot_encode(&s1, buf, 65536);
  assert_true(n > 0);
  assert_int_equal(-1, crdt_snapshot_apply(&s2, buf, (size_t)n));
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);

  /* OOB add-tag in the trailing global OR-Set section (silences) */
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);
  bad.origin = (uint16_t)CRDT_MAX_SERVERS;
  bad.seq = 11;
  crdt_orset_merge_add(&s1.silences, "k", 1, bad);
  n = crdt_snapshot_encode(&s1, buf, 65536);
  assert_true(n > 0);
  assert_int_equal(-1, crdt_snapshot_apply(&s2, buf, (size_t)n));
  crdt_state_clear(&s1);
  crdt_state_clear(&s2);

  free(buf);
}

/* ================================================================== */
/* M1 — crdt_orset_remove never reports beyond max_out                */
/* ================================================================== */

static void test_orset_remove_caps_at_max_out(void **state)
{
  (void)state;
  struct CrdtORSet set;
  struct CrdtTag out[8];
  int seen[70];
  int i, n, total = 0, rounds = 0;

  crdt_orset_init(&set);
  memset(seen, 0, sizeof seen);
  for (i = 0; i < 70; i++) {
    struct CrdtTag t;
    t.origin = 2;
    t.seq = (uint64_t)(1000 + i);
    crdt_orset_add(&set, "m", 1, t);
  }
  assert_true(crdt_orset_contains(&set, "m", 1));

  /* the caller-loop contract: each call reports AT MOST max_out removals; loop
   * until a short round.  Every removal must surface exactly once so callers
   * that mint one REMOVE op per reported tag replicate the whole removal. */
  do {
    n = crdt_orset_remove(&set, "m", 1, 0, out, 8);
    assert_in_range(n, 0, 8);        /* never beyond the caller's buffer */
    for (i = 0; i < n; i++) {
      int idx;
      assert_int_equal(2, out[i].origin);
      assert_in_range(out[i].seq, 1000, 1069);
      idx = (int)(out[i].seq - 1000);
      assert_int_equal(0, seen[idx]);      /* no duplicate reports */
      seen[idx] = 1;
      total++;
    }
    rounds++;
  } while (n == 8 && rounds < 32);

  assert_int_equal(70, total);             /* every tag reported exactly once */
  assert_false(crdt_orset_contains(&set, "m", 1));
  crdt_orset_clear(&set);
}

static void test_chan_remove_beyond_cap_replicates(void **state)
{
  (void)state;
  struct CrdtNetworkState s1, s2;
  int i;

  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  /* 70 add-tags for one member (ban-list-churn shape: re-adds mint fresh tags) */
  for (i = 0; i < 70; i++)
    crdt_chan_join(&s1, "#m", "AAAAA");
  crdt_state_sync(&s2, &s1);
  assert_int_equal(1, crdt_chan_visible_members(&s2, "#m"));

  /* one caller-level remove must fully remove AND fully replicate, even though
   * the tag count exceeds the 64-slot reporting buffer */
  crdt_chan_remove(&s1, "#m", "AAAAA", 0);
  assert_int_equal(0, crdt_chan_visible_members(&s1, "#m"));

  crdt_state_sync(&s2, &s1);
  assert_int_equal(0, crdt_chan_visible_members(&s2, "#m"));
  assert_true(crdt_state_equal(&s1, &s2));

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
}

/* ================================================================== */
/* truncation robustness                                              */
/* ================================================================== */

static void test_op_and_delta_truncation_clean(void **state)
{
  (void)state;
  struct CrdtOp op, dec;
  uint8_t buf[256], dbuf[4096];
  struct CrdtStateVector empty_sv;
  struct CrdtNetworkState src;
  size_t cut;
  int n, nd;

  /* every proper prefix of an op must fail decode cleanly */
  mk_add_op(&op, 2, 1, 2, 5);
  n = crdt_op_encode(&op, buf, sizeof buf);
  assert_true(n > 0);
  for (cut = 0; cut < (size_t)n; cut++)
    assert_int_equal(-1, crdt_op_decode(&dec, buf, cut));
  assert_int_equal(n, crdt_op_decode(&dec, buf, (size_t)n));
  crdt_op_free_fields(&dec);

  /* every proper prefix of a real delta must fail apply cleanly */
  crdt_state_init(&src, 1);
  crdt_chan_join(&src, "#t", "AAAAA");
  crdt_chan_join(&src, "#t", "BBBBB");
  crdt_sv_init(&empty_sv);
  nd = crdt_delta_encode(&src.oplog, &empty_sv, dbuf, sizeof dbuf);
  assert_true(nd > 0);
  for (cut = 0; cut < (size_t)nd; cut++) {
    struct CrdtNetworkState st;
    crdt_state_init(&st, 3);
    assert_int_equal(-1, crdt_delta_apply(&st, dbuf, cut));
    crdt_state_clear(&st);
  }
  crdt_state_clear(&src);
}

static void test_snapshot_truncation_clean(void **state)
{
  (void)state;
  struct CrdtNetworkState src;
  struct CrdtTag t;
  uint8_t *buf = malloc(65536);
  size_t cut;
  int n;

  assert_non_null(buf);
  crdt_state_init(&src, 1);
  crdt_chan_join(&src, "#t", "AAAAA");
  t.origin = 1;
  t.seq = 99;
  crdt_orset_merge_add(&src.silences, "k", 1, t);  /* include the trailing section */
  n = crdt_snapshot_encode(&src, buf, 65536);
  assert_true(n > 0);

  /* count-framed sections make SOME prefixes a valid shorter (older-format)
   * snapshot — that tolerance is deliberate (see crdt_snapshot_apply).  The
   * hard requirement is: never crash, never report success with an error. */
  for (cut = 0; cut < (size_t)n; cut++) {
    struct CrdtNetworkState st;
    int r;
    crdt_state_init(&st, 3);
    r = crdt_snapshot_apply(&st, buf, cut);
    assert_true(r == 0 || r == -1);
    crdt_state_clear(&st);
  }
  crdt_state_clear(&src);
  free(buf);
}

/* ================================================================== */
/* C4 — chunk reassembly must be bounded                              */
/* ================================================================== */

static void test_chunk_large_stream_under_cap_completes(void **state)
{
  (void)state;
  /* a legit full snapshot b64 is ~350 KiB (CR_SNAP_MAX raw * 4/3) — the
   * reassembly cap must not break it.  300 KiB must still complete. */
  static char big[1025];
  char *out = NULL;
  size_t len = 0;
  int i;

  memset(big, 'A', sizeof big - 1);
  big[sizeof big - 1] = '\0';
  for (i = 0; i < 300; i++)
    assert_int_equal(0, s2s_chunk_feed((void *)0xB16, "big", big, 1, &out, &len));
  assert_int_equal(1, s2s_chunk_feed((void *)0xB16, "big", "END", 0, &out, &len));
  assert_int_equal(300 * 1024 + 3, (int)len);
  free(out);
}

static void test_chunk_feed_caps_unterminated_stream(void **state)
{
  (void)state;
  /* a peer that NEVER sends the final chunk must not grow the slot without
   * bound: the feed must abort (-1) and free the slot well before this
   * runaway ceiling (the exact cap lives in s2s_chunk).  2048 x 1 KiB = 2 MiB
   * is far beyond any legit reassembly (~350 KiB). */
  static char big[1025];
  char *out = NULL;
  size_t len = 0;
  long fed = 0;
  int i, r = 0, aborted = 0;

  memset(big, 'A', sizeof big - 1);
  big[sizeof big - 1] = '\0';
  for (i = 0; i < 2048; i++) {
    r = s2s_chunk_feed((void *)0xF00D, "endless", big, 1, &out, &len);
    if (r == -1) { aborted = 1; break; }
    assert_int_equal(0, r);
    fed += (long)(sizeof big - 1);
  }
  assert_true(aborted);
  assert_true(fed <= 2L * 1024 * 1024);

  /* the aborted slot must be FREED: the same (link,id) starts a fresh stream */
  assert_int_equal(1, s2s_chunk_feed((void *)0xF00D, "endless", "OK", 0, &out, &len));
  assert_int_equal(2, (int)len);
  assert_string_equal("OK", out);
  free(out);
}

/* ================================================================== */
/* C2 — unknown collection byte must not deref a NULL map             */
/* (kept LAST: pre-fix this SIGSEGVs and aborts the whole binary)     */
/* ================================================================== */

static void test_apply_op_unknown_coll_ignored(void **state)
{
  (void)state;
  struct CrdtNetworkState s;
  struct CrdtOp op;
  uint8_t buf[512];
  uint64_t d0;
  int n;

  crdt_state_init(&s, 1);
  d0 = crdt_state_digest(&s);

  /* SET with a collection id this build doesn't know (a NEWER peer's op) */
  mk_set_op(&op, 2, 1);
  op.coll = (enum CrdtCollection)0x7F;
  crdt_state_apply_op(&s, &op);
  assert_true(d0 == crdt_state_digest(&s));    /* no known map touched */
  /* forward-compat: still recorded, so relay + SV dedup stay coherent */
  assert_non_null(s.oplog.head);
  assert_true(crdt_sv_has_seen(&s.local_sv, 2, 1));

  /* DELETE flavor takes the same NULL-map path */
  mk_set_op(&op, 2, 2);
  op.type = CRDT_OP_DELETE;
  op.coll = (enum CrdtCollection)0x7E;
  op.val = NULL;
  op.val_len = 0;
  crdt_state_apply_op(&s, &op);
  assert_true(d0 == crdt_state_digest(&s));
  assert_true(crdt_sv_has_seen(&s.local_sv, 2, 2));

  /* and end-to-end through the wire: a delta carrying an unknown-coll op
   * applies (returns 1) instead of crashing or rejecting the whole delta */
  buf[0] = 0; buf[1] = 0; buf[2] = 0; buf[3] = 1;
  mk_set_op(&op, 2, 3);
  op.coll = (enum CrdtCollection)0x70;
  n = crdt_op_encode(&op, buf + 4, sizeof buf - 4);
  assert_true(n > 0);
  assert_int_equal(1, crdt_delta_apply(&s, buf, (size_t)(4 + n)));
  assert_true(d0 == crdt_state_digest(&s));

  crdt_state_clear(&s);
}

/* ================================================================== */

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_op_decode_rejects_oob_origin),
    cmocka_unit_test(test_op_decode_rejects_oob_tag_origin),
    cmocka_unit_test(test_delta_apply_rejects_oob_origin),
    cmocka_unit_test(test_apply_op_rejects_oob_origin),
    cmocka_unit_test(test_snapshot_rejects_oob_tag_origin),
    cmocka_unit_test(test_orset_remove_caps_at_max_out),
    cmocka_unit_test(test_chan_remove_beyond_cap_replicates),
    cmocka_unit_test(test_op_and_delta_truncation_clean),
    cmocka_unit_test(test_snapshot_truncation_clean),
    cmocka_unit_test(test_chunk_large_stream_under_cap_completes),
    cmocka_unit_test(test_chunk_feed_caps_unterminated_stream),
    cmocka_unit_test(test_apply_op_unknown_coll_ignored),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
