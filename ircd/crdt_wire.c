/*
 * crdt_wire.c - Binary wire serialization for CRDT sync (Phase 2)
 *
 * Implements crdt_wire.h. Big-endian, bounds-checked. libc + crdt_types +
 * crdt_state only — unit-testable in isolation (see ircd/test/crdt_cmocka.c).
 */

#include "crdt_wire.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* big-endian write cursor                                            */
/* ------------------------------------------------------------------ */

/* @a need accumulates the total bytes the encode requires REGARDLESS of
 * overflow, so an overflowing encoder (crdt_snapshot_encode) can report the
 * document size vs. cap to its integration caller. @a off stops advancing once
 * @a err is set; @a need does not. */
struct wbuf { uint8_t *p; size_t cap; size_t off; int err; size_t need; };

static void wput(struct wbuf *w, const void *src, size_t n)
{
  w->need += n;
  if (w->err || w->off + n > w->cap) { w->err = 1; return; }
  memcpy(w->p + w->off, src, n);
  w->off += n;
}
static void wput_u8(struct wbuf *w, uint8_t v) { wput(w, &v, 1); }
static void wput_u16(struct wbuf *w, uint16_t v)
{ uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v }; wput(w, b, 2); }
static void wput_u32(struct wbuf *w, uint32_t v)
{ uint8_t b[4] = { (uint8_t)(v>>24),(uint8_t)(v>>16),(uint8_t)(v>>8),(uint8_t)v }; wput(w, b, 4); }
static void wput_u64(struct wbuf *w, uint64_t v)
{ uint8_t b[8]; int i; for (i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (56 - 8*i)); wput(w, b, 8); }

/* ------------------------------------------------------------------ */
/* big-endian read cursor                                            */
/* ------------------------------------------------------------------ */

struct rbuf { const uint8_t *p; size_t len; size_t off; int err; };

static void rget(struct rbuf *r, void *dst, size_t n)
{
  if (r->err || r->off + n > r->len) { r->err = 1; return; }
  memcpy(dst, r->p + r->off, n);
  r->off += n;
}
static uint8_t rget_u8(struct rbuf *r) { uint8_t v = 0; rget(r, &v, 1); return v; }
static uint16_t rget_u16(struct rbuf *r)
{ uint8_t b[2] = {0}; rget(r, b, 2); return (uint16_t)((b[0] << 8) | b[1]); }
static uint32_t rget_u32(struct rbuf *r)
{ uint8_t b[4] = {0}; rget(r, b, 4);
  return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3]; }
static uint64_t rget_u64(struct rbuf *r)
{
  uint8_t b[8] = {0};
  uint64_t v = 0;
  int i;
  rget(r, b, 8);
  for (i = 0; i < 8; i++)
    v = (v << 8) | b[i];
  return v;
}

/* Read a length-prefixed blob into a freshly malloc'd buffer (NULL if n==0). */
static void rget_blob(struct rbuf *r, void **out, size_t n)
{
  if (n == 0) { *out = NULL; return; }
  if (r->err || r->off + n > r->len) { r->err = 1; *out = NULL; return; }
  *out = malloc(n);
  if (!*out) { r->err = 1; return; }     /* never memcpy after a failed alloc */
  memcpy(*out, r->p + r->off, n);
  r->off += n;
}

/* ================================================================== */
/* state vector                                                       */
/* ================================================================== */

int crdt_sv_encode(const struct CrdtStateVector *sv, uint8_t *buf, size_t cap)
{
  struct wbuf w = { buf, cap, 0, 0, 0 };
  uint16_t count = 0;
  int i;
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    if (sv->seq[i]) count++;
  wput_u16(&w, count);
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    if (sv->seq[i]) { wput_u16(&w, (uint16_t)i); wput_u64(&w, sv->seq[i]); }
  return w.err ? -1 : (int)w.off;
}

int crdt_sv_decode(struct CrdtStateVector *sv, const uint8_t *buf, size_t len)
{
  struct rbuf r = { buf, len, 0, 0 };
  uint16_t count, i;
  crdt_sv_init(sv);
  count = rget_u16(&r);
  for (i = 0; i < count; i++) {
    uint16_t o = rget_u16(&r);
    uint64_t s = rget_u64(&r);
    if (!r.err && o < CRDT_MAX_SERVERS) sv->seq[o] = s;
  }
  return r.err ? -1 : (int)r.off;
}

/* ================================================================== */
/* single operation                                                   */
/* ================================================================== */

int crdt_op_encode(const struct CrdtOp *op, uint8_t *buf, size_t cap)
{
  struct wbuf w = { buf, cap, 0, 0, 0 };
  wput_u16(&w, op->origin);
  wput_u64(&w, op->seq);
  wput_u8(&w, (uint8_t)op->type);
  wput_u8(&w, (uint8_t)op->coll);
  wput_u16(&w, (uint16_t)op->chan_len);
  if (op->chan_len) wput(&w, op->chan, op->chan_len);
  wput_u16(&w, (uint16_t)op->key_len);
  if (op->key_len) wput(&w, op->key, op->key_len);
  wput_u16(&w, op->tag.origin);
  wput_u64(&w, op->tag.seq);
  wput_u8(&w, op->priority);
  wput_u64(&w, op->ts.physical_ms);
  wput_u16(&w, op->ts.logical);
  wput_u16(&w, op->ts.node_id);
  wput_u16(&w, op->writer);
  wput_u32(&w, op->val_len);
  if (op->val_len) wput(&w, op->val, op->val_len);
  return w.err ? -1 : (int)w.off;
}

void crdt_op_free_fields(struct CrdtOp *op)
{
  free(op->chan); op->chan = NULL;
  free(op->key);  op->key = NULL;
  free(op->val);  op->val = NULL;
}

int crdt_op_decode(struct CrdtOp *op, const uint8_t *buf, size_t len)
{
  struct rbuf r = { buf, len, 0, 0 };
  memset(op, 0, sizeof *op);
  op->origin = rget_u16(&r);
  op->seq = rget_u64(&r);
  op->type = (enum CrdtOpType)rget_u8(&r);
  op->coll = (enum CrdtCollection)rget_u8(&r);
  op->chan_len = rget_u16(&r);
  rget_blob(&r, (void **)&op->chan, op->chan_len);
  op->key_len = rget_u16(&r);
  rget_blob(&r, (void **)&op->key, op->key_len);
  op->tag.origin = rget_u16(&r);
  op->tag.seq = rget_u64(&r);
  op->priority = rget_u8(&r);
  op->ts.physical_ms = rget_u64(&r);
  op->ts.logical = rget_u16(&r);
  op->ts.node_id = rget_u16(&r);
  op->writer = rget_u16(&r);
  op->val_len = rget_u32(&r);
  rget_blob(&r, &op->val, op->val_len);
  if (r.err) { crdt_op_free_fields(op); return -1; }
  /* origin/tag.origin index seq[CRDT_MAX_SERVERS] downstream (sv_has_seen /
   * sv_update — a conditional WRITE — and the OR-Set GC) — reject OOB at the
   * trust boundary, mirroring crdt_sv_decode.  Never remap to another slot:
   * that would corrupt a real server's SV entry. */
  if (op->origin >= CRDT_MAX_SERVERS || op->tag.origin >= CRDT_MAX_SERVERS) {
    crdt_op_free_fields(op);
    return -1;
  }
  return (int)r.off;
}

/* ================================================================== */
/* delta                                                              */
/* ================================================================== */

int crdt_delta_encode(const struct CrdtOpLog *log,
                      const struct CrdtStateVector *remote,
                      uint8_t *buf, size_t cap)
{
  struct wbuf w = { buf, cap, 0, 0, 0 };
  struct CrdtOp *op;
  uint32_t count = 0;
  wput_u32(&w, 0);                 /* count placeholder at offset 0 */
  for (op = log->head; op; op = op->next) {
    if (op->seq > remote->seq[op->origin]) {
      int n = crdt_op_encode(op, w.p + w.off, w.cap - w.off);
      if (n < 0) { w.err = 1; break; }
      w.off += (size_t)n;
      count++;
    }
  }
  if (w.err) return -1;
  buf[0] = (uint8_t)(count >> 24); buf[1] = (uint8_t)(count >> 16);
  buf[2] = (uint8_t)(count >> 8);  buf[3] = (uint8_t)count;
  return (int)w.off;
}

int crdt_delta_apply(struct CrdtNetworkState *st,
                     const uint8_t *buf, size_t len)
{
  struct rbuf r = { buf, len, 0, 0 };
  uint32_t count, i;
  int applied = 0;
  count = rget_u32(&r);
  if (r.err) return -1;
  for (i = 0; i < count; i++) {
    struct CrdtOp op;
    int n = crdt_op_decode(&op, r.p + r.off, r.len - r.off);
    if (n < 0) return -1;
    r.off += (size_t)n;
    if (!crdt_sv_has_seen(&st->local_sv, op.origin, op.seq)) {
      crdt_state_apply_op(st, &op);
      applied++;
    }
    crdt_op_free_fields(&op);
  }
  crdt_state_resume_seq(st);   /* resume our seq past any adopted SV (restart epoch) */
  return applied;
}

/* ================================================================== */
/* full-state snapshot (CR F)                                         */
/* ================================================================== */

/* Patch a u32 already written at offset @a off (inside the written region). */
static void wpatch_u32(struct wbuf *w, size_t off, uint32_t v)
{
  if (off + 4 > w->cap) { w->err = 1; return; }
  w->p[off]     = (uint8_t)(v >> 24);
  w->p[off + 1] = (uint8_t)(v >> 16);
  w->p[off + 2] = (uint8_t)(v >> 8);
  w->p[off + 3] = (uint8_t)v;
}

/* Encode every entry of one LWW map (including deletes) under collection id. */
static void snap_put_lww(struct wbuf *w, const struct CrdtLWWMap *m,
                         uint8_t coll, uint32_t *total)
{
  uint32_t b;
  for (b = 0; b < m->nbuckets; b++) {
    struct CrdtLWWEntry *e;
    for (e = m->buckets[b]; e; e = e->ht_next) {
      wput_u8(w, coll);
      wput_u16(w, (uint16_t)e->key_len);
      wput(w, e->key, e->key_len);
      wput_u8(w, (uint8_t)(e->deleted ? 1 : 0));
      wput_u64(w, e->val.ts.physical_ms);
      wput_u16(w, e->val.ts.logical);
      wput_u16(w, e->val.ts.node_id);
      wput_u16(w, e->val.writer);
      if (e->deleted) {
        wput_u32(w, 0);
      } else {
        wput_u32(w, e->val.data_len);
        if (e->val.data_len) wput(w, e->val.data, e->val.data_len);
      }
      (*total)++;
    }
  }
}

/* Encode one OR-Set: [add_count] adds [tomb_count] tombs. */
static void snap_put_orset(struct wbuf *w, const struct CrdtORSet *s)
{
  size_t add_off, tomb_off;
  uint32_t add_n = 0, tomb_n = 0, b;
  uint16_t i;
  add_off = w->off; wput_u32(w, 0);
  for (b = 0; b < s->nbuckets; b++) {
    struct CrdtORSetEntry *e;
    for (e = s->buckets[b]; e; e = e->ht_next)
      for (i = 0; i < e->add_count; i++) {
        wput_u16(w, (uint16_t)e->key_len);
        wput(w, e->key, e->key_len);
        wput_u16(w, e->add_tags[i].origin);
        wput_u64(w, e->add_tags[i].seq);
        add_n++;
      }
  }
  wpatch_u32(w, add_off, add_n);
  tomb_off = w->off; wput_u32(w, 0);
  for (b = 0; b < s->tomb_nbuckets; b++) {
    struct CrdtTombstone *t;
    for (t = s->tomb[b]; t; t = t->ht_next) {
      wput_u16(w, t->tag.origin);
      wput_u64(w, t->tag.seq);
      wput_u8(w, t->priority);
      tomb_n++;
    }
  }
  wpatch_u32(w, tomb_off, tomb_n);
}

int crdt_snapshot_encode(const struct CrdtNetworkState *st,
                         uint8_t *buf, size_t cap)
{
  struct wbuf w = { buf, cap, 0, 0, 0 };
  size_t sv_off, lww_off, chan_off;
  uint32_t lww_total = 0, chan_n = 0;
  int svn, b;

  /* state vector, length-prefixed (encoded straight into the buffer) */
  sv_off = w.off;
  wput_u16(&w, 0);                              /* length placeholder */
  if (w.err) return -1;
  svn = crdt_sv_encode(&st->local_sv, w.p + w.off, w.cap - w.off);
  if (svn < 0) return -1;
  w.off += (size_t)svn;
  w.need += (size_t)svn;    /* SV body bypasses wput; count it for the overflow report */
  w.p[sv_off]     = (uint8_t)((unsigned)svn >> 8);
  w.p[sv_off + 1] = (uint8_t)svn;

  /* LWW maps (count is dynamic; the decoder routes each entry by its coll byte
   * via crdt_state_lww_for, so adding maps here needs no decoder change) */
  lww_off = w.off; wput_u32(&w, 0);
  snap_put_lww(&w, &st->servers, (uint8_t)CRDT_COLL_SERVERS, &lww_total);
  snap_put_lww(&w, &st->users,   (uint8_t)CRDT_COLL_USERS,   &lww_total);
  snap_put_lww(&w, &st->nicks,   (uint8_t)CRDT_COLL_NICKS,   &lww_total);
  snap_put_lww(&w, &st->topics,  (uint8_t)CRDT_COLL_TOPICS,  &lww_total);
  snap_put_lww(&w, &st->modes,   (uint8_t)CRDT_COLL_MODES,   &lww_total);
  snap_put_lww(&w, &st->members_status, (uint8_t)CRDT_COLL_MEMBER_STATUS, &lww_total);
  snap_put_lww(&w, &st->kick_info, (uint8_t)CRDT_COLL_KICK_INFO, &lww_total);
  snap_put_lww(&w, &st->chanmeta, (uint8_t)CRDT_COLL_CHANMETA, &lww_total);
  snap_put_lww(&w, &st->glines, (uint8_t)CRDT_COLL_GLINES, &lww_total);
  snap_put_lww(&w, &st->shuns, (uint8_t)CRDT_COLL_SHUNS, &lww_total);
  snap_put_lww(&w, &st->zlines, (uint8_t)CRDT_COLL_ZLINES, &lww_total);
  snap_put_lww(&w, &st->jupes, (uint8_t)CRDT_COLL_JUPES, &lww_total);
  snap_put_lww(&w, &st->bsessions, (uint8_t)CRDT_COLL_BSESSIONS, &lww_total); /* 5-5e */
  snap_put_lww(&w, &st->bconns, (uint8_t)CRDT_COLL_BCONNS, &lww_total);       /* 5-5e M4 */
  snap_put_lww(&w, &st->bleases, (uint8_t)CRDT_COLL_BLEASES, &lww_total);     /* 5-5e M5 */
  snap_put_lww(&w, &st->markers, (uint8_t)CRDT_COLL_MARKERS, &lww_total);     /* Tier C F2-a */
  snap_put_lww(&w, &st->metadata, (uint8_t)CRDT_COLL_METADATA, &lww_total);   /* Tier C F2-b */
  snap_put_lww(&w, &st->tempshuns, (uint8_t)CRDT_COLL_TEMPSHUNS, &lww_total); /* Tier C F3 */
  snap_put_lww(&w, &st->webpush, (uint8_t)CRDT_COLL_WEBPUSH, &lww_total);     /* Tier C F2-c */
  snap_put_lww(&w, &st->decommissions, (uint8_t)CRDT_COLL_DECOMMISSIONS, &lww_total); /* decommission markers */
  wpatch_u32(&w, lww_off, lww_total);

  /* channels: members / bans / excepts */
  chan_off = w.off; wput_u32(&w, 0);
  for (b = 0; b < CRDT_CHAN_BUCKETS; b++) {
    struct CrdtChannel *c;
    for (c = st->chan_buckets[b]; c; c = c->next) {
      wput_u16(&w, (uint16_t)c->name_len);
      wput(&w, c->name, c->name_len);
      snap_put_orset(&w, &c->members);
      snap_put_orset(&w, &c->bans);
      snap_put_orset(&w, &c->excepts);
      /* Phase 3j: ctime incarnation min-register {value, set_hlc, del_hlc} */
      wput_u64(&w, c->ctime);
      wput_u64(&w, c->ctime_set.physical_ms);
      wput_u16(&w, c->ctime_set.logical);
      wput_u16(&w, c->ctime_set.node_id);
      wput_u64(&w, c->ctime_del.physical_ms);
      wput_u16(&w, c->ctime_del.logical);
      wput_u16(&w, c->ctime_del.node_id);
      chan_n++;
    }
  }
  wpatch_u32(&w, chan_off, chan_n);

  /* Tier C F1-c: global OR-Sets (count-framed, coll-byte routed). Appended AFTER
   * channels so it is forward/backward tolerant: an older decoder stops after the
   * channel section and ignores these trailing bytes; a newer decoder reads them
   * only when bytes remain (see crdt_snapshot_apply). */
  {
    size_t go_off = w.off;
    uint32_t go_n = 0;
    wput_u32(&w, 0);
    wput_u8(&w, (uint8_t)CRDT_COLL_SILENCES);
    snap_put_orset(&w, &st->silences);
    go_n++;
    wpatch_u32(&w, go_off, go_n);
  }

  if (w.err) {
    /* Overflow: the document does not fit in @a cap, so no CR F snapshot can be
     * built.  Return a NEGATIVE value whose magnitude is the number of bytes the
     * full snapshot needs, so the integration caller (m_crdt.c send_crdt_snapshot)
     * can name doc-size-vs-cap in an operator warning rather than silently drop.
     * The engine stays pure — it detects, it never logs.  Clamp the (astronomical,
     * never-in-practice) >INT_MAX case so the magnitude survives the int return. */
    return w.need > (size_t)INT_MAX ? -INT_MAX : -(int)w.need;
  }
  return (int)w.off;
}

/* Decode + merge one OR-Set. Returns 0 ok, -1 malformed. */
static int snap_get_orset(struct rbuf *r, struct CrdtORSet *set)
{
  uint32_t add_n, tomb_n, j;
  add_n = rget_u32(r);
  if (r->err) return -1;
  for (j = 0; j < add_n; j++) {
    uint16_t klen = rget_u16(r);
    const uint8_t *kp;
    struct CrdtTag tag;
    if (r->err || r->off + klen > r->len) return -1;
    kp = r->p + r->off; r->off += klen;
    tag.origin = rget_u16(r);
    tag.seq = rget_u64(r);
    if (r->err) return -1;
    if (tag.origin >= CRDT_MAX_SERVERS) return -1;  /* indexes seq[] in GC — reject */
    crdt_orset_merge_add(set, (const char *)kp, klen, tag);   /* copies key */
  }
  tomb_n = rget_u32(r);
  if (r->err) return -1;
  for (j = 0; j < tomb_n; j++) {
    struct CrdtTag tag;
    uint8_t prio;
    tag.origin = rget_u16(r);
    tag.seq = rget_u64(r);
    prio = rget_u8(r);
    if (r->err) return -1;
    if (tag.origin >= CRDT_MAX_SERVERS) return -1;  /* indexes seq[] in GC — reject */
    crdt_orset_merge_remove(set, tag, prio);
  }
  return 0;
}

int crdt_snapshot_apply(struct CrdtNetworkState *st,
                        const uint8_t *buf, size_t len)
{
  struct rbuf r = { buf, len, 0, 0 };
  struct CrdtStateVector snap_sv;
  uint16_t svlen;
  uint32_t lww_total, chan_n, i;

  /* state vector */
  svlen = rget_u16(&r);
  if (r.err || r.off + svlen > r.len) return -1;
  if (crdt_sv_decode(&snap_sv, r.p + r.off, svlen) < 0) return -1;
  r.off += svlen;

  /* LWW entries */
  lww_total = rget_u32(&r);
  if (r.err) return -1;
  for (i = 0; i < lww_total; i++) {
    uint8_t coll, deleted;
    uint16_t klen, writer;
    uint32_t vlen;
    char *key = NULL;
    void *val = NULL;
    struct HLC ts;
    struct CrdtLWWMap *map;
    coll = rget_u8(&r);
    klen = rget_u16(&r);
    rget_blob(&r, (void **)&key, klen);
    deleted = rget_u8(&r);
    ts.physical_ms = rget_u64(&r);
    ts.logical = rget_u16(&r);
    ts.node_id = rget_u16(&r);
    writer = rget_u16(&r);
    vlen = rget_u32(&r);
    rget_blob(&r, &val, vlen);
    if (r.err) { free(key); free(val); return -1; }
    map = crdt_state_lww_for(st, (enum CrdtCollection)coll);
    if (map) {
      if (deleted)
        crdt_lwwmap_delete(map, key ? key : "", klen, ts, writer);
      else if (coll == (uint8_t)CRDT_COLL_BLEASES &&
               vlen == sizeof(struct CrdtBouncerLease))
        /* 5-5e M5: comparator-merge, NOT a generic HLC-LWW assign (which would regress
         * the lease to a clock-skewed loser on snapshot catch-up). Mirrors ctime. */
        crdt_blease_merge_snapshot(st, key ? key : "", klen,
                                   (const struct CrdtBouncerLease *)val, writer, ts);
      else if (coll == (uint8_t)CRDT_COLL_MARKERS && vlen)
        /* Tier C F2-a: lexical-MAX-register merge, NOT a generic HLC-LWW assign (which
         * would regress a read-marker on snapshot catch-up). Mirrors blease/ctime. */
        crdt_marker_merge_snapshot(st, key ? key : "", klen, val, vlen, writer, ts);
      else if (coll == (uint8_t)CRDT_COLL_TOPICS && vlen > sizeof(uint64_t))
        /* M11: topic_time MAX-register merge, NOT a generic HLC-LWW assign (which would
         * regress a topic to a clock-skewed lower-topic_time on snapshot catch-up and
         * re-open the legacy P10 split). Mirrors marker/blease/ctime. */
        crdt_topic_merge_snapshot(st, key ? key : "", klen, val, vlen, writer, ts);
      else
        crdt_lwwmap_set(map, key ? key : "", klen, val, vlen, ts, writer);
    }
    free(key); free(val);
  }

  /* channels */
  chan_n = rget_u32(&r);
  if (r.err) return -1;
  for (i = 0; i < chan_n; i++) {
    char cname[512];
    uint16_t nlen = rget_u16(&r);
    struct CrdtChannel *ch;
    if (r.err || nlen >= sizeof cname || r.off + nlen > r.len) return -1;
    memcpy(cname, r.p + r.off, nlen);
    cname[nlen] = '\0';
    r.off += nlen;
    ch = crdt_state_channel(st, cname, 1);
    if (!ch) return -1;
    if (snap_get_orset(&r, &ch->members) < 0) return -1;
    if (snap_get_orset(&r, &ch->bans) < 0) return -1;
    if (snap_get_orset(&r, &ch->excepts) < 0) return -1;
    /* Phase 3j: ctime register — MERGE (not assign) so snapshot catch-up on a
     * non-fresh replica can't regress the min-resolved value. */
    {
      uint64_t cv = rget_u64(&r);
      struct HLC cs, cd;
      cs.physical_ms = rget_u64(&r);
      cs.logical = rget_u16(&r);
      cs.node_id = rget_u16(&r);
      cd.physical_ms = rget_u64(&r);
      cd.logical = rget_u16(&r);
      cd.node_id = rget_u16(&r);
      if (r.err) return -1;
      crdt_chan_ctime_merge(st, cname, nlen, cv, cs, cd);
    }
  }

  /* Tier C F1-c: global OR-Sets — present only in newer snapshots. Guard on
   * bytes-remaining so an OLDER snapshot (no trailing section) is tolerated
   * (no spurious r.err -> no reject). Count-framed + coll-byte routed. */
  if (!r.err && r.off < r.len) {
    uint32_t go_n = rget_u32(&r), gi;
    for (gi = 0; gi < go_n && !r.err; gi++) {
      uint8_t coll = rget_u8(&r);
      if (coll == (uint8_t)CRDT_COLL_SILENCES) {
        if (snap_get_orset(&r, &st->silences) < 0) return -1;
      } else {
        return -1;  /* unknown global OR-Set (a newer peer's collection) — reject;
                     * snap_get_orset is self-framing but unskippable blind, so a
                     * fresh snapshot will be re-requested. No second one exists yet. */
      }
    }
  }

  if (r.err) return -1;

  /* we now know everything up to the sender's SV (own newer ops are preserved
   * by the merge semantics; crdt_sv_update never lowers) */
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    crdt_sv_update(&st->local_sv, (uint16_t)i, snap_sv.seq[i]);
  crdt_state_resume_seq(st);   /* resume our seq past the adopted SV (restart epoch) */

  /* Phase 4c: a snapshot delivers STATE up to snap_sv but NO ops below it — those
   * seq ranges are unserveable as deltas from here.  Raise gc_floor to snap_sv so
   * a peer still behind that point is detected as below-floor and served a fresh
   * snapshot (crdt_shadow_peer_behind_floor -> send_crdt_snapshot) instead of an
   * empty/incomplete delta that would leave it permanently stale.  This is the
   * op-level analog of resume_seq; without it, state acquired via a relink
   * snapshot cannot RE-PROPAGATE to a third node (the mesh-merge gap that the
   * partition/merge demo exposed).  crdt_sv_update never lowers, so this only
   * raises the floor. */
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    crdt_sv_update(&st->gc_floor, (uint16_t)i, snap_sv.seq[i]);

  return 0;
}

/* ================================================================== */
/* base64 (RFC 4648)                                                  */
/* ================================================================== */

static const char B64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int crdt_b64_encode(const uint8_t *in, size_t inlen, char *out, size_t cap)
{
  size_t need = ((inlen + 2) / 3) * 4 + 1;
  size_t i = 0, o = 0, rem;
  if (cap < need) return -1;
  while (i + 3 <= inlen) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = B64[(v >> 6) & 63];
    out[o++] = B64[v & 63];
    i += 3;
  }
  rem = inlen - i;
  if (rem == 1) {
    uint32_t v = (uint32_t)in[i] << 16;
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = '='; out[o++] = '=';
  } else if (rem == 2) {
    uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8);
    out[o++] = B64[(v >> 18) & 63];
    out[o++] = B64[(v >> 12) & 63];
    out[o++] = B64[(v >> 6) & 63];
    out[o++] = '=';
  }
  out[o] = '\0';
  return (int)o;
}

int crdt_b64_decode(const char *in, uint8_t *out, size_t cap)
{
  int8_t rev[256];
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0, i;
  const char *p;
  for (i = 0; i < 256; i++) rev[i] = -1;
  for (i = 0; i < 64; i++) rev[(unsigned char)B64[i]] = (int8_t)i;
  for (p = in; *p; p++) {
    int8_t d;
    if (*p == '=') break;
    d = rev[(unsigned char)*p];
    if (d < 0) continue;                 /* skip whitespace/newlines */
    acc = (acc << 6) | (uint32_t)d;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o >= cap) return -1;
      out[o++] = (uint8_t)((acc >> bits) & 0xff);
    }
  }
  return (int)o;
}
