/*
 * crdt_wire.c - Binary wire serialization for CRDT sync (Phase 2)
 *
 * Implements crdt_wire.h. Big-endian, bounds-checked. libc + crdt_types +
 * crdt_state only — unit-testable in isolation (see ircd/test/crdt_cmocka.c).
 */

#include "crdt_wire.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* big-endian write cursor                                            */
/* ------------------------------------------------------------------ */

struct wbuf { uint8_t *p; size_t cap; size_t off; int err; };

static void wput(struct wbuf *w, const void *src, size_t n)
{
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
  memcpy(*out, r->p + r->off, n);
  r->off += n;
}

/* ================================================================== */
/* state vector                                                       */
/* ================================================================== */

int crdt_sv_encode(const struct CrdtStateVector *sv, uint8_t *buf, size_t cap)
{
  struct wbuf w = { buf, cap, 0, 0 };
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
  struct wbuf w = { buf, cap, 0, 0 };
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
  return (int)r.off;
}

/* ================================================================== */
/* delta                                                              */
/* ================================================================== */

int crdt_delta_encode(const struct CrdtOpLog *log,
                      const struct CrdtStateVector *remote,
                      uint8_t *buf, size_t cap)
{
  struct wbuf w = { buf, cap, 0, 0 };
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
  return applied;
}
