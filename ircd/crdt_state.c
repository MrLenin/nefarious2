/*
 * crdt_state.c - IRC network state composed from CRDT primitives
 *
 * Implements crdt_state.h: network-state composition, the operation log used
 * for delta sync, the nick-collision resolution state machine (§17.5), and
 * SQUIT-as-server-state-transition (§17.3). libc + crdt_hlc + crdt_types only.
 *
 * Phase 0 PoC (CRDT-mesh proposal §17.1.6, 17.3, 17.5).
 */

#include "crdt_state.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* helpers                                                            */
/* ------------------------------------------------------------------ */

static void *xmalloc(size_t n) { return malloc(n ? n : 1); }
static void *memdup(const void *d, uint32_t n)
{
  void *p = xmalloc(n);
  if (d && n) memcpy(p, d, n);
  return p;
}

/** Format a server numeric as a decimal string key. Returns length. */
static uint32_t server_key(uint16_t numeric, char *buf, size_t buflen)
{
  int n = snprintf(buf, buflen, "%u", (unsigned)numeric);
  return (uint32_t)(n < 0 ? 0 : n);
}

/* ------------------------------------------------------------------ */
/* operation log                                                      */
/* ------------------------------------------------------------------ */

static struct CrdtOp *op_new(uint16_t origin, uint64_t seq,
                             enum CrdtOpType type, enum CrdtCollection coll)
{
  struct CrdtOp *op = xmalloc(sizeof(*op));
  memset(op, 0, sizeof(*op));
  op->origin = origin;
  op->seq = seq;
  op->type = type;
  op->coll = coll;
  return op;
}

static struct CrdtOp *op_clone(const struct CrdtOp *src)
{
  struct CrdtOp *op = xmalloc(sizeof(*op));
  *op = *src;
  op->next = NULL;
  if (src->chan) op->chan = memdup(src->chan, src->chan_len);
  if (src->key) op->key = memdup(src->key, src->key_len);
  if (src->val) op->val = memdup(src->val, src->val_len);
  return op;
}

static void op_free(struct CrdtOp *op)
{
  free(op->chan);
  free(op->key);
  free(op->val);
  free(op);
}

static void oplog_append(struct CrdtOpLog *log, struct CrdtOp *op)
{
  op->next = NULL;
  if (log->tail) log->tail->next = op;
  else log->head = op;
  log->tail = op;
  log->count++;
}

/* ------------------------------------------------------------------ */
/* channel table                                                      */
/* ------------------------------------------------------------------ */

static uint32_t chan_hash(const char *name, uint32_t len)
{
  uint32_t h = 2166136261u;
  for (uint32_t i = 0; i < len; i++) { h ^= (unsigned char)name[i]; h *= 16777619u; }
  return h % CRDT_CHAN_BUCKETS;
}

static struct CrdtChannel *chan_find(const struct CrdtNetworkState *st,
                                     const char *name, uint32_t len)
{
  uint32_t b = chan_hash(name, len);
  for (struct CrdtChannel *c = st->chan_buckets[b]; c; c = c->next)
    if (c->name_len == len && memcmp(c->name, name, len) == 0) return c;
  return NULL;
}

static struct CrdtChannel *chan_get(struct CrdtNetworkState *st,
                                    const char *name, uint32_t len, int create)
{
  struct CrdtChannel *c = chan_find(st, name, len);
  if (c || !create) return c;
  uint32_t b = chan_hash(name, len);
  c = xmalloc(sizeof(*c));
  memset(c, 0, sizeof(*c));
  c->name = memdup(name, len);
  c->name_len = len;
  crdt_orset_init(&c->members);
  crdt_orset_init(&c->bans);
  crdt_orset_init(&c->excepts);
  c->next = st->chan_buckets[b];
  st->chan_buckets[b] = c;
  return c;
}

struct CrdtChannel *crdt_state_channel(struct CrdtNetworkState *st,
                                       const char *chan, int create)
{
  return chan_get(st, chan, (uint32_t)strlen(chan), create);
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                          */
/* ------------------------------------------------------------------ */

void crdt_state_init(struct CrdtNetworkState *st, uint16_t my_numeric)
{
  memset(st, 0, sizeof(*st));
  st->my_numeric = my_numeric;
  st->next_seq = 1;
  st->clock.physical_ms = 0;
  st->clock.logical = 0;
  st->clock.node_id = my_numeric;
  crdt_sv_init(&st->local_sv);
  crdt_sv_init(&st->gc_floor);
  crdt_lwwmap_init(&st->servers);
  crdt_lwwmap_init(&st->users);
  crdt_lwwmap_init(&st->nicks);
  crdt_lwwmap_init(&st->topics);
  crdt_lwwmap_init(&st->modes);
  crdt_lwwmap_init(&st->members_status);
  crdt_lwwmap_init(&st->kick_info);
  crdt_lwwmap_init(&st->chanmeta);
  crdt_lwwmap_init(&st->glines);
  crdt_lwwmap_init(&st->shuns);
  crdt_lwwmap_init(&st->zlines);
  crdt_lwwmap_init(&st->jupes);
  crdt_lwwmap_init(&st->bsessions);
  crdt_lwwmap_init(&st->bconns);
  crdt_lwwmap_init(&st->bleases);
  crdt_lwwmap_init(&st->markers);
  crdt_lwwmap_init(&st->metadata);
  crdt_lwwmap_init(&st->tempshuns);
  crdt_orset_init(&st->silences);
}

void crdt_state_clear(struct CrdtNetworkState *st)
{
  struct CrdtOp *op = st->oplog.head;
  while (op) { struct CrdtOp *n = op->next; op_free(op); op = n; }
  crdt_lwwmap_clear(&st->servers);
  crdt_lwwmap_clear(&st->users);
  crdt_lwwmap_clear(&st->nicks);
  crdt_lwwmap_clear(&st->topics);
  crdt_lwwmap_clear(&st->modes);
  crdt_lwwmap_clear(&st->members_status);
  crdt_lwwmap_clear(&st->kick_info);
  crdt_lwwmap_clear(&st->chanmeta);
  crdt_lwwmap_clear(&st->glines);
  crdt_lwwmap_clear(&st->shuns);
  crdt_lwwmap_clear(&st->zlines);
  crdt_lwwmap_clear(&st->jupes);
  crdt_lwwmap_clear(&st->bsessions);
  crdt_lwwmap_clear(&st->bconns);
  crdt_lwwmap_clear(&st->bleases);
  crdt_lwwmap_clear(&st->markers);
  crdt_lwwmap_clear(&st->metadata);
  crdt_lwwmap_clear(&st->tempshuns);
  crdt_orset_clear(&st->silences);
  for (int b = 0; b < CRDT_CHAN_BUCKETS; b++) {
    struct CrdtChannel *c = st->chan_buckets[b];
    while (c) {
      struct CrdtChannel *n = c->next;
      crdt_orset_clear(&c->members);
      crdt_orset_clear(&c->bans);
      crdt_orset_clear(&c->excepts);
      free(c->name);
      free(c);
      c = n;
    }
  }
  memset(st, 0, sizeof(*st));
}

/* ------------------------------------------------------------------ */
/* local mutations (mutate structure + record op + advance SV)        */
/* ------------------------------------------------------------------ */

static void record(struct CrdtNetworkState *st, struct CrdtOp *op)
{
  oplog_append(&st->oplog, op);
  crdt_sv_update(&st->local_sv, op->origin, op->seq);
}

void crdt_user_set(struct CrdtNetworkState *st, const char *numeric,
                   const struct CrdtUserRecord *rec)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(numeric);
  crdt_lwwmap_set(&st->users, numeric, klen, rec, sizeof(*rec),
                  ts, st->my_numeric);
  uint64_t seq = st->next_seq++;
  struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_USERS);
  op->key = memdup(numeric, klen);
  op->key_len = klen;
  op->val = memdup(rec, sizeof(*rec));
  op->val_len = sizeof(*rec);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_user_remove(struct CrdtNetworkState *st, const char *numeric)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(numeric);
  crdt_lwwmap_delete(&st->users, numeric, klen, ts, st->my_numeric);
  uint64_t seq = st->next_seq++;
  struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_USERS);
  op->key = memdup(numeric, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
  /* M9: reap this user's SILENCE masks SYNCHRONOUSLY (not sweep-only) so the REMOVE
   * ops get seqs immediately after the user DELETE and before any numeric-reuse SET,
   * closing the numeric-reuse bleed via per-origin in-order delivery. */
  crdt_state_reclaim_user_silences(st, numeric);
  /* Tier C F3: same reasoning for the tempshun register (numeric-reuse would
   * otherwise inherit the predecessor's shun). */
  crdt_state_reclaim_user_tempshun(st, numeric);
}

/* Phase 3m: 1 iff this numeric has an explicit user delete-tombstone in the doc
 * (the gate for doc->live delete-on-leave; never fires on mere absence). */
int crdt_user_is_explicitly_removed(const struct CrdtNetworkState *st,
                                    const char *numeric)
{
  return crdt_lwwmap_is_deleted(&st->users, numeric, (uint32_t)strlen(numeric));
}

void crdt_nick_claim(struct CrdtNetworkState *st, const char *nick_lc,
                     const struct CrdtNickClaim *claim)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(nick_lc);
  crdt_lwwmap_set(&st->nicks, nick_lc, klen, claim, sizeof(*claim),
                  ts, st->my_numeric);
  uint64_t seq = st->next_seq++;
  struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_NICKS);
  op->key = memdup(nick_lc, klen);
  op->key_len = klen;
  op->val = memdup(claim, sizeof(*claim));
  op->val_len = sizeof(*claim);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_chan_join(struct CrdtNetworkState *st, const char *chan,
                    const char *numeric)
{
  uint64_t seq = st->next_seq++;
  struct CrdtTag tag = { st->my_numeric, seq };
  struct CrdtChannel *ch = crdt_state_channel(st, chan, 1);
  uint32_t klen = (uint32_t)strlen(numeric);
  uint32_t clen = (uint32_t)strlen(chan);
  crdt_orset_add(&ch->members, numeric, klen, tag);
  struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_ADD,
                             CRDT_COLL_CHAN_MEMBERS);
  op->chan = memdup(chan, clen);
  op->chan_len = clen;
  op->key = memdup(numeric, klen);
  op->key_len = klen;
  op->tag = tag;
  record(st, op);
}

void crdt_chan_remove(struct CrdtNetworkState *st, const char *chan,
                      const char *numeric, uint8_t priority)
{
  struct CrdtChannel *ch = crdt_state_channel(st, chan, 0);
  if (!ch) return;
  uint32_t klen = (uint32_t)strlen(numeric);
  uint32_t clen = (uint32_t)strlen(chan);
  struct CrdtTag removed[64];
  int n;
  /* crdt_orset_remove reports at most 64 tags per call — loop until a short
   * round so a member holding more add-tags (join churn) still fully removes
   * AND every tombstoned tag gets its REMOVE op (an unreported removal never
   * replicates -> divergence). */
  do {
    n = crdt_orset_remove(&ch->members, numeric, klen, priority, removed, 64);
    for (int i = 0; i < n; i++) {
      uint64_t seq = st->next_seq++;
      struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_REMOVE,
                                 CRDT_COLL_CHAN_MEMBERS);
      op->chan = memdup(chan, clen);
      op->chan_len = clen;
      op->key = memdup(numeric, klen);
      op->key_len = klen;
      op->tag = removed[i];
      op->priority = priority;
      record(st, op);
    }
  } while (n == 64);
}

/* Phase 3i: op-recording ban/except add/remove (mirrors crdt_chan_join/remove,
 * but on the bans/excepts OR-Set so steady-state +b/-b replicate via delta sync
 * — a direct crdt_orset_add records no op and only replicates via snapshot). */
void crdt_chan_ban_add(struct CrdtNetworkState *st, const char *chan,
                       const char *mask, int is_except)
{
  uint64_t seq = st->next_seq++;
  struct CrdtTag tag = { st->my_numeric, seq };
  struct CrdtChannel *ch = crdt_state_channel(st, chan, 1);
  struct CrdtORSet *set = is_except ? &ch->excepts : &ch->bans;
  enum CrdtCollection coll = is_except ? CRDT_COLL_CHAN_EXCEPTS : CRDT_COLL_CHAN_BANS;
  uint32_t klen = (uint32_t)strlen(mask);
  uint32_t clen = (uint32_t)strlen(chan);
  struct CrdtOp *op;
  crdt_orset_add(set, mask, klen, tag);
  op = op_new(st->my_numeric, seq, CRDT_OP_ADD, coll);
  op->chan = memdup(chan, clen);
  op->chan_len = clen;
  op->key = memdup(mask, klen);
  op->key_len = klen;
  op->tag = tag;
  record(st, op);
}

void crdt_chan_ban_remove(struct CrdtNetworkState *st, const char *chan,
                          const char *mask, uint8_t priority, int is_except)
{
  struct CrdtChannel *ch = crdt_state_channel(st, chan, 0);
  struct CrdtORSet *set;
  enum CrdtCollection coll;
  struct CrdtTag removed[64];
  uint32_t klen, clen;
  int n, i;
  if (!ch) return;
  set = is_except ? &ch->excepts : &ch->bans;
  coll = is_except ? CRDT_COLL_CHAN_EXCEPTS : CRDT_COLL_CHAN_BANS;
  klen = (uint32_t)strlen(mask);
  clen = (uint32_t)strlen(chan);
  /* loop until a short round — see crdt_chan_remove */
  do {
    n = crdt_orset_remove(set, mask, klen, priority, removed, 64);
    for (i = 0; i < n; i++) {
      uint64_t seq = st->next_seq++;
      struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_REMOVE, coll);
      op->chan = memdup(chan, clen);
      op->chan_len = clen;
      op->key = memdup(mask, klen);
      op->key_len = klen;
      op->tag = removed[i];
      op->priority = priority;
      record(st, op);
    }
  } while (n == 64);
}

/* Tier C F1-c: per-user SILENCE OR-Set (global collection keyed usernumeric\0mask).
 * Mirrors crdt_chan_ban_add/remove but on st->silences with op->chan unused (the
 * collection is global; the user numeric is folded into the composite op->key).
 * The mask must not contain a NUL (it never does — it's an IRC ban mask). */
static uint32_t silence_key(char *out, const char *usernumeric, const char *mask)
{
  uint32_t ul = (uint32_t)strlen(usernumeric);
  uint32_t ml = (uint32_t)strlen(mask);
  memcpy(out, usernumeric, ul);
  out[ul] = '\0';
  memcpy(out + ul + 1, mask, ml);
  return ul + 1 + ml;
}

void crdt_silence_add(struct CrdtNetworkState *st, const char *usernumeric,
                      const char *mask)
{
  uint64_t seq = st->next_seq++;
  struct CrdtTag tag = { st->my_numeric, seq };
  char key[CRDT_NUMERICLEN + 1 + 256];
  uint32_t klen = silence_key(key, usernumeric, mask);
  struct CrdtOp *op;
  crdt_orset_add(&st->silences, key, klen, tag);
  op = op_new(st->my_numeric, seq, CRDT_OP_ADD, CRDT_COLL_SILENCES);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->tag = tag;
  record(st, op);
}

void crdt_silence_remove(struct CrdtNetworkState *st, const char *usernumeric,
                         const char *mask, uint8_t priority)
{
  char key[CRDT_NUMERICLEN + 1 + 256];
  uint32_t klen = silence_key(key, usernumeric, mask);
  struct CrdtTag removed[64];
  int n, i;
  /* loop until a short round — see crdt_chan_remove */
  do {
    n = crdt_orset_remove(&st->silences, key, klen, priority, removed, 64);
    for (i = 0; i < n; i++) {
      uint64_t seq = st->next_seq++;
      struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_REMOVE, CRDT_COLL_SILENCES);
      op->key = memdup(key, klen);
      op->key_len = klen;
      op->tag = removed[i];
      op->priority = priority;
      record(st, op);
    }
  } while (n == 64);
}

/* ------------------------------------------------------------------ */
/* Phase 3j: channel creationtime — incarnation MIN-register           */
/* ------------------------------------------------------------------ */
/* Wire/op payload for a CRDT_COLL_CHAN_CTIME SET op. memcpy'd into op->val
 * (same-build layout, like CrdtChanMeta); the digest hashes fields, not the
 * struct, to stay padding-independent. */
struct ctime_payload {
  uint64_t   value;
  struct HLC set_hlc;
  struct HLC del_hlc;
};

static struct HLC hlc_max(struct HLC a, struct HLC b)
{
  return (hlc_compare(&a, &b) >= 0) ? a : b;
}

/* Merge an incoming {value, set_hlc, del_hlc} into a channel's ctime register.
 * Commutative/associative/idempotent (a proper join): del = max; within the
 * surviving incarnation (set > del) the LOWER value wins (IRC lower-TS-wins);
 * a set older than the merged del is a superseded incarnation and is dropped. */
static void ctime_merge(struct CrdtChannel *ch, uint64_t value,
                        struct HLC set_hlc, struct HLC del_hlc)
{
  struct HLC del2 = hlc_max(ch->ctime_del, del_hlc);
  int a_live = hlc_compare(&ch->ctime_set, &del2) > 0;   /* current entry survives */
  int b_live = hlc_compare(&set_hlc, &del2) > 0;          /* incoming survives */
  if (a_live && b_live) {
    ch->ctime = (ch->ctime < value) ? ch->ctime : value;  /* min */
    ch->ctime_set = hlc_max(ch->ctime_set, set_hlc);
  } else if (b_live) {
    ch->ctime = value;
    ch->ctime_set = set_hlc;
  } else if (a_live) {
    /* keep current value/set */
  } else {
    ch->ctime = 0;                                         /* deleted (no live set) */
    ch->ctime_set = hlc_max(ch->ctime_set, set_hlc);
  }
  ch->ctime_del = del2;
}

void crdt_chan_ctime_set(struct CrdtNetworkState *st, const char *chan,
                         uint64_t creationtime)
{
  struct HLC now = hlc_local_event(&st->clock);
  uint32_t clen = (uint32_t)strlen(chan);
  struct CrdtChannel *ch = chan_get(st, chan, clen, 1);
  struct HLC incarnation = ch->ctime_del;   /* the incarnation this create belongs to */
  struct ctime_payload pl;
  uint64_t seq;
  struct CrdtOp *op;
  ctime_merge(ch, creationtime, now, incarnation);
  /* memdup(&pl) below serializes the WHOLE struct into op->val, so its padding goes
   * on the wire. Each struct HLC is sizeof 16 but 12 bytes used (4 trailing pad), and
   * hlc_max/ctime_merge pass HLCs BY VALUE — gcc copies only the 12 used bytes,
   * leaving the locals' pad uninit. So `pl.set_hlc = now` (a whole-struct copy) would
   * drag that uninit pad in even after a memset. Zero pl, then copy HLCs FIELD-BY-FIELD
   * so the memset-zeroed padding survives (valgrind-clean + cross-build wire-determinism). */
  memset(&pl, 0, sizeof pl);
  pl.value = creationtime;
  pl.set_hlc.physical_ms = now.physical_ms;
  pl.set_hlc.logical     = now.logical;
  pl.set_hlc.node_id     = now.node_id;
  pl.del_hlc.physical_ms = incarnation.physical_ms;
  pl.del_hlc.logical     = incarnation.logical;
  pl.del_hlc.node_id     = incarnation.node_id;
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_CHAN_CTIME);
  op->chan = memdup(chan, clen);
  op->chan_len = clen;
  op->val = memdup(&pl, sizeof pl);
  op->val_len = sizeof pl;
  op->ts = now;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_chan_ctime_clear(struct CrdtNetworkState *st, const char *chan)
{
  struct HLC now = hlc_local_event(&st->clock);
  struct CrdtChannel *ch = chan_find(st, chan, (uint32_t)strlen(chan));
  if (!ch) return;
  /* LOCAL incarnation bump — no op recorded; the NEXT create's set-op carries
   * this del_hlc, so the boundary propagates with the recreate. */
  if (hlc_compare(&now, &ch->ctime_del) > 0)
    ch->ctime_del = now;
}

uint64_t crdt_chan_ctime_get(struct CrdtNetworkState *st, const char *chan)
{
  struct CrdtChannel *ch = chan_find(st, chan, (uint32_t)strlen(chan));
  if (!ch) return 0;
  return (hlc_compare(&ch->ctime_set, &ch->ctime_del) > 0) ? ch->ctime : 0;
}

void crdt_chan_ctime_merge(struct CrdtNetworkState *st, const char *chan,
                           uint32_t clen, uint64_t value,
                           struct HLC set_hlc, struct HLC del_hlc)
{
  struct CrdtChannel *ch = chan_get(st, chan, clen, 1);
  ctime_merge(ch, value, set_hlc, del_hlc);
}

void crdt_server_set(struct CrdtNetworkState *st, uint16_t numeric,
                     enum CrdtServerState state)
{
  char key[8];
  uint32_t klen = server_key(numeric, key, sizeof key);
  struct CrdtServerRecord rec;
  rec.state = (uint8_t)state;
  struct HLC ts = hlc_local_event(&st->clock);
  crdt_lwwmap_set(&st->servers, key, klen, &rec, sizeof rec, ts, st->my_numeric);
  uint64_t seq = st->next_seq++;
  struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_SERVERS);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->val = memdup(&rec, sizeof rec);
  op->val_len = sizeof rec;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_server_squit(struct CrdtNetworkState *st, uint16_t numeric)
{
  crdt_server_set(st, numeric, CRDT_SRV_SPLIT);
}

void crdt_server_relink(struct CrdtNetworkState *st, uint16_t numeric)
{
  crdt_server_set(st, numeric, CRDT_SRV_ACTIVE);
}

void crdt_state_resume_seq(struct CrdtNetworkState *st)
{
  /* After adopting a peer's snapshot/delta (which raises local_sv to the peer's
   * view), resume our own op-seq ABOVE that floor.  A process restart resets
   * next_seq to 1 while peers still remember our pre-restart seq; without this,
   * our post-restart ops carry already-seen seqs and peers dedup them via
   * crdt_sv_has_seen, dropping them forever.  Idempotent; never lowers next_seq. */
  uint64_t seen = st->local_sv.seq[st->my_numeric];
  if (seen >= st->next_seq)
    st->next_seq = seen + 1;
}

int crdt_server_state(const struct CrdtNetworkState *st, uint16_t numeric)
{
  char key[8];
  uint32_t klen = server_key(numeric, key, sizeof key);
  const struct CrdtLWWValue *sv = crdt_lwwmap_get(&st->servers, key, klen);
  if (!sv)
    return -1;   /* absent */
  return (int)((const struct CrdtServerRecord *)sv->data)->state;  /* ACTIVE/SPLIT */
}

/* ------------------------------------------------------------------ */
/* M11: channel topic — MAX-register on topic_time (legacy P10 order)   */
/* ------------------------------------------------------------------ */
/* The topics LWW value is a SERIALIZED buffer, NOT a padded struct:
 *   [ uint64_t topic_time ][ topic text, NUL-terminated ]
 * Built member-by-member (INVARIANT 4): topic_time is a scalar (no struct padding),
 * the text follows it — nothing memcpy's a struct-with-padding onto the wire. Native
 * byte order, same convention as ctime_payload's uint64 value (the mesh is homogeneous).
 * topic_nick is deliberately NOT folded in — it stays in chanmeta (deferred). */
#define TOPIC_VAL_HDR ((uint32_t)sizeof(uint64_t))   /* 8-byte topic_time prefix */

/* value-only lexical comparator, shared with the read-marker MAX-register (defined
 * below); forward-declared so topic_merge can reuse it for the same-second tiebreak. */
static int marker_ts_cmp(const void *a, uint32_t alen, const void *b, uint32_t blen);

static uint32_t topic_val_build(char *buf, uint64_t topic_time,
                                const char *text, uint32_t textlen)
{
  memcpy(buf, &topic_time, sizeof topic_time);       /* scalar: no padding, deterministic */
  memcpy(buf + TOPIC_VAL_HDR, text, textlen);        /* text (setter includes the NUL) */
  return TOPIC_VAL_HDR + textlen;
}

const char *crdt_topic_value_text(const void *data, uint32_t data_len,
                                  uint64_t *out_time)
{
  if (out_time)
    *out_time = 0;
  if (!data || data_len < TOPIC_VAL_HDR)
    return "";                                       /* absent/short -> empty topic */
  if (out_time)
    memcpy(out_time, data, sizeof *out_time);
  if (data_len == TOPIC_VAL_HDR)
    return "";                                       /* topic_time present, no text */
  return (const char *)data + TOPIC_VAL_HDR;         /* NUL-terminated (setter guarantees) */
}

/* MAX-register merge: topic_time is the PRIMARY key (so the mesh converges on the
 * highest-topic_time topic, which every legacy island's m_topic gate then accepts);
 * text lexical-max is the deterministic TIEBREAK for the same-second case. This mirrors
 * marker_merge — a VALUE-ONLY comparator that reads the FAITHFULLY-STORED value, never
 * the synthesized LWW write-HLC (reading the synth HLC as a tiebreak is provably NON-
 * convergent across 3+ same-second writers; the lexical-on-text tiebreak is a proper
 * join: commutative/associative/idempotent). On a win we synthesize an HLC strictly >
 * the stored write so crdt_lwwmap_set accepts it (the ordering decision is already made
 * by the MAX compare; the synth only makes the winner stick). Returns 1 if it changed. */
static int topic_merge(struct CrdtNetworkState *st, const char *key, uint32_t klen,
                       uint64_t topic_time, const char *text, uint32_t textlen,
                       uint16_t writer, struct HLC fresh_ts)
{
  const struct CrdtLWWValue *cur;
  struct HLC ts;
  char buf[TOPIC_VAL_HDR + CRDT_TOPIC_MAXLEN];
  uint32_t vlen;
  if (!textlen || textlen > CRDT_TOPIC_MAXLEN)
    return 0;                            /* empty / oversized -> ignore (degradation) */
  cur = crdt_lwwmap_get(&st->topics, key, klen);
  if (cur && cur->data && cur->data_len >= TOPIC_VAL_HDR) {
    uint64_t cur_time = 0;
    const char *cur_text = (const char *)cur->data + TOPIC_VAL_HDR;
    uint32_t cur_textlen = cur->data_len - TOPIC_VAL_HDR;
    memcpy(&cur_time, cur->data, sizeof cur_time);
    if (topic_time < cur_time)
      return 0;                          /* lower wall-clock topic_time -> no-op (MAX) */
    if (topic_time == cur_time &&
        marker_ts_cmp(text, textlen, cur_text, cur_textlen) <= 0)
      return 0;                          /* tie & not lexically-greater text -> no-op */
    ts = cur->ts;                        /* synth HLC strictly > the stored write */
    if (++ts.logical == 0)
      ts.physical_ms++;
  } else {
    ts = fresh_ts;
  }
  vlen = topic_val_build(buf, topic_time, text, textlen);
  crdt_lwwmap_set(&st->topics, key, klen, buf, vlen, ts, writer);
  return 1;
}

void crdt_topic_set(struct CrdtNetworkState *st, const char *chan,
                    const char *topic, uint64_t topic_time)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(chan);
  uint32_t textlen = (uint32_t)strlen(topic) + 1;   /* include the NUL */
  char buf[TOPIC_VAL_HDR + CRDT_TOPIC_MAXLEN];
  uint32_t vlen;
  uint64_t seq;
  struct CrdtOp *op;
  if (textlen > CRDT_TOPIC_MAXLEN)
    textlen = CRDT_TOPIC_MAXLEN;                     /* clamp (keeps the trailing NUL slot) */
  if (!topic_merge(st, chan, klen, topic_time, topic, textlen, st->my_numeric, ts))
    return;                             /* not a MAX win -> no op storm (idempotent) */
  vlen = topic_val_build(buf, topic_time, topic, textlen);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_TOPICS);
  op->key = memdup(chan, klen);
  op->key_len = klen;
  op->val = memdup(buf, vlen);
  op->val_len = vlen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

/* Snapshot-apply entry (crdt_wire.c): decode the serialized value + MERGE via the
 * topic_time MAX-register (NOT a generic HLC-LWW assign). Mirrors marker/blease/ctime. */
void crdt_topic_merge_snapshot(struct CrdtNetworkState *st, const char *key,
                               uint32_t klen, const void *val, uint32_t vlen,
                               uint16_t writer, struct HLC ts)
{
  uint64_t topic_time = 0;
  if (!val || vlen <= TOPIC_VAL_HDR)
    return;
  memcpy(&topic_time, val, sizeof topic_time);
  topic_merge(st, key, klen, topic_time, (const char *)val + TOPIC_VAL_HDR,
              vlen - TOPIC_VAL_HDR, writer, ts);
}

void crdt_modes_set(struct CrdtNetworkState *st, const char *chan,
                    const void *snap, uint32_t snaplen)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(chan);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_set(&st->modes, chan, klen, snap, snaplen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_MODES);
  op->key = memdup(chan, klen);
  op->key_len = klen;
  op->val = memdup(snap, snaplen);
  op->val_len = snaplen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_member_status_set(struct CrdtNetworkState *st, const char *chan,
                            const char *numeric,
                            const struct CrdtMemberRecord *rec)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t clen = (uint32_t)strlen(chan);
  uint32_t nlen = (uint32_t)strlen(numeric);
  char key[512];                 /* chan \0 numeric (chan<=CHANNELLEN, num<=5) */
  uint32_t klen;
  uint64_t seq;
  struct CrdtOp *op;
  if (clen + 1 + nlen > sizeof key)
    return;                      /* defensive: oversized key, skip */
  memcpy(key, chan, clen);
  key[clen] = '\0';
  memcpy(key + clen + 1, numeric, nlen);
  klen = clen + 1 + nlen;
  crdt_lwwmap_set(&st->members_status, key, klen, rec, sizeof(*rec),
                  ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_MEMBER_STATUS);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->val = memdup(rec, sizeof(*rec));
  op->val_len = sizeof(*rec);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

/* Phase 3k: build a chan\0numeric key into buf; returns length, or 0 if oversized. */
static uint32_t chan_num_key(const char *chan, const char *numeric,
                             char *buf, size_t bufsz)
{
  uint32_t clen = (uint32_t)strlen(chan);
  uint32_t nlen = (uint32_t)strlen(numeric);
  if (clen + 1 + nlen > bufsz)
    return 0;
  memcpy(buf, chan, clen);
  buf[clen] = '\0';
  memcpy(buf + clen + 1, numeric, nlen);
  return clen + 1 + nlen;
}

void crdt_kick_info_set(struct CrdtNetworkState *st, const char *chan,
                        const char *numeric, const struct CrdtKickInfo *ki)
{
  struct HLC ts = hlc_local_event(&st->clock);
  char key[512];
  uint32_t klen = chan_num_key(chan, numeric, key, sizeof key);
  uint64_t seq;
  struct CrdtOp *op;
  if (!klen)
    return;
  crdt_lwwmap_set(&st->kick_info, key, klen, ki, sizeof(*ki), ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_KICK_INFO);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->val = memdup(ki, sizeof(*ki));
  op->val_len = sizeof(*ki);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

const struct CrdtLWWValue *crdt_kick_info_get(struct CrdtNetworkState *st,
                                              const char *chan, const char *numeric)
{
  char key[512];
  uint32_t klen = chan_num_key(chan, numeric, key, sizeof key);
  if (!klen)
    return NULL;
  return crdt_lwwmap_get(&st->kick_info, key, klen);
}

const struct CrdtLWWValue *crdt_member_status_get(struct CrdtNetworkState *st,
                                                  const char *chan, const char *numeric)
{
  char key[512];
  uint32_t klen = chan_num_key(chan, numeric, key, sizeof key);
  if (!klen)
    return NULL;
  return crdt_lwwmap_get(&st->members_status, key, klen);
}

void crdt_chanmeta_set(struct CrdtNetworkState *st, const char *chan,
                       const struct CrdtChanMeta *meta)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(chan);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_set(&st->chanmeta, chan, klen, meta, sizeof(*meta),
                  ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_CHANMETA);
  op->key = memdup(chan, klen);
  op->key_len = klen;
  op->val = memdup(meta, sizeof(*meta));
  op->val_len = sizeof(*meta);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

/* Global-state track: set a G-line in the GLINES LWW-map (op-recording, like
 * crdt_chanmeta_set), keyed by its ban mask. */
void crdt_gline_set(struct CrdtNetworkState *st, const char *mask,
                    const struct CrdtGlineRecord *rec)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(mask);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_set(&st->glines, mask, klen, rec, sizeof(*rec),
                  ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_GLINES);
  op->key = memdup(mask, klen);
  op->key_len = klen;
  op->val = memdup(rec, sizeof(*rec));
  op->val_len = sizeof(*rec);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

/* Global-state track: tombstone a G-line in the GLINES LWW-map (op-recording
 * DELETE; mirrors mint_meta_delete, inlined to avoid a forward reference). */
void crdt_gline_del(struct CrdtNetworkState *st, const char *mask)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(mask);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_delete(&st->glines, mask, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_GLINES);
  op->key = memdup(mask, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

/* GLINE step 3: 1 iff this mask has an explicit gline delete-tombstone in the doc
 * (the gate for doc->live removal; never fires on mere absence — sync-lag safety,
 * mirrors crdt_user_is_explicitly_removed). */
int crdt_gline_is_explicitly_removed(const struct CrdtNetworkState *st,
                                     const char *mask)
{
  return crdt_lwwmap_is_deleted(&st->glines, mask, (uint32_t)strlen(mask));
}

/* Tier C F2-b: account metadata as a plain HLC-LWW collection (clone of crdt_gline_*,
 * but the key carries an embedded NUL (account\0metakey) so klen is passed explicitly,
 * and the value is a variable-length blob). Uses the GENERIC apply + snapshot paths —
 * no special-case merge (plain last-write-wins). */
void crdt_metadata_set(struct CrdtNetworkState *st, const char *key, uint32_t klen,
                       const void *val, uint32_t vlen)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_set(&st->metadata, key, klen, val, vlen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_METADATA);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->val = vlen ? memdup(val, vlen) : NULL;
  op->val_len = vlen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_metadata_del(struct CrdtNetworkState *st, const char *key, uint32_t klen)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_delete(&st->metadata, key, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_METADATA);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

int crdt_metadata_is_explicitly_removed(const struct CrdtNetworkState *st,
                                        const char *key, uint32_t klen)
{
  return crdt_lwwmap_is_deleted(&st->metadata, key, klen);
}

const struct CrdtLWWValue *crdt_metadata_get(const struct CrdtNetworkState *st,
                                             const char *key, uint32_t klen)
{
  return crdt_lwwmap_get(&st->metadata, key, klen);
}

/* SHUN (global-state track): op-recording set/del/gate, mirroring crdt_gline_*. */
void crdt_shun_set(struct CrdtNetworkState *st, const char *mask,
                   const struct CrdtShunRecord *rec)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(mask);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_set(&st->shuns, mask, klen, rec, sizeof(*rec),
                  ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_SHUNS);
  op->key = memdup(mask, klen);
  op->key_len = klen;
  op->val = memdup(rec, sizeof(*rec));
  op->val_len = sizeof(*rec);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_shun_del(struct CrdtNetworkState *st, const char *mask)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(mask);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_delete(&st->shuns, mask, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_SHUNS);
  op->key = memdup(mask, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

int crdt_shun_is_explicitly_removed(const struct CrdtNetworkState *st,
                                    const char *mask)
{
  return crdt_lwwmap_is_deleted(&st->shuns, mask, (uint32_t)strlen(mask));
}

/* ZLINE (global-state track): op-recording set/del/gate, mirroring crdt_shun_*. */
void crdt_zline_set(struct CrdtNetworkState *st, const char *mask,
                    const struct CrdtZlineRecord *rec)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(mask);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_set(&st->zlines, mask, klen, rec, sizeof(*rec),
                  ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_ZLINES);
  op->key = memdup(mask, klen);
  op->key_len = klen;
  op->val = memdup(rec, sizeof(*rec));
  op->val_len = sizeof(*rec);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_zline_del(struct CrdtNetworkState *st, const char *mask)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(mask);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_delete(&st->zlines, mask, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_ZLINES);
  op->key = memdup(mask, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

int crdt_zline_is_explicitly_removed(const struct CrdtNetworkState *st,
                                     const char *mask)
{
  return crdt_lwwmap_is_deleted(&st->zlines, mask, (uint32_t)strlen(mask));
}

/* JUPE (global-state track): op-recording set/del/gate, keyed by server name. */
void crdt_jupe_set(struct CrdtNetworkState *st, const char *server,
                   const struct CrdtJupeRecord *rec)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(server);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_set(&st->jupes, server, klen, rec, sizeof(*rec),
                  ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_JUPES);
  op->key = memdup(server, klen);
  op->key_len = klen;
  op->val = memdup(rec, sizeof(*rec));
  op->val_len = sizeof(*rec);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_jupe_del(struct CrdtNetworkState *st, const char *server)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(server);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_delete(&st->jupes, server, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_JUPES);
  op->key = memdup(server, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

int crdt_jupe_is_explicitly_removed(const struct CrdtNetworkState *st,
                                    const char *server)
{
  return crdt_lwwmap_is_deleted(&st->jupes, server, (uint32_t)strlen(server));
}

/* 5-5e doc-native bouncer: op-recording set/del/get/gate, keyed by account\0sessid
 * (embedded NUL like members_status' chan\0numeric — avoids delimiter collision). */
static uint32_t bsess_key(const char *account, const char *sessid,
                          char *out, size_t outsz)
{
  uint32_t al = (uint32_t)strlen(account);
  uint32_t sl = (uint32_t)strlen(sessid);
  if ((size_t)al + 1 + sl > outsz)
    return 0;                      /* defensive: oversized key */
  memcpy(out, account, al);
  out[al] = '\0';
  memcpy(out + al + 1, sessid, sl);
  return al + 1 + sl;
}

void crdt_bsess_set(struct CrdtNetworkState *st, const char *account,
                    const char *sessid, const struct CrdtBouncerSession *rec)
{
  struct HLC ts = hlc_local_event(&st->clock);
  char key[128];
  uint32_t klen = bsess_key(account, sessid, key, sizeof key);
  uint64_t seq;
  struct CrdtOp *op;
  if (!klen)
    return;
  crdt_lwwmap_set(&st->bsessions, key, klen, rec, sizeof(*rec),
                  ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_BSESSIONS);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->val = memdup(rec, sizeof(*rec));
  op->val_len = sizeof(*rec);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_bsess_del(struct CrdtNetworkState *st, const char *account,
                    const char *sessid)
{
  struct HLC ts = hlc_local_event(&st->clock);
  char key[128];
  uint32_t klen = bsess_key(account, sessid, key, sizeof key);
  uint64_t seq;
  struct CrdtOp *op;
  if (!klen)
    return;
  crdt_lwwmap_delete(&st->bsessions, key, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_BSESSIONS);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

const struct CrdtBouncerSession *crdt_bsess_get(const struct CrdtNetworkState *st,
                                                const char *account, const char *sessid)
{
  char key[128];
  uint32_t klen = bsess_key(account, sessid, key, sizeof key);
  const struct CrdtLWWValue *v;
  if (!klen)
    return NULL;
  v = crdt_lwwmap_get(&st->bsessions, key, klen);
  return v ? (const struct CrdtBouncerSession *)v->data : NULL;
}

int crdt_bsess_is_explicitly_removed(const struct CrdtNetworkState *st,
                                     const char *account, const char *sessid)
{
  char key[128];
  uint32_t klen = bsess_key(account, sessid, key, sizeof key);
  if (!klen)
    return 0;
  return crdt_lwwmap_is_deleted(&st->bsessions, key, klen);
}

/* 5-5e M3: derive the cross-sessid election winner from the converged doc — the
 * strcmp-lowest sessid among @a account's LIVE (non-tombstoned) bsessions records.
 * Matches the live election (bouncer_session.c: strcmp(sessid, local) < 0 -> lower
 * wins); a denormalized min-register is unnecessary since the bsess set already
 * converges, and deriving over live records correctly excludes a collapsed loser. */
struct bsess_winner_ctx {
  const char *account;
  uint32_t    acclen;
  char        best[64];   /* sessid <= BOUNCER_SESSID_LEN (40) */
  int         found;
};
static void bsess_winner_cb(const char *key, uint32_t key_len,
                            const struct CrdtLWWValue *val, void *ctx)
{
  struct bsess_winner_ctx *c = ctx;
  uint32_t sidlen;
  char sid[64];
  if (!val->data || val->data_len != sizeof(struct CrdtBouncerSession))
    return;                              /* tombstone / wrong size -> skip */
  if (key_len <= c->acclen + 1)
    return;
  if (memcmp(key, c->account, c->acclen) != 0 || key[c->acclen] != '\0')
    return;                              /* different account */
  sidlen = key_len - c->acclen - 1;
  if (sidlen >= sizeof sid)
    return;
  memcpy(sid, key + c->acclen + 1, sidlen);
  sid[sidlen] = '\0';
  if (!c->found || strcmp(sid, c->best) < 0) {
    memcpy(c->best, sid, sidlen + 1);   /* sid is NUL-terminated; sidlen+1 <= sizeof best */
    c->found = 1;
  }
}

const char *crdt_bsess_winner(const struct CrdtNetworkState *st, const char *account,
                              char *out, size_t outsz)
{
  struct bsess_winner_ctx c;
  c.account = account;
  c.acclen  = (uint32_t)strlen(account);
  c.best[0] = '\0';
  c.found   = 0;
  crdt_lwwmap_foreach(&st->bsessions, bsess_winner_cb, &c);
  if (!c.found)
    return NULL;
  if (outsz) {
    size_t bl = strlen(c.best);
    if (bl >= outsz)
      bl = outsz - 1;
    memcpy(out, c.best, bl);
    out[bl] = '\0';
  }
  return out;
}

/* 5-5e M4: per-connection records, keyed account\0sessid\0connnum (single-writer = the
 * connection's host). Op-recording set/del/get/gate, mirroring the bsess pattern. */
static uint32_t bconn_key(const char *account, const char *sessid, const char *connnum,
                          char *out, size_t outsz)
{
  uint32_t al = (uint32_t)strlen(account);
  uint32_t sl = (uint32_t)strlen(sessid);
  uint32_t nl = (uint32_t)strlen(connnum);
  if ((size_t)al + 1 + sl + 1 + nl > outsz)
    return 0;
  memcpy(out, account, al);            out[al] = '\0';
  memcpy(out + al + 1, sessid, sl);    out[al + 1 + sl] = '\0';
  memcpy(out + al + 1 + sl + 1, connnum, nl);
  return al + 1 + sl + 1 + nl;
}

void crdt_bconn_set(struct CrdtNetworkState *st, const char *account,
                    const char *sessid, const char *connnum,
                    const struct CrdtBouncerConn *rec)
{
  struct HLC ts = hlc_local_event(&st->clock);
  char key[160];
  uint32_t klen = bconn_key(account, sessid, connnum, key, sizeof key);
  uint64_t seq;
  struct CrdtOp *op;
  if (!klen)
    return;
  crdt_lwwmap_set(&st->bconns, key, klen, rec, sizeof(*rec), ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_BCONNS);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->val = memdup(rec, sizeof(*rec));
  op->val_len = sizeof(*rec);
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_bconn_del(struct CrdtNetworkState *st, const char *account,
                    const char *sessid, const char *connnum)
{
  struct HLC ts = hlc_local_event(&st->clock);
  char key[160];
  uint32_t klen = bconn_key(account, sessid, connnum, key, sizeof key);
  uint64_t seq;
  struct CrdtOp *op;
  if (!klen)
    return;
  crdt_lwwmap_delete(&st->bconns, key, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_BCONNS);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

const struct CrdtBouncerConn *crdt_bconn_get(const struct CrdtNetworkState *st,
                                             const char *account, const char *sessid,
                                             const char *connnum)
{
  char key[160];
  uint32_t klen = bconn_key(account, sessid, connnum, key, sizeof key);
  const struct CrdtLWWValue *v;
  if (!klen)
    return NULL;
  v = crdt_lwwmap_get(&st->bconns, key, klen);
  return v ? (const struct CrdtBouncerConn *)v->data : NULL;
}

int crdt_bconn_is_explicitly_removed(const struct CrdtNetworkState *st,
                                     const char *account, const char *sessid,
                                     const char *connnum)
{
  char key[160];
  uint32_t klen = bconn_key(account, sessid, connnum, key, sizeof key);
  if (!klen)
    return 0;
  return crdt_lwwmap_is_deleted(&st->bconns, key, klen);
}

/* Roster count: live (non-tombstoned) bconns entries for (account,sessid). Reuses the
 * bsess_winner_ctx-style prefix scan but counts the (account\0sessid\0) prefix. */
struct bconn_count_ctx { const char *prefix; uint32_t plen; int n; };
static void bconn_count_cb(const char *key, uint32_t key_len,
                           const struct CrdtLWWValue *val, void *ctx)
{
  struct bconn_count_ctx *c = ctx;
  if (!val->data || val->data_len != sizeof(struct CrdtBouncerConn))
    return;                              /* tombstone / wrong size */
  if (key_len <= c->plen)
    return;
  if (memcmp(key, c->prefix, c->plen) == 0)
    c->n++;
}

int crdt_bconn_roster_count(const struct CrdtNetworkState *st,
                            const char *account, const char *sessid)
{
  struct bconn_count_ctx c;
  char prefix[160];
  uint32_t al = (uint32_t)strlen(account);
  uint32_t sl = (uint32_t)strlen(sessid);
  if ((size_t)al + 1 + sl + 1 > sizeof prefix)
    return 0;
  memcpy(prefix, account, al);          prefix[al] = '\0';
  memcpy(prefix + al + 1, sessid, sl);  prefix[al + 1 + sl] = '\0';
  c.prefix = prefix;
  c.plen   = al + 1 + sl + 1;            /* account\0sessid\0 */
  c.n      = 0;
  crdt_lwwmap_foreach(&st->bconns, bconn_count_cb, &c);
  return c.n;
}

/* 5-5e M6a-2: the PRIMARY connection's numeric for (account,sessid) — the is_primary
 * bconn entry. Writes the NUL-terminated connnum to @a out; returns out, or NULL if the
 * session has no primary connection in the doc. Prefix-scan over (account\0sessid\0). */
struct bconn_primary_ctx { const char *prefix; uint32_t plen; char *out; size_t outsz; int found; };
static void bconn_primary_cb(const char *key, uint32_t key_len,
                             const struct CrdtLWWValue *val, void *ctx)
{
  struct bconn_primary_ctx *c = ctx;
  const struct CrdtBouncerConn *rec;
  uint32_t nlen;
  if (c->found)
    return;
  if (!val->data || val->data_len != sizeof(struct CrdtBouncerConn))
    return;
  if (key_len <= c->plen || memcmp(key, c->prefix, c->plen) != 0)
    return;
  rec = (const struct CrdtBouncerConn *)val->data;
  if (!rec->is_primary)
    return;
  nlen = key_len - c->plen;                 /* connnum = the suffix after account\0sessid\0 */
  if (nlen == 0 || nlen >= c->outsz)
    return;
  memcpy(c->out, key + c->plen, nlen);
  c->out[nlen] = '\0';
  c->found = 1;
}

const char *crdt_bconn_primary(const struct CrdtNetworkState *st,
                               const char *account, const char *sessid,
                               char *out, size_t outsz)
{
  struct bconn_primary_ctx c;
  char prefix[160];
  uint32_t al = (uint32_t)strlen(account);
  uint32_t sl = (uint32_t)strlen(sessid);
  if ((size_t)al + 1 + sl + 1 > sizeof prefix || outsz == 0)
    return NULL;
  memcpy(prefix, account, al);          prefix[al] = '\0';
  memcpy(prefix + al + 1, sessid, sl);  prefix[al + 1 + sl] = '\0';
  c.prefix = prefix;
  c.plen   = al + 1 + sl + 1;
  c.out    = out;
  c.outsz  = outsz;
  c.found  = 0;
  crdt_lwwmap_foreach(&st->bconns, bconn_primary_cb, &c);
  return c.found ? out : NULL;
}

/* ------------------------------------------------------------------ */
/* 5-5e M5: liveness lease — a deterministic-merge (comparator) register */
/* ------------------------------------------------------------------ */

/* PURE comparator (cmocka-gated). Total order: higher generation wins; tie -> lower
 * host numeric. Returns >0 (a wins), <0 (b wins), 0 (identical authority). claim_ms
 * is deliberately NOT consulted — (generation,host) is already total since numerics
 * are unique, so the register is a clean join-semilattice. */
int crdt_blease_compare(const struct CrdtBouncerLease *a,
                        const struct CrdtBouncerLease *b)
{
  if (a->generation != b->generation)
    return (a->generation > b->generation) ? 1 : -1;
  if (a->host != b->host)
    return (a->host < b->host) ? 1 : -1;
  return 0;
}

/* PURE claim decision (cmocka-gated truth table). See header. */
long crdt_blease_decide(const struct CrdtBouncerLease *cur, int cur_host_fresh,
                        uint16_t me)
{
  if (!cur)
    return 0;                       /* fresh session: me becomes the gen-0 holder */
  if (cur->host == me)
    return (long)cur->generation;   /* re-affirm my own claim (idempotent) */
  if (cur_host_fresh)
    return -1;                      /* another fresh holder -> stand down */
  return (long)cur->generation + 1; /* prior holder stale -> revive (supersede) */
}

/* 5-5e M6d: the AUTHORITATIVE lease ACTION (pure; see header for the truth table). */
enum CrdtBLeaseAction
crdt_blease_action(const struct CrdtBouncerLease *cur, uint16_t me,
                   int holder_beacon_fresh, int have_local_primary, int want_revive)
{
  if (!cur)
    return CRDT_BLEASE_NOOP;          /* no lease yet: the claim path owns this */
  if (cur->host == me)
    return CRDT_BLEASE_NOOP;          /* I am the authoritative holder */
  if (holder_beacon_fresh)
    /* another LIVE holder owns it: a local primary here is the split-brain loser and
     * stands down; a bare replica does nothing. */
    return have_local_primary ? CRDT_BLEASE_DEMOTE_TO_ALIAS : CRDT_BLEASE_NOOP;
  /* holder stale/gone */
  if (want_revive)
    return CRDT_BLEASE_REVIVE_LOCAL;  /* a fresh connection takes over a split-away holder */
  return CRDT_BLEASE_NOOP;            /* not a revive site: the periodic claim supersedes it */
}

/* Merge an incoming lease into the bleases map. Order-independent in VALUE: the stored
 * entry always converges to the comparator-max of all claims seen, regardless of arrival
 * order (a join over the total order). Because the underlying LWW store gates writes by
 * HLC, the comparator-winner is written with an HLC synthesized to strictly beat the
 * stored one; the digest hashes the VALUE (host,generation) only, so the synthetic HLC
 * never causes false divergence (mirrors the ctime register). A tombstoned key is never
 * resurrected — a sessid is single-use, so any later SET to it is a stale re-delivery.
 * Returns 1 if the stored value changed (used to suppress no-op ops locally). */
static int blease_merge(struct CrdtNetworkState *st, const char *key, uint32_t klen,
                        const struct CrdtBouncerLease *incoming, uint16_t writer,
                        struct HLC fresh_ts)
{
  const struct CrdtLWWValue *cur;
  struct HLC ts;
  if (crdt_lwwmap_is_deleted(&st->bleases, key, klen))
    return 0;                       /* session ended: lease key is single-use, never revive */
  cur = crdt_lwwmap_get(&st->bleases, key, klen);
  if (cur && cur->data && cur->data_len == sizeof(*incoming)) {
    if (crdt_blease_compare(incoming, (const struct CrdtBouncerLease *)cur->data) <= 0)
      return 0;                     /* current wins or identical -> no-op (idempotent) */
    ts = cur->ts;                   /* synth an HLC strictly > the stored write so it sticks */
    if (++ts.logical == 0)
      ts.physical_ms++;
  } else {
    ts = fresh_ts;
  }
  crdt_lwwmap_set(&st->bleases, key, klen, incoming, sizeof(*incoming), ts, writer);
  return 1;
}

void crdt_blease_claim(struct CrdtNetworkState *st, const char *account,
                       const char *sessid, uint16_t host, uint32_t generation,
                       uint64_t claim_ms)
{
  struct HLC ts = hlc_local_event(&st->clock);
  char key[128];
  uint32_t klen = bsess_key(account, sessid, key, sizeof key);  /* same account\0sessid shape */
  struct CrdtBouncerLease rec;
  uint64_t seq;
  struct CrdtOp *op;
  if (!klen)
    return;
  memset(&rec, 0, sizeof rec);      /* zero pad -> stable digest/wire layout */
  rec.host       = host;
  rec.generation = generation;
  rec.claim_ms   = claim_ms;
  if (!blease_merge(st, key, klen, &rec, st->my_numeric, ts))
    return;                         /* no change (re-affirm / lost) -> no op storm */
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_BLEASES);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->val = memdup(&rec, sizeof rec);
  op->val_len = sizeof rec;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_blease_del(struct CrdtNetworkState *st, const char *account,
                     const char *sessid)
{
  struct HLC ts = hlc_local_event(&st->clock);
  char key[128];
  uint32_t klen = bsess_key(account, sessid, key, sizeof key);
  uint64_t seq;
  struct CrdtOp *op;
  if (!klen)
    return;
  crdt_lwwmap_delete(&st->bleases, key, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, CRDT_COLL_BLEASES);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

/* Snapshot-apply entry point (crdt_wire.c): MERGE an incoming lease blob via the
 * comparator (NOT a generic LWW assign, which would pick by HLC and break the register).
 * Exposed parallel to crdt_chan_ctime_merge. */
void crdt_blease_merge_snapshot(struct CrdtNetworkState *st, const char *key,
                                uint32_t klen, const struct CrdtBouncerLease *rec,
                                uint16_t writer, struct HLC ts)
{
  blease_merge(st, key, klen, rec, writer, ts);
}

/* Lexical compare of two timestamp-string values (length-aware; == strcmp for the
 * fixed-width "seconds.milliseconds" form markread uses). */
static int marker_ts_cmp(const void *a, uint32_t alen, const void *b, uint32_t blen)
{
  uint32_t n = alen < blen ? alen : blen;
  int c = (n ? memcmp(a, b, n) : 0);
  if (c) return c;
  return (alen > blen) - (alen < blen);
}

/* Tier C F2-a: read-marker MAX-register merge. Markers only advance (monotonic),
 * and the SAME account writes from any server (multi-writer) -> the merge keeps the
 * LEXICALLY-GREATER timestamp string, NOT HLC-LWW (which would regress a marker to a
 * clock-skewed lower-value-later-write). Lexical-max is order-independent + idempotent
 * -> multi-writer-safe. Byte-identical to markread's own strcmp "only if newer".
 * Clone of blease_merge with the value-string max comparator. */
static int marker_merge(struct CrdtNetworkState *st, const char *key, uint32_t klen,
                        const void *inval, uint32_t inlen, uint16_t writer,
                        struct HLC fresh_ts)
{
  const struct CrdtLWWValue *cur;
  struct HLC ts;
  if (!inlen)
    return 0;
  cur = crdt_lwwmap_get(&st->markers, key, klen);
  if (cur && cur->data && cur->data_len) {
    if (marker_ts_cmp(inval, inlen, cur->data, cur->data_len) <= 0)
      return 0;                       /* current >= incoming -> no-op (idempotent max) */
    ts = cur->ts;                     /* synth HLC strictly > the stored write so it sticks */
    if (++ts.logical == 0)
      ts.physical_ms++;
  } else {
    ts = fresh_ts;
  }
  crdt_lwwmap_set(&st->markers, key, klen, inval, inlen, ts, writer);
  return 1;
}

void crdt_marker_set(struct CrdtNetworkState *st, const char *key, uint32_t klen,
                     const char *tsstr)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t vlen;
  uint64_t seq;
  struct CrdtOp *op;
  if (!klen || !tsstr || !tsstr[0])
    return;
  vlen = (uint32_t)strlen(tsstr);
  if (!marker_merge(st, key, klen, tsstr, vlen, st->my_numeric, ts))
    return;                           /* not newer -> no op storm (idempotent) */
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_MARKERS);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->val = memdup(tsstr, vlen);
  op->val_len = vlen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

/* Snapshot-apply entry (crdt_wire.c): MERGE via the lexical-max comparator, NOT a
 * generic HLC-LWW assign (which would regress on snapshot catch-up). Mirrors blease. */
void crdt_marker_merge_snapshot(struct CrdtNetworkState *st, const char *key,
                                uint32_t klen, const void *val, uint32_t vlen,
                                uint16_t writer, struct HLC ts)
{
  marker_merge(st, key, klen, val, vlen, writer, ts);
}

int crdt_marker_get(const struct CrdtNetworkState *st, const char *key, uint32_t klen,
                    char *out, size_t outsz)
{
  const struct CrdtLWWValue *v = crdt_lwwmap_get(&st->markers, key, klen);
  if (!v || !v->data || !v->data_len || v->data_len >= outsz)
    return -1;
  memcpy(out, v->data, v->data_len);
  out[v->data_len] = '\0';
  return (int)v->data_len;
}

const struct CrdtBouncerLease *crdt_blease_get(const struct CrdtNetworkState *st,
                                               const char *account, const char *sessid)
{
  char key[128];
  uint32_t klen = bsess_key(account, sessid, key, sizeof key);
  const struct CrdtLWWValue *v;
  if (!klen)
    return NULL;
  v = crdt_lwwmap_get(&st->bleases, key, klen);
  return (v && v->data && v->data_len == sizeof(struct CrdtBouncerLease))
           ? (const struct CrdtBouncerLease *)v->data : NULL;
}

/* ------------------------------------------------------------------ */
/* sync / merge                                                       */
/* ------------------------------------------------------------------ */

static struct CrdtLWWMap *lww_for(struct CrdtNetworkState *st,
                                  enum CrdtCollection coll)
{
  switch (coll) {
  case CRDT_COLL_SERVERS: return &st->servers;
  case CRDT_COLL_USERS:   return &st->users;
  case CRDT_COLL_NICKS:   return &st->nicks;
  case CRDT_COLL_TOPICS:  return &st->topics;
  case CRDT_COLL_MODES:   return &st->modes;
  case CRDT_COLL_MEMBER_STATUS: return &st->members_status;
  case CRDT_COLL_KICK_INFO:     return &st->kick_info;
  case CRDT_COLL_CHANMETA:      return &st->chanmeta;
  case CRDT_COLL_GLINES:        return &st->glines;
  case CRDT_COLL_SHUNS:         return &st->shuns;
  case CRDT_COLL_ZLINES:        return &st->zlines;
  case CRDT_COLL_JUPES:         return &st->jupes;
  case CRDT_COLL_BSESSIONS:     return &st->bsessions;
  case CRDT_COLL_BCONNS:        return &st->bconns;
  case CRDT_COLL_BLEASES:       return &st->bleases;
  case CRDT_COLL_MARKERS:       return &st->markers;
  case CRDT_COLL_METADATA:      return &st->metadata;
  case CRDT_COLL_TEMPSHUNS:     return &st->tempshuns;
  default:                return NULL;
  }
}

struct CrdtLWWMap *crdt_state_lww_for(struct CrdtNetworkState *st,
                                      enum CrdtCollection coll)
{
  return lww_for(st, coll);
}

void crdt_state_apply_op(struct CrdtNetworkState *st, const struct CrdtOp *op)
{
  /* origin/tag.origin index seq[CRDT_MAX_SERVERS] (sv_has_seen below, sv_update
   * at the bottom, OR-Set GC on the tag) — crdt_op_decode already rejects OOB
   * values at the wire; mirror it here so no in-process caller can index the
   * state vector out of bounds either. */
  if (op->origin >= CRDT_MAX_SERVERS || op->tag.origin >= CRDT_MAX_SERVERS)
    return;

  if (crdt_sv_has_seen(&st->local_sv, op->origin, op->seq))
    return;                                  /* idempotent */

  if (op->coll == CRDT_COLL_CHAN_MEMBERS) {
    struct CrdtChannel *ch = chan_get(st, op->chan, op->chan_len, 1);
    if (op->type == CRDT_OP_ADD)
      crdt_orset_merge_add(&ch->members, op->key, op->key_len, op->tag);
    else
      crdt_orset_merge_remove(&ch->members, op->tag, op->priority);
  } else if (op->coll == CRDT_COLL_CHAN_BANS ||
             op->coll == CRDT_COLL_CHAN_EXCEPTS) {   /* Phase 3i ban/except OR-Sets */
    struct CrdtChannel *ch = chan_get(st, op->chan, op->chan_len, 1);
    struct CrdtORSet *set = (op->coll == CRDT_COLL_CHAN_EXCEPTS) ? &ch->excepts
                                                                 : &ch->bans;
    if (op->type == CRDT_OP_ADD)
      crdt_orset_merge_add(set, op->key, op->key_len, op->tag);
    else
      crdt_orset_merge_remove(set, op->tag, op->priority);
  } else if (op->coll == CRDT_COLL_CHAN_CTIME) {   /* Phase 3j incarnation min-register */
    if (op->val && op->val_len == sizeof(struct ctime_payload)) {
      const struct ctime_payload *pl = (const struct ctime_payload *)op->val;
      crdt_chan_ctime_merge(st, op->chan, op->chan_len, pl->value,
                            pl->set_hlc, pl->del_hlc);
      hlc_receive(&st->clock, &pl->set_hlc);       /* advance our clock */
    }
  } else if (op->coll == CRDT_COLL_BLEASES) {  /* 5-5e M5 comparator-merge register */
    if (op->type == CRDT_OP_SET && op->val &&
        op->val_len == sizeof(struct CrdtBouncerLease))
      blease_merge(st, op->key, op->key_len,
                   (const struct CrdtBouncerLease *)op->val, op->writer, op->ts);
    else if (op->type == CRDT_OP_DELETE)
      crdt_lwwmap_delete(&st->bleases, op->key, op->key_len, op->ts, op->writer);
    hlc_receive(&st->clock, &op->ts);            /* advance our clock */
  } else if (op->coll == CRDT_COLL_SILENCES) {   /* Tier C F1-c global silences OR-Set */
    if (op->type == CRDT_OP_ADD)
      crdt_orset_merge_add(&st->silences, op->key, op->key_len, op->tag);
    else
      crdt_orset_merge_remove(&st->silences, op->tag, op->priority);
  } else if (op->coll == CRDT_COLL_MARKERS) {    /* Tier C F2-a read-marker MAX-register */
    if (op->type == CRDT_OP_SET && op->val && op->val_len)
      marker_merge(st, op->key, op->key_len, op->val, op->val_len, op->writer, op->ts);
    hlc_receive(&st->clock, &op->ts);            /* advance our clock */
  } else if (op->coll == CRDT_COLL_TOPICS) {     /* M11 topic MAX-register on topic_time */
    if (op->type == CRDT_OP_SET && op->val && op->val_len > TOPIC_VAL_HDR) {
      /* val_len guard (mirrors ctime's == sizeof): a wrong-sized payload is IGNORED,
       * not misread — forward/backward-compat degradation across a mixed-binary mesh. */
      uint64_t topic_time = 0;
      memcpy(&topic_time, op->val, sizeof topic_time);
      topic_merge(st, op->key, op->key_len, topic_time,
                  (const char *)op->val + TOPIC_VAL_HDR,
                  op->val_len - TOPIC_VAL_HDR, op->writer, op->ts);
    } else if (op->type == CRDT_OP_DELETE) {
      crdt_lwwmap_delete(&st->topics, op->key, op->key_len, op->ts, op->writer);
    }
    hlc_receive(&st->clock, &op->ts);            /* advance our clock */
  } else {
    struct CrdtLWWMap *map = lww_for(st, op->coll);
    /* unknown collection (an op from a NEWER peer): lww_for returns NULL —
     * ignore the payload instead of derefing a NULL map, but still fall
     * through to record + sv_update below so the op relays onward and the
     * anti-entropy dedup never re-requests it (forward compat: a mixed-
     * version mesh degrades gracefully).  Mirrors the snapshot decoder's
     * if (map) guard. */
    if (map) {
      if (op->type == CRDT_OP_SET)
        crdt_lwwmap_set(map, op->key, op->key_len, op->val, op->val_len,
                        op->ts, op->writer);
      else
        crdt_lwwmap_delete(map, op->key, op->key_len, op->ts, op->writer);
    }
    hlc_receive(&st->clock, &op->ts);        /* advance our clock */
  }

  oplog_append(&st->oplog, op_clone(op));     /* keep for relay */
  crdt_sv_update(&st->local_sv, op->origin, op->seq);
}

int crdt_state_sync(struct CrdtNetworkState *dst,
                    const struct CrdtNetworkState *src)
{
  int applied = 0;
  for (struct CrdtOp *op = src->oplog.head; op; op = op->next) {
    if (!crdt_sv_has_seen(&dst->local_sv, op->origin, op->seq)) {
      crdt_state_apply_op(dst, op);
      applied++;
    }
  }
  return applied;
}

/* ------------------------------------------------------------------ */
/* equality (for convergence assertions)                              */
/* ------------------------------------------------------------------ */

static int lww_live_eq(const struct CrdtLWWMap *x, const struct CrdtLWWMap *y)
{
  if (crdt_lwwmap_size(x) != crdt_lwwmap_size(y)) return 0;
  for (uint32_t b = 0; b < x->nbuckets; b++) {
    for (struct CrdtLWWEntry *e = x->buckets[b]; e; e = e->ht_next) {
      if (e->deleted) continue;
      const struct CrdtLWWValue *vy = crdt_lwwmap_get(y, e->key, e->key_len);
      if (!vy) return 0;
      if (vy->data_len != e->val.data_len) return 0;
      if (e->val.data_len &&
          memcmp(vy->data, e->val.data, e->val.data_len) != 0) return 0;
    }
  }
  return 1;
}

struct subset_ctx { const struct CrdtORSet *other; int ok; };
static void subset_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct subset_ctx *c = ctx;
  if (!crdt_orset_contains(c->other, key, key_len)) c->ok = 0;
}

static int members_eq(const struct CrdtORSet *a, const struct CrdtORSet *b)
{
  if (crdt_orset_size(a) != crdt_orset_size(b)) return 0;
  struct subset_ctx c = { b, 1 };
  crdt_orset_foreach(a, subset_cb, &c);
  return c.ok;
}

static int chans_eq(const struct CrdtNetworkState *a,
                    const struct CrdtNetworkState *b)
{
  for (int bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    for (struct CrdtChannel *ca = a->chan_buckets[bk]; ca; ca = ca->next) {
      struct CrdtChannel *cb = chan_find(b, ca->name, ca->name_len);
      if (!cb) { if (crdt_orset_size(&ca->members) != 0) return 0; continue; }
      if (!members_eq(&ca->members, &cb->members)) return 0;
      /* Phase 3j: live creationtime must agree (the incarnation min-register).
       * Compare ONLY the live value — ctime_set/ctime_del are local bookkeeping
       * that legitimately differ for a destroyed channel. */
      {
        uint64_t va = (hlc_compare(&ca->ctime_set, &ca->ctime_del) > 0) ? ca->ctime : 0;
        uint64_t vb = (hlc_compare(&cb->ctime_set, &cb->ctime_del) > 0) ? cb->ctime : 0;
        if (va != vb) return 0;
      }
    }
    for (struct CrdtChannel *cb = b->chan_buckets[bk]; cb; cb = cb->next) {
      struct CrdtChannel *ca = chan_find(a, cb->name, cb->name_len);
      if (!ca && crdt_orset_size(&cb->members) != 0) return 0;
    }
  }
  return 1;
}

int crdt_state_equal(const struct CrdtNetworkState *a,
                     const struct CrdtNetworkState *b)
{
  return lww_live_eq(&a->servers, &b->servers)
      && lww_live_eq(&a->users, &b->users)
      && lww_live_eq(&a->nicks, &b->nicks)
      && chans_eq(a, b);
}

/* ------------------------------------------------------------------ */
/* digest (order-independent; includes tags + tombstones)             */
/* ------------------------------------------------------------------ */

#define FNV64_OFFSET 14695981039346656037ULL

static uint64_t fnv64(uint64_t h, const void *d, size_t n)
{
  const unsigned char *p = d;
  size_t i;
  for (i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
  return h;
}

/* Hash HLC / CrdtTag field-by-field — never the raw struct, whose padding
 * bytes are unspecified and would make the digest nondeterministic. */
static uint64_t hash_hlc(uint64_t h, const struct HLC *t)
{
  h = fnv64(h, &t->physical_ms, sizeof t->physical_ms);
  h = fnv64(h, &t->logical, sizeof t->logical);
  h = fnv64(h, &t->node_id, sizeof t->node_id);
  return h;
}
static uint64_t hash_tag(uint64_t h, const struct CrdtTag *tg)
{
  h = fnv64(h, &tg->origin, sizeof tg->origin);
  h = fnv64(h, &tg->seq, sizeof tg->seq);
  return h;
}

static uint64_t digest_lww(uint64_t acc, const struct CrdtLWWMap *m, uint8_t ns)
{
  uint32_t b;
  for (b = 0; b < m->nbuckets; b++) {
    struct CrdtLWWEntry *e;
    for (e = m->buckets[b]; e; e = e->ht_next) {
      uint64_t h = FNV64_OFFSET;
      h = fnv64(h, &ns, 1);
      h = fnv64(h, e->key, e->key_len);
      h = fnv64(h, &e->deleted, sizeof e->deleted);
      if (!e->deleted) {
        h = fnv64(h, e->val.data, e->val.data_len);
        h = hash_hlc(h, &e->val.ts);
        h = fnv64(h, &e->val.writer, sizeof e->val.writer);
      }
      acc ^= h;
    }
  }
  return acc;
}

/* Phase 3j: hash a channel's LIVE creationtime only. ctime_set/ctime_del are
 * local (a destroyed channel's del differs per server), so hashing them would
 * make destroyed channels falsely diverge; the live value (min-resolved, or 0
 * when destroyed) is the convergent observable. */
static uint64_t digest_ctime(uint64_t acc, const struct CrdtChannel *c)
{
  if (hlc_compare(&c->ctime_set, &c->ctime_del) > 0) {
    uint64_t h = FNV64_OFFSET;
    uint8_t ns = 13;
    h = fnv64(h, &ns, 1);
    h = fnv64(h, c->name, c->name_len);
    h = fnv64(h, &c->ctime, sizeof c->ctime);
    acc ^= h;
  }
  return acc;
}

/* 5-5e M5: hash the lease's AUTHORITY value (host,generation) only — NOT the synthetic
 * write HLC/writer (which legitimately differ per node after a comparator-merge), and NOT
 * claim_ms (observability only). Mirrors digest_ctime's value-only convergence. Tombstones
 * are hashed by key+deleted so a converged tombstone matches. */
static uint64_t digest_blease(uint64_t acc, const struct CrdtLWWMap *m, uint8_t ns)
{
  uint32_t b;
  for (b = 0; b < m->nbuckets; b++) {
    struct CrdtLWWEntry *e;
    for (e = m->buckets[b]; e; e = e->ht_next) {
      uint64_t h = FNV64_OFFSET;
      h = fnv64(h, &ns, 1);
      h = fnv64(h, e->key, e->key_len);
      h = fnv64(h, &e->deleted, sizeof e->deleted);
      if (!e->deleted && e->val.data &&
          e->val.data_len == sizeof(struct CrdtBouncerLease)) {
        const struct CrdtBouncerLease *l = e->val.data;
        h = fnv64(h, &l->host, sizeof l->host);
        h = fnv64(h, &l->generation, sizeof l->generation);
      }
      acc ^= h;
    }
  }
  return acc;
}

/* Tier C F2-a: digest a read-marker MAX-register collection — value-aware (the
 * ts_ms value IS the convergence metric, unlike a plain LWW where the HLC suffices).
 * Used for both the full and materialized digest (no GC-variant divergence). */
static uint64_t digest_marker(uint64_t acc, const struct CrdtLWWMap *m, uint8_t ns)
{
  uint32_t b;
  for (b = 0; b < m->nbuckets; b++) {
    struct CrdtLWWEntry *e;
    for (e = m->buckets[b]; e; e = e->ht_next) {
      uint64_t h = FNV64_OFFSET;
      h = fnv64(h, &ns, 1);
      h = fnv64(h, e->key, e->key_len);
      h = fnv64(h, &e->deleted, sizeof e->deleted);
      if (!e->deleted && e->val.data && e->val.data_len)
        h = fnv64(h, e->val.data, e->val.data_len);
      acc ^= h;
    }
  }
  return acc;
}

/* M11: digest the topics MAX-register VALUE-ONLY. The value buffer already encodes
 * topic_time + text (the convergent observable); hashing the LWW write-HLC/writer —
 * as the generic digest_lww does — would FALSELY diverge two nodes that converged on
 * the SAME topic via different synthesized write HLCs (topic_merge synth-on-win), which
 * would trip Fix-A's anti-entropy into a perpetual CR F snapshot storm. Clone of
 * digest_marker (value-only for the identical reason). Salt 4 (unchanged). */
static uint64_t digest_topic(uint64_t acc, const struct CrdtLWWMap *m, uint8_t ns)
{
  uint32_t b;
  for (b = 0; b < m->nbuckets; b++) {
    struct CrdtLWWEntry *e;
    for (e = m->buckets[b]; e; e = e->ht_next) {
      uint64_t h = FNV64_OFFSET;
      h = fnv64(h, &ns, 1);
      h = fnv64(h, e->key, e->key_len);
      h = fnv64(h, &e->deleted, sizeof e->deleted);
      if (!e->deleted && e->val.data && e->val.data_len)
        h = fnv64(h, e->val.data, e->val.data_len);
      acc ^= h;
    }
  }
  return acc;
}

static uint64_t digest_orset(uint64_t acc, const struct CrdtORSet *s,
                             const char *cname, uint32_t cnlen, uint8_t ns)
{
  uint32_t b;
  uint16_t i;
  for (b = 0; b < s->nbuckets; b++) {
    struct CrdtORSetEntry *e;
    for (e = s->buckets[b]; e; e = e->ht_next)
      for (i = 0; i < e->add_count; i++) {
        uint64_t h = FNV64_OFFSET;
        h = fnv64(h, &ns, 1);
        h = fnv64(h, cname, cnlen);
        h = fnv64(h, e->key, e->key_len);
        h = hash_tag(h, &e->add_tags[i]);
        acc ^= h;
      }
  }
  for (b = 0; b < s->tomb_nbuckets; b++) {
    struct CrdtTombstone *t;
    for (t = s->tomb[b]; t; t = t->ht_next) {
      uint64_t h = FNV64_OFFSET;
      h = fnv64(h, &ns, 1);
      h = fnv64(h, cname, cnlen);
      h = hash_tag(h, &t->tag);
      h = fnv64(h, &t->priority, 1);
      acc ^= h;
    }
  }
  return acc;
}

uint64_t crdt_state_digest(const struct CrdtNetworkState *st)
{
  uint64_t acc = 0;
  int bk;
  acc = digest_lww(acc, &st->servers, 1);
  acc = digest_lww(acc, &st->users, 2);
  acc = digest_lww(acc, &st->nicks, 3);
  acc = digest_topic(acc, &st->topics, 4);   /* M11: value-only (TRAP 2 — see digest_topic) */
  acc = digest_lww(acc, &st->modes, 5);
  acc = digest_lww(acc, &st->members_status, 6);
  acc = digest_lww(acc, &st->chanmeta, 7);
  acc = digest_lww(acc, &st->kick_info, 8);
  acc = digest_lww(acc, &st->glines, 9);
  acc = digest_lww(acc, &st->shuns, 13);   /* salt 13: 1-9 LWW, 10-12 OR-Set */
  acc = digest_lww(acc, &st->zlines, 14);  /* salt 14 */
  acc = digest_lww(acc, &st->jupes, 15);   /* salt 15 */
  acc = digest_lww(acc, &st->bsessions, 16); /* salt 16: 5-5e bouncer sessions */
  acc = digest_lww(acc, &st->bconns, 17);    /* salt 17: 5-5e M4 bouncer connections */
  acc = digest_blease(acc, &st->bleases, 18);/* salt 18: 5-5e M5 lease (value-only) */
  acc = digest_marker(acc, &st->markers, 20);/* salt 20: Tier C F2-a read-markers */
  acc = digest_lww(acc, &st->metadata, 21);  /* salt 21: Tier C F2-b account metadata */
  acc = digest_lww(acc, &st->tempshuns, 22); /* salt 22: Tier C F3 tempshuns */
  acc = digest_orset(acc, &st->silences, "", 0, 19);/* salt 19: Tier C F1-c silences */
  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *c;
    for (c = st->chan_buckets[bk]; c; c = c->next) {
      acc = digest_orset(acc, &c->members, c->name, c->name_len, 10);
      acc = digest_orset(acc, &c->bans, c->name, c->name_len, 11);
      acc = digest_orset(acc, &c->excepts, c->name, c->name_len, 12);
      acc = digest_ctime(acc, c);
    }
  }
  return acc;
}

/* Materialized-state digest: hash only PRESENT OR-Set elements (no add-tags,
 * no tombstones), plus the LWW maps (which carry no GC-reclaimable bookkeeping).
 * Unlike crdt_state_digest this is invariant under independent/asymmetric GC —
 * two replicas with the same observable state agree even if they have reclaimed
 * different tombstone subsets. This is the true convergence metric. */
static uint64_t digest_orset_present(uint64_t acc, const struct CrdtORSet *s,
                                     const char *cname, uint32_t cnlen,
                                     uint8_t ns)
{
  uint32_t b;
  for (b = 0; b < s->nbuckets; b++) {
    struct CrdtORSetEntry *e;
    for (e = s->buckets[b]; e; e = e->ht_next)
      if (crdt_orset_contains(s, e->key, e->key_len)) {
        uint64_t h = FNV64_OFFSET;
        h = fnv64(h, &ns, 1);
        h = fnv64(h, cname, cnlen);
        h = fnv64(h, e->key, e->key_len);
        acc ^= h;
      }
  }
  return acc;
}

uint64_t crdt_state_digest_materialized(const struct CrdtNetworkState *st)
{
  uint64_t acc = 0;
  int bk;
  acc = digest_lww(acc, &st->servers, 1);
  acc = digest_lww(acc, &st->users, 2);
  acc = digest_lww(acc, &st->nicks, 3);
  acc = digest_topic(acc, &st->topics, 4);   /* M11: value-only (TRAP 2 — see digest_topic) */
  acc = digest_lww(acc, &st->modes, 5);
  acc = digest_lww(acc, &st->members_status, 6);
  acc = digest_lww(acc, &st->chanmeta, 7);
  acc = digest_lww(acc, &st->kick_info, 8);
  acc = digest_lww(acc, &st->glines, 9);
  acc = digest_lww(acc, &st->shuns, 13);   /* salt 13: 1-9 LWW, 10-12 OR-Set */
  acc = digest_lww(acc, &st->zlines, 14);  /* salt 14 */
  acc = digest_lww(acc, &st->jupes, 15);   /* salt 15 */
  acc = digest_lww(acc, &st->bsessions, 16); /* salt 16: 5-5e bouncer sessions */
  acc = digest_lww(acc, &st->bconns, 17);    /* salt 17: 5-5e M4 bouncer connections */
  acc = digest_blease(acc, &st->bleases, 18);/* salt 18: 5-5e M5 lease (value-only) */
  acc = digest_marker(acc, &st->markers, 20);/* salt 20: Tier C F2-a read-markers */
  acc = digest_lww(acc, &st->metadata, 21);  /* salt 21: Tier C F2-b account metadata */
  acc = digest_lww(acc, &st->tempshuns, 22); /* salt 22: Tier C F3 tempshuns */
  acc = digest_orset_present(acc, &st->silences, "", 0, 19);/* salt 19: Tier C F1-c silences */
  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *c;
    for (c = st->chan_buckets[bk]; c; c = c->next) {
      acc = digest_orset_present(acc, &c->members, c->name, c->name_len, 10);
      acc = digest_orset_present(acc, &c->bans, c->name, c->name_len, 11);
      acc = digest_orset_present(acc, &c->excepts, c->name, c->name_len, 12);
      acc = digest_ctime(acc, c);
    }
  }
  return acc;
}


/* ------------------------------------------------------------------ */
/* orphaned per-member metadata reclaim (members_status / kick_info)    */
/* ------------------------------------------------------------------ */
/* members_status (CrdtMemberRecord) and kick_info (CrdtKickInfo) are LWW
 * registers keyed chan\0numeric, parallel to the members OR-Set. When a member
 * departs, the OR-Set entry is tombstoned then GC'd, but these LIVE LWW entries
 * are not deletes, so the tombstone GC never reclaims them — they leak forever for
 * churned members. Reclaim them by minting a DELETE op (NOT a local free: a local
 * free would be resurrected by a peer's CR F snapshot that still holds the live
 * entry → digest flap; a real tombstone propagates + LWW-wins + rides the existing
 * tombstone GC). Gate on the member being FULLY gone: neither contained NOR
 * explicitly-removed in the OR-Set, i.e. the removal is causally stable (its
 * tombstone already GC'd) — by which point reconcile-remove has consumed kick_info
 * on every peer, so deleting it is safe (KICK-vs-PART already decided). members_
 * status and kick_info are reclaimed independently; a later rejoin writes a fresh
 * members_status whose newer HLC gates any still-lingering stale kick_info (NB10).
 * NB: every peer's sweep mints these at ~the same causal point (multi-writer, but
 * the deletes are idempotent + LWW-dedup'd + GC quickly — benign at this scale). */

/* Mint a DELETE op for @a key in @a map/@a coll (mirrors crdt_user_remove). */
static void mint_meta_delete(struct CrdtNetworkState *st, struct CrdtLWWMap *map,
                             int coll, const char *key, uint32_t klen)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_delete(map, key, klen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_DELETE, coll);
  op->key = memdup(key, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

#define ORPHAN_MAX 64                 /* per-pass cap; survivors caught next cycle */
struct orphan_ctx {
  struct CrdtNetworkState *st;
  char     keys[ORPHAN_MAX][256];     /* full chan\0numeric keys to reclaim */
  uint32_t lens[ORPHAN_MAX];
  int      n;
};

/* foreach callback: collect (don't mutate the map mid-iterate) the keys of entries
 * whose member is FULLY gone from the channel's OR-Set. */
static void orphan_collect_cb(const char *key, uint32_t key_len,
                              const struct CrdtLWWValue *val, void *ctx)
{
  struct orphan_ctx *o = (struct orphan_ctx *)ctx;
  uint32_t clen, nlen;
  const char *num;
  struct CrdtChannel *ch;
  (void)val;
  if (o->n >= ORPHAN_MAX || key_len >= sizeof o->keys[0])
    return;
  clen = (uint32_t)strlen(key);          /* chan is NUL-terminated within the key */
  if (clen + 1 > key_len)
    return;                              /* malformed (no numeric part) */
  num = key + clen + 1;
  nlen = key_len - clen - 1;
  ch = chan_get(o->st, key, clen, 0);    /* lookup, no create */
  if (ch && (crdt_orset_contains(&ch->members, num, nlen) ||
             crdt_orset_is_explicitly_removed(&ch->members, num, nlen)))
    return;                              /* still a member, or mid-removal -> keep */
  memcpy(o->keys[o->n], key, key_len);
  o->lens[o->n] = key_len;
  o->n++;
}

/* Generalized LWW-orphan reap core: collect the keys of @a map whose ANCHOR (tested
 * by @a collect_cb, which fills the shared orphan_ctx) is fully-gone-and-causally-
 * stable, then mint a DELETE op for each. Bounded ORPHAN_MAX per pass (survivors
 * caught next cycle); collect-then-act so the map is never mutated mid-iterate.
 * Returns the count reclaimed. Shared by the member-meta anchor (chan\0numeric ->
 * per-member OR-Set slot) and the chan-meta anchor (channel name -> channel gone). */
static int reclaim_lww_orphans(struct CrdtNetworkState *st,
                               struct CrdtLWWMap *map, int coll,
                               crdt_lwwmap_iter_fn collect_cb)
{
  static struct orphan_ctx o;            /* static: 32KB, avoids a huge stack frame */
  int i;
  o.st = st; o.n = 0;
  crdt_lwwmap_foreach(map, collect_cb, &o);
  for (i = 0; i < o.n; i++)
    mint_meta_delete(st, map, coll, o.keys[i], o.lens[i]);
  return o.n;
}

/* Reclaim orphaned members_status/kick_info entries for fully-departed members by
 * minting DELETE ops. Returns the number reclaimed. Idempotent + safe to call every
 * GC cycle. */
int crdt_state_reclaim_orphan_member_meta(struct CrdtNetworkState *st)
{
  int total = 0;
  total += reclaim_lww_orphans(st, &st->members_status, CRDT_COLL_MEMBER_STATUS,
                               orphan_collect_cb);
  total += reclaim_lww_orphans(st, &st->kick_info, CRDT_COLL_KICK_INFO,
                               orphan_collect_cb);
  return total;
}

/* m15 (delete-on-leave): mint a members_status DELETE for a cleanly-departed member.
 * Mirrors mint_meta_delete, keyed chan\0numeric exactly like crdt_member_status_set.
 * NO stability gate — this is the real leave event on the single-writer home, minted
 * unconditionally, exactly like the crdt_chan_remove one line above it at the part/kick
 * integration hook (the GC reap gates on fully-gone-and-stable because it is a
 * SPECULATIVE sweep; this is not). Coordinates cleanly with the reap above:
 * crdt_lwwmap_foreach skips the tombstone this creates, so orphan_collect_cb never
 * double-mints for the same key; the reap stays the backstop for UNCLEAN departures
 * where the part/kick hook never fires on this node (home SQUIT/crash / netsplit). */
void crdt_member_status_remove(struct CrdtNetworkState *st, const char *chan,
                               const char *numeric)
{
  char key[512];                 /* chan \0 numeric — same key form as _set */
  uint32_t klen = chan_num_key(chan, numeric, key, sizeof key);
  if (klen)
    mint_meta_delete(st, &st->members_status, CRDT_COLL_MEMBER_STATUS, key, klen);
}

/* M10 anchor test: a channel is FULLY gone iff its members OR-Set is empty AND
 * causally stable (no live member-removes: tomb_count==0) AND its ctime incarnation
 * is dead. tomb_count==0 (NOT ctime-dead alone) is the causal-stability signal:
 * ctime_del is local-only (bumped by crdt_chan_ctime_clear, no op), so ctime-dead-
 * locally does not prove death network-wide; members-empty-AND-stable proves every
 * peer saw the departures. A NULL struct is NOT proof of fully-gone: a
 * topic/modes/chanmeta SET op does not create the CrdtChannel struct (only
 * member/ban/except/ctime ops do), so under cross-origin delta lag a node can
 * hold a meta entry before the struct-creating ops arrive — chan_find is then
 * NULL for a channel that is forming, not gone. Reaping there would DELETE a
 * live channel's meta network-wide. Since M6 keeps every struct ever created, a
 * genuinely fully-gone channel ALWAYS still has its struct, so it is reaped via
 * the real predicate below; NULL means "can't prove gone yet" -> keep. */
static int chan_fully_gone(struct CrdtNetworkState *st,
                           const char *name, uint32_t nlen)
{
  struct CrdtChannel *ch = chan_find(st, name, nlen);
  if (!ch)
    return 0;
  if (crdt_orset_size(&ch->members) != 0 || crdt_orset_tomb_count(&ch->members) != 0)
    return 0;
  if (hlc_compare(&ch->ctime_set, &ch->ctime_del) > 0)   /* ctime incarnation still live */
    return 0;
  return 1;
}

/* foreach callback: collect (don't mutate mid-iterate) the keys of per-channel meta
 * entries whose CHANNEL is fully gone. The key IS the channel name (no numeric part
 * to parse). Foreach-ing LIVE meta entries and gating on the channel anchor is
 * legitimate (invariant 11 bars foreach-ing a *tombstone*, not present entries). */
static void chanmeta_orphan_collect_cb(const char *key, uint32_t key_len,
                                       const struct CrdtLWWValue *val, void *ctx)
{
  struct orphan_ctx *o = (struct orphan_ctx *)ctx;
  (void)val;
  if (o->n >= ORPHAN_MAX || key_len >= sizeof o->keys[0])
    return;
  if (!chan_fully_gone(o->st, key, key_len))
    return;
  memcpy(o->keys[o->n], key, key_len);
  o->lens[o->n] = key_len;
  o->n++;
}

/* M10: reclaim orphaned topic/modes/chanmeta LWW entries for fully-gone channels by
 * minting DELETE ops (NOT a local free — a local free is resurrected by a peer's CR F
 * snapshot that still holds the live entry -> digest flap; a real tombstone propagates
 * + LWW-wins + rides the existing tombstone GC). These three LWW registers are keyed
 * by channel name and, unlike the members OR-Set, are never tombstoned on destroy, so
 * they leak forever for churned channels and bloat every CR F snapshot without this
 * reap. Returns the count reclaimed. Safe + idempotent to call every GC cycle. */
int crdt_state_reclaim_orphan_chan_meta(struct CrdtNetworkState *st)
{
  int total = 0;
  total += reclaim_lww_orphans(st, &st->topics, CRDT_COLL_TOPICS,
                               chanmeta_orphan_collect_cb);
  total += reclaim_lww_orphans(st, &st->modes, CRDT_COLL_MODES,
                               chanmeta_orphan_collect_cb);
  total += reclaim_lww_orphans(st, &st->chanmeta, CRDT_COLL_CHANMETA,
                               chanmeta_orphan_collect_cb);
  return total;
}

/* ------------------------------------------------------------------ */
/* M9: per-user SILENCE-mask reaps (global silences OR-Set, keyed numeric\0mask) */
/* ------------------------------------------------------------------ */
/* A departed user's masks are never tombstoned by user_remove, so they persist as
 * LIVE OR-Set entries (growth) and -- worse -- a reused P10 numeric inherits them via
 * the numeric-keyed doc->live sync (the bleed). Both reaps collect (numeric,mask)
 * pairs read-only, then mint crdt_silence_remove (priority-0, the exact op the live
 * shadow-mirror path uses on a manual /SILENCE -mask) for each -- never a raw
 * orset_remove, so each tombstone replicates as a delta. The reaped mask bytes are
 * copied VERBATIM from the doc key, so crdt_silence_remove's silence_key() rebuilds
 * the byte-identical key it tombstones: no mask re-canonicalization, hence no
 * add/remove flip-flop with the live mirror. */
#define SILENCE_REAP_MAX 64
struct silence_reap_ctx {
  struct CrdtNetworkState *st;
  const char *only_numeric;              /* non-NULL: only this user (targeted reap) */
  uint32_t    only_numlen;               /* NULL: sweep fully-gone users (backstop)  */
  char        num[SILENCE_REAP_MAX][CRDT_NUMERICLEN + 1];
  char        mask[SILENCE_REAP_MAX][256];
  int         n;
};

/* foreach callback: collect (don't mutate mid-iterate) the numeric+mask of silence
 * entries to reap. Targeted: entries matching only_numeric. Sweep: entries whose
 * owning user is FULLY absent (get==NULL AND !is_deleted -> removal causally stable;
 * a live user or a not-yet-stable delete-tombstone is kept). */
static void silence_reap_collect_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct silence_reap_ctx *c = (struct silence_reap_ctx *)ctx;
  uint32_t numlen, masklen;
  const char *mask;
  if (c->n >= SILENCE_REAP_MAX)
    return;
  numlen = (uint32_t)strlen(key);        /* numeric is NUL-terminated within the key */
  if (numlen + 1 > key_len)
    return;                              /* malformed (no mask part) */
  mask = key + numlen + 1;
  masklen = key_len - numlen - 1;
  if (numlen >= sizeof c->num[0] || masklen >= sizeof c->mask[0])
    return;
  if (c->only_numeric) {
    if (numlen != c->only_numlen || memcmp(key, c->only_numeric, numlen) != 0)
      return;                            /* a different user's mask -> skip */
  } else if (crdt_lwwmap_get(&c->st->users, key, numlen) != NULL ||
             crdt_lwwmap_is_deleted(&c->st->users, key, numlen)) {
    return;                              /* user live, or removal not yet stable -> keep */
  }
  memcpy(c->num[c->n], key, numlen);    c->num[c->n][numlen] = '\0';
  memcpy(c->mask[c->n], mask, masklen); c->mask[c->n][masklen] = '\0';
  c->n++;
}

/* Targeted reap (from crdt_user_remove): mint crdt_silence_remove for every mask of
 * @a numeric. Loops until a short round so a user with > SILENCE_REAP_MAX masks is
 * FULLY drained synchronously -- the bleed close requires ALL of the departing user's
 * masks tombstoned before any numeric reuse, not just the first bounded batch. */
void crdt_state_reclaim_user_silences(struct CrdtNetworkState *st, const char *numeric)
{
  static struct silence_reap_ctx c;      /* static: avoids a large stack frame */
  int i;
  if (crdt_orset_size(&st->silences) == 0)   /* overwhelming common case: none */
    return;
  c.st = st;
  c.only_numeric = numeric;
  c.only_numlen = (uint32_t)strlen(numeric);
  do {
    c.n = 0;
    crdt_orset_foreach(&st->silences, silence_reap_collect_cb, &c);
    for (i = 0; i < c.n; i++)
      crdt_silence_remove(st, c.num[i], c.mask[i], CRDT_PRIORITY_USER);
  } while (c.n == SILENCE_REAP_MAX);
}

/* Backstop sweep (from crdt_shadow_gc): mint crdt_silence_remove for every mask whose
 * owning user is fully absent. Bounded SILENCE_REAP_MAX per pass (survivors caught
 * next cycle, like the member-meta template). Returns the count reclaimed. */
int crdt_state_reclaim_orphan_silences(struct CrdtNetworkState *st)
{
  static struct silence_reap_ctx c;      /* static: avoids a large stack frame */
  int i;
  if (crdt_orset_size(&st->silences) == 0)
    return 0;
  c.st = st;
  c.only_numeric = NULL;
  c.only_numlen = 0;
  c.n = 0;
  crdt_orset_foreach(&st->silences, silence_reap_collect_cb, &c);
  for (i = 0; i < c.n; i++)
    crdt_silence_remove(st, c.num[i], c.mask[i], CRDT_PRIORITY_USER);
  return c.n;
}

/* ------------------------------------------------------------------ */
/* causal-stability GC                                                */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Tier C F3: TEMPSHUN register (victim numeric -> CrdtTempshun, LWW)  */
/* ------------------------------------------------------------------ */

void crdt_tempshun_set(struct CrdtNetworkState *st, const char *numeric,
                       int active, const char *reason)
{
  struct CrdtTempshun rec;
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(numeric);
  uint64_t seq;
  struct CrdtOp *op;
  memset(&rec, 0, sizeof rec);          /* deterministic wire bytes (inv. 4) */
  rec.active = active ? 1 : 0;
  if (reason)
    strncpy(rec.reason, reason, sizeof rec.reason - 1);
  crdt_lwwmap_set(&st->tempshuns, numeric, klen, &rec, sizeof rec,
                  ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_TEMPSHUNS);
  op->key = memdup(numeric, klen);
  op->key_len = klen;
  op->val = memdup(&rec, sizeof rec);
  op->val_len = sizeof rec;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

const struct CrdtTempshun *crdt_tempshun_get(const struct CrdtNetworkState *st,
                                             const char *numeric)
{
  const struct CrdtLWWValue *v =
    crdt_lwwmap_get(&st->tempshuns, numeric, (uint32_t)strlen(numeric));
  return (v && v->data && v->data_len == sizeof(struct CrdtTempshun))
           ? (const struct CrdtTempshun *)v->data : NULL;
}

/* Mint the doc DELETE for one tempshun entry (reap path only — a '-' flip is
 * a live active=0 SET, never a delete). */
static void tempshun_mint_delete(struct CrdtNetworkState *st,
                                 const char *numeric, uint32_t klen)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint64_t seq = st->next_seq++;
  struct CrdtOp *op = op_new(st->my_numeric, seq, CRDT_OP_DELETE,
                             CRDT_COLL_TEMPSHUNS);
  crdt_lwwmap_delete(&st->tempshuns, numeric, klen, ts, st->my_numeric);
  op->key = memdup(numeric, klen);
  op->key_len = klen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
}

void crdt_state_reclaim_user_tempshun(struct CrdtNetworkState *st,
                                      const char *numeric)
{
  uint32_t klen = (uint32_t)strlen(numeric);
  const struct CrdtLWWValue *v = crdt_lwwmap_get(&st->tempshuns, numeric, klen);
  if (v && v->data)                     /* live entry only (inv. 5/11) */
    tempshun_mint_delete(st, numeric, klen);
}

#define TEMPSHUN_REAP_MAX 64
struct tempshun_reap_ctx {
  struct CrdtNetworkState *st;
  char num[TEMPSHUN_REAP_MAX][8];      /* 5-char numeric + NUL */
  uint32_t nlen[TEMPSHUN_REAP_MAX];
  int n;
};

static void tempshun_reap_collect_cb(const char *key, uint32_t key_len,
                                     const struct CrdtLWWValue *val, void *ctx)
{
  struct tempshun_reap_ctx *c = (struct tempshun_reap_ctx *)ctx;
  (void)val;
  if (c->n >= TEMPSHUN_REAP_MAX || key_len >= sizeof c->num[0])
    return;
  /* the silences gate (inv. 5): user live, or removal not yet causally
   * stable -> keep; reap only the FULLY-absent. */
  if (crdt_lwwmap_get(&c->st->users, key, key_len) != NULL ||
      crdt_lwwmap_is_deleted(&c->st->users, key, key_len))
    return;
  memcpy(c->num[c->n], key, key_len);
  c->num[c->n][key_len] = '\0';
  c->nlen[c->n] = key_len;
  c->n++;
}

int crdt_state_reclaim_orphan_tempshuns(struct CrdtNetworkState *st)
{
  struct tempshun_reap_ctx c;
  int total = 0, i;
  if (crdt_lwwmap_size(&st->tempshuns) == 0)  /* common case: none */
    return 0;
  do {
    c.st = st;
    c.n = 0;
    crdt_lwwmap_foreach(&st->tempshuns, tempshun_reap_collect_cb, &c);
    for (i = 0; i < c.n; i++)
      tempshun_mint_delete(st, c.num[i], c.nlen[i]);
    total += c.n;
  } while (c.n == TEMPSHUN_REAP_MAX);
  return total;
}

int crdt_state_gc(struct CrdtNetworkState *st,
                  const struct CrdtStateVector *stable)
{
  int freed = 0;

  /* oplog: drop ops every peer has seen */
  struct CrdtOp *cur = st->oplog.head, *nh = NULL, *nt = NULL;
  uint32_t cnt = 0;
  while (cur) {
    struct CrdtOp *nx = cur->next;
    if (stable->seq[cur->origin] >= cur->seq) {
      /* This op is causally stable (every peer has it). If it's an LWW delete, its
       * tombstone is now reclaimable too — free it (unless a newer write superseded
       * it). Fixes unbounded growth of delete-tombstones (e.g. quit users / 3m). */
      if (cur->type == CRDT_OP_DELETE) {
        struct CrdtLWWMap *m = lww_for(st, cur->coll);
        if (m)
          freed += crdt_lwwmap_gc_deleted(m, cur->key, cur->key_len, cur->ts);
      }
      op_free(cur);
      freed++;
    } else {
      cur->next = NULL;
      if (nt) nt->next = cur; else nh = cur;
      nt = cur;
      cnt++;
    }
    cur = nx;
  }
  st->oplog.head = nh;
  st->oplog.tail = nt;
  st->oplog.count = cnt;

  /* channel member sets: reclaim stable tombstones */
  for (int b = 0; b < CRDT_CHAN_BUCKETS; b++)
    for (struct CrdtChannel *c = st->chan_buckets[b]; c; c = c->next) {
      freed += crdt_orset_gc(&c->members, stable);
      freed += crdt_orset_gc(&c->bans, stable);
      freed += crdt_orset_gc(&c->excepts, stable);
    }
  freed += crdt_orset_gc(&st->silences, stable);  /* Tier C F1-c global silences OR-Set */

  /* record the reclaimed cut: anything <= gc_floor is gone from the oplog, so a
   * peer whose SV is below it must be sent a full snapshot, not a delta. */
  for (int i = 0; i < CRDT_MAX_SERVERS; i++)
    crdt_sv_update(&st->gc_floor, (uint16_t)i, stable->seq[i]);

  return freed;
}

/* ------------------------------------------------------------------ */
/* queries                                                            */
/* ------------------------------------------------------------------ */

const struct CrdtUserRecord *crdt_user_get(const struct CrdtNetworkState *st,
                                           const char *numeric)
{
  const struct CrdtLWWValue *v =
    crdt_lwwmap_get(&st->users, numeric, (uint32_t)strlen(numeric));
  return v ? (const struct CrdtUserRecord *)v->data : NULL;
}

int crdt_user_visible(const struct CrdtNetworkState *st, const char *numeric)
{
  const struct CrdtUserRecord *rec = crdt_user_get(st, numeric);
  if (!rec) return 0;
  char key[8];
  uint32_t klen = server_key(rec->server, key, sizeof key);
  const struct CrdtLWWValue *sv = crdt_lwwmap_get(&st->servers, key, klen);
  if (!sv) return 1;                          /* unknown server -> visible */
  return ((const struct CrdtServerRecord *)sv->data)->state == CRDT_SRV_ACTIVE;
}

struct vis_ctx { struct CrdtNetworkState *st; uint32_t n; };
static void vis_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct vis_ctx *c = ctx;
  char buf[CRDT_NUMERICLEN];
  if (key_len >= sizeof buf) key_len = sizeof buf - 1;
  memcpy(buf, key, key_len);
  buf[key_len] = '\0';
  if (crdt_user_visible(c->st, buf)) c->n++;
}

uint32_t crdt_chan_visible_members(struct CrdtNetworkState *st,
                                   const char *chan)
{
  struct CrdtChannel *ch = crdt_state_channel(st, chan, 0);
  if (!ch) return 0;
  struct vis_ctx c = { st, 0 };
  crdt_orset_foreach(&ch->members, vis_cb, &c);
  return c.n;
}

/* ------------------------------------------------------------------ */
/* nick-collision state machine (§17.5)                               */
/* ------------------------------------------------------------------ */

const struct CrdtNickClaim *
crdt_resolve_nick_collision(const struct CrdtNickClaim *local,
                            const struct CrdtNickClaim *remote,
                            const char *registered_owner)
{
  /* 1. account owner wins regardless of timestamp */
  if (registered_owner && registered_owner[0]) {
    int lo = strcmp(local->account, registered_owner) == 0;
    int ro = strcmp(remote->account, registered_owner) == 0;
    if (lo && !ro) return local;
    if (ro && !lo) return remote;
  }

  int differ = (local->ip != remote->ip) ||
               (strcmp(local->ident, remote->ident) != 0);
  int c = hlc_compare(&local->claimed_at, &remote->claimed_at);

  if (differ) {
    /* different user@host: OLDER claim wins (keep established user) */
    if (c < 0) return local;
    if (c > 0) return remote;
  } else {
    /* same user@host reconnecting: NEWER wins */
    if (c > 0) return local;
    if (c < 0) return remote;
  }

  /* 4. tie -> lower node_id */
  return (local->claimed_at.node_id <= remote->claimed_at.node_id)
         ? local : remote;
}

void crdt_nick_force_rename(struct CrdtNetworkState *st,
                            const struct CrdtNickClaim *loser,
                            struct HLC now)
{
  uint32_t nlen = (uint32_t)strlen(loser->numeric);

  /* rename the loser's user record nick -> its numeric (NOT a kill) */
  const struct CrdtLWWValue *v = crdt_lwwmap_get(&st->users, loser->numeric, nlen);
  if (v && v->data) {
    struct CrdtUserRecord r = *(const struct CrdtUserRecord *)v->data;
    memset(r.nick, 0, sizeof r.nick);
    strncpy(r.nick, loser->numeric, sizeof r.nick - 1);
    crdt_lwwmap_set(&st->users, loser->numeric, nlen, &r, sizeof r,
                    now, st->my_numeric);
  }

  /* claim the numeric as the loser's new (lowercased) nick */
  char lc[CRDT_NUMERICLEN];
  size_t i;
  for (i = 0; loser->numeric[i] && i < sizeof lc - 1; i++)
    lc[i] = (char)tolower((unsigned char)loser->numeric[i]);
  lc[i] = '\0';
  struct CrdtNickClaim nc = *loser;
  nc.claimed_at = now;
  crdt_lwwmap_set(&st->nicks, lc, (uint32_t)strlen(lc), &nc, sizeof nc,
                  now, st->my_numeric);
}
