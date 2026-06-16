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
  int n = crdt_orset_remove(&ch->members, numeric, klen, priority, removed, 64);
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

void crdt_topic_set(struct CrdtNetworkState *st, const char *chan,
                    const char *topic)
{
  struct HLC ts = hlc_local_event(&st->clock);
  uint32_t klen = (uint32_t)strlen(chan);
  uint32_t vlen = (uint32_t)strlen(topic) + 1;   /* include the NUL */
  uint64_t seq;
  struct CrdtOp *op;
  crdt_lwwmap_set(&st->topics, chan, klen, topic, vlen, ts, st->my_numeric);
  seq = st->next_seq++;
  op = op_new(st->my_numeric, seq, CRDT_OP_SET, CRDT_COLL_TOPICS);
  op->key = memdup(chan, klen);
  op->key_len = klen;
  op->val = memdup(topic, vlen);
  op->val_len = vlen;
  op->ts = ts;
  op->writer = st->my_numeric;
  record(st, op);
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
  } else {
    struct CrdtLWWMap *map = lww_for(st, op->coll);
    if (op->type == CRDT_OP_SET)
      crdt_lwwmap_set(map, op->key, op->key_len, op->val, op->val_len,
                      op->ts, op->writer);
    else
      crdt_lwwmap_delete(map, op->key, op->key_len, op->ts, op->writer);
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
  acc = digest_lww(acc, &st->topics, 4);
  acc = digest_lww(acc, &st->modes, 5);
  acc = digest_lww(acc, &st->members_status, 6);
  acc = digest_lww(acc, &st->chanmeta, 7);
  acc = digest_lww(acc, &st->kick_info, 8);
  acc = digest_lww(acc, &st->glines, 9);
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
  acc = digest_lww(acc, &st->topics, 4);
  acc = digest_lww(acc, &st->modes, 5);
  acc = digest_lww(acc, &st->members_status, 6);
  acc = digest_lww(acc, &st->chanmeta, 7);
  acc = digest_lww(acc, &st->kick_info, 8);
  acc = digest_lww(acc, &st->glines, 9);
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

/* Reclaim orphaned members_status/kick_info entries for fully-departed members by
 * minting DELETE ops. Returns the number reclaimed. Idempotent + safe to call every
 * GC cycle. */
int crdt_state_reclaim_orphan_member_meta(struct CrdtNetworkState *st)
{
  static struct orphan_ctx o;            /* static: 32KB, avoids a huge stack frame */
  int i, total = 0;

  o.st = st; o.n = 0;
  crdt_lwwmap_foreach(&st->members_status, orphan_collect_cb, &o);
  for (i = 0; i < o.n; i++)
    mint_meta_delete(st, &st->members_status, CRDT_COLL_MEMBER_STATUS,
                     o.keys[i], o.lens[i]);
  total += o.n;

  o.n = 0;
  crdt_lwwmap_foreach(&st->kick_info, orphan_collect_cb, &o);
  for (i = 0; i < o.n; i++)
    mint_meta_delete(st, &st->kick_info, CRDT_COLL_KICK_INFO, o.keys[i], o.lens[i]);
  total += o.n;

  return total;
}

/* ------------------------------------------------------------------ */
/* causal-stability GC                                                */
/* ------------------------------------------------------------------ */

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
