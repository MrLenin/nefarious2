/*
 * crdt_types.c - Custom C CRDT primitives (OR-Set, LWW-Map, state vector)
 *
 * Implements crdt_types.h. libc + crdt_hlc only — no IRCd coupling, so the
 * engine is unit-testable in isolation (see ircd/test/crdt_cmocka.c).
 *
 * Phase 0 PoC (CRDT-mesh proposal §17.1-17.2).
 */

#include "crdt_types.h"

#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void *xmalloc(size_t n)
{
  void *p = malloc(n ? n : 1);
  return p; /* PoC: callers operate on bounded test/sim data */
}

static void *memdup(const void *d, uint32_t n)
{
  void *p = xmalloc(n);
  if (d && n) memcpy(p, d, n);
  return p;
}

static uint32_t fnv1a(const void *d, uint32_t n)
{
  uint32_t h = 2166136261u;
  const unsigned char *p = (const unsigned char *)d;
  for (uint32_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
  return h;
}

static uint32_t tag_hash(struct CrdtTag t)
{
  uint32_t h = 2166136261u;
  h = (h ^ t.origin) * 16777619u;
  for (int i = 0; i < 8; i++)
    h = (h ^ (uint32_t)((t.seq >> (i * 8)) & 0xff)) * 16777619u;
  return h;
}

static int key_eq(const struct CrdtORSetEntry *e,
                  const char *key, uint32_t key_len)
{
  return e->key_len == key_len && memcmp(e->key, key, key_len) == 0;
}

/* ================================================================== */
/* CrdtORSet                                                          */
/* ================================================================== */

#define ORSET_BUCKETS 64
#define TOMB_BUCKETS  64

void crdt_orset_init(struct CrdtORSet *set)
{
  set->buckets = xmalloc(ORSET_BUCKETS * sizeof(*set->buckets));
  memset(set->buckets, 0, ORSET_BUCKETS * sizeof(*set->buckets));
  set->nbuckets = ORSET_BUCKETS;
  set->entry_count = 0;
  set->tomb = xmalloc(TOMB_BUCKETS * sizeof(*set->tomb));
  memset(set->tomb, 0, TOMB_BUCKETS * sizeof(*set->tomb));
  set->tomb_nbuckets = TOMB_BUCKETS;
  set->tomb_count = 0;
}

void crdt_orset_clear(struct CrdtORSet *set)
{
  if (!set->buckets && !set->tomb) return;
  for (uint32_t b = 0; b < set->nbuckets; b++) {
    struct CrdtORSetEntry *e = set->buckets[b];
    while (e) {
      struct CrdtORSetEntry *n = e->ht_next;
      free(e->add_tags);
      free(e->key);
      free(e);
      e = n;
    }
  }
  for (uint32_t b = 0; b < set->tomb_nbuckets; b++) {
    struct CrdtTombstone *t = set->tomb[b];
    while (t) { struct CrdtTombstone *n = t->ht_next; free(t); t = n; }
  }
  free(set->buckets);
  free(set->tomb);
  memset(set, 0, sizeof(*set));
}

static struct CrdtORSetEntry *orset_find(const struct CrdtORSet *set,
                                         const char *key, uint32_t key_len)
{
  uint32_t b = fnv1a(key, key_len) % set->nbuckets;
  struct CrdtORSetEntry *e = set->buckets[b];
  for (; e; e = e->ht_next)
    if (key_eq(e, key, key_len)) return e;
  return NULL;
}

static struct CrdtORSetEntry *orset_find_or_create(struct CrdtORSet *set,
                                                   const char *key,
                                                   uint32_t key_len)
{
  struct CrdtORSetEntry *e = orset_find(set, key, key_len);
  if (e) return e;
  uint32_t b = fnv1a(key, key_len) % set->nbuckets;
  e = xmalloc(sizeof(*e));
  memset(e, 0, sizeof(*e));
  e->key = memdup(key, key_len);
  e->key_len = key_len;
  e->ht_next = set->buckets[b];
  set->buckets[b] = e;
  set->entry_count++;
  return e;
}

static void entry_add_tag(struct CrdtORSetEntry *e, struct CrdtTag tag)
{
  for (uint16_t i = 0; i < e->add_count; i++)
    if (crdt_tag_eq(e->add_tags[i], tag)) return;   /* idempotent */
  if (e->add_count == e->add_cap) {
    e->add_cap = e->add_cap ? (uint16_t)(e->add_cap * 2) : 4;
    e->add_tags = realloc(e->add_tags, e->add_cap * sizeof(*e->add_tags));
  }
  e->add_tags[e->add_count++] = tag;
}

static struct CrdtTombstone *tomb_find(const struct CrdtORSet *set,
                                       struct CrdtTag tag)
{
  uint32_t b = tag_hash(tag) % set->tomb_nbuckets;
  struct CrdtTombstone *t = set->tomb[b];
  for (; t; t = t->ht_next)
    if (crdt_tag_eq(t->tag, tag)) return t;
  return NULL;
}

static void tomb_put(struct CrdtORSet *set, struct CrdtTag tag, uint8_t prio)
{
  struct CrdtTombstone *t = tomb_find(set, tag);
  if (t) { if (prio > t->priority) t->priority = prio; return; } /* max prio */
  uint32_t b = tag_hash(tag) % set->tomb_nbuckets;
  t = xmalloc(sizeof(*t));
  t->tag = tag;
  t->priority = prio;
  t->ht_next = set->tomb[b];
  set->tomb[b] = t;
  set->tomb_count++;
}

int crdt_orset_contains(const struct CrdtORSet *set,
                        const char *key, uint32_t key_len)
{
  struct CrdtORSetEntry *e = orset_find(set, key, key_len);
  if (!e) return 0;
  int live = 0, prio_remove = 0;
  for (uint16_t i = 0; i < e->add_count; i++) {
    struct CrdtTombstone *t = tomb_find(set, e->add_tags[i]);
    if (!t) live = 1;
    else if (t->priority > 0) prio_remove = 1;
  }
  return live && !prio_remove;
}

int crdt_orset_is_explicitly_removed(const struct CrdtORSet *set,
                                     const char *key, uint32_t key_len)
{
  /* Distinguish "tombstoned" (entry exists but all add-tags covered → a real
   * remove happened) from "absent" (never added / GC'd). The linchpin for a safe
   * doc→live reconcile-remove: fire ONLY on an explicit tombstone, NEVER on mere
   * absence (which could be sync lag or a P10-only member we haven't seen added). */
  if (!orset_find(set, key, key_len))
    return 0;                                 /* absent → NOT explicitly removed */
  return !crdt_orset_contains(set, key, key_len);  /* exists but not contained → removed */
}

void crdt_orset_add(struct CrdtORSet *set, const char *key, uint32_t key_len,
                    struct CrdtTag tag)
{
  entry_add_tag(orset_find_or_create(set, key, key_len), tag);
}

void crdt_orset_merge_add(struct CrdtORSet *set, const char *key,
                          uint32_t key_len, struct CrdtTag tag)
{
  entry_add_tag(orset_find_or_create(set, key, key_len), tag);
}

int crdt_orset_remove(struct CrdtORSet *set, const char *key, uint32_t key_len,
                      uint8_t priority, struct CrdtTag *out_tags, int max_out)
{
  struct CrdtORSetEntry *e = orset_find(set, key, key_len);
  if (!e) return 0;
  int n = 0;
  for (uint16_t i = 0; i < e->add_count; i++) {
    struct CrdtTag t = e->add_tags[i];
    if (tomb_find(set, t)) continue;        /* already covered */
    tomb_put(set, t, priority);
    if (out_tags && n < max_out) out_tags[n] = t;
    n++;
  }
  return n;
}

void crdt_orset_merge_remove(struct CrdtORSet *set, struct CrdtTag tag,
                             uint8_t priority)
{
  tomb_put(set, tag, priority);
}

int crdt_orset_gc(struct CrdtORSet *set, const struct CrdtStateVector *stable)
{
  /* Phase 1: drop add-tags that are tombstoned AND causally stable. */
  for (uint32_t b = 0; b < set->nbuckets; b++) {
    for (struct CrdtORSetEntry *e = set->buckets[b]; e; e = e->ht_next) {
      uint16_t w = 0;
      for (uint16_t i = 0; i < e->add_count; i++) {
        struct CrdtTag t = e->add_tags[i];
        int is_stable = stable->seq[t.origin] >= t.seq;
        if (is_stable && tomb_find(set, t))
          continue;                          /* removed + stable -> drop */
        e->add_tags[w++] = t;
      }
      e->add_count = w;
    }
  }

  /* Phase 2: free entries left with no add-tags. */
  for (uint32_t b = 0; b < set->nbuckets; b++) {
    struct CrdtORSetEntry **pp = &set->buckets[b];
    while (*pp) {
      struct CrdtORSetEntry *e = *pp;
      if (e->add_count == 0) {
        *pp = e->ht_next;
        free(e->add_tags);
        free(e->key);
        free(e);
        set->entry_count--;
      } else {
        pp = &e->ht_next;
      }
    }
  }

  /* Phase 3: free causally-stable tombstones. */
  int freed = 0;
  for (uint32_t b = 0; b < set->tomb_nbuckets; b++) {
    struct CrdtTombstone **pp = &set->tomb[b];
    while (*pp) {
      struct CrdtTombstone *t = *pp;
      if (stable->seq[t->tag.origin] >= t->tag.seq) {
        *pp = t->ht_next;
        free(t);
        set->tomb_count--;
        freed++;
      } else {
        pp = &t->ht_next;
      }
    }
  }
  return freed;
}

uint32_t crdt_orset_size(const struct CrdtORSet *set)
{
  uint32_t n = 0;
  for (uint32_t b = 0; b < set->nbuckets; b++)
    for (struct CrdtORSetEntry *e = set->buckets[b]; e; e = e->ht_next)
      if (crdt_orset_contains(set, e->key, e->key_len)) n++;
  return n;
}

uint32_t crdt_orset_tomb_count(const struct CrdtORSet *set)
{
  return set->tomb_count;
}

void crdt_orset_foreach(const struct CrdtORSet *set,
                        crdt_orset_iter_fn fn, void *ctx)
{
  for (uint32_t b = 0; b < set->nbuckets; b++)
    for (struct CrdtORSetEntry *e = set->buckets[b]; e; e = e->ht_next)
      if (crdt_orset_contains(set, e->key, e->key_len))
        fn(e->key, e->key_len, ctx);
}

/* ================================================================== */
/* CrdtLWWMap                                                         */
/* ================================================================== */

#define LWW_BUCKETS 256

void crdt_lwwmap_init(struct CrdtLWWMap *map)
{
  map->buckets = xmalloc(LWW_BUCKETS * sizeof(*map->buckets));
  memset(map->buckets, 0, LWW_BUCKETS * sizeof(*map->buckets));
  map->nbuckets = LWW_BUCKETS;
  map->entry_count = 0;
}

void crdt_lwwmap_clear(struct CrdtLWWMap *map)
{
  if (!map->buckets) return;
  for (uint32_t b = 0; b < map->nbuckets; b++) {
    struct CrdtLWWEntry *e = map->buckets[b];
    while (e) {
      struct CrdtLWWEntry *n = e->ht_next;
      free(e->val.data);
      free(e->key);
      free(e);
      e = n;
    }
  }
  free(map->buckets);
  memset(map, 0, sizeof(*map));
}

static struct CrdtLWWEntry *lww_find(const struct CrdtLWWMap *map,
                                     const char *key, uint32_t key_len)
{
  uint32_t b = fnv1a(key, key_len) % map->nbuckets;
  for (struct CrdtLWWEntry *e = map->buckets[b]; e; e = e->ht_next)
    if (e->key_len == key_len && memcmp(e->key, key, key_len) == 0) return e;
  return NULL;
}

int crdt_lwwmap_set(struct CrdtLWWMap *map, const char *key, uint32_t key_len,
                    const void *data, uint32_t data_len,
                    struct HLC ts, uint16_t writer)
{
  struct CrdtLWWEntry *e = lww_find(map, key, key_len);
  if (!e) {
    uint32_t b = fnv1a(key, key_len) % map->nbuckets;
    e = xmalloc(sizeof(*e));
    memset(e, 0, sizeof(*e));
    e->key = memdup(key, key_len);
    e->key_len = key_len;
    e->val.data = memdup(data, data_len);
    e->val.data_len = data_len;
    e->val.ts = ts;
    e->val.writer = writer;
    e->deleted = 0;
    e->ht_next = map->buckets[b];
    map->buckets[b] = e;
    map->entry_count++;
    return 1;
  }
  if (hlc_compare(&ts, &e->val.ts) > 0) {     /* newer write wins */
    free(e->val.data);
    e->val.data = memdup(data, data_len);
    e->val.data_len = data_len;
    e->val.ts = ts;
    e->val.writer = writer;
    e->deleted = 0;
    return 1;
  }
  return 0;                                    /* stale */
}

const struct CrdtLWWValue *crdt_lwwmap_get(const struct CrdtLWWMap *map,
                                           const char *key, uint32_t key_len)
{
  struct CrdtLWWEntry *e = lww_find(map, key, key_len);
  if (!e || e->deleted) return NULL;
  return &e->val;
}

int crdt_lwwmap_delete(struct CrdtLWWMap *map, const char *key,
                       uint32_t key_len, struct HLC ts, uint16_t writer)
{
  struct CrdtLWWEntry *e = lww_find(map, key, key_len);
  if (!e) {
    uint32_t b = fnv1a(key, key_len) % map->nbuckets;
    e = xmalloc(sizeof(*e));
    memset(e, 0, sizeof(*e));
    e->key = memdup(key, key_len);
    e->key_len = key_len;
    e->val.ts = ts;
    e->val.writer = writer;
    e->deleted = 1;
    e->ht_next = map->buckets[b];
    map->buckets[b] = e;
    map->entry_count++;
    return 1;
  }
  if (hlc_compare(&ts, &e->val.ts) > 0) {
    free(e->val.data);
    e->val.data = NULL;
    e->val.data_len = 0;
    e->val.ts = ts;
    e->val.writer = writer;
    e->deleted = 1;
    return 1;
  }
  return 0;
}

uint32_t crdt_lwwmap_size(const struct CrdtLWWMap *map)
{
  uint32_t n = 0;
  for (uint32_t b = 0; b < map->nbuckets; b++)
    for (struct CrdtLWWEntry *e = map->buckets[b]; e; e = e->ht_next)
      if (!e->deleted) n++;
  return n;
}

void crdt_lwwmap_foreach(const struct CrdtLWWMap *map,
                         crdt_lwwmap_iter_fn fn, void *ctx)
{
  for (uint32_t b = 0; b < map->nbuckets; b++)
    for (struct CrdtLWWEntry *e = map->buckets[b]; e; e = e->ht_next)
      if (!e->deleted)
        fn(e->key, e->key_len, &e->val, ctx);
}

/* ================================================================== */
/* CrdtStateVector                                                    */
/* ================================================================== */

void crdt_sv_init(struct CrdtStateVector *sv)
{
  memset(sv, 0, sizeof(*sv));
}

void crdt_sv_global_min(struct CrdtStateVector *out,
                        const struct CrdtStateVector *const *vecs, int n)
{
  if (n <= 0) { crdt_sv_init(out); return; }
  for (int s = 0; s < CRDT_MAX_SERVERS; s++) {
    uint64_t m = vecs[0]->seq[s];
    for (int i = 1; i < n; i++)
      if (vecs[i]->seq[s] < m) m = vecs[i]->seq[s];
    out->seq[s] = m;
  }
}
