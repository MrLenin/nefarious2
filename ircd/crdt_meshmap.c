/*
 * crdt_meshmap.c - gossiped mesh-topology map (single-writer adjacency).
 *
 * See crdt_meshmap.h for the design contract.  Pure: libc only, no IRCd
 * coupling, so it links in the cmocka harness with just test_stub.o.
 *
 * Reachability/spanning are a BFS over the union of single-writer adjacency
 * rows, traversing only into FRESH nodes (a beacon within the stale window).
 * The query origin is always reachable (we always know ourselves) and its own
 * links are traversed regardless of its freshness; every other reachable node
 * is, by construction, fresh.
 */

#include "crdt_meshmap.h"

#include <string.h>

void crdt_meshmap_init(struct CrdtMeshMap *m)
{
  if (m)
    memset(m, 0, sizeof *m);
}

int crdt_meshmap_set(struct CrdtMeshMap *m, uint16_t node,
                     const uint16_t *peers, int n, time_t recv_ts)
{
  int i, stored = 0;

  if (!m || node >= CRDT_MAX_SERVERS)
    return 0;

  for (i = 0; i < n && stored < CRDT_MESH_MAXDEG; i++) {
    if (!peers || peers[i] >= CRDT_MAX_SERVERS)
      continue;                          /* skip out-of-range neighbour */
    m->peers[node][stored++] = peers[i];
  }
  m->npeers[node]  = (uint8_t)stored;
  m->present[node] = 1;
  m->recv_ts[node] = recv_ts;
  return stored;
}

void crdt_meshmap_clear(struct CrdtMeshMap *m, uint16_t node)
{
  if (!m || node >= CRDT_MAX_SERVERS)
    return;
  m->present[node] = 0;
  m->npeers[node]  = 0;
  m->recv_ts[node] = 0;
}

int crdt_meshmap_fresh(const struct CrdtMeshMap *m, uint16_t node,
                       time_t now, time_t stale)
{
  if (!m || node >= CRDT_MAX_SERVERS || !m->present[node])
    return 0;
  return (now - m->recv_ts[node]) <= stale;
}

int crdt_meshmap_reachable(const struct CrdtMeshMap *m, uint16_t from,
                           time_t now, time_t stale, uint8_t *out)
{
  static uint16_t queue[CRDT_MAX_SERVERS];
  int head = 0, tail = 0, count = 0;
  uint16_t u;
  int i;

  if (!m || !out || from >= CRDT_MAX_SERVERS)
    return 0;

  memset(out, 0, CRDT_MAX_SERVERS);
  out[from] = 1;                         /* always know ourselves */
  count = 1;
  queue[tail++] = from;

  while (head < tail) {
    u = queue[head++];
    if (!m->present[u])                  /* no declared row -> no edges to follow */
      continue;
    for (i = 0; i < m->npeers[u]; i++) {
      uint16_t v = m->peers[u][i];
      if (v >= CRDT_MAX_SERVERS || out[v])
        continue;
      if (!crdt_meshmap_fresh(m, v, now, stale))   /* prune partitioned/absent */
        continue;
      out[v] = 1;
      count++;
      queue[tail++] = v;
    }
  }
  return count;
}

/* insertion-sort a small neighbour list ascending (deg <= CRDT_MESH_MAXDEG) */
static void sort_u16(uint16_t *a, int n)
{
  int i, j;
  for (i = 1; i < n; i++) {
    uint16_t k = a[i];
    for (j = i - 1; j >= 0 && a[j] > k; j--)
      a[j + 1] = a[j];
    a[j + 1] = k;
  }
}

int crdt_meshmap_spanning(const struct CrdtMeshMap *m, uint16_t from,
                          time_t now, time_t stale,
                          int16_t *parent, uint8_t *depth, uint16_t *order)
{
  static uint16_t queue[CRDT_MAX_SERVERS];
  static uint8_t  seen[CRDT_MAX_SERVERS];
  int head = 0, tail = 0, count = 0;
  uint16_t u;
  int i;

  if (!m || from >= CRDT_MAX_SERVERS)
    return 0;

  memset(seen, 0, sizeof seen);
  if (parent) {
    for (i = 0; i < CRDT_MAX_SERVERS; i++)
      parent[i] = -1;
  }

  seen[from] = 1;
  if (depth)  depth[from] = 0;
  if (order)  order[count] = from;
  count = 1;
  queue[tail++] = from;

  while (head < tail) {
    uint16_t nbr[CRDT_MESH_MAXDEG];
    int nn = 0;
    u = queue[head++];
    if (!m->present[u])
      continue;
    /* visit neighbours in ascending numeric order -> deterministic tree */
    for (i = 0; i < m->npeers[u]; i++) {
      uint16_t v = m->peers[u][i];
      if (v < CRDT_MAX_SERVERS && !seen[v] && crdt_meshmap_fresh(m, v, now, stale))
        nbr[nn++] = v;
    }
    sort_u16(nbr, nn);
    for (i = 0; i < nn; i++) {
      uint16_t v = nbr[i];
      if (seen[v])                       /* a sibling earlier in this batch */
        continue;
      seen[v] = 1;
      if (parent) parent[v] = (int16_t)u;
      if (depth)  depth[v]  = (uint8_t)(depth[u] + 1);
      if (order)  order[count] = v;
      count++;
      queue[tail++] = v;
    }
  }
  return count;
}

int crdt_meshmap_set_diff(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  int i, n = 0;
  if (!a || !b)
    return 0;
  for (i = 0; i < CRDT_MAX_SERVERS; i++) {
    uint8_t c = 0;
    if (a[i] && !b[i]) c = 1;            /* A only */
    else if (!a[i] && b[i]) c = 2;       /* B only */
    if (out)
      out[i] = c;
    if (c)
      n++;
  }
  return n;
}

int crdt_meshmap_crossedges(const struct CrdtMeshMap *m, time_t now, time_t stale,
                            const int16_t *parent,
                            uint16_t *out_u, uint16_t *out_v, int max)
{
  static uint8_t reach[CRDT_MAX_SERVERS];
  int total = 0;
  int u, i;

  if (!m || !parent)
    return 0;

  /* reachable = {n : parent[n] != -1} U {n appearing as a parent} (captures
   * the root, whose own parent is -1). */
  memset(reach, 0, sizeof reach);
  for (i = 0; i < CRDT_MAX_SERVERS; i++) {
    if (parent[i] != -1) {
      reach[i] = 1;
      reach[parent[i]] = 1;
    }
  }

  /* dedup undirected edges from the lower endpoint's declared peers */
  for (u = 0; u < CRDT_MAX_SERVERS; u++) {
    if (!m->present[u] || !reach[u])
      continue;
    for (i = 0; i < m->npeers[u]; i++) {
      uint16_t v = m->peers[u][i];
      if (v <= u || v >= CRDT_MAX_SERVERS || !reach[v])
        continue;
      if (parent[v] == (int16_t)u || parent[u] == (int16_t)v)
        continue;                        /* a tree edge, not a cross edge */
      (void)now; (void)stale;            /* reach[] already encodes freshness */
      if (total < max && out_u && out_v) {
        out_u[total] = (uint16_t)u;
        out_v[total] = v;
      }
      total++;
    }
  }
  return total;
}

/* S4/R7: the cutover suppression rule, isolated as a pure 4-bit AND so the
 * truth table is cmocka-pinned (see crdt_should_suppress_tree in the header).
 * The integration layer (crdt_tree_presence_suppress) feeds it the live feature
 * flags + per-end IsCrdtAware bits. */
int crdt_should_suppress_tree(int meshmap_on, int primary,
                              int peer_aware, int subject_aware)
{
  return meshmap_on && primary && peer_aware && subject_aware;
}
