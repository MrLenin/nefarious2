/*
 * crdt_meshmap.h - gossiped mesh-topology map (single-writer adjacency)
 *
 * The observability substrate behind the oper /CRDT command.  Each CRDT node
 * declares ONLY its own direct-peer set on its CR H beacon (single-writer per
 * key, ephemeral, OUTSIDE crdt_state_digest) — so this map can never cause the
 * Phase 4a divergence that killed the replicated ACTIVE/SPLIT servers-map
 * (crdt_shadow.c:370).  Reachability is NOT replicated; it is DERIVED here, by a
 * local BFS over the union of single-writer adjacency rows, pruning beacon-stale
 * nodes.  ("X's peer-set" is a per-owner fact and converges; "X is reachable" is
 * a per-viewpoint value and must stay local — replicating it has conflicting
 * writers.)
 *
 * Observability-only: this feeds the /CRDT diagram (and optionally the verify
 * line).  It does NOT feed materialization/routing — those keep the proven local
 * FindNServer reachability check.  Promoting this to a routing input is the
 * separate, deliberate Tier-2 step (crdt_shadow.c:393).
 *
 * Pure: libc only (no Client / feature_int / sendto_*), so it links in the
 * cmocka harness against just test_stub.o and is TDD-covered up front.
 *
 * Edge semantics are DIRECTIONAL (BFS follows u's declared peers[u]).  In a
 * converged mesh declarations are symmetric, so directional == undirected; the
 * only divergence is the brief warmup before a neighbour's first beacon arrives
 * (it appears once its beacon floods in, sub-second) and a partition (its beacon
 * goes stale -> pruned).  Both are self-correcting and documented.
 */

#ifndef INCLUDED_crdt_meshmap_h
#define INCLUDED_crdt_meshmap_h

#include <stdint.h>
#include <sys/types.h>      /* time_t */
#include "crdt_types.h"     /* CRDT_MAX_SERVERS */

/** Max direct CRDT peers recorded per node.  A mesh's direct degree is small;
 *  beyond this the extra are dropped and the integration layer logs it (no
 *  silent cap).  Only affects the diagram, never routing. */
#define CRDT_MESH_MAXDEG 32

/** Max undirected edges the canonical-tree builder materializes before Kruskal.
 *  Bounds the static edge scratch; a mesh's edge count is tiny in practice
 *  (degree is small).  Exceeding it truncates the edge set fed to Kruskal — the
 *  integration layer logs it (no silent cap).  Only affects the broadcast tree. */
#define CRDT_MESH_MAXEDGES (CRDT_MAX_SERVERS * 4)

/** Direct-indexed by server numeric (like crdt_beacon[]).  ~size:
 *  CRDT_MAX_SERVERS * (CRDT_MESH_MAXDEG*2 + ...) — a single static instance. */
struct CrdtMeshMap {
  uint8_t  present[CRDT_MAX_SERVERS];                    /**< a row has been set */
  uint8_t  npeers[CRDT_MAX_SERVERS];                    /**< peers stored (<=MAXDEG) */
  uint16_t peers[CRDT_MAX_SERVERS][CRDT_MESH_MAXDEG];   /**< neighbour numerics */
  time_t   recv_ts[CRDT_MAX_SERVERS];                   /**< local recv time (staleness) */
};

/** Zero the whole map. */
void crdt_meshmap_init(struct CrdtMeshMap *m);

/** Record node @a node's declared direct-peer set (single-writer: the owner).
 *  Stores up to CRDT_MESH_MAXDEG peers; out-of-range node/peer numerics are
 *  skipped.  @a recv_ts is the local receive time used for staleness.  Returns
 *  the number of peers actually stored; a return < @a n means the degree cap
 *  truncated (caller should log). */
int crdt_meshmap_set(struct CrdtMeshMap *m, uint16_t node,
                     const uint16_t *peers, int n, time_t recv_ts);

/** Drop a node's row (e.g. on retire). */
void crdt_meshmap_clear(struct CrdtMeshMap *m, uint16_t node);

/** True iff @a node is present and its last beacon is within @a stale of @a now. */
int crdt_meshmap_fresh(const struct CrdtMeshMap *m, uint16_t node,
                       time_t now, time_t stale);

/** BFS reachability from @a from over FRESH nodes only.  @a out must be
 *  CRDT_MAX_SERVERS bytes; out[n]=1 for each reachable node.  @a from is always
 *  reachable (we always know ourselves) even if its own row is stale/absent.
 *  Returns the reachable count (>=1). */
int crdt_meshmap_reachable(const struct CrdtMeshMap *m, uint16_t from,
                           time_t now, time_t stale, uint8_t *out);

/** BFS spanning tree from @a from over FRESH nodes.  Arrays are indexed by
 *  numeric and sized CRDT_MAX_SERVERS (parent/depth) — for each reachable node:
 *    parent[n] = parent numeric, or -1 for the root and for unreachable nodes.
 *    depth[n]  = hop distance from the root (0 = root).
 *  @a order receives the reachable numerics in BFS visitation order (sized
 *  CRDT_MAX_SERVERS).  Neighbours are visited in ascending numeric order, so the
 *  tree is deterministic.  Returns the reachable count (== entries in order[]).
 *  Any of parent/depth/order may be NULL if not needed. */
int crdt_meshmap_spanning(const struct CrdtMeshMap *m, uint16_t from,
                          time_t now, time_t stale,
                          int16_t *parent, uint8_t *depth, uint16_t *order);

/** Per-numeric set-difference classification of two boolean reachability sets
 *  @a a and @a b (each CRDT_MAX_SERVERS bytes): out[n] = 0 if a[n]==b[n],
 *  1 if a[n] && !b[n] (in A only), 2 if !a[n] && b[n] (in B only).  Returns the
 *  number of divergent (nonzero) entries.  The Stage-1 shadow-oracle primitive
 *  for comparing mesh-map BFS reachability against the per-node beacon set and
 *  the P10 tree — pure so the classification is TDD-pinned before any presence
 *  decision trusts it.  @a out may be NULL (count only). */
int crdt_meshmap_set_diff(const uint8_t *a, const uint8_t *b, uint8_t *out);

/** Enumerate "cross edges": fresh declared edges (u<v, both endpoints reachable)
 *  that are NOT tree edges (neither endpoint is the other's @a parent).  Writes
 *  up to @a max (u,v) pairs into @a out_u / @a out_v.  Returns the TOTAL cross
 *  edge count (may exceed @a max -> caller knows it truncated).  @a parent is the
 *  crdt_meshmap_spanning result for the same (from,now,stale). */
int crdt_meshmap_crossedges(const struct CrdtMeshMap *m, time_t now, time_t stale,
                            const int16_t *parent,
                            uint16_t *out_u, uint16_t *out_v, int max);

/** MR-0 unicast next-hop: for each destination, the direct neighbour of @a from
 *  on the shortest (BFS) path toward it.  @a nexthop is int16_t[CRDT_MAX_SERVERS]:
 *  nexthop[d] = that neighbour numeric, or -1 for @a from itself and for any
 *  unreachable d.  Neighbours are expanded in ascending numeric order, so the
 *  first-hop choice is deterministic and matches crdt_meshmap_spanning's parent
 *  tie-break.  Returns the reachable count (>=1, includes @a from).  This is the
 *  per-viewpoint routing table mesh-native unicast (MR-1) will consult; MR-0 only
 *  derives + measures it (no routing).  Pure (cmocka-pinned). */
int crdt_meshmap_nexthop(const struct CrdtMeshMap *m, uint16_t from,
                         time_t now, time_t stale, int16_t *nexthop);

/** MR-0 canonical broadcast tree: the VIEWPOINT-INDEPENDENT spanning forest over
 *  FRESH edges, built by Kruskal over undirected edges keyed (min,max) ascending
 *  with union-find — a pure function of the fresh-edge set, so EVERY node derives
 *  the SAME tree (the shared-tree prerequisite for loop-free mesh broadcast, MR-2;
 *  scope §4.1, root-free preferred).  An edge {u,v} (u<v) exists iff both are fresh
 *  and (v in peers[u] OR u in peers[v]) — symmetric closure, robust to the
 *  one-sided warmup window.  Writes up to @a max tree edges as (u<v) into @a tu /
 *  @a tv; returns the TOTAL tree-edge count (> @a max -> truncated, like
 *  crdt_meshmap_crossedges).  Pure (cmocka-pinned). */
int crdt_meshmap_canon_tree(const struct CrdtMeshMap *m, time_t now, time_t stale,
                            uint16_t *tu, uint16_t *tv, int max);

/** MR-1 pure routing decision for a unicast CR frame at a node.  Inputs are 0/1
 *  except @a ttl_remaining (the frame's TTL as seen here, before decrement):
 *  @a owner_is_self (this node owns the target / the target is local here),
 *  @a nexthop_known (the routing table has a next-hop toward the owner),
 *  @a ttl_remaining.  Result:
 *    CRDT_ROUTE_DELIVER  — target is here, hand to the local user (ttl/nexthop n/a).
 *    CRDT_ROUTE_DROP     — ttl exhausted (the storm backstop; only when not owner).
 *    CRDT_ROUTE_NEXTHOP  — forward to the single next-hop peer toward the owner.
 *    CRDT_ROUTE_FLOOD    — next-hop unknown/stale -> flood-fallback (§4.1 robustness).
 *  Pure so the decision is cmocka-pinned. */
enum CrdtRouteAction {
  CRDT_ROUTE_DELIVER = 0,
  CRDT_ROUTE_DROP,
  CRDT_ROUTE_NEXTHOP,
  CRDT_ROUTE_FLOOD
};
int crdt_route_action(int owner_is_self, int nexthop_known, int ttl_remaining);

/** S4/R7a pure suppression truth-table: should a P10 SQUIT (a server DEPARTURE)
 *  for a subject server be SUPPRESSED toward a peer, letting the CR H beacon set
 *  carry the departure instead (stale beacon + keep-gate + sweep)?  All four
 *  inputs are 0/1: @a meshmap_on (FEAT_CRDT_MESHMAP_PRESENCE — the cutover flag,
 *  shared with the S3 keep-gate), @a primary (FEAT_CRDT_PRIMARY), @a peer_aware
 *  (the receiver is a CRDT-aware server), @a subject_aware (the subject server is
 *  CRDT-aware — a legacy subject has no beacon, so it must NEVER be suppressed).
 *  Suppress IFF all four hold.  Pure so the gate is TDD-pinned.  (SERVER-intro
 *  retirement was found infeasible under P10 prefix routing — SQUIT only.) */
int crdt_should_suppress_tree(int meshmap_on, int primary,
                              int peer_aware, int subject_aware);

#endif /* INCLUDED_crdt_meshmap_h */
