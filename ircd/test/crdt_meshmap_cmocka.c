/*
 * crdt_meshmap_cmocka.c - CMocka tests for the gossiped mesh-topology map.
 *
 * Written test-first (TDD): pins the graph contract before crdt_meshmap.c
 * exists.  The module is pure (libc only), so this links against just
 * crdt_meshmap.o + test_stub.o.
 *
 * Coverage:
 *   - set/get/staleness + degree-cap truncation
 *   - reachability: chain, star, cycle-terminates, partition-prunes-subtree,
 *     disconnected-component-excluded, self-always-reachable
 *   - spanning tree: parent/depth/order, deterministic ascending order
 *   - cross-edges: triangle + diamond, truncation
 *   - MR-0 next-hop: chain/star/diamond/leaf shortest-path first-hop, partition
 *   - MR-0 canonical tree: triangle/diamond/K4/forest (root-free Kruskal-lex,
 *     viewpoint-independent), stale prune, truncation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "crdt_meshmap.h"

#define NOW      1000
#define STALE    90
#define FRESH    1000        /* age 0    -> fresh */
#define OLD       900        /* age 100  -> stale (>90) */

/* set node's row from a varargs neighbour list */
static void row(struct CrdtMeshMap *m, int node, time_t ts, int n, ...)
{
  uint16_t p[CRDT_MESH_MAXDEG + 8];
  va_list ap;
  int i;
  va_start(ap, n);
  for (i = 0; i < n && i < (int)(sizeof p / sizeof p[0]); i++)
    p[i] = (uint16_t)va_arg(ap, int);
  va_end(ap);
  crdt_meshmap_set(m, (uint16_t)node, p, n, ts);
}

static struct CrdtMeshMap *new_map(void)
{
  struct CrdtMeshMap *m = calloc(1, sizeof *m);
  assert_non_null(m);
  crdt_meshmap_init(m);
  return m;
}

/* is undirected edge (a,b) in the (tu,tv) set?  canon_tree writes u<v */
static int has_edge(const uint16_t *tu, const uint16_t *tv, int n, int a, int b)
{
  int lo = a < b ? a : b, hi = a < b ? b : a, i;
  for (i = 0; i < n; i++)
    if (tu[i] == lo && tv[i] == hi)
      return 1;
  return 0;
}

/* ---------------------------------------------------------------- */

static void test_set_fresh_and_truncate(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint16_t big[CRDT_MESH_MAXDEG + 5];
  int i, stored;
  (void)state;

  row(m, 1, FRESH, 2, 2, 3);
  assert_int_equal(1, crdt_meshmap_fresh(m, 1, NOW, STALE));
  assert_int_equal(0, crdt_meshmap_fresh(m, 2, NOW, STALE)); /* never set */

  /* stale row */
  row(m, 5, OLD, 1, 1);
  assert_int_equal(0, crdt_meshmap_fresh(m, 5, NOW, STALE));

  /* degree cap: storing MAXDEG+5 returns MAXDEG (truncated) */
  for (i = 0; i < (int)(sizeof big / sizeof big[0]); i++)
    big[i] = (uint16_t)(100 + i);
  stored = crdt_meshmap_set(m, 7, big, CRDT_MESH_MAXDEG + 5, FRESH);
  assert_int_equal(CRDT_MESH_MAXDEG, stored);

  crdt_meshmap_clear(m, 1);
  assert_int_equal(0, crdt_meshmap_fresh(m, 1, NOW, STALE));
  free(m);
}

static void test_reachable_chain(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint8_t out[CRDT_MAX_SERVERS];
  (void)state;
  /* 1-2-3-4 */
  row(m, 1, FRESH, 1, 2);
  row(m, 2, FRESH, 2, 1, 3);
  row(m, 3, FRESH, 2, 2, 4);
  row(m, 4, FRESH, 1, 3);
  assert_int_equal(4, crdt_meshmap_reachable(m, 1, NOW, STALE, out));
  assert_int_equal(1, out[1]);
  assert_int_equal(1, out[2]);
  assert_int_equal(1, out[3]);
  assert_int_equal(1, out[4]);
  free(m);
}

static void test_reachable_star(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint8_t out[CRDT_MAX_SERVERS];
  (void)state;
  /* hub 1, spokes 2,3,4 */
  row(m, 1, FRESH, 3, 2, 3, 4);
  row(m, 2, FRESH, 1, 1);
  row(m, 3, FRESH, 1, 1);
  row(m, 4, FRESH, 1, 1);
  assert_int_equal(4, crdt_meshmap_reachable(m, 1, NOW, STALE, out));
  /* reachable from a leaf too */
  assert_int_equal(4, crdt_meshmap_reachable(m, 2, NOW, STALE, out));
  free(m);
}

static void test_reachable_cycle_terminates(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint8_t out[CRDT_MAX_SERVERS];
  (void)state;
  /* triangle 1-2-3-1 */
  row(m, 1, FRESH, 2, 2, 3);
  row(m, 2, FRESH, 2, 1, 3);
  row(m, 3, FRESH, 2, 1, 2);
  assert_int_equal(3, crdt_meshmap_reachable(m, 1, NOW, STALE, out)); /* no hang */
  free(m);
}

static void test_reachable_partition_prunes_subtree(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint8_t out[CRDT_MAX_SERVERS];
  (void)state;
  /* 1-2-3-4, node 3 STALE -> 3 and 4 (reachable only through 3) pruned */
  row(m, 1, FRESH, 1, 2);
  row(m, 2, FRESH, 2, 1, 3);
  row(m, 3, OLD,   2, 2, 4);   /* partitioned */
  row(m, 4, FRESH, 1, 3);
  assert_int_equal(2, crdt_meshmap_reachable(m, 1, NOW, STALE, out));
  assert_int_equal(1, out[1]);
  assert_int_equal(1, out[2]);
  assert_int_equal(0, out[3]);
  assert_int_equal(0, out[4]);
  free(m);
}

static void test_reachable_disconnected_excluded(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint8_t out[CRDT_MAX_SERVERS];
  (void)state;
  row(m, 1, FRESH, 1, 2);
  row(m, 2, FRESH, 1, 1);
  /* separate component 5-6, all fresh but unlinked to 1 */
  row(m, 5, FRESH, 1, 6);
  row(m, 6, FRESH, 1, 5);
  assert_int_equal(2, crdt_meshmap_reachable(m, 1, NOW, STALE, out));
  assert_int_equal(0, out[5]);
  assert_int_equal(0, out[6]);
  free(m);
}

static void test_reachable_self_always(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint8_t out[CRDT_MAX_SERVERS];
  (void)state;
  /* empty map: only self reachable */
  assert_int_equal(1, crdt_meshmap_reachable(m, 9, NOW, STALE, out));
  assert_int_equal(1, out[9]);
  /* self stale but still counts as itself */
  row(m, 9, OLD, 0);
  assert_int_equal(1, crdt_meshmap_reachable(m, 9, NOW, STALE, out));
  assert_int_equal(1, out[9]);
  free(m);
}

static void test_spanning_parent_depth_order(void **state)
{
  struct CrdtMeshMap *m = new_map();
  int16_t parent[CRDT_MAX_SERVERS];
  uint8_t depth[CRDT_MAX_SERVERS];
  uint16_t order[CRDT_MAX_SERVERS];
  int n;
  (void)state;
  /* diamond: 1-{2,3}; 2-{1,4}; 3-{1,4}; 4-{2,3} */
  row(m, 1, FRESH, 2, 2, 3);
  row(m, 2, FRESH, 2, 1, 4);
  row(m, 3, FRESH, 2, 1, 4);
  row(m, 4, FRESH, 2, 2, 3);
  n = crdt_meshmap_spanning(m, 1, NOW, STALE, parent, depth, order);
  assert_int_equal(4, n);
  /* deterministic ascending BFS order from root 1 */
  assert_int_equal(1, order[0]);
  assert_int_equal(2, order[1]);
  assert_int_equal(3, order[2]);
  assert_int_equal(4, order[3]);
  assert_int_equal(-1, parent[1]);
  assert_int_equal(1, parent[2]);
  assert_int_equal(1, parent[3]);
  assert_int_equal(2, parent[4]);   /* 4 first reached via 2 (2<3) */
  assert_int_equal(0, depth[1]);
  assert_int_equal(1, depth[2]);
  assert_int_equal(1, depth[3]);
  assert_int_equal(2, depth[4]);
  free(m);
}

static void test_crossedges_triangle(void **state)
{
  struct CrdtMeshMap *m = new_map();
  int16_t parent[CRDT_MAX_SERVERS];
  uint16_t cu[8], cv[8];
  int n;
  (void)state;
  row(m, 1, FRESH, 2, 2, 3);
  row(m, 2, FRESH, 2, 1, 3);
  row(m, 3, FRESH, 2, 1, 2);
  crdt_meshmap_spanning(m, 1, NOW, STALE, parent, NULL, NULL);
  n = crdt_meshmap_crossedges(m, NOW, STALE, parent, cu, cv, 8);
  assert_int_equal(1, n);          /* tree=(1,2),(1,3); cross=(2,3) */
  assert_int_equal(2, cu[0]);
  assert_int_equal(3, cv[0]);
  free(m);
}

static void test_crossedges_diamond_and_truncation(void **state)
{
  struct CrdtMeshMap *m = new_map();
  int16_t parent[CRDT_MAX_SERVERS];
  uint16_t cu[8], cv[8];
  int n;
  (void)state;
  /* diamond -> exactly one cross edge (3,4) */
  row(m, 1, FRESH, 2, 2, 3);
  row(m, 2, FRESH, 2, 1, 4);
  row(m, 3, FRESH, 2, 1, 4);
  row(m, 4, FRESH, 2, 2, 3);
  crdt_meshmap_spanning(m, 1, NOW, STALE, parent, NULL, NULL);
  n = crdt_meshmap_crossedges(m, NOW, STALE, parent, cu, cv, 8);
  assert_int_equal(1, n);
  assert_int_equal(3, cu[0]);
  assert_int_equal(4, cv[0]);

  /* truncation: a fully-meshed K4 has 6 edges, 3 tree -> 3 cross; cap at 1 */
  crdt_meshmap_init(m);
  row(m, 1, FRESH, 3, 2, 3, 4);
  row(m, 2, FRESH, 3, 1, 3, 4);
  row(m, 3, FRESH, 3, 1, 2, 4);
  row(m, 4, FRESH, 3, 1, 2, 3);
  crdt_meshmap_spanning(m, 1, NOW, STALE, parent, NULL, NULL);
  n = crdt_meshmap_crossedges(m, NOW, STALE, parent, cu, cv, 1);
  assert_int_equal(3, n);          /* TOTAL reported even though only 1 written */
  free(m);
}

static void test_set_diff(void **state)
{
  uint8_t a[CRDT_MAX_SERVERS], b[CRDT_MAX_SERVERS], out[CRDT_MAX_SERVERS];
  (void)state;
  memset(a, 0, sizeof a); memset(b, 0, sizeof b);
  /* 1: agree-present, 2: A-only, 3: B-only, 4: agree-absent */
  a[1] = 1; b[1] = 1;
  a[2] = 1; b[2] = 0;
  a[3] = 0; b[3] = 1;
  /* index 4 left 0/0 */
  assert_int_equal(2, crdt_meshmap_set_diff(a, b, out));
  assert_int_equal(0, out[1]);     /* agree */
  assert_int_equal(1, out[2]);     /* A only */
  assert_int_equal(2, out[3]);     /* B only */
  assert_int_equal(0, out[4]);     /* agree (both absent) */
  /* NULL out = count only */
  assert_int_equal(2, crdt_meshmap_set_diff(a, b, NULL));
  /* identical sets -> 0 */
  assert_int_equal(0, crdt_meshmap_set_diff(a, a, out));
}

/* ---- MR-0: unicast next-hop (per-viewpoint shortest path) ---------------- */

static void test_nexthop_chain(void **state)
{
  struct CrdtMeshMap *m = new_map();
  int16_t nh[CRDT_MAX_SERVERS];
  (void)state;
  /* 1-2-3-4 : everything from 1 leaves via 2 */
  row(m, 1, FRESH, 1, 2);
  row(m, 2, FRESH, 2, 1, 3);
  row(m, 3, FRESH, 2, 2, 4);
  row(m, 4, FRESH, 1, 3);
  assert_int_equal(4, crdt_meshmap_nexthop(m, 1, NOW, STALE, nh));
  assert_int_equal(-1, nh[1]);     /* self: no hop */
  assert_int_equal(2, nh[2]);
  assert_int_equal(2, nh[3]);
  assert_int_equal(2, nh[4]);
  free(m);
}

static void test_nexthop_star(void **state)
{
  struct CrdtMeshMap *m = new_map();
  int16_t nh[CRDT_MAX_SERVERS];
  (void)state;
  /* hub 1 -> each spoke is its own next hop */
  row(m, 1, FRESH, 3, 2, 3, 4);
  row(m, 2, FRESH, 1, 1);
  row(m, 3, FRESH, 1, 1);
  row(m, 4, FRESH, 1, 1);
  assert_int_equal(4, crdt_meshmap_nexthop(m, 1, NOW, STALE, nh));
  assert_int_equal(2, nh[2]);
  assert_int_equal(3, nh[3]);
  assert_int_equal(4, nh[4]);
  free(m);
}

static void test_nexthop_diamond_and_leaf(void **state)
{
  struct CrdtMeshMap *m = new_map();
  int16_t nh[CRDT_MAX_SERVERS];
  (void)state;
  /* diamond: 1-{2,3}; 2-{1,4}; 3-{1,4}; 4-{2,3} */
  row(m, 1, FRESH, 2, 2, 3);
  row(m, 2, FRESH, 2, 1, 4);
  row(m, 3, FRESH, 2, 1, 4);
  row(m, 4, FRESH, 2, 2, 3);
  assert_int_equal(4, crdt_meshmap_nexthop(m, 1, NOW, STALE, nh));
  assert_int_equal(-1, nh[1]);
  assert_int_equal(2, nh[2]);
  assert_int_equal(3, nh[3]);
  assert_int_equal(2, nh[4]);      /* 4 via 2 (2<3 tie-break, matches _spanning) */
  /* from leaf 4: reach 1 via lower-numeric parent 2 */
  assert_int_equal(4, crdt_meshmap_nexthop(m, 4, NOW, STALE, nh));
  assert_int_equal(2, nh[1]);
  assert_int_equal(2, nh[2]);
  assert_int_equal(3, nh[3]);
  assert_int_equal(-1, nh[4]);
  free(m);
}

static void test_nexthop_partition(void **state)
{
  struct CrdtMeshMap *m = new_map();
  int16_t nh[CRDT_MAX_SERVERS];
  (void)state;
  /* 1-2-3-4, node 3 stale -> 3,4 unreachable */
  row(m, 1, FRESH, 1, 2);
  row(m, 2, FRESH, 2, 1, 3);
  row(m, 3, OLD,   2, 2, 4);
  row(m, 4, FRESH, 1, 3);
  assert_int_equal(2, crdt_meshmap_nexthop(m, 1, NOW, STALE, nh));
  assert_int_equal(2, nh[2]);
  assert_int_equal(-1, nh[3]);
  assert_int_equal(-1, nh[4]);
  free(m);
}

/* ---- MR-0: canonical (root-free, Kruskal-lex) broadcast tree ------------- */

static void test_canon_tree_triangle(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint16_t tu[16], tv[16];
  int n;
  (void)state;
  row(m, 1, FRESH, 2, 2, 3);
  row(m, 2, FRESH, 2, 1, 3);
  row(m, 3, FRESH, 2, 1, 2);
  n = crdt_meshmap_canon_tree(m, NOW, STALE, tu, tv, 16);
  /* lex-min spanning tree = {(1,2),(1,3)} -- VIEWPOINT-INDEPENDENT, not a BFS-from-X */
  assert_int_equal(2, n);
  assert_true(has_edge(tu, tv, n, 1, 2));
  assert_true(has_edge(tu, tv, n, 1, 3));
  assert_false(has_edge(tu, tv, n, 2, 3));
  free(m);
}

static void test_canon_tree_diamond(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint16_t tu[16], tv[16];
  int n;
  (void)state;
  row(m, 1, FRESH, 2, 2, 3);
  row(m, 2, FRESH, 2, 1, 4);
  row(m, 3, FRESH, 2, 1, 4);
  row(m, 4, FRESH, 2, 2, 3);
  n = crdt_meshmap_canon_tree(m, NOW, STALE, tu, tv, 16);
  /* edges (1,2)(1,3)(2,4)(3,4); Kruskal adds first 3, (3,4) closes a cycle */
  assert_int_equal(3, n);
  assert_true(has_edge(tu, tv, n, 1, 2));
  assert_true(has_edge(tu, tv, n, 1, 3));
  assert_true(has_edge(tu, tv, n, 2, 4));
  assert_false(has_edge(tu, tv, n, 3, 4));
  free(m);
}

static void test_canon_tree_k4_and_forest(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint16_t tu[16], tv[16];
  int n;
  (void)state;
  /* K4: lex-min = star at the lowest numeric */
  row(m, 1, FRESH, 3, 2, 3, 4);
  row(m, 2, FRESH, 3, 1, 3, 4);
  row(m, 3, FRESH, 3, 1, 2, 4);
  row(m, 4, FRESH, 3, 1, 2, 3);
  n = crdt_meshmap_canon_tree(m, NOW, STALE, tu, tv, 16);
  assert_int_equal(3, n);
  assert_true(has_edge(tu, tv, n, 1, 2));
  assert_true(has_edge(tu, tv, n, 1, 3));
  assert_true(has_edge(tu, tv, n, 1, 4));

  /* disconnected forest {1,2}+{5,6} -> 2 trees */
  crdt_meshmap_init(m);
  row(m, 1, FRESH, 1, 2);
  row(m, 2, FRESH, 1, 1);
  row(m, 5, FRESH, 1, 6);
  row(m, 6, FRESH, 1, 5);
  n = crdt_meshmap_canon_tree(m, NOW, STALE, tu, tv, 16);
  assert_int_equal(2, n);
  assert_true(has_edge(tu, tv, n, 1, 2));
  assert_true(has_edge(tu, tv, n, 5, 6));
  free(m);
}

static void test_canon_tree_stale_and_truncation(void **state)
{
  struct CrdtMeshMap *m = new_map();
  uint16_t tu[16], tv[16];
  int n;
  (void)state;
  /* chain 1-2-3-4 with 3 stale -> only edge (1,2) (both endpoints fresh) */
  row(m, 1, FRESH, 1, 2);
  row(m, 2, FRESH, 2, 1, 3);
  row(m, 3, OLD,   2, 2, 4);
  row(m, 4, FRESH, 1, 3);
  n = crdt_meshmap_canon_tree(m, NOW, STALE, tu, tv, 16);
  assert_int_equal(1, n);
  assert_true(has_edge(tu, tv, n, 1, 2));

  /* truncation: K4 tree has 3 edges; cap at 1 -> returns total 3, writes 1 */
  crdt_meshmap_init(m);
  row(m, 1, FRESH, 3, 2, 3, 4);
  row(m, 2, FRESH, 3, 1, 3, 4);
  row(m, 3, FRESH, 3, 1, 2, 4);
  row(m, 4, FRESH, 3, 1, 2, 3);
  n = crdt_meshmap_canon_tree(m, NOW, STALE, tu, tv, 1);
  assert_int_equal(3, n);
  free(m);
}

/* MR-1: the unicast routing decision (deliver / drop / next-hop / flood). */
static void test_route_action(void **state)
{
  (void)state;
  /* owner short-circuits regardless of ttl/nexthop */
  assert_int_equal(CRDT_ROUTE_DELIVER, crdt_route_action(1, 0, 0));
  assert_int_equal(CRDT_ROUTE_DELIVER, crdt_route_action(1, 1, 5));
  assert_int_equal(CRDT_ROUTE_DELIVER, crdt_route_action(1, 0, -3));
  /* not owner: ttl backstop fires before route/flood */
  assert_int_equal(CRDT_ROUTE_DROP, crdt_route_action(0, 1, 0));
  assert_int_equal(CRDT_ROUTE_DROP, crdt_route_action(0, 0, 0));
  assert_int_equal(CRDT_ROUTE_DROP, crdt_route_action(0, 1, -1));
  /* not owner, ttl left: next-hop known -> route */
  assert_int_equal(CRDT_ROUTE_NEXTHOP, crdt_route_action(0, 1, 1));
  assert_int_equal(CRDT_ROUTE_NEXTHOP, crdt_route_action(0, 1, 32));
  /* not owner, ttl left, next-hop unknown -> flood fallback */
  assert_int_equal(CRDT_ROUTE_FLOOD, crdt_route_action(0, 0, 1));
  assert_int_equal(CRDT_ROUTE_FLOOD, crdt_route_action(0, 0, 32));
}

/* S4/R7: the cutover suppression truth table.  Suppress a P10 SERVER/SQUIT
 * primitive (let the beacon carry presence) IFF all four bits hold. */
static void test_should_suppress_tree(void **state)
{
  int mm, pr, pa, sa;
  (void)state;
  /* exhaustive 16-row table: result == AND of all four inputs */
  for (mm = 0; mm <= 1; mm++)
    for (pr = 0; pr <= 1; pr++)
      for (pa = 0; pa <= 1; pa++)
        for (sa = 0; sa <= 1; sa++)
          assert_int_equal(mm && pr && pa && sa,
                           crdt_should_suppress_tree(mm, pr, pa, sa));
  /* named anchors for the live scenarios */
  assert_int_equal(1, crdt_should_suppress_tree(1, 1, 1, 1)); /* cutover, both-ends */
  assert_int_equal(0, crdt_should_suppress_tree(0, 1, 1, 1)); /* flag off -> shadow */
  assert_int_equal(0, crdt_should_suppress_tree(1, 0, 1, 1)); /* not CRDT-primary */
  assert_int_equal(0, crdt_should_suppress_tree(1, 1, 0, 1)); /* legacy peer */
  assert_int_equal(0, crdt_should_suppress_tree(1, 1, 1, 0)); /* legacy subject */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_set_fresh_and_truncate),
    cmocka_unit_test(test_reachable_chain),
    cmocka_unit_test(test_reachable_star),
    cmocka_unit_test(test_reachable_cycle_terminates),
    cmocka_unit_test(test_reachable_partition_prunes_subtree),
    cmocka_unit_test(test_reachable_disconnected_excluded),
    cmocka_unit_test(test_reachable_self_always),
    cmocka_unit_test(test_spanning_parent_depth_order),
    cmocka_unit_test(test_crossedges_triangle),
    cmocka_unit_test(test_crossedges_diamond_and_truncation),
    cmocka_unit_test(test_set_diff),
    cmocka_unit_test(test_nexthop_chain),
    cmocka_unit_test(test_nexthop_star),
    cmocka_unit_test(test_nexthop_diamond_and_leaf),
    cmocka_unit_test(test_nexthop_partition),
    cmocka_unit_test(test_canon_tree_triangle),
    cmocka_unit_test(test_canon_tree_diamond),
    cmocka_unit_test(test_canon_tree_k4_and_forest),
    cmocka_unit_test(test_canon_tree_stale_and_truncation),
    cmocka_unit_test(test_route_action),
    cmocka_unit_test(test_should_suppress_tree),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
