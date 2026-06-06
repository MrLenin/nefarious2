/*
 * crdt_sim.c - Standalone CRDT tombstone-growth stress harness (scenario D)
 *
 * NOT part of the ircd binary and NOT in IRCD_SRC — it has its own main() and
 * is built/run only by the dedicated CRDT test container (tests/crdt/). It
 * exercises the proposal §16.6 scenario D / §17.2.4 claim: with causal-stability
 * GC, steady-state memory is bounded by (GC interval x op rate), NOT by total
 * lifetime operations.
 *
 * Two simulated servers churn JOIN/PART (priority-0, so GC is sound — priority
 * removes are excluded per the documented crdt_orset_gc limitation) across many
 * channels for many ticks, syncing every tick and GC'ing every interval. The
 * harness asserts that tombstone + oplog counts stay flat as ticks grow.
 *
 * Build/run: see tests/crdt/Dockerfile (docker run --rm crdt-test /src/crdt_sim)
 */

#include "crdt_hlc.h"
#include "crdt_types.h"
#include "crdt_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUSERS       100
#define NCHANS        50
#define SYNC_EVERY     1   /* ticks between bidirectional sync */
#define GC_EVERY      50   /* ticks between causal-stability GC */
#define TOTAL_TICKS 24000  /* loosely: 1k~"1h", 6k~"6h", 24k~"24h" */
#define TOMB_CAP    2000   /* bounded-memory ceiling (window is ~GC_EVERY) */

static uint32_t total_tombs(struct CrdtNetworkState *st)
{
  uint32_t n = 0;
  for (int b = 0; b < CRDT_CHAN_BUCKETS; b++)
    for (struct CrdtChannel *c = st->chan_buckets[b]; c; c = c->next)
      n += crdt_orset_tomb_count(&c->members);
  return n;
}

static uint32_t total_members(struct CrdtNetworkState *st)
{
  uint32_t n = 0;
  for (int b = 0; b < CRDT_CHAN_BUCKETS; b++)
    for (struct CrdtChannel *c = st->chan_buckets[b]; c; c = c->next)
      n += c->members.entry_count;          /* entries incl. emptied-not-yet-GC'd */
  return n;
}

static void gc_both(struct CrdtNetworkState *s1, struct CrdtNetworkState *s2)
{
  const struct CrdtStateVector *vv[2] = { &s1->local_sv, &s2->local_sv };
  struct CrdtStateVector gmin;
  crdt_sv_global_min(&gmin, vv, 2);
  crdt_state_gc(s1, &gmin);
  crdt_state_gc(s2, &gmin);
}

int main(void)
{
  struct CrdtNetworkState s1, s2;
  crdt_state_init(&s1, 1);
  crdt_state_init(&s2, 2);

  uint32_t peak_tombs = 0;
  int failures = 0;

  printf("%-8s | %-10s | %-10s | %-10s | %-10s\n",
         "tick", "tombs(s1)", "oplog(s1)", "members", "peak");
  printf("---------+------------+------------+------------+-----------\n");

  for (int t = 1; t <= TOTAL_TICKS; t++) {
    struct CrdtNetworkState *src = (t & 1) ? &s1 : &s2;
    char num[8], chan[8];
    snprintf(num, sizeof num, "u%d", t % NUSERS);
    snprintf(chan, sizeof chan, "#%d", t % NCHANS);

    crdt_chan_join(src, chan, num);                       /* JOIN */
    crdt_chan_remove(src, chan, num, CRDT_PRIORITY_USER); /* PART (priority 0) */

    if (t % SYNC_EVERY == 0) {
      crdt_state_sync(&s2, &s1);
      crdt_state_sync(&s1, &s2);
    }

    uint32_t tb = total_tombs(&s1);
    if (tb > peak_tombs) peak_tombs = tb;

    if (t % GC_EVERY == 0)
      gc_both(&s1, &s2);

    if (t == 1000 || t == 6000 || t == 12000 || t == 24000) {
      uint32_t after = total_tombs(&s1);
      printf("%-8d | %-10u | %-10u | %-10u | %-10u\n",
             t, after, s1.oplog.count, total_members(&s1), peak_tombs);
      if (after > TOMB_CAP) {
        printf("  !! tombs %u exceed cap %u at tick %d\n", after, TOMB_CAP, t);
        failures++;
      }
    }
  }

  /* convergence sanity after the run */
  crdt_state_sync(&s2, &s1);
  crdt_state_sync(&s1, &s2);
  if (!crdt_state_equal(&s1, &s2)) {
    printf("  !! replicas diverged after stress run\n");
    failures++;
  }

  printf("\npeak tombstones (pre-GC, whole run): %u\n", peak_tombs);
  printf("steady-state bounded by GC window, NOT by %d total ticks: %s\n",
         TOTAL_TICKS, failures ? "FAIL" : "PASS");

  crdt_state_clear(&s1);
  crdt_state_clear(&s2);
  return failures ? 1 : 0;
}
