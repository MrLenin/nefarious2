/*
 * crdt_shadow.c - Phase 1 shadow-mode bridge (see crdt_shadow.h).
 *
 * Mirrors live channel membership into a CRDT document and periodically
 * compares it to the real ircd state, gated behind FEAT_CRDT_ENABLED.
 * Behavior-neutral when the flag is off.
 */

#include "config.h"

#include "crdt_shadow.h"
#include "crdt_state.h"
#include "crdt_types.h"
#include "crdt_wire.h"
#include "crdt_meshmap.h"   /* gossiped mesh-topology map (observability) */

#include "channel.h"
#include "client.h"
#include "bouncer_session.h" /* 5-5e M2: bounce_crdt_bsess_sweep (doc-native bouncer shadow) */
#include "gline.h"           /* struct Gline + GlineIs* (GLINE step 2 shadow-write) */
#include "shun.h"            /* struct Shun + ShunIs* (SHUN global-state track) */
#include "zline.h"           /* struct Zline + ZlineIs* (ZLINE global-state track) */
#include "jupe.h"            /* struct Jupe + JupeIs* (JUPE global-state track) */
#include "hash.h"            /* FindChannel (Phase 3b dry-run lookup) */
#include "list.h"            /* make_client / add_client_to_list (3c materialize) */
#include "struct.h"          /* struct User (cli_user(c)->server) */
#include "ircd.h"           /* GlobalClientList, me, TStime */
#include "ircd_alloc.h"     /* MyMalloc/DupString (3i ban-mask dup) */
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"   /* ircd_snprintf %Tu for the 3n reconcile-rename TS */
#include "ircd_string.h"     /* ircd_strncpy (3c materialize) */
#include "msg.h"             /* CMD_TOPIC (Phase 3d gateway) */
#include "numnicks.h"
#include "querycmds.h"       /* UserStats, Count_newremoteclient (3c materialize) */
#include "s2s_chunk.h"       /* s2s_chunk_cleanup_link (stub conversion kills the feed link) */
#include "s_misc.h"          /* exit_client (Phase 3m user delete-on-leave) */
#include "s_user.h"          /* umode_str, make_user, user_apply_umode_str */
#include "send.h"            /* sendcmdto_* (Phase 3d topic gateway) */
#include "handlers.h"        /* crdt_sync_broadcast */
#include "mark.h"            /* Tier C F1-b: MARK_* sub-type tags */
#include "ircd_geoip.h"      /* Tier C F1-b: geoip_apply_mark (rebuild names from codes) */
#include "metadata.h"        /* Tier C F2-a: metadata_readmarker_set (doc -> readmarkers_cf) */
#include "webpush_store.h"   /* Tier C F2-c: webpush subscription store (doc <-> LMDB) */

#include <stdarg.h>          /* verify_emit dual log/client targeting */
#include <stdio.h>
#include <string.h>

/** The shadow replica of network state for this server. */
static struct CrdtNetworkState g_crdt;
static int                     g_inited = 0;
static struct Timer            g_verify_timer;

/* GLINE step 3 re-entrancy guard: set while crdt_shadow_reconcile_glines drives the
 * live gline subsystem FROM the doc. The crdt_shadow_gline_add/_remove hooks self-skip
 * when it is set, so a doc-driven materialize does NOT re-mint the op it came from
 * (loop prevention; the analog of reconcile_topic_cb writing chptr->topic directly).
 * Synchronous — reconcile is never re-entrant. */
static int                     g_gline_reconciling = 0;
static int                     g_shun_reconciling = 0;   /* SHUN: same role as g_gline_reconciling */
static int                     g_marker_reconciling = 0; /* Tier C F2-a: same role (read-markers) */
static int                     g_metadata_reconciling = 0;    /* Tier C F2-b: same role (metadata) */
static int                     g_metadata_remote_applying = 0;/* Tier C F2-b: set by ms_metadata
                                                               * around a P10-relayed store write so
                                                               * the mirror does NOT re-enter the doc
                                                               * (single-writer; analog of
                                                               * from_crdt_peer for the storage hook) */
static int                     g_zline_reconciling = 0;  /* ZLINE: same role */
static int                     g_jupe_reconciling = 0;   /* JUPE: same role */

/* Gossiped mesh-topology map: single-writer adjacency rows accumulated from CR H
 * beacons (each node declares only its own direct CRDT peers).  Ephemeral, NOT in
 * the digest -> cannot diverge.  Observability-only: feeds the /CRDT command (and
 * /CRDT status verify), NEVER materialization/routing.  See crdt_meshmap.h. */
static struct CrdtMeshMap      g_meshmap;

/* MR-2: timestamp of the last STRUCTURAL mesh-map change (a row's peer-set changed,
 * not a same-set beacon refresh).  Broadcast tree-forwarding is gap-safe only when
 * every node agrees on the canonical tree, which holds once adjacency has converged;
 * during the lag after a change, nodes can disagree -> we flood instead (gap-free).
 * crdt_shadow_mesh_bcast_stable() gates on (now - this) > the settle window. */
static time_t                  g_mesh_changed_ts;
#define CRDT_MESH_BCAST_STABLE 35      /* s; > the 30s beacon interval -> covers a round */

/** Eager-push high-water mark: the highest own-origin op seq we have already
 *  pushed to peers via CR U. Bounds eager push to ops WE created since last time
 *  (relay of foreign-origin ops stays on the anti-entropy path), keeping it
 *  O(new ops) instead of re-sending a growing cumulative delta each write. */
static uint64_t                g_last_pushed_seq = 0;

/** Recorded peer state vectors, for causal-stability GC (one slot per peer). */
#define CRDT_MAX_PEERS 8
struct crdt_peer_sv {
  int                    used;
  uint16_t               origin;
  time_t                 when;
  struct CrdtStateVector sv;
};
static struct crdt_peer_sv g_peers[CRDT_MAX_PEERS];

/** How often the shadow is reconciled against real state (seconds). */
#define CRDT_VERIFY_INTERVAL 30

/* Tier2 full-partition liveness: every CRDT-primary server gossips an ephemeral
 * CR H beacon each verify cycle; receivers track the last beacon per server
 * numeric.  A mesh stub whose beacon goes stale (no beacon for CRDT_BEACON_STALE
 * seconds — the peer is unreachable via ANY CRDT path, i.e. a full/permanent
 * partition) is retired.  This is what the coarse keep-vs-teardown gate cannot
 * detect (an unrelated transport still existing != the stubbed peer reachable). */
#define CRDT_BEACON_STALE 90            /* 3 verify intervals */
static struct {
  time_t emit_ts; time_t recv_ts;
  uint8_t seen_since_tick;          /* M2+U6: set on ANY beacon arrival for this server (in
                                       crdt_shadow_beacon_record, ABOVE the relay/dedup gate);
                                       the verify sweep counts consecutive CLEAR windows via
                                       miss_ticks instead of the clock-step-fragile
                                       CurrentTime-recv_ts delta. */
  uint8_t miss_ticks;               /* U6: consecutive verify ticks with no beacon for this
                                       server (>= CRDT_BEACON_MISS_TICKS -> full-partition retire). */
  char name[HOSTLEN + 1];           /* #3: real server name (for the synthetic anchor) */
  char nn_cap[4];                   /* #3: base64 client capacity -> right-sized anchor mask */
  char min_fronter[4];              /* MR-4d: lowest-numeric gateway seen proxy-beaconing this
                                       legacy server (the double-delivery election); "" = none */
  time_t min_fronter_ts;            /* MR-4d: when min_fronter was last (re)set (freshness) */
} crdt_beacon[CRDT_MAX_SERVERS];

/* Record a beacon for server `num` emitted at `emit_ts`.  Returns 1 if FRESH
 * (newer than the last seen -> the caller should relay it), 0 if dup/old (drop,
 * which terminates the gossip flood).  #3: @a nn_cap (base64 client capacity) and
 * @a name (server name) ride the beacon append-only; either may be "" (old-form
 * beacon) -> left unchanged so a later full beacon can fill them. */
int crdt_shadow_beacon_record(unsigned int num, time_t emit_ts,
                              const char *nn_cap, const char *name,
                              const char *peers, const char *fronted_by)
{
  if (num >= CRDT_MAX_SERVERS)
    return 0;
  /* Part A (M2 — INVARIANT 9 applied to reception): ANY beacon arrival for `num`
   * proves the server reachable RIGHT NOW, so refresh the liveness signal
   * UNCONDITIONALLY — even a dup / replay / backward-NTP-stepped beacon that must
   * NOT be relayed.  The emit_ts monotonicity check below now gates ONLY the
   * relay/dedup + the append-only metadata (nn_cap/name/min_fronter/meshmap), never
   * liveness.  Previously it early-returned ABOVE these two stamps, so a future-
   * dated or backward-stepped emit_ts froze recv_ts and the sweep retired a live,
   * still-beaconing server.  Bounded-staleness caveat: crdt_shadow_beacon_burst
   * replays only beacons it still considers fresh (recv within CRDT_BEACON_STALE),
   * so a genuinely dead server is kept "alive" at most ~one staleness window past
   * its last real beacon — the identical bound already accepted today. */
  crdt_beacon[num].recv_ts         = CurrentTime;
  crdt_beacon[num].seen_since_tick = 1;
  if (emit_ts <= crdt_beacon[num].emit_ts)
    return 0;                       /* relay/dedup gate ONLY — terminates the gossip flood */
  crdt_beacon[num].emit_ts = emit_ts;
  if (nn_cap && nn_cap[0])
    ircd_strncpy(crdt_beacon[num].nn_cap, nn_cap, sizeof crdt_beacon[num].nn_cap);
  if (name && name[0])
    ircd_strncpy(crdt_beacon[num].name, name, sizeof crdt_beacon[num].name);

  /* MR-4d: track the lowest-numeric gateway proxy-beaconing this legacy server (the
   * double-delivery election input).  fronted_by carries the FRONTING gateway's own
   * numeric on a proxy beacon ("" on a self-beacon / old-form).  Keep the lowest; let
   * a fresh higher one take over once the current min goes stale (departed-gateway
   * promotion).  Two gateways' beacons alternate-pass the emit_ts gate over time, so
   * the min converges within a staleness window. */
  if (fronted_by && fronted_by[0]) {
    int stale = !crdt_beacon[num].min_fronter[0] ||
                (CurrentTime - crdt_beacon[num].min_fronter_ts
                 > crdt_shadow_beacon_stale_secs());
    if (stale || base64toint(fronted_by) <= base64toint(crdt_beacon[num].min_fronter)) {
      ircd_strncpy(crdt_beacon[num].min_fronter, fronted_by,
                   sizeof crdt_beacon[num].min_fronter);
      crdt_beacon[num].min_fronter_ts = CurrentTime;
    }
  }

  /* Mesh-map: this node declared its own direct-peer set (single-writer per key).
   * peers is a comma-joined list of base64 server numerics; absent on an old-form
   * beacon, in which case the prior row is left intact (a stale binary just won't
   * refresh adjacency — observability-only, so harmless). */
  if (peers && peers[0] && strcmp(peers, "*") != 0) {
    uint16_t adj[CRDT_MESH_MAXDEG];
    int n = 0;
    const char *p = peers;
    while (*p && n < CRDT_MESH_MAXDEG) {
      char tok[8];
      int t = 0;
      while (*p && *p != ',' && t < (int)sizeof tok - 1)
        tok[t++] = *p++;
      tok[t] = '\0';
      while (*p == ',')
        p++;
      if (t > 0) {
        unsigned int pn = base64toint(tok);
        if (pn < CRDT_MAX_SERVERS)
          adj[n++] = (uint16_t)pn;
      }
    }
    if (crdt_meshmap_row_changed(&g_meshmap, (uint16_t)num, adj, n))
      g_mesh_changed_ts = CurrentTime;     /* MR-2: structural change -> flood window */
    crdt_meshmap_set(&g_meshmap, (uint16_t)num, adj, n, CurrentTime);
  }
  return 1;
}

/* MR-4d: should THIS gateway stand down from re-emitting CR-M traffic for legacy
 * server `num` because a lower-numeric gateway also fronts it?  Consults the recorded
 * min_fronter (lowest gateway seen beaconing `num`) + its freshness, then defers to
 * the pure crdt_gateway_should_standby rule.  my_yxx = our own server numeric. */
int crdt_shadow_should_standby(unsigned int num, const char *my_yxx)
{
  int fronter_num, fresh;
  if (num >= CRDT_MAX_SERVERS || !crdt_beacon[num].min_fronter[0])
    return 0;
  fronter_num = (int)base64toint(crdt_beacon[num].min_fronter);
  fresh = (CurrentTime - crdt_beacon[num].min_fronter_ts
           <= crdt_shadow_beacon_stale_secs());
  return crdt_gateway_should_standby((int)base64toint(my_yxx), fronter_num, fresh);
}

/* MR-5 event-driven beacon-burst: when a CRDT peer links, hand it the full current
 * beacon set at once, instead of making it wait up to a CRDT_BEACON_STALE window for the
 * periodic 30s flood + eager relay to reach it.  Closes the cold-link "blind leaf" gap
 * that tree-retirement (MR-5-2/5-3) opened: with the far CRDT/legacy servers' P10 SERVER
 * intros suppressed, the new leaf learns those servers ONLY via beacons (Case-B anchors),
 * so until the beacons arrive it cannot anchor them or materialize their users (the
 * transient N/0 verify state observed at bringup).  Sends, targeted to the one new peer:
 *   (a) our own self-beacon + (b) our proxy-legacy beacons (crdt_gossip_beacon_to), and
 *   (c) a replay of every fresh beacon we currently hold for OTHER servers, so the peer
 *       also learns servers 2+ hops away immediately (not just our direct neighbourhood).
 * Steady state still belongs to the periodic flood; this is bringup latency only.  Each
 * replayed (c) beacon carries peers="*" (no mesh-map adjacency) and omits fronted_by: the
 * mesh-map + the MR-4d double-delivery election self-correct on the next real beacon tick
 * (both observability-only).  Gated to FRESH (recv within the staleness window) so we never
 * resurrect a server we ourselves already consider gone.  Loop-safe: the new peer relays
 * onward (excluding us) and the emit_ts dedup terminates it exactly as the normal flood. */
void crdt_shadow_beacon_burst(struct Client *peer)
{
  unsigned int me_num, num;
  int replayed = 0;
  if (!crdt_shadow_active() || !peer || !IsCrdtSyncTarget(peer))
    return;
  crdt_gossip_beacon_to(peer);             /* (a) our self-beacon + (b) our proxy-legacy beacons */
  me_num = (unsigned int)base64toint(cli_yxx(&me));
  for (num = 0; num < CRDT_MAX_SERVERS; num++) {  /* (c) replay fresh far-server beacons */
    char yxx[4];
    if (num == me_num)
      continue;                            /* us -> already sent via (a) */
    if (!crdt_beacon[num].emit_ts || !crdt_beacon[num].name[0] ||
        !crdt_beacon[num].nn_cap[0])
      continue;                            /* never fully seen this server */
    if (CurrentTime - crdt_beacon[num].recv_ts > CRDT_BEACON_STALE)
      continue;                            /* stale by our own reckoning -> don't resurrect */
    inttobase64(yxx, num, 2);
    sendcmdto_one(&me, CMD_CRDT_REPLICATION, peer, "H %s %ld %s %s :%s",
                  yxx, (long)crdt_beacon[num].emit_ts,
                  crdt_beacon[num].nn_cap, "*", crdt_beacon[num].name);
    replayed++;
  }
  log_write(LS_SYSTEM, L_INFO, 0,
            "MR-5 beacon-burst: handed %s our liveness set + %d replayed far-server "
            "beacon(s) at link time (cold-link bringup)", cli_name(peer), replayed);
}

/* Overlay liveness probe (active, traffic-based).  An overlay edge is ping-EXEMPT
 * (check_pings) because it never "registers"; its design liveness is TCP-EOF +
 * write-failure.  But a half-open / black-holed socket (peer host crash, kernel
 * panic, silent partition) delivers NO EOF and a write() into it is buffered by the
 * kernel and does NOT fail for ~15 min (TCP give-up) — so the passive checks never
 * fire, the overlay zombies, and try_connections' "already present" dedup blocks
 * reconnect for the whole window.  Close the gap with an ACTIVE probe: CR traffic
 * (the CR H beacon alone arrives every CRDT_VERIFY_INTERVAL=30s over every overlay
 * edge) refreshes cli_lasttime on read (s_bsd.c read_packet).  U6: instead of a
 * CurrentTime-cli_lasttime delta (which a wall-clock step makes lie for every edge
 * at once), crdt_shadow_verify_cb drives a per-overlay CHANGE-DETECTOR each tick —
 * con_ov_miss counts consecutive ticks in which cli_lasttime did NOT move (an
 * inequality of two same-epoch reads, immune to any clock step).  This function just
 * reads that verdict.  Returns 1 (>= CRDT_BEACON_MISS_TICKS silent ticks = 90s) →
 * caller (check_pings) tears it down so the normal reap→try_connections reconnect
 * runs.  Mirrors the mesh-stub tick-counted retirement (same helper, same rationale). */
int crdt_overlay_is_stale(const struct Client *ov)
{
  if (!ov || !IsCrdtOverlay(ov))
    return 0;
  /* con_ov_miss is advanced only by crdt_shadow_verify_cb's change-detector; a fresh
   * overlay starts miss=0 (alloc_connection memset) and its first tick snapshots
   * cli_lasttime (!= 0 from make_client) resetting to 0 -> no startup false-kill. */
  return con_ov_miss(cli_connect(ov)) >= CRDT_BEACON_MISS_TICKS;
}

/* Build this server's own direct-CRDT-peer list (base64 numerics, comma-joined)
 * into @a out for the CR H beacon, AND record our own mesh-map row locally so the
 * map is populated before any beacon round-trips back.  A node's direct peers are
 * its IsCrdtSyncTarget transports (the same set crdt_gossip_beacon emits to).
 * Returns the number of peers; logs once if the degree cap truncates. */
int crdt_shadow_local_peers(char *out, size_t outsz)
{
  struct Client *acptr;
  uint16_t adj[CRDT_MESH_MAXDEG];
  int n = 0, total = 0;
  size_t len = 0;

  if (out && outsz)
    out[0] = '\0';

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    const char *yxx;
    size_t need;
    if (!IsCrdtSyncTarget(acptr))
      continue;
    total++;
    yxx = cli_yxx(acptr);
    if (!yxx || !yxx[0])
      continue;
    if (n < CRDT_MESH_MAXDEG) {
      unsigned int pn = base64toint(yxx);
      if (pn < CRDT_MAX_SERVERS)
        adj[n++] = (uint16_t)pn;
    }
    /* append "yxx," to the wire string, leaving room for the NUL */
    need = strlen(yxx) + 1;
    if (out && len + need + 1 < outsz) {
      if (len)
        out[len++] = ',';
      memcpy(out + len, yxx, strlen(yxx));
      len += strlen(yxx);
      out[len] = '\0';
    }
  }

  /* our own row, recorded locally (single-writer: us) */
  if (crdt_meshmap_row_changed(&g_meshmap, (uint16_t)base64toint(cli_yxx(&me)), adj, n))
    g_mesh_changed_ts = CurrentTime;       /* MR-2: a local link formed/dropped */
  crdt_meshmap_set(&g_meshmap, (uint16_t)base64toint(cli_yxx(&me)), adj, n, CurrentTime);

  if (total > CRDT_MESH_MAXDEG)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT meshmap: direct CRDT degree %d exceeds cap %d; diagram truncated",
              total, CRDT_MESH_MAXDEG);
  return n;
}

/* Accessors for the /CRDT introspection command (observability). */
const struct CrdtMeshMap *crdt_shadow_meshmap(void)
{
  return &g_meshmap;
}

/* MR-2: is the mesh-map settled enough to forward broadcast over the canonical
 * tree (vs flood)?  True iff no structural change for CRDT_MESH_BCAST_STABLE s AND
 * we actually have a CRDT peer (a lone node trivially "stable" has nothing to
 * forward).  Conservative: any topology flux -> flood (gap-free) until it settles. */
int crdt_shadow_mesh_bcast_stable(time_t now)
{
  if (g_mesh_changed_ts == 0)              /* pre-first-beacon cold start -> flood */
    return 0;
  return (now - g_mesh_changed_ts) > CRDT_MESH_BCAST_STABLE;
}

const char *crdt_shadow_beacon_name(unsigned int num)
{
  return (num < CRDT_MAX_SERVERS) ? crdt_beacon[num].name : "";
}

time_t crdt_shadow_beacon_recv(unsigned int num)
{
  return (num < CRDT_MAX_SERVERS) ? crdt_beacon[num].recv_ts : 0;
}

time_t crdt_shadow_beacon_stale_secs(void)
{
  return CRDT_BEACON_STALE;
}

/* R4a (channel-over-mesh): per-server "this channel message was already delivered to my
 * LOCAL members" dedup, keyed by msgid.  Shared by the tree path (sendcmdto_channel_butone,
 * via the channel relay) and the CR-M path (ms_crdt 'M'): whichever plane reaches a given
 * server first delivers to its locals + marks the msgid; the other plane skips its LOCAL
 * delivery (relay/flood propagation is unaffected).  This is what makes widening CR M to
 * all-CRDT-peer members (so channel traffic survives a tree-edge cut) exactly-once at the
 * client.  Deliberately SEPARATE from crdt_m_seen (the CR-M FLOOD dedup, which gates relay)
 * — sharing would let a tree-first delivery suppress the CR-M relay and break the flood.
 * Returns 1 if already delivered within the window (caller skips LOCAL delivery), else
 * records it and returns 0 (caller delivers).  A missing/"*" msgid never dedupes. */
#define CRDT_CHAN_LOCAL_WINDOW 90       /* s; > worst-case tree-vs-mesh arrival skew */
static struct CrdtMsgidDedup crdt_chan_local_seen;
int crdt_shadow_chan_local_check_add(const char *msgid)
{
  if (!msgid || !*msgid || (msgid[0] == '*' && !msgid[1]))
    return 0;
  return crdt_dedup_check_add(&crdt_chan_local_seen, msgid, (uint64_t)CurrentTime,
                              CRDT_CHAN_LOCAL_WINDOW);
}

/** Shadow is active only once initialised AND the feature is enabled. */
static int shadow_on(void)
{
  return g_inited && feature_bool(FEAT_CRDT_ENABLED);
}

/** Single-writer gate (Phase 3a). Returns true if a state event reached us via
 *  a CRDT-aware peer — in which case that peer is the single writer for it and
 *  we must NOT re-mirror it locally; we receive its op via CR sync. We DO mirror
 *  (we are the writer / CRDT-mesh entry point) when the event is local
 *  (cli_from == self, not a server) or arrived over a non-CRDT P10 link (the
 *  gateway case). `from != &me` matters because &me is itself CrdtAware
 *  (SetCrdtAware(&me) in ircd.c) and IsServer(&me) is true, so a local-origin
 *  change carrying &me as its source must not be mistaken for a peer relay.
 *
 *  Caveat: full-digest convergence holds only within a contiguous CRDT-aware
 *  region. A non-CRDT server bridging two CRDT islands makes each island's entry
 *  server a second writer for cross-bridge users (gateway case at both ends), so
 *  the re-mirror redundancy persists across that bridge. Phase 3d (hybrid
 *  gateway) formalizes the boundary.
 *
 *  Tier2: a STAT_MESH_SERVER stub (a tree-departed-but-mesh-reachable CRDT peer,
 *  crdt_shadow_convert_to_stub) counts as a peer too. Its held users belong to
 *  the partitioned peer, which still owns them in the doc and replicates their
 *  state over the mesh — so we must NOT re-mirror changes to them, including the
 *  teardown in crdt_shadow_retire_mesh_stub (the stub keeps FLAG_CRDT_AWARE).
 *  Without this, exit_one_client on a held user would mint a DELETE/PART
 *  tombstone, breaking the retire's zero-tombstone contract and creating an
 *  HLC-bearing divergence that SV-only anti-entropy cannot repair. */
static int from_crdt_peer(struct Client *from)
{
  return from && from != &me && (IsServer(from) || IsMeshStub(from))
         && IsCrdtAware(from);
}

/* Tier2 P1: true if @a u is a "mesh-only" user — its owning server is a
 * STAT_MESH_SERVER stub (tree-departed but mesh-reachable).  Such a user exists
 * only in the CRDT layer here; legacy (non-CRDT) peers already received the SQUIT
 * for its server, so the §17.7 legacy gateway emits (NICK/JOIN/PART/KICK) MUST be
 * skipped for it — it propagates to other CRDT-mesh servers via the doc, and the
 * real P10 introduction returns when its server relinks.
 * R6c: a stub the gateway has PRESENTED to legacy (FLAG_CRDT_PRESENTED) is NO LONGER
 * mesh-only toward legacy — legacy now knows its server, so all the §17.7 gates
 * (which consult this helper) emit for its users.  Flipping this one predicate flips
 * every gate at once. */
int crdt_user_is_mesh_only(struct Client *u)
{
  struct Client *srv = (u && cli_user(u)) ? cli_user(u)->server : NULL;
  return srv && IsMeshStub(srv) && !IsPresented(srv);
}

/* Tier B: is SERVER @a srv reachable ONLY via the mesh (a STAT_MESH_SERVER anchor with no
 * live P10 link), so a P10 sendcmdto_one to it would dead-sink?  Used by the services-anchor
 * bridge to decide CR-X routing vs P10 for a services target (x3.services).  On a LEAF, x3 is
 * never presented, so the IsPresented term is correct there.  On the GATEWAY the reverse path
 * must NOT use this predicate (a presented stub returns 0 yet still dead-sinks) — it uses the
 * cli_from-dead test instead (the presented-stub trap from the INVITE fix). */
int crdt_server_is_mesh_only(struct Client *srv)
{
  return srv && IsMeshStub(srv) && !IsPresented(srv);   /* IsMeshStub == STAT_MESH_SERVER (IsServer is false for it) */
}

/* R6c flood-on-partition: O(1) count of STAT_MESH_SERVER stubs this node holds (created in
 * crdt_shadow_convert_to_stub + crdt_shadow_make_anchor, freed in crdt_shadow_retire_mesh_stub
 * — the only 3 lifecycle sites).  >0 means this node is partitioned: some servers are reachable
 * only via the mesh, so its live channel views may be MISSING members (e.g. legacy users whose
 * server can't be re-materialized here).  A partitioned node therefore floods channel traffic
 * unconditionally so the mesh + a gateway can deliver/bridge it (see ircd_relay.c / m_tagmsg.c). */
static unsigned int crdt_mesh_stub_count = 0;
int crdt_have_mesh_stub(void) { return crdt_mesh_stub_count > 0; }
void crdt_mesh_stub_dec(void) { if (crdt_mesh_stub_count) crdt_mesh_stub_count--; }

/** Build the full P10 numeric ("YYXXX") for a user into @a buf. */
static const char *user_numeric(struct Client *who, char *buf, size_t n)
{
  snprintf(buf, n, "%s%s", cli_yxx(cli_user(who)->server), cli_yxx(who));
  return buf;
}

/* ---- Phase 3b reconstruction payload helpers ---- */

/** Copy just the mode-LETTERS of a umode_str() result into @a dst (the first
 *  whitespace-delimited token). Parameters (sethost, account, the volatile
 *  IP-list field) are deliberately dropped: sethost lives in rec.host, account
 *  in rec.account, and param fields can be observer-relative. The bare flags are
 *  S2S-propagated and observer-consistent, so they converge. */
static void umode_letters(char *dst, size_t dstsz, const char *um)
{
  size_t i = 0;
  if (um)
    while (um[i] && um[i] != ' ' && i + 1 < dstsz) { dst[i] = um[i]; i++; }
  dst[i] = '\0';
}

/** Map live Membership status bits to the compact CRDT status byte. */
static uint8_t compact_status(unsigned int st)
{
  uint8_t s = 0;
  if (st & CHFL_CHANOP) s |= CRDT_MEMBER_OP;
  if (st & CHFL_VOICE)  s |= CRDT_MEMBER_VOICE;
  if (st & CHFL_HALFOP) s |= CRDT_MEMBER_HALFOP;
  return s;
}

/** Mirror one member's status+oplevel into the members_status LWW map. */
static void write_member_status(struct Channel *chptr, struct Membership *m)
{
  char num[16];
  struct CrdtMemberRecord rec;
  if (!m || (m->status & CHFL_ALIAS) || !cli_user(m->user))
    return;
  memset(&rec, 0, sizeof rec);
  rec.status = compact_status(m->status);
  rec.oplevel = (uint16_t)m->oplevel;
  crdt_member_status_set(&g_crdt, chptr->chname,
                         user_numeric(m->user, num, sizeof num), &rec);
}

/** Mirror a channel's metadata (creationtime + topic provenance) into chanmeta. */
static void write_chanmeta(struct Channel *chptr)
{
  struct CrdtChanMeta meta;
  memset(&meta, 0, sizeof meta);
  meta.creationtime = (uint64_t)chptr->creationtime;
  meta.topic_time = (uint64_t)chptr->topic_time;
  strncpy(meta.topic_nick, chptr->topic_nick, sizeof meta.topic_nick - 1);
  crdt_chanmeta_set(&g_crdt, chptr->chname, &meta);
  /* Phase 3j: creationtime ALSO rides a dedicated incarnation min-register (IRC
   * is lower-TS-wins, not LWW). chanmeta keeps topic_time/topic_nick (genuinely
   * LWW). reconcile-create + the materialize !existed rebuild read ctime from here. */
  crdt_chan_ctime_set(&g_crdt, chptr->chname, (uint64_t)chptr->creationtime);
}

void crdt_shadow_join(struct Channel *chptr, struct Client *who,
                      unsigned int flags)
{
  char num[16];
  if (!shadow_on())
    return;
  if (flags & CHFL_ALIAS)            /* bouncer alias — not a real member */
    return;
  if (!cli_user(who))
    return;
  if (from_crdt_peer(cli_from(who)))  /* single-writer: peer owns this op */
    return;
  crdt_chan_join(&g_crdt, chptr->chname, user_numeric(who, num, sizeof num));
  /* Always stamp member status on join (not just op-on-join): members_status is
   * LWW and is NOT cleared on PART (delete-on-leave deferred), so a member who was
   * op'd, parted, and now rejoins PLAIN must overwrite the stale op record with a
   * fresh status=0 (newer HLC) — otherwise Phase-3h reconcile would re-op them.
   * write_member_status reads the member's current flags (0 for a plain join). */
  write_member_status(chptr, find_member_link(chptr, who));
  write_chanmeta(chptr);
  /* Phase 3j AUTOCHANMODES fix: SetAutoChanModes (channel.c) sets mode.mode
   * DIRECTLY (no modebuf), so the create's default modes (+nt…) never reach the
   * doc via the modebuf->crdt_shadow_modes path. Snapshot them here the FIRST time
   * we record this channel (doc has no modes entry yet) so a reconcile-created
   * channel on a CRDT peer rebuilds +nt. Fires ~once per channel lifecycle; only
   * for local-origin joins (peer-origin joins returned at the from_crdt_peer gate). */
  if ((chptr->mode.mode & CRDT_MODE_MASK) &&
      !crdt_lwwmap_get(&g_crdt.modes, chptr->chname,
                       (uint32_t)strlen(chptr->chname)))
    crdt_shadow_modes(chptr, cli_from(who));
  crdt_sync_push();                   /* eager-propagate to CRDT peers */
}

void crdt_shadow_part(struct Channel *chptr, struct Client *who)
{
  char num[16];
  if (!shadow_on())
    return;
  if (!cli_user(who))
    return;
  if (from_crdt_peer(cli_from(who)))  /* single-writer: peer owns this op */
    return;
  crdt_chan_remove(&g_crdt, chptr->chname, user_numeric(who, num, sizeof num),
                   CRDT_PRIORITY_USER);
  /* m15 (delete-on-leave): clear the member's status LWW on a clean leave so a stale
   * +o can't re-op them on a later rejoin (reconcile_mstatus_cb re-drives m->status
   * from the LWW-winning record). Mirrors the OR-Set remove above; `num` was just
   * filled by the user_numeric() call. The GC reap (crdt_state_reclaim_orphan_member_
   * meta) backstops UNCLEAN departures where this hook never fires (home SQUIT/crash). */
  crdt_member_status_remove(&g_crdt, chptr->chname, num);
  crdt_sync_push();                   /* eager-propagate to CRDT peers */
}

void crdt_shadow_kick(struct Channel *chptr, struct Client *who,
                      struct Client *kicker, const char *reason,
                      struct Client *from)
{
  char whonum[16], kicknum[16];
  struct CrdtKickInfo ki;
  if (!shadow_on() || !cli_user(who))
    return;
  if (from_crdt_peer(from))            /* kick already minted by the CRDT-aware origin */
    return;
  /* Phase 3k: remove the member with PRIORITY_USER (a standard OR-Set remove that
   * tombstones the OBSERVED add-tags). KICK is NOT a ban — a kicked user must be
   * able to rejoin; a priority>0 (CHANOP) tombstone would suppress the element
   * permanently (crdt_orset_contains rejects an element if ANY add-tag is covered
   * by a priority>0 tombstone, and the old tag lingers until GC), blocking rejoin.
   * KICK-vs-PART is distinguished by kick_info below, NOT by priority. Mint BEFORE
   * the live removal so it covers the current add-tags (the subsequent
   * crdt_shadow_part remove then finds nothing uncovered → no double-mint). */
  user_numeric(who, whonum, sizeof whonum);
  crdt_chan_remove(&g_crdt, chptr->chname, whonum, CRDT_PRIORITY_USER);
  /* m15 (delete-on-leave): clear the member's status LWW on kick too (same rationale as
   * PART). kick_info below still rides its own HLC gate; this delete only tombstones the
   * stale status so a rejoin isn't re-op'd. The subsequent crdt_shadow_part (from
   * remove_user_from_channel) mints a second, idempotent status delete — benign, LWW-
   * dedup'd, GC'd — mirroring the double crdt_chan_remove these two hooks already do. */
  crdt_member_status_remove(&g_crdt, chptr->chname, whonum);
  /* kick metadata so reconcile-remove emits a KICK (with attribution) not a PART;
   * the HLC gate (kick_info.ts vs the member's last-join members_status.ts) keeps a
   * stale kick from re-tagging a later plain PART after a rejoin. */
  memset(&ki, 0, sizeof ki);
  if (kicker && !IsServer(kicker) && cli_user(kicker))
    ircd_strncpy(ki.kicker, user_numeric(kicker, kicknum, sizeof kicknum),
                 sizeof ki.kicker);
  ircd_strncpy(ki.reason, reason ? reason : "", sizeof ki.reason);
  crdt_kick_info_set(&g_crdt, chptr->chname, whonum, &ki);
  crdt_sync_push();
}

void crdt_shadow_channel_destroy(struct Channel *chptr)
{
  if (!shadow_on())
    return;
  /* Phase 3j: bump the LOCAL ctime incarnation marker so a later recreate to a
   * HIGHER TS is not resurrected to this incarnation's (lower) creationtime.
   * Local-only (no op recorded); the next create's set-op carries the new
   * del_hlc to peers. Called from destruct_channel. */
  crdt_chan_ctime_clear(&g_crdt, chptr->chname);
}

void crdt_shadow_user_add(struct Client *cptr)
{
  char num[16];
  struct CrdtUserRecord rec;
  if (!shadow_on())
    return;
  /* non-alias users that are fully numbered (own + server numeric set) — guards
   * against the set_user_mode hook firing mid-registration before the local
   * numeric is assigned (which would mint a malformed server-only key). */
  if (!cli_user(cptr) || !cli_user(cptr)->server || !cli_yxx(cptr)[0] ||
      IsBouncerAlias(cptr))
    return;
  if (from_crdt_peer(cli_from(cptr)))  /* single-writer: peer owns this op */
    return;
  memset(&rec, 0, sizeof rec);
  strncpy(rec.nick, cli_name(cptr), sizeof rec.nick - 1);
  strncpy(rec.ident, cli_user(cptr)->username, sizeof rec.ident - 1);
  strncpy(rec.host, cli_user(cptr)->host, sizeof rec.host - 1);
  strncpy(rec.realhost, cli_user(cptr)->realhost, sizeof rec.realhost - 1);
  strncpy(rec.realname, cli_info(cptr), sizeof rec.realname - 1);
  strncpy(rec.account, cli_user(cptr)->account, sizeof rec.account - 1);
  strncpy(rec.swhois, cli_user(cptr)->swhois, sizeof rec.swhois - 1);
  if (cli_user(cptr)->away)
    strncpy(rec.away, cli_user(cptr)->away, sizeof rec.away - 1);
  /* Tier C F1-b: MARK-carried per-user state (CVERSION/SSLCLIFP/GEOIP codes). */
  strncpy(rec.version, cli_version(cptr), sizeof rec.version - 1);
  strncpy(rec.sslclifp, cli_sslclifp(cptr), sizeof rec.sslclifp - 1);
  strncpy(rec.countrycode, cli_countrycode(cptr), sizeof rec.countrycode - 1);
  strncpy(rec.continentcode, cli_continentcode(cptr), sizeof rec.continentcode - 1);
  umode_letters(rec.umodes, sizeof rec.umodes, umode_str(cptr));
  memcpy(rec.ip6, &cli_ip(cptr), sizeof rec.ip6);   /* struct irc_in_addr, 16B */
  rec.nick_ts = (uint64_t)cli_lastnick(cptr);
  rec.acc_create = (uint64_t)cli_user(cptr)->acc_create;
  rec.server = (uint16_t)base64toint(cli_yxx(cli_user(cptr)->server));
  crdt_user_set(&g_crdt, user_numeric(cptr, num, sizeof num), &rec);
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

void crdt_shadow_user_remove(struct Client *cptr)
{
  char num[16];
  if (!shadow_on())
    return;
  if (!cli_user(cptr) || IsBouncerAlias(cptr))
    return;
  if (from_crdt_peer(cli_from(cptr)))  /* single-writer: peer owns this op */
    return;
  crdt_user_remove(&g_crdt, user_numeric(cptr, num, sizeof num));
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

/* 5-5e M2 (doc-native bouncer, SHADOW): thin wrappers so bouncer_session.c can mirror
 * session state into the doc without reaching g_crdt directly.  Single-writer (primary
 * holder) is enforced by the caller (bounce_crdt_bsess_sweep). */
void crdt_shadow_bsess_set(const char *account, const char *sessid,
                           const struct CrdtBouncerSession *rec)
{
  if (!shadow_on())
    return;
  crdt_bsess_set(&g_crdt, account, sessid, rec);
  crdt_sync_push();
}

void crdt_shadow_bsess_remove(const char *account, const char *sessid)
{
  if (!shadow_on())
    return;
  crdt_bsess_del(&g_crdt, account, sessid);
  crdt_sync_push();
}

const char *crdt_shadow_bsess_winner(const char *account, char *out, size_t outsz)
{
  if (!shadow_on())
    return NULL;
  return crdt_bsess_winner(&g_crdt, account, out, outsz);
}

/* 5-5e M6a-3: live-presence check on the bsessions doc record.  Returns 1
 * iff a non-tombstone entry exists.  The replica reap uses this to tear a
 * materialized replica down once its owner tombstones the record (the doc
 * is the sole teardown signal once BS X relay is suppressed). */
int crdt_shadow_bsess_present(const char *account, const char *sessid)
{
  if (!shadow_on())
    return 0;
  return crdt_bsess_get(&g_crdt, account, sessid) != NULL;
}

/* Batch P3-5b2 (crdt-mesh INVARIANT 11): is this session's bsessions doc record
 * EXPLICITLY tombstoned (a genuine owner-side bounce_destroy minted a DELETE op)?
 * Distinct from crdt_shadow_bsess_present's NULL: crdt_bsess_get is NULL for a
 * tombstone AND for a never-written key, but is_explicitly_removed is 1 ONLY for a
 * real tombstone.  The replica reap gates on THIS so absence (a legacy-primaried
 * session that no CRDT node wrote, or a not-yet-synced record) is never mistaken
 * for removal.  Mirrors every other CRDT reap (user/metadata/gline/shun/...). */
int crdt_shadow_bsess_removed(const char *account, const char *sessid)
{
  if (!shadow_on())
    return 0;
  return crdt_bsess_is_explicitly_removed(&g_crdt, account, sessid);
}

/* M6c-1 BX Inc-2 (fix): is this connection's bconn doc record still LIVE (not
 * tombstoned/absent)?  The alias-reap oracle, mirror of crdt_shadow_bsess_present
 * for the replica-session reap.  crdt_bconn_get returns NULL for a tombstone. */
int crdt_shadow_bconn_present(const char *account, const char *sessid,
                             const char *connnum)
{
  if (!shadow_on())
    return 0;
  return crdt_bconn_get(&g_crdt, account, sessid, connnum) != NULL;
}

/* Batch P3-5b2 (crdt-mesh INVARIANT 11): is this connection's bconn doc record
 * EXPLICITLY tombstoned (a genuine owner-side alias teardown minted a DELETE op)?
 * The alias-reap oracle, mirror of crdt_shadow_bsess_removed.  Supersedes the M14
 * FindNServer host-gate: a legacy-hosted alias is never written -> removed==0 ->
 * spared without host resolution, and a CRDT-hosted sync-lag-absent alias is
 * likewise removed==0 -> spared (the residual over-reap M14 could not close). */
int crdt_shadow_bconn_removed(const char *account, const char *sessid,
                             const char *connnum)
{
  if (!shadow_on())
    return 0;
  return crdt_bconn_is_explicitly_removed(&g_crdt, account, sessid, connnum);
}

/* 5-5e M6d: the full P10 numeric of the doc-recorded PRIMARY connection for
 * (account,sessid), or NULL if none in the doc.  Used by the lease-authoritative
 * resume decision to resolve the live holder's primary Client (findNUser) when a
 * fresh connection must alias onto a still-live holder rather than reclaim. */
const char *crdt_shadow_bconn_primary(const char *account, const char *sessid,
                                      char *out, size_t outsz)
{
  if (!shadow_on())
    return NULL;
  return crdt_bconn_primary(&g_crdt, account, sessid, out, outsz);
}

/* 5-5e M4: per-connection roster wrappers + a reconcile-style reap. */
void crdt_shadow_bconn_set(const char *account, const char *sessid,
                           const char *connnum, const struct CrdtBouncerConn *rec)
{
  if (!shadow_on())
    return;
  crdt_bconn_set(&g_crdt, account, sessid, connnum, rec);
  crdt_sync_push();
}

void crdt_shadow_bconn_remove(const char *account, const char *sessid,
                              const char *connnum)
{
  if (!shadow_on())
    return;
  crdt_bconn_del(&g_crdt, account, sessid, connnum);
  crdt_sync_push();
}

/* Reap stale connections THIS node owns: a bconn entry whose host is us but whose
 * connnum no longer resolves to a live client (disconnected) is tombstoned, so the
 * roster stays exact without hooking every connection-teardown site.  Single-writer:
 * only entries with host==me are touched.  Collect-then-delete (no mutation mid-walk). */
struct bconn_reap_ctx {
  uint16_t me;
  struct { char acc[ACCOUNTLEN + 1]; char sid[64]; char num[16]; } stale[64];
  int count;
};
static void bconn_reap_cb(const char *key, uint32_t key_len,
                          const struct CrdtLWWValue *val, void *ctx)
{
  struct bconn_reap_ctx *c = ctx;
  const struct CrdtBouncerConn *rec;
  const char *p1, *p2;          /* the two embedded NULs: account\0sessid\0connnum */
  uint32_t alen, slen, nlen;
  if (!val->data || val->data_len != sizeof(struct CrdtBouncerConn))
    return;                              /* already a tombstone */
  rec = (const struct CrdtBouncerConn *)val->data;
  if (rec->host != c->me)
    return;                              /* not ours (single-writer) */
  if (c->count >= (int)(sizeof c->stale / sizeof c->stale[0]))
    return;                              /* capped; remaining reaped next sweep */
  p1 = memchr(key, '\0', key_len);
  if (!p1) return;
  alen = (uint32_t)(p1 - key);
  p2 = memchr(p1 + 1, '\0', key_len - alen - 1);
  if (!p2) return;
  slen = (uint32_t)(p2 - (p1 + 1));
  nlen = (uint32_t)(key_len - alen - 1 - slen - 1);
  if (alen > ACCOUNTLEN || slen >= sizeof c->stale[0].sid ||
      nlen == 0 || nlen >= sizeof c->stale[0].num)
    return;
  { char numbuf[16];
    memcpy(numbuf, p2 + 1, nlen); numbuf[nlen] = '\0';
    if (findNUser(numbuf))
      return;                            /* still live -> keep */
    memcpy(c->stale[c->count].acc, key, alen);  c->stale[c->count].acc[alen] = '\0';
    memcpy(c->stale[c->count].sid, p1 + 1, slen); c->stale[c->count].sid[slen] = '\0';
    memcpy(c->stale[c->count].num, numbuf, nlen + 1);
    c->count++;
  }
}

void crdt_shadow_bconn_reap(void)
{
  struct bconn_reap_ctx c;
  int i;
  if (!shadow_on())
    return;
  c.me = (uint16_t)base64toint(cli_yxx(&me));
  c.count = 0;
  crdt_lwwmap_foreach(&g_crdt.bconns, bconn_reap_cb, &c);
  for (i = 0; i < c.count; i++)
    crdt_bconn_del(&g_crdt, c.stale[i].acc, c.stale[i].sid, c.stale[i].num);
  if (c.count)
    crdt_sync_push();
}

int crdt_shadow_bconn_roster_count(const char *account, const char *sessid)
{
  if (!shadow_on())
    return 0;
  return crdt_bconn_roster_count(&g_crdt, account, sessid);
}

/* Dead-node doc-residue reap — INCREMENT 0: DETECT-AND-LOG ONLY (no delete).
 *
 * When a CRDT node dies (crash / hard SQUIT, no clean teardown) its single-writer
 * doc records (bconns host=dead, the matching user records) have no live writer to
 * tombstone them, so they linger and re-materialize as GHOST users on restart.  This
 * scan walks the bconn collection for entries owned by a FOREIGN host whose self-
 * beacon has gone STALE (a dead/partitioned candidate) and logs the full reap
 * predicate WITHOUT deleting, so we can confirm on a real bed that the predicate
 * fires on a truly-dead node (docker kill) and STAYS SILENT for a partitioned-but-
 * healing node (netns cut + heal), before any destructive non-owner tombstone exists.
 *
 * The lease (CRDT_COLL_BLEASES) is the partition-vs-death oracle.  Two candidate
 * predicates are logged so the live tests can decide which is safe:
 *   would_reap_A (partition-SAFE) = grace && lease_MOVED off host && no live client
 *       — a revive elsewhere bumped the lease generation; a partition never moves it.
 *         Covers the revive/transfer case (the OBSERVED revtest/demtest ghost).
 *   would_reap_B (broader)        = grace && (lease_moved || lease_holder_beacon_dead
 *         || no_lease) && no live client — also covers a pure crash with no revive,
 *         but the lease_dead/no_lease arms can FALSE-POSITIVE on a full partition
 *         (the partitioned holder's beacon is stale everywhere).  The netns test is
 *         the oracle for whether B is usable or must wait for a longer grace / Opt B
 *         (lowest-numeric survivor) election.
 * findNUser(connnum)==NULL = no live client here (mesh-stub-retire already exited it);
 * user_in_doc = the doc still carries the user record (== the leak to also tombstone). */
#define CRDT_ORPHAN_REAP_GRACE 60   /* seconds past beacon-stale before reap-eligible */
struct orphan_scan_ctx { uint16_t me; int candidates; };
static void orphan_scan_cb(const char *key, uint32_t key_len,
                           const struct CrdtLWWValue *val, void *ctx)
{
  struct orphan_scan_ctx *c = ctx;
  const struct CrdtBouncerConn *rec;
  const struct CrdtBouncerLease *lease;
  const char *p1, *p2;
  uint32_t alen, slen, nlen;
  char acc[ACCOUNTLEN + 1], sid[64], num[16];
  time_t age;
  uint16_t host, lease_host;
  int no_lease, lease_moved, lease_dead, live_client, user_in_doc;
  int grace_ok, would_reap_A, would_reap_B;

  if (!val->data || val->data_len != sizeof(struct CrdtBouncerConn))
    return;                                  /* tombstone */
  rec = (const struct CrdtBouncerConn *)val->data;
  host = rec->host;
  if (host == c->me || host >= CRDT_MAX_SERVERS)
    return;                                  /* ours -> M4 owner-reap; or out of range */
  if (crdt_shadow_server_beacon_fresh(host))
    return;                                  /* owner alive -> normal foreign bconn */

  /* key = account\0sessid\0connnum */
  p1 = memchr(key, '\0', key_len); if (!p1) return;
  alen = (uint32_t)(p1 - key);
  p2 = memchr(p1 + 1, '\0', key_len - alen - 1); if (!p2) return;
  slen = (uint32_t)(p2 - (p1 + 1));
  nlen = (uint32_t)(key_len - alen - 1 - slen - 1);
  if (alen > ACCOUNTLEN || slen >= sizeof sid || nlen == 0 || nlen >= sizeof num)
    return;
  memcpy(acc, key, alen); acc[alen] = '\0';
  memcpy(sid, p1 + 1, slen); sid[slen] = '\0';
  memcpy(num, p2 + 1, nlen); num[nlen] = '\0';

  age = crdt_beacon[host].recv_ts ? (CurrentTime - crdt_beacon[host].recv_ts) : (time_t)-1;
  grace_ok = (age < 0) || (age > CRDT_BEACON_STALE + CRDT_ORPHAN_REAP_GRACE);
  lease = crdt_blease_get(&g_crdt, acc, sid);
  lease_host = lease ? lease->host : 0;
  no_lease = (lease == NULL);
  lease_moved = (lease && lease->host != host);
  lease_dead = (lease && !crdt_shadow_server_beacon_fresh(lease->host));
  live_client = (findNUser(num) != NULL);
  user_in_doc = (crdt_user_get(&g_crdt, num) != NULL);
  would_reap_A = grace_ok && lease_moved && !live_client;
  would_reap_B = grace_ok && (lease_moved || lease_dead || no_lease) && !live_client;

  c->candidates++;
  log_write(LS_SYSTEM, L_NOTICE, 0,
    "CRDT orphan-residue CANDIDATE host=%u connnum=%s acct=%s sid=%s "
    "beacon_age=%lds no_lease=%d lease_host=%u lease_moved=%d lease_dead=%d "
    "live_client=%d user_in_doc=%d grace_ok=%d would_reap_A=%d would_reap_B=%d",
    (unsigned)host, num, acc, sid, (long)age, no_lease, (unsigned)lease_host,
    lease_moved, lease_dead, live_client, user_in_doc, grace_ok,
    would_reap_A, would_reap_B);
}

void crdt_shadow_orphan_reap_scan(void)
{
  struct orphan_scan_ctx c;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_BOUNCER_DOC))
    return;
  c.me = (uint16_t)base64toint(cli_yxx(&me));
  c.candidates = 0;
  crdt_lwwmap_foreach(&g_crdt.bconns, orphan_scan_cb, &c);
}

/* Orphan-reap milestone, Inc 1 — STALE-MATERIALIZATION detector (DETECT-AND-LOG ONLY).
 *
 * Class-1 ghost: a materialized remote user lingers as a live Client here but its
 * CRDT_COLL_USERS doc record is WHOLLY ABSENT (no value, no tombstone) — its delete
 * tombstone was GC'd (crdt_lwwmap_gc_deleted, once the DELETE op went causally stable —
 * e.g. the deleting peer left the gmin set) before crdt_shadow_reconcile_user_removes
 * (tombstone-ONLY) reaped it.  Invariant: a present doc entry never vanishes (GC reclaims
 * only tombstones), so a previously-materialized user now wholly absent WAS deleted.
 *
 * Predicate note: the LEASE is the WRONG oracle for class-1 — it tracks the session/
 * account (alive on its home), not the individual user incarnation that quit, so a ghost
 * shows lease_moved=0.  The correct signal is owner-BEACON-fresh + not-bursting +
 * persistence (a partitioned owner goes beacon-stale -> self-suppresses, the proven
 * partition oracle from the bconn orphan scan).
 *
 * Inc 1 LOGS would_reap WITHOUT acting, so a real bed can confirm it stays 0 across a
 * netns partition+heal UNDER CHURN (false-death gate) and fires only on genuine churn
 * ghosts, before Inc 2 makes it destructive.  No exit_client here — cannot crash. */
static void crdt_shadow_stale_user_scan(void)
{
  struct Client *acptr;
  int bursting = 0;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_BOUNCER_DOC))
    return;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsServer(acptr) && IsBurstOrBurstAck(acptr)) { bursting = 1; break; }
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    char num[CRDT_NUMERICLEN];
    struct Client *owner;
    uint16_t onum;
    int owner_fresh, prev_absent, would_reap;
    if (!IsUser(acptr) || MyUser(acptr) || IsBouncerAlias(acptr))
      continue;
    if (crdt_user_is_mesh_only(acptr))
      continue;                       /* mesh-stub user — retire path owns it */
    user_numeric(acptr, num, sizeof num);
    if (crdt_user_get(&g_crdt, num) || crdt_user_is_explicitly_removed(&g_crdt, num)) {
      ClrFlag(acptr, FLAG_CRDT_ORPHAN_PENDING);   /* present or tombstoned — healthy */
      continue;
    }
    /* wholly absent from the doc: candidate ghost */
    owner = cli_user(acptr) ? cli_user(acptr)->server : NULL;
    onum  = (owner && IsServer(owner)) ? (uint16_t)base64toint(cli_yxx(owner)) : 0;
    owner_fresh = (owner && IsServer(owner) && IsCrdtAware(owner) && !IsMeshStub(owner)
                   && crdt_shadow_server_beacon_fresh(onum));
    prev_absent = HasFlag(acptr, FLAG_CRDT_ORPHAN_PENDING);
    would_reap = owner_fresh && !bursting && prev_absent;  /* 2nd consecutive absent pass */
    log_write(LS_SYSTEM, L_NOTICE, 0,
      "CRDT stale-mat CANDIDATE num=%s nick=%s acct=%s owner=%s owner_fresh=%d "
      "bursting=%d prev_absent=%d would_reap=%d",
      num, cli_name(acptr), cli_account(acptr)[0] ? cli_account(acptr) : "-",
      owner ? cli_name(owner) : "?", owner_fresh, bursting, prev_absent, would_reap);
    SetFlag(acptr, FLAG_CRDT_ORPHAN_PENDING);     /* mark for next-pass debounce */
  }
}

/* Orphan-reap OWNER SWEEP (2026-07-26): a doc user record whose OWNER is ME but for
 * which I hold no live Client is self-evidently stale — I am the single writer for
 * my own users, so no other node can legitimately account for it.  Live repro (the
 * characterization's run 4): heal-after-complete-tombstone-GC re-imports
 * quit-during-partition users network-wide as UNKILLABLE doc-present zombies —
 * a non-owner KILL exits the local materialized Client without minting a tombstone
 * (single-writer self-skip) and reconcile re-materializes it next tick, while the
 * owner's quit path can never fire without a live client.  The owner minting the
 * DELETE is the only clean kill: same-origin monotonic seqs make a concurrent
 * numeric-reuse SET win LWW (delete seq k < re-add seq k+1, applied in-order
 * everywhere), and peers' tombstone-driven reconcile_user_removes finishes the
 * network-wide de-materialize.  Also the catch-all for restart re-import residue
 * (my pre-crash records pulled back from peers' snapshots) and teardown paths that
 * free a live Client without the shadow hook (bounce_detach hs_client NULL, KILL —
 * P3-5b2 follow-up item 2).  A standing sweep beats one-shot cleanup: a partitioned
 * peer re-importing the record after our tombstone GC'd is simply caught again.
 *
 * DESTRUCTIVE (mints real tombstones) -> dedicated kill-switch
 * FEAT_CRDT_OWNER_SWEEP.  Safety gates: !bursting (resync in flight) + a 2-pass
 * debounce (registration is NOT a window — a local record is minted only after the
 * client is numeric-hashed — but the debounce cheaply covers windows not yet
 * imagined).  Bounded per pass; a reaped record turns tombstone so it self-drops
 * from the next pass's candidate walk.  The engine-side convergence contract
 * (owner re-delete beats a snapshot re-import) is cmocka-encoded in
 * test_owner_remove_beats_snapshot_reimport; the findNUser/burst/debounce half is
 * integration-layer, verified LIVE (cmocka cannot construct Clients). */
#define OWN_SWEEP_MAX 64
struct own_sweep_ctx {
  uint16_t me;
  char cand[OWN_SWEEP_MAX][CRDT_NUMERICLEN];
  int  n;
};

static void own_sweep_collect_cb(const char *key, uint32_t key_len,
                                 const struct CrdtLWWValue *val, void *ctx)
{
  struct own_sweep_ctx *c = (struct own_sweep_ctx *)ctx;
  const struct CrdtUserRecord *rec;
  char num[CRDT_NUMERICLEN];
  if (c->n >= OWN_SWEEP_MAX || !val->data ||
      val->data_len != sizeof(struct CrdtUserRecord))
    return;                                /* full, or foreign shape */
  rec = (const struct CrdtUserRecord *)val->data;
  if (rec->server != c->me)
    return;                                /* not my origin — its owner sweeps it */
  if (key_len == 0 || key_len >= sizeof num)
    return;
  memcpy(num, key, key_len);
  num[key_len] = '\0';
  if (findNUser(num))
    return;                                /* live client (incl. held) — healthy */
  memcpy(c->cand[c->n], num, key_len + 1);
  c->n++;
}

void crdt_shadow_own_user_sweep(void)
{
  static char pending[OWN_SWEEP_MAX][CRDT_NUMERICLEN];
  static int pending_n;
  static struct own_sweep_ctx c;
  struct Client *acptr;
  int i, j, reaped = 0;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_OWNER_SWEEP))
    return;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsServer(acptr) && IsBurstOrBurstAck(acptr))
      return;                              /* resync in flight — defer the pass
                                            * (pending survives, so no debounce reset) */
  c.me = (uint16_t)base64toint(cli_yxx(&me));
  c.n = 0;
  crdt_lwwmap_foreach(&g_crdt.users, own_sweep_collect_cb, &c);
  for (i = 0; i < c.n; i++) {
    for (j = 0; j < pending_n; j++)
      if (strcmp(c.cand[i], pending[j]) == 0)
        break;
    if (j >= pending_n)
      continue;                            /* first sighting — 2-pass debounce */
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT owner-sweep: reaping own-origin user record %s (no live client)",
              c.cand[i]);
    crdt_user_remove(&g_crdt, c.cand[i]);
    reaped++;
  }
  memcpy(pending, c.cand, sizeof pending);
  pending_n = c.n;
  if (reaped)
    crdt_sync_push();                      /* eager-propagate the tombstones */
}

/* Own-record RE-ASSERT (the recovery completion for the sweeps): a LIVE local
 * registered user whose doc record is absent-or-tombstoned is ALWAYS wrong — the
 * record was minted at registration and only I may legitimately remove it.  The
 * cases that create it: a wrongly-decommissioned-while-partitioned server heals
 * and merges the reap tombstones over its still-connected users; or any future
 * path that loses a record.  Re-mint via crdt_shadow_user_add (idempotent full-
 * record SET, fresh HLC -> beats any stale tombstone by LWW).  This upgrades the
 * verify count-detector ("shadow user missing") from log-only to self-healing
 * for the MyUser half; remote missing users stay log-only (their owner
 * re-asserts).  No debounce: the predicate is exact and the act idempotent —
 * a repeated re-assert fighting a repeated delete is a bug we WANT loud. */
/* 5-5f B2: publish OUR chathistory storage capability into the doc.
 *
 * Single-writer by construction — a server only ever describes itself, keyed
 * by its own numeric — so this needs no conflict handling beyond LWW.
 *
 * WRITE ONLY ON CHANGE.  The doc value is compared against the live feature
 * state first and a matching entry is left completely alone: an unconditional
 * re-mint every 30s tick would append an op per server per tick forever,
 * churning the oplog and (because each SET carries a fresh HLC) the digest
 * with it.  That makes this cheap enough to sit on the verify path and to be
 * called eagerly from the delta path (the F3 lesson: a collection that only
 * converges on the 30s tick races every live gate).
 *
 * Withdrawal is a real DELETE tombstone, never a local drop (inv. 5), so a
 * peer's snapshot cannot resurrect a capability we turned off. */
void crdt_shadow_ch_storage_publish(void)
{
  const struct CrdtChStorage *cur;
  char num[3];
  uint32_t stores, retention;

  if (!shadow_on() || !cli_yxx(&me)[0])
    return;
  num[0] = cli_yxx(&me)[0];
  num[1] = cli_yxx(&me)[1];
  num[2] = '\0';

  stores    = feature_bool(FEAT_CHATHISTORY_STORE) ? 1u : 0u;
  retention = (uint32_t)feature_int(FEAT_CHATHISTORY_RETENTION);
  cur       = crdt_chstore_get(&g_crdt, num);

  if (!stores) {
    if (cur) {                             /* storage turned off -> withdraw */
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT CH-storage: withdrawing capability for %s", num);
      crdt_chstore_remove(&g_crdt, num);
      crdt_sync_push();
    }
    return;
  }
  if (cur && cur->stores && cur->retention_days == retention)
    return;                                /* unchanged — no op, no churn */
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT CH-storage: publishing capability for %s (retention %u)",
            num, (unsigned)retention);
  crdt_chstore_set(&g_crdt, num, stores, retention);
  crdt_sync_push();
}

/* 5-5f B2 read side: does the DOC say server @a srvnum stores channel history?
 * Returns 1 and fills @a retention_out when so, else 0.  m_chathistory.c uses
 * this as a fallback behind the legacy CH A S table (which stays authoritative
 * for P10-linked peers), so the two sources never both write one struct. */
int crdt_shadow_ch_storage_lookup(const char *srvnum, unsigned int *retention_out)
{
  const struct CrdtChStorage *rec;
  if (!shadow_on() || !srvnum || !srvnum[0])
    return 0;
  rec = crdt_chstore_get(&g_crdt, srvnum);
  if (!rec || !rec->stores)
    return 0;
  if (retention_out)
    *retention_out = (unsigned int)rec->retention_days;
  return 1;
}

/* 5-5f B2 part 2: doc-side storage-server enumeration.  The federation
 * dispatch path needs the FULL set of storage servers, not a point lookup —
 * count_storage_servers() iterates the legacy server_ads[] table directly and
 * never consults has_chathistory_advertisement(), so the lookup fallback alone
 * left doc-only servers (overlay-only / anchored) invisible to the one
 * consumer that decides who gets queried.  This walks the doc's live entries
 * (crdt_lwwmap_foreach skips tombstones, which is correct here — enumeration
 * is CREATE-direction, inv. 11 concerns removal reconciles).  Keys are stored
 * unterminated (memdup of key_len); re-terminate into a local buf. */
struct ChStorageIterShim {
  crdt_ch_storage_iter_fn fn;
  void *ctx;
};

static void ch_storage_iter_shim(const char *key, uint32_t key_len,
                                 const struct CrdtLWWValue *val, void *ctx)
{
  struct ChStorageIterShim *shim = (struct ChStorageIterShim *)ctx;
  const struct CrdtChStorage *rec;
  char num[4];
  if (!val->data || val->data_len != sizeof(struct CrdtChStorage))
    return;
  rec = (const struct CrdtChStorage *)val->data;
  if (!rec->stores || key_len == 0 || key_len >= sizeof(num))
    return;
  memcpy(num, key, key_len);
  num[key_len] = '\0';
  shim->fn(num, (unsigned int)rec->retention_days, shim->ctx);
}

void crdt_shadow_ch_storage_foreach(crdt_ch_storage_iter_fn fn, void *ctx)
{
  struct ChStorageIterShim shim;
  if (!shadow_on() || !fn)
    return;
  shim.fn = fn;
  shim.ctx = ctx;
  crdt_lwwmap_foreach(&g_crdt.ch_storage, ch_storage_iter_shim, &shim);
}

/* 5-5f B4: legacy-ward capability synth.  Legacy dispatches CH Q only to
 * servers it holds CH A S ads for, and a mesh-only store can never deliver
 * one itself (CH A S rides EOB over a real P10 link).  The gateway therefore
 * advertises doc-known stores to its legacy CH-capable links ON THEIR BEHALF,
 * sourced from the store's own numeric so get_server_ad() on the receiver
 * keys the right slot.
 *
 * Reachability-gated (the scope-doc constraint: never advertise a store that
 * only ever answers empty): a store is synthesized only when it resolves
 * locally OR its CR H beacon is fresh — the same predicate the B2 collector
 * uses.  Skips ourselves (m_endburst sends our own ad) and CRDT-aware peers
 * (they read the doc).  A Client-less store (meshmap peer) is emitted via
 * sendrawto_one with the raw numeric prefix — the CR-M prefix-reconstruction
 * pattern; never a %C with a stub source (hard-invariant 2). */
struct ChStorageSynthCtx {
  struct Client *to;      /* NULL = all local legacy IRCv3-aware links */
  int changed_only;       /* 1 = only entries differing from last_synth[] */
};

static uint32_t ch_synth_last[CRDT_MAX_SERVERS]; /* retention+1; 0 = never */

static void ch_storage_synth_one(const char *srvnum, unsigned int retention,
                                 void *vctx)
{
  struct ChStorageSynthCtx *ctx = (struct ChStorageSynthCtx *)vctx;
  struct Client *store;
  struct DLink *lp;
  int idx = base64toint(srvnum);

  if (idx < 0 || idx >= CRDT_MAX_SERVERS)
    return;
  if (srvnum[0] == cli_yxx(&me)[0] && srvnum[1] == cli_yxx(&me)[1])
    return;                                   /* own ad rides m_endburst */
  if (ctx->changed_only && ch_synth_last[idx] == retention + 1)
    return;

  store = FindNServer(srvnum);
  if (!store && !crdt_shadow_server_beacon_fresh((uint16_t)idx))
    return;                                   /* unreachable — do not advertise */
  if (store == &me)
    return;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *peer = lp->value.cptr;
    if (ctx->to && peer != ctx->to)
      continue;
    if (IsCrdtAware(peer) || !IsIRCv3Aware(peer))
      continue;
    if (store)
      sendcmdto_one(store, CMD_CHATHISTORY, peer, "A S %u", retention);
    else
      sendrawto_one(peer, "%s %s A S %u", srvnum, TOK_CHATHISTORY, retention);
  }
  ch_synth_last[idx] = retention + 1;
}

void crdt_shadow_ch_storage_synth_to(struct Client *sptr)
{
  struct ChStorageSynthCtx ctx;
  if (!shadow_on())
    return;
  ctx.to = sptr;              /* new legacy link: full resend, ignore cache */
  ctx.changed_only = (sptr == NULL);
  crdt_shadow_ch_storage_foreach(ch_storage_synth_one, &ctx);
}

void crdt_shadow_own_user_reassert(void)
{
  struct Client *acptr;
  char num[CRDT_NUMERICLEN];
  int minted = 0;
  if (!shadow_on())
    return;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsServer(acptr) && IsBurstOrBurstAck(acptr))
      return;                              /* resync in flight — defer the pass */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyUser(acptr) || IsBouncerAlias(acptr) || !cli_user(acptr) ||
        !cli_yxx(acptr)[0])
      continue;
    user_numeric(acptr, num, sizeof num);
    if (crdt_user_get(&g_crdt, num))
      continue;                            /* record present — healthy */
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT own-user re-assert: re-minting record for live local %s (%s)",
              num, cli_name(acptr));
    crdt_shadow_user_add(acptr);           /* fresh SET; sync_push inside */
    minted++;
  }
  (void)minted;
}

/* DECOMMISSION standing sweep + auto-dissolve ("jupe without the jupe part").
 * An operator asserts a server is permanently gone (hardware death, provider
 * loss) via /CRDT decommission; the marker is a standing doc record, so nodes
 * that were partitioned/below-floor during the assertion still reap the residue
 * when they next see it (a one-shot reap would be undone by merge-keep snapshot
 * re-import — the resurrection lesson).  While the marker stands, every node
 * reaps user records (rec->server) and bouncer-conn records (rec->host) owned
 * by the decommissioned server; the reclaim family (members/silences/tempshuns/
 * member-meta) cascades from the user tombstones.  Sessions and LEASES are
 * deliberately NOT touched — the bouncer revive path owns those.
 *
 * NOT a link ban: if the server returns, the FIRST branch below dissolves the
 * marker (any node may mint the delete; LWW).  The skip-if-present guard runs
 * BEFORE any reap so a relink-vs-sweep race can never reap a returning server's
 * fresh records — and those carry later HLCs than any reap tombstone anyway
 * (test_decommission_reap_and_return).  A wrongly-decommissioned-but-alive
 * server heals itself on relink: marker dissolves + own_user_reassert re-mints
 * its records.  Gated with the owner sweep's kill-switch (same destructive-reap
 * family). */
#define DECOMM_MAX_SRV   8                 /* markers handled per pass */
struct decomm_reap_ctx {
  struct CrdtNetworkState *st;
  uint16_t srv[DECOMM_MAX_SRV];
  int      nsrv;
  /* user-record candidates */
  char unum[OWN_SWEEP_MAX][CRDT_NUMERICLEN];
  int  nu;
  /* bconn candidates (account\0sessid\0connnum key split) */
  char bacc[OWN_SWEEP_MAX][ACCOUNTLEN + 1];
  char bsid[OWN_SWEEP_MAX][64];
  char bnum[OWN_SWEEP_MAX][16];
  int  nb;
};

static int decomm_srv_match(const struct decomm_reap_ctx *c, uint16_t host)
{
  int i;
  for (i = 0; i < c->nsrv; i++)
    if (c->srv[i] == host)
      return 1;
  return 0;
}

static void decomm_collect_srv_cb(const char *key, uint32_t key_len,
                                  const struct CrdtLWWValue *val, void *ctx)
{
  struct decomm_reap_ctx *c = (struct decomm_reap_ctx *)ctx;
  char srvnum[3];
  unsigned int n;
  if (c->nsrv >= DECOMM_MAX_SRV || !val->data || key_len == 0 || key_len > 2)
    return;
  memcpy(srvnum, key, key_len);
  srvnum[key_len] = '\0';
  n = (unsigned int)base64toint(srvnum);
  if (n >= CRDT_MAX_SERVERS)
    return;
  c->srv[c->nsrv++] = (uint16_t)n;
}

static void decomm_collect_user_cb(const char *key, uint32_t key_len,
                                   const struct CrdtLWWValue *val, void *ctx)
{
  struct decomm_reap_ctx *c = (struct decomm_reap_ctx *)ctx;
  const struct CrdtUserRecord *rec;
  if (c->nu >= OWN_SWEEP_MAX || !val->data ||
      val->data_len != sizeof(struct CrdtUserRecord))
    return;
  rec = (const struct CrdtUserRecord *)val->data;
  if (!decomm_srv_match(c, rec->server))
    return;
  if (key_len == 0 || key_len >= sizeof c->unum[0])
    return;
  memcpy(c->unum[c->nu], key, key_len);
  c->unum[c->nu][key_len] = '\0';
  c->nu++;
}

static void decomm_collect_bconn_cb(const char *key, uint32_t key_len,
                                    const struct CrdtLWWValue *val, void *ctx)
{
  struct decomm_reap_ctx *c = (struct decomm_reap_ctx *)ctx;
  const struct CrdtBouncerConn *rec;
  const char *p1, *p2;
  uint32_t alen, slen, nlen;
  if (c->nb >= OWN_SWEEP_MAX || !val->data ||
      val->data_len != sizeof(struct CrdtBouncerConn))
    return;
  rec = (const struct CrdtBouncerConn *)val->data;
  if (!decomm_srv_match(c, rec->host))
    return;
  p1 = memchr(key, '\0', key_len); if (!p1) return;
  alen = (uint32_t)(p1 - key);
  p2 = memchr(p1 + 1, '\0', key_len - alen - 1); if (!p2) return;
  slen = (uint32_t)(p2 - (p1 + 1));
  nlen = key_len - alen - 1 - slen - 1;
  if (alen > ACCOUNTLEN || slen >= sizeof c->bsid[0] || nlen == 0 ||
      nlen >= sizeof c->bnum[0])
    return;
  memcpy(c->bacc[c->nb], key, alen);      c->bacc[c->nb][alen] = '\0';
  memcpy(c->bsid[c->nb], p1 + 1, slen);   c->bsid[c->nb][slen] = '\0';
  memcpy(c->bnum[c->nb], p2 + 1, nlen);   c->bnum[c->nb][nlen] = '\0';
  c->nb++;
}

void crdt_shadow_decomm_sweep(void)
{
  static struct decomm_reap_ctx c;
  struct Client *acptr;
  char srvnum[3];
  int i, minted = 0, bursting = 0;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_OWNER_SWEEP))
    return;
  if (crdt_lwwmap_size(&g_crdt.decommissions) == 0)
    return;                                /* overwhelming common case */
  c.st = &g_crdt;
  c.nsrv = 0;
  crdt_lwwmap_foreach(&g_crdt.decommissions, decomm_collect_srv_cb, &c);
  if (c.nsrv == 0)
    return;
  /* AUTO-DISSOLVE first (runs even mid-burst — removing a marker for a present
   * server is always right, and doing it before any reap closes the race). */
  for (i = 0; i < c.nsrv; i++) {
    struct Client *srv;
    inttobase64(srvnum, c.srv[i], 2);
    srvnum[2] = '\0';
    srv = FindNServer(srvnum);
    if ((srv && (IsServer(srv) || IsMeshStub(srv))) ||
        crdt_shadow_server_beacon_fresh(c.srv[i])) {
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT decommission: dissolving marker for %s (server returned)",
                srvnum);
      crdt_decomm_remove(&g_crdt, srvnum);
      c.srv[i] = 0xFFFF;                   /* out of every reap match below */
      minted++;
    }
  }
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsServer(acptr) && IsBurstOrBurstAck(acptr)) { bursting = 1; break; }
  if (!bursting) {
    c.nu = c.nb = 0;
    crdt_lwwmap_foreach(&g_crdt.users, decomm_collect_user_cb, &c);
    crdt_lwwmap_foreach(&g_crdt.bconns, decomm_collect_bconn_cb, &c);
    for (i = 0; i < c.nu; i++) {
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT decomm-sweep: reaping user record %s (decommissioned server)",
                c.unum[i]);
      crdt_user_remove(&g_crdt, c.unum[i]);
      minted++;
    }
    for (i = 0; i < c.nb; i++) {
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT decomm-sweep: reaping bconn %s/%s/%s (decommissioned server)",
                c.bacc[i], c.bsid[i], c.bnum[i]);
      crdt_bconn_del(&g_crdt, c.bacc[i], c.bsid[i], c.bnum[i]);
      minted++;
    }
  }
  if (minted)
    crdt_sync_push();
}

/* /CRDT decommission wrappers (m_crdtinfo.c cannot reach g_crdt directly).
 * Return: 0 = done; 1 = refused, server present; 2 = refused, beacon fresh;
 * 3 = no such marker (unmark). */
int crdt_shadow_decomm_mark(const char *srvnum, const char *oper,
                            const char *reason)
{
  struct Client *srv;
  unsigned int n;
  if (!shadow_on())
    return 1;
  srv = FindNServer(srvnum);
  if (srv && (IsServer(srv) || IsMeshStub(srv)))
    return 1;                              /* reachable — refuse */
  n = (unsigned int)base64toint(srvnum);
  if (n < CRDT_MAX_SERVERS && crdt_shadow_server_beacon_fresh((uint16_t)n))
    return 2;                              /* mesh-reachable — refuse */
  crdt_decomm_set(&g_crdt, srvnum, oper, reason);
  crdt_sync_push();
  return 0;
}

int crdt_shadow_decomm_unmark(const char *srvnum)
{
  if (!shadow_on() || !crdt_decomm_get(&g_crdt, srvnum))
    return 3;
  crdt_decomm_remove(&g_crdt, srvnum);
  crdt_sync_push();
  return 0;
}

const struct CrdtDecommission *crdt_shadow_decomm_query(const char *srvnum)
{
  return shadow_on() ? crdt_decomm_get(&g_crdt, srvnum) : NULL;
}

/* 5-5e M5: liveness-lease wrappers + the beacon-freshness liveness signal. */
const struct CrdtBouncerLease *crdt_shadow_blease_get(const char *account,
                                                      const char *sessid)
{
  if (!shadow_on())
    return NULL;
  return crdt_blease_get(&g_crdt, account, sessid);
}

void crdt_shadow_blease_claim(const char *account, const char *sessid, uint16_t host,
                              uint32_t generation, uint64_t claim_ms)
{
  if (!shadow_on())
    return;
  crdt_blease_claim(&g_crdt, account, sessid, host, generation, claim_ms);
  crdt_sync_push();
}

void crdt_shadow_blease_remove(const char *account, const char *sessid)
{
  if (!shadow_on())
    return;
  crdt_blease_del(&g_crdt, account, sessid);
  crdt_sync_push();
}

/* Locally-derived liveness (HARD-INVARIANT-10): a server is "live" to us iff its CR-H
 * self-beacon is FRESH (within the staleness window).  Our OWN numeric is always live.
 * This is the signal the revive gate uses to decide a split holder has gone away — never
 * a shared/replicated value. */
int crdt_shadow_server_beacon_fresh(uint16_t num)
{
  if (num == (uint16_t)base64toint(cli_yxx(&me)))
    return 1;
  if (num >= CRDT_MAX_SERVERS)
    return 0;
  return crdt_beacon[num].recv_ts != 0 &&
         (CurrentTime - crdt_beacon[num].recv_ts) <= CRDT_BEACON_STALE;
}

/* 5-5e M6a (doc-native bouncer cutover): doc->live reconcile of bouncer SESSION records.
 * For each bsessions doc entry whose authoritative lease holder != us and for which we
 * have no local session, materialize a REPLICA (bounce_create_replica_from_doc). This is
 * the rebuild-from-doc that becomes load-bearing once M6b suppresses BS/BX relay among
 * CRDT peers; while relay still flows it is INERT (bounce_find_by_token hits -> 0 creates
 * at rest = the shadow-of-the-shadow proof). Gated FEAT_CRDT_BOUNCER_DOC (rolled
 * node-by-node) + FEAT_CRDT_PRIMARY. M6a-2 will materialize the alias roster (bconns);
 * this step does sessions only. */
/* NB (M6a-2): no re-entrancy guard is needed here.  Driving bounce_alias_create from the
 * reconcile triggers no doc re-mint because every minting hook it could reach self-skips an
 * alias: crdt_shadow_join returns on CHFL_ALIAS (:476), crdt_shadow_user_add returns on
 * IsBouncerAlias (:570), and the bconn sweep only mints entries whose ba_server==me (a
 * materialized remote alias has ba_server=its host != me).  So the materialize is mint-free. */

static int crdt_gateway_has_legacy_peer(void);  /* defined below; used by the M6c-1 hooks */

/* M6c-1 (gateway doc->legacy BS/BX synthesis), Increment 0 helper: build the
 * channel string for a doc session from its MATERIALIZED primary client's LIVE
 * memberships — NOT the replica's hs_channels[] (which is empty; that is also the
 * latent bounce_burst replica defect).  Returns the client, or NULL if it is not
 * materialized yet (reconcile orders users before bouncer, so the first cycle may
 * be PENDING — inv#8: caller MUST tolerate NULL, never deref).  Mirrors the proven
 * bounce_materialize_alias_from_doc channel-build (walk cli_user(primary)->channel). */
static struct Client *crdt_m6c1_session_chans(const char *account, const char *sessid,
                                              char *out, size_t outlen)
{
  char pnum[16];
  struct Client *uc;
  struct Membership *lp;
  size_t off = 0;
  out[0] = '\0';
  if (!crdt_bconn_primary(&g_crdt, account, sessid, pnum, sizeof pnum))
    return NULL;
  uc = findNUser(pnum);
  if (!uc || !IsUser(uc) || !cli_user(uc))
    return NULL;                          /* not materialized yet (inv#8: no deref) */
  for (lp = cli_user(uc)->channel; lp; lp = lp->next_channel) {
    const char *cn = lp->channel->chname;
    size_t need = strlen(cn) + 1;
    if (off + need >= outlen)
      break;
    if (off)
      out[off++] = ' ';
    memcpy(out + off, cn, strlen(cn));
    off += strlen(cn);
    out[off] = '\0';
  }
  return uc;
}

/* M6c-1 Increment 1: synthesize BS C toward legacy for a doc-origin replica the
 * gateway just materialized — the originating CRDT leaf's BS C died (no legacy
 * downlink), so the gateway re-originates it (the §17.7 gateway applied to BS).
 * skip_crdt = legacy leg only (CRDT peers already have the doc). Source &me
 * (server-sourced, matches bounce_broadcast/bounce_burst; .2 routes it). Format
 * mirrors bounce_broadcast case 'C' (active) and the bounce_handle BS C holding
 * re-relay EXACTLY. Channels come from live memberships (chans), never the
 * replica's empty hs_channels[]. Gated by the caller on crdt_gateway_has_legacy_peer. */
static void crdt_m6c1_synth_bs_c(const char *account, const char *sessid,
                                 const struct CrdtBouncerSession *rec,
                                 const struct BouncerSession *sess,
                                 const char *chans)
{
  sendcmdto_set_skip_crdt_servers();
  if (rec->state == BOUNCE_HOLDING)
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION, NULL,
                          "C %s %s %s holding %Tu %Tu %u %Tu :%s",
                          account, sessid, rec->token, (time_t)rec->created,
                          sess->hs_disconnect_time, (unsigned)rec->attach_count,
                          (time_t)rec->total_active, chans);
  else
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION, NULL,
                          "C %s %s %s active %Tu %u %Tu :%s",
                          account, sessid, rec->token, (time_t)rec->created,
                          (unsigned)rec->attach_count, (time_t)rec->total_active, chans);
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT M6c-1: synth BS C -> legacy acct=%s sid=%s state=%s chans=[%s]",
            account, sessid, rec->state == BOUNCE_HOLDING ? "holding" : "active", chans);
}

/* M6c-1 Increment 2: synthesize BS A (HOLDING->ACTIVE) / BS D (ACTIVE->HOLDING)
 * toward legacy for a doc state transition on a replica.  SOURCE = the owning leaf
 * stub (cli_user(uc)->server), NOT &me — the A/D conn/ghost field is a 3-char XXX
 * the receiver prefixes with the SOURCE server's YY; sourcing from the leaf stub
 * (present-stub on .2) makes .2 resolve the full numeric to the right user, never a
 * wrong-server hijack (inv#3).  skip_crdt = legacy leg only.  Format mirrors
 * bounce_broadcast cases 'A'/'D' exactly.  uc must be the live materialized client
 * (caller guarantees cli_user(uc) via crdt_m6c1_session_chans); inv#8: re-guard. */
static void crdt_m6c1_synth_bs_ad(const char *account, const char *sessid,
                                  const struct CrdtBouncerSession *rec,
                                  const struct BouncerSession *sess,
                                  struct Client *uc, const char *chans)
{
  struct Client *srv;
  if (!uc || !cli_user(uc))
    return;
  srv = cli_user(uc)->server;
  if (!srv)
    return;
  sendcmdto_set_skip_crdt_servers();
  if (rec->state == BOUNCE_HOLDING)
    sendcmdto_serv_butone_v3(srv, CMD_BOUNCER_SESSION, NULL,
                          "D %s %s %s %Tu :%s",
                          account, sessid, cli_yxx(uc),
                          sess->hs_disconnect_time, chans);
  else
    sendcmdto_serv_butone_v3(srv, CMD_BOUNCER_SESSION, NULL,
                          "A %s %s %s %lu %x",
                          account, sessid, cli_yxx(uc),
                          (unsigned long)sess->hs_last_active, 0u);
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT M6c-1: synth BS %s -> legacy acct=%s sid=%s src=%s chans=[%s]",
            rec->state == BOUNCE_HOLDING ? "D" : "A", account, sessid,
            cli_name(srv), chans);
}

/* M6b-2 BS O (Inc-B): synthesize the session oper grant set/clear toward legacy
 * from the doc.  SOURCE = &me (unlike BS A/D): BS O is account/sessid-keyed —
 * the receiver resolves the session via bounce_find_by_token_sessid and never a
 * source-prefixed numeric — so inv#3 does NOT apply.  skip_crdt = legacy leg
 * only.  Format mirrors bounce_broadcast case 'O' exactly.  Gated by the caller
 * on crdt_gateway_has_legacy_peer; on first materialize the caller MUST emit BS
 * C before BS O (the receiver drops O if the session does not exist yet). */
static void crdt_m6c1_synth_bs_o(const char *account, const char *sessid,
                                 const struct CrdtBouncerSession *rec)
{
  sendcmdto_set_skip_crdt_servers();
  if (rec->oper_name[0])
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION, NULL,
                          "O %s %s %Tu %s",
                          account, sessid, (time_t)rec->oper_granted_at,
                          rec->oper_name);
  else
    sendcmdto_serv_butone_v3(&me, CMD_BOUNCER_SESSION, NULL,
                          "O %s %s", account, sessid);
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT M6b-2: synth BS O -> legacy acct=%s sid=%s grant=%s",
            account, sessid, rec->oper_name[0] ? rec->oper_name : "(cleared)");
}

struct reconcile_bsess_ctx { unsigned created; unsigned state_applied; };
static void reconcile_bsess_cb(const char *key, uint32_t key_len,
                               const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_bsess_ctx *c = ctx;
  const struct CrdtBouncerSession *rec;
  const struct CrdtBouncerLease *lease;
  const char *p;
  uint32_t alen, slen;
  char account[ACCOUNTLEN + 1], sessid[64], origin[4];
  uint16_t myn;
  if (!val->data || val->data_len != sizeof(struct CrdtBouncerSession))
    return;                                   /* tombstone / wrong size */
  rec = (const struct CrdtBouncerSession *)val->data;
  p = memchr(key, '\0', key_len);             /* key = account\0sessid */
  if (!p)
    return;
  alen = (uint32_t)(p - key);
  slen = key_len - alen - 1;
  if (alen > ACCOUNTLEN || slen == 0 || slen >= sizeof sessid)
    return;
  memcpy(account, key, alen);  account[alen] = '\0';
  memcpy(sessid, p + 1, slen); sessid[slen] = '\0';
  {
    struct BouncerSession *existing = bounce_find_by_token(rec->token);
    if (existing) {
      /* M6b-1b (HOLDING doc-coverage): the BS A/D equivalent on the doc path.
       * reconcile_bsess was CREATE-only; once BS A/D relay is suppressed among
       * CRDT peers, a replica materialized ACTIVE would never flip to HOLDING
       * (or back) -> silent stale state.  So flip an existing REPLICA's
       * HOLDING<->ACTIVE from the converged doc record here.  INERT at rest:
       * with relay still flowing the BS A/D handler already flipped the replica
       * before this runs, so state_applied stays ~0 (the shadow-of-the-shadow
       * proof); it becomes load-bearing only once M6b-1b suppresses A/D.
       * Single-writer: NEVER touch the authoritative local holder (a MyConnect
       * hs_client) — its sweep owns the doc write.  inv#1: NEVER start a hold
       * timer on a replica.  inv#8: hs_client may be NULL — do not deref it. */
      if (existing->hs_client && MyConnect(existing->hs_client))
        return;                                 /* local holder = single-writer */
      if (rec->state != BOUNCE_HOLDING && rec->state != BOUNCE_ACTIVE)
        return;                                 /* destroy rides the X tombstone, not here */
      /* M6b-2 BS O: converge the oper grant onto an already-materialized
       * REPLICA from the doc (a grant set/cleared after this replica
       * materialized).  Past the single-writer gate above => never the
       * authoritative local holder, so this writes only local replica state
       * (the sweep's MyConnect gate means it never re-writes the doc).
       * Populate only; +o on a live local promote is applied later by
       * bounce_apply_oper_grant from this name.  inv: NO O:line revalidation
       * here (persist-across-move; revalidation is restart-only). */
      if (0 != strncmp(existing->hs_oper_name, rec->oper_name,
                       sizeof existing->hs_oper_name)
          || existing->hs_oper_granted_at != (time_t)rec->oper_granted_at) {
        ircd_strncpy(existing->hs_oper_name, rec->oper_name,
                     sizeof existing->hs_oper_name);
        existing->hs_oper_granted_at = (time_t)rec->oper_granted_at;
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT bsess M6b-2: replica acct=%s sid=%s oper grant -> %s "
                  "(doc-apply)", account, sessid,
                  rec->oper_name[0] ? rec->oper_name : "(cleared)");
        /* M6b-2 Inc-B: the gateway re-originates the grant set/clear toward
         * legacy (the leaf's BS O is now suppressed among CRDT peers).  The
         * session already exists on the legacy peer (BS C synth'd at create),
         * so BS O alone suffices here.  Fires once per actual change (the
         * strncmp/granted_at guard above), so no repeat-storm. */
        if (crdt_gateway_has_legacy_peer())
          crdt_m6c1_synth_bs_o(account, sessid, rec);
      }
      if ((int)existing->hs_state != (int)rec->state) {
        if (rec->state == BOUNCE_HOLDING) {
          existing->hs_state = BOUNCE_HOLDING;
          existing->hs_enforced = 0;
          if (existing->hs_disconnect_time == 0)
            existing->hs_disconnect_time = CurrentTime;  /* approx; host owns the real timer */
        } else {
          existing->hs_state = BOUNCE_ACTIVE;
          existing->hs_disconnect_time = 0;
        }
        c->state_applied++;
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT bsess M6b-1b: replica acct=%s sid=%s state -> %s (doc-apply)",
                  account, sessid,
                  rec->state == BOUNCE_HOLDING ? "HOLDING" : "ACTIVE");
        /* M6c-1 Increment 2: the gateway re-originates BS A (HOLDING->ACTIVE) /
         * BS D (ACTIVE->HOLDING) toward legacy on a doc transition (the leaf's
         * BS A/D was suppressed + the leaf has no legacy downlink).  If the user
         * isn't materialized here yet, defer+log rather than emit a bad numeric. */
        if (crdt_gateway_has_legacy_peer()) {
          char chans[512];
          struct Client *uc = crdt_m6c1_session_chans(account, sessid, chans, sizeof chans);
          if (uc)
            crdt_m6c1_synth_bs_ad(account, sessid, rec, existing, uc, chans);
          else
            log_write(LS_SYSTEM, L_NOTICE, 0,
                      "CRDT M6c-1: BS %s synth deferred (user not materialized) "
                      "acct=%s sid=%s",
                      rec->state == BOUNCE_HOLDING ? "D" : "A", account, sessid);
        }
      }
      return;                                   /* already materialized; state reconciled above */
    }
  }
  lease = crdt_blease_get(&g_crdt, account, sessid);
  if (!lease)
    return;                                   /* no authoritative holder claimed yet */
  myn = (uint16_t)base64toint(cli_yxx(&me));
  if (lease->host == myn)
    return;                                   /* I am the holder but have no local session — anomaly; skip */
  inttobase64(origin, lease->host, 2);
  origin[2] = '\0';
  {
    struct BouncerSession *newsess =
      bounce_create_replica_from_doc(account, sessid, rec->token, origin,
                                     (time_t)rec->created, (time_t)rec->last_active,
                                     (time_t)rec->total_active, rec->attach_count,
                                     (int)rec->state);
    if (newsess) {
      c->created++;
      /* M6b-2 BS O: carry the doc oper grant onto the freshly-materialized
       * replica session.  POPULATE ONLY — do not apply +o here: this user is
       * remote (!MyConnect on this node), so live +o state arrives via normal
       * P10 umode propagation; the stored name is what a FUTURE local
       * promote/revive (bounce_apply_oper_grant) needs to re-oper.  Persist-
       * across-move: NO local-O:line revalidation on the materialize path
       * (that is restart-only, in bounce_create_ghost). */
      ircd_strncpy(newsess->hs_oper_name, rec->oper_name,
                   sizeof newsess->hs_oper_name);
      newsess->hs_oper_granted_at = (time_t)rec->oper_granted_at;
      /* M6c-1 Increment 1: the gateway re-originates BS C toward legacy (the
       * leaf's BS C died — no legacy downlink).  Channels from live memberships.
       * If the materializing user isn't live here yet (PENDING), defer one cycle
       * rather than emit empty channels (the state-apply / next create pass will
       * carry it). */
      if (crdt_gateway_has_legacy_peer()) {
        char chans[512];
        struct Client *uc = crdt_m6c1_session_chans(account, sessid, chans, sizeof chans);
        if (uc) {
          crdt_m6c1_synth_bs_c(account, sessid, rec, newsess, chans);
          /* M6b-2 Inc-B: C-before-O — emit the oper grant right after BS C so
           * the just-created legacy session records it (the receiver drops a
           * BS O whose session does not exist yet). */
          if (rec->oper_name[0])
            crdt_m6c1_synth_bs_o(account, sessid, rec);
        } else
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT M6c-1: BS C synth deferred (user not materialized) "
                    "acct=%s sid=%s", account, sessid);
      }
    }
  }
}

/* M6a-2: materialize remote aliases (bconns host != me, is_primary=0) by driving the real
 * BX-C path. Idempotent — at rest (relay flowing) every alias is already linked so this is
 * a pure no-op (the inert proof); it becomes load-bearing only once M6b suppresses relay. */
/* Parse a bconns doc key (account\0sessid\0connnum) into its three parts.
 * Returns 1 on success.  Used by reconcile_bconn_cb for both the live and
 * the tombstone branches (Item1 BX). */
static int crdt_parse_bconn_key(const char *key, uint32_t key_len,
                                char *account, size_t acclen,
                                char *sessid, size_t sesslen,
                                char *connnum, size_t connlen)
{
  const char *p1, *p2;
  uint32_t alen, slen, nlen;
  p1 = memchr(key, '\0', key_len);
  if (!p1) return 0;
  alen = (uint32_t)(p1 - key);
  p2 = memchr(p1 + 1, '\0', key_len - alen - 1);
  if (!p2) return 0;
  slen = (uint32_t)(p2 - (p1 + 1));
  nlen = (uint32_t)(key_len - alen - 1 - slen - 1);
  if (alen >= acclen || slen == 0 || slen >= sesslen ||
      nlen == 0 || nlen >= connlen)
    return 0;
  memcpy(account, key, alen);    account[alen] = '\0';
  memcpy(sessid, p1 + 1, slen);  sessid[slen] = '\0';
  memcpy(connnum, p2 + 1, nlen); connnum[nlen] = '\0';
  return 1;
}

struct reconcile_bconn_ctx { unsigned created; };
static void reconcile_bconn_cb(const char *key, uint32_t key_len,
                               const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_bconn_ctx *c = ctx;
  const struct CrdtBouncerConn *rec;
  char account[ACCOUNTLEN + 1], sessid[64], aliasn[16], primary[16];
  uint16_t myn;
  if (!val->data || val->data_len != sizeof(struct CrdtBouncerConn))
    return;                                   /* tombstone — NOTE: crdt_lwwmap_foreach
                                               * SKIPS deleted entries, so this branch is
                                               * never reached for a tombstone.  Alias
                                               * de-materialization rides bounce_crdt_alias_reap
                                               * (a live-walk + crdt_shadow_bconn_present check,
                                               * mirror of the replica-session reap), NOT here. */
  rec = (const struct CrdtBouncerConn *)val->data;
  if (rec->is_primary)
    return;                                   /* primary = a real user (reconcile_users), not an alias */
  myn = (uint16_t)base64toint(cli_yxx(&me));
  if (rec->host == myn)
    return;                                   /* real local fd alias — never materialize our own */
  if (!crdt_parse_bconn_key(key, key_len, account, sizeof account,
                            sessid, sizeof sessid, aliasn, sizeof aliasn))
    return;
  if (!crdt_bconn_primary(&g_crdt, account, sessid, primary, sizeof primary))
    return;                                   /* no primary in doc yet — retry next cycle */
  if (bounce_materialize_alias_from_doc(account, sessid, primary, aliasn)) {
    c->created++;
    /* Item1 BX Inc-0: confirm the gateway materialize fires + has a legacy
     * peer (bounce_materialize_alias_from_doc -> bounce_alias_create's forward
     * already delivers BX C to legacy today, ungated — Inc-1 makes it
     * skip_crdt so it's the clean legacy-only synth). */
    if (crdt_gateway_has_legacy_peer())
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT M6c-1 BX Inc0: materialized alias %s from doc (acct=%s "
                "sid=%s) — alias_create forward delivers BX C to legacy",
                aliasn, account, sessid);
  }
}

void crdt_shadow_reconcile_bouncer(void)
{
  struct reconcile_bsess_ctx cs = { 0 };
  struct reconcile_bconn_ctx ca = { 0 };
  if (!shadow_on() || !feature_bool(FEAT_CRDT_BOUNCER_DOC) ||
      !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  /* sessions first (the replica record must exist before its aliases attach), then
   * aliases (their primary user must already be materialized by reconcile_users, which
   * runs before this in the verify timer). */
  crdt_lwwmap_foreach(&g_crdt.bsessions, reconcile_bsess_cb, &cs);
  crdt_lwwmap_foreach(&g_crdt.bconns, reconcile_bconn_cb, &ca);
  if (cs.created || ca.created || cs.state_applied)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT bouncer-reconcile: created %u replica session(s) + %u alias(es), "
              "%u state-apply (M6b-1b) from doc",
              cs.created, ca.created, cs.state_applied);
  /* M6a-3: removal half — tear down replica sessions whose owner tombstoned
   * their doc record (the teardown counterpart that makes BS X suppression
   * correct).  Lives in bouncer_session.c (owns the session hashes). */
  bounce_crdt_replica_reap();
  /* M6c-1 BX Inc-2 (fix): the ALIAS removal half — tear down replica ALIASES whose
   * owner tombstoned their bconn (live-walk + crdt_shadow_bconn_present check, mirror
   * of replica_reap).  This is the WORKING de-materialize path — the earlier
   * reconcile_bconn_cb tombstone-branch approach was dead code (crdt_lwwmap_foreach
   * skips deleted entries).  On the gateway it synthesizes BX X to legacy. */
  bounce_crdt_alias_reap();
}

/* Phase 4c: server reachability is a LOCAL determination, NOT replicated state.
 *
 * Phase 4a tried to replicate per-server ACTIVE/SPLIT in the convergent doc (a
 * servers LWW map, single observer-writer per entry, SQUIT-as-SPLIT §17.3).  Live
 * MESH testing (triangle: P10 star nef3-nef4,nef3-nef5 + CR overlay nef4<->nef5)
 * proved it does NOT converge: reachability is inherently PER-VIEWPOINT — during a
 * partition nef3 truthfully sees nef5 unreachable while nef5 sees nef3 unreachable,
 * so the shared LWW map has genuinely conflicting writers; and the racing
 * SPLIT/ACTIVE ops get GC'd before the self-ACTIVE heal propagates across the
 * redundant edge, leaving a node whose links never dropped permanently stale (it
 * gets no refreshing snapshot).  The engine LWW itself converges fine
 * (test_server_state_converges_mesh) — the gap is the live wire layer, and no
 * amount of patching makes a per-viewpoint value robust as shared state.
 *
 * So SPLIT is derived LOCALLY: a remote server's users are materialized iff that
 * server is reachable via a live CRDT transport from HERE — which the
 * FindNServer + IsServer guard in crdt_materialize_one_user already enforces (P10
 * routability).  That IS the plan's crdt_transport_reachable intent (SPLIT iff
 * unreachable via ALL transports), realized as a local check rather than a
 * replicated map.  No observer writes another server's state and we no longer
 * write our own, so the servers map stays empty in production and the doc digest
 * (data: users/channels/topics) converges across the mesh.
 *
 * The engine servers-map + crdt_server_* / crdt_user_visible are retained (tested,
 * unused in production) for a future Tier-2 design where overlay-reachability is
 * the routing input and a convergent liveness model (e.g. single-writer-per-key
 * heartbeat with locally-derived staleness) can be built deliberately. */
void crdt_shadow_server_add(struct Client *srv)
{
  (void)srv;   /* reachability is local now (FindNServer); nothing to replicate */
}

/* Tier 2 (T2-a/c): on a CRDT-server SQUIT, keep a tree-departed but mesh-reachable
 * server's users ALIVE as a "mesh stub" instead of tearing them down.  Split into a
 * GATE (crdt_shadow_mesh_reachable) and a CONVERSION (crdt_shadow_convert_to_stub),
 * orchestrated from exit_client (which owns exit_downlinks/exit_one_client): for a
 * NON-leaf departed server (T2-c) exit_client tears down its tree-downlinks first,
 * then converts the now-leaf server.  Keeping the departed server addressable here
 * is what enables deliver-FROM (a local user messaging one of its users hits the
 * T2-b send-hooks).  close_connection has already run (cli_fd==-1, FLAG_DEADSOCKET,
 * cli_connect valid, MyConnect still true).
 *
 * The conversion is near-empty because remote users SHARE their introducing
 * server's Connection (list.c:248): cli_from(user) and cli_user(user)->server
 * already point at srv, so once srv is a dead-sink stub (cli_fd==-1) every user
 * auto-routes through it and can_send() drops the send (presence-only).  We only
 * flip its status to STAT_MESH_SERVER; the tree DLink (cli_serv->updown) is left in
 * place (STAT_MESH_SERVER is excluded from every IsServer-gated tree/burst/LINKS
 * walk, and keeping updown lets crdt_shadow_retire_mesh_stub() reuse
 * exit_one_client()'s server teardown, whose remove_dlink asserts lp!=NULL). */
int crdt_shadow_mesh_reachable(struct Client *srv)
{
  struct Client *acptr;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return 0;
  if (!srv || !IsServer(srv) || !IsCrdtAware(srv) || !cli_serv(srv))
    return 0;
  /* DIRECT peers only.  The stub model is valid solely for a server we were
   * directly linked to: close_connection ran (cli_fd==-1 dead-sink) and its remote
   * users share ITS Connection (list.c:248), so cli_from(user)==srv routes them to
   * the dead sink.  A RELAYED departed server (reached via another link, MyConnect
   * false) has neither property — its users route via the relay link, and
   * materializing a NEW split-born user onto such a "stub" crashed nef4.  Relayed
   * views tear down normally; the mesh still relays the gossip (CR M) and carries
   * the doc via the overlay, so delivery is unaffected. */
  if (!MyConnect(srv))
    return 0;
  /* Tier-2 S3: PRECISE keep-gate = is THIS server's own beacon fresh (S1 proved the
   * beacon set is the presence oracle), vs the legacy COARSE heuristic "is there ANY
   * live CRDT transport other than the dying link." Compute both; log a divergence;
   * return the gated choice (FEAT_CRDT_MESHMAP_PRESENCE default off => coarse =>
   * inert). The staleness sweep + relink retire remain the backstops either way; the
   * beacon verdict only fails SAFE relative to coarse (tears down an already-mesh-
   * stale server now instead of after the 90s sweep — no ghost, doc re-materializes
   * if still reachable). */
  {
    unsigned int n = (unsigned int)base64toint(cli_yxx(srv));
    int beacon_ok = (n < CRDT_MAX_SERVERS && crdt_beacon[n].recv_ts &&
                     (CurrentTime - crdt_beacon[n].recv_ts) <= CRDT_BEACON_STALE);
    int coarse_ok = 0;
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
      if (acptr != srv && IsCrdtSyncTarget(acptr)) { coarse_ok = 1; break; }
    if (beacon_ok != coarse_ok)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT keep-gate %s: coarse=%d beacon=%d (S3 %s)", cli_name(srv),
                coarse_ok, beacon_ok,
                feature_bool(FEAT_CRDT_MESHMAP_PRESENCE) ? "beacon" : "coarse/shadow");
    return feature_bool(FEAT_CRDT_MESHMAP_PRESENCE) ? beacon_ok : coarse_ok;
  }
}

/* S4/R7a (SQUIT-only): gate (+ shadow-measure) the P10 SQUIT for `subject` toward
 * the directly-linked peer `peer`.  Among CRDT-aware-both-ends peers a departure
 * rides the CR H beacon set instead — the beacon goes stale and the keep-gate
 * (crdt_shadow_mesh_reachable) + the staleness sweep retire the server, so the
 * up-front SQUIT is redundant.
 *
 * R7b (SERVER-intro retirement) was attempted and REVERTED: P10 is a flat server
 * namespace with hierarchical delivery, so a relayed SERVER carries a source-prefix
 * that every downstream server must already know.  Suppressing a CRDT server's own
 * SERVER intro orphans everything sourced through it — notably legacy servers
 * relayed INTO the mesh (e.g. x3.services behind hub2): a leaf with no direct P10
 * link to the suppressed introducer drops the ':introducer SERVER <legacy>' line and
 * can never materialize that server's users (legacy servers don't beacon, so the
 * anchor fallback can't fire either).  Retiring SERVER needs mesh-native routing
 * (flat presentation), not prefix-hiding — out of scope here.  Hence SQUIT only.
 *
 * Both-ends rule: a departure rides the beacon only when BOTH the receiver and the
 * subject are CRDT-aware servers (a legacy subject has no beacon; a legacy peer
 * never learns the beacon).  Flag-gated on FEAT_CRDT_MESHMAP_PRESENCE (shared with
 * the S3 keep-gate) so default-off is inert.  While the flag is OFF but the both-
 * ends candidate holds, emit one shadow line reporting the beacon presence/age and
 * time-to-stale (the worst-case post-cutover detection gap).  `kind` is "SQUIT".
 *
 * Returns nonzero IFF the caller should SKIP the P10 SQUIT emit. */
int crdt_tree_presence_suppress(struct Client *peer, struct Client *subject,
                                const char *kind)
{
  int peer_aware, subj_aware, primary, suppress;
  if (!shadow_on())
    return 0;
  peer_aware = peer && IsServer(peer) && IsCrdtAware(peer);
  subj_aware = subject && IsServer(subject) && IsCrdtAware(subject);
  primary    = feature_bool(FEAT_CRDT_PRIMARY);
  suppress   = crdt_should_suppress_tree(feature_bool(FEAT_CRDT_MESHMAP_PRESENCE),
                                         primary, peer_aware, subj_aware);
  /* Shadow: flag still off but the candidate holds -> measure the beacon path. */
  if (!suppress && crdt_should_suppress_tree(1, primary, peer_aware, subj_aware)) {
    unsigned int n = (unsigned int)base64toint(cli_yxx(subject));
    time_t recv = (n < CRDT_MAX_SERVERS) ? crdt_beacon[n].recv_ts : 0;
    long age      = recv ? (long)(CurrentTime - recv) : -1;
    long stale_in = recv ? (long)(CRDT_BEACON_STALE - (CurrentTime - recv)) : -1;
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "R7-shadow %s subject=%s yxx=%s -> peer=%s : would-suppress; "
              "beacon present=%d age=%lds stale_in=%lds",
              kind ? kind : "?", cli_name(subject), cli_yxx(subject),
              cli_name(peer), recv ? 1 : 0, age, stale_in);
  }
  return suppress;
}

/* MR-3c: gate the P10 SERVER intro for a LEGACY @a subject toward a directly-linked
 * CRDT-aware @a peer.  When FEAT_CRDT_LEGACY_PRESENCE is on, the CRDT peer learns the
 * legacy server via the gateway's proxy-beacon + Case-B anchor (MR-3a), so its SERVER
 * intro is redundant — and relaying it would defeat the cutover.  Inverted subject-
 * awareness vs crdt_tree_presence_suppress: a LEGACY subject (no beacon of its own —
 * the gateway proxy-beacons it) toward a CRDT peer.  NEVER suppresses a CRDT subject
 * (the R7b-infeasible case) or toward a legacy peer (it needs the P10 tree).  Returns
 * nonzero IFF the caller should SKIP the SERVER emit.  No-op unless FEAT_CRDT_LEGACY_
 * PRESENCE + FEAT_CRDT_PRIMARY. */
int crdt_intro_presence_suppress(struct Client *peer, struct Client *subject)
{
  int peer_aware, subj_aware;
  if (!shadow_on())
    return 0;
  peer_aware = peer && IsServer(peer) && IsCrdtAware(peer);
  subj_aware = subject && IsServer(subject) && IsCrdtAware(subject);
  return crdt_should_suppress_intro(feature_bool(FEAT_CRDT_LEGACY_PRESENCE),
                                    feature_bool(FEAT_CRDT_PRIMARY),
                                    peer_aware, subj_aware);
}

/* MR-5: suppress a CRDT @a subject's own SERVER intro toward a CRDT-aware @a peer (the
 * SERVER half of tree-retirement; the SQUIT half is crdt_tree_presence_suppress).  The
 * peer learns the CRDT server via ITS OWN self-liveness beacon + Case-B anchor (exactly
 * how MR-3 does it for legacy servers — the difference from the R7b-infeasible era, when
 * the orphaned subject didn't beacon).  Reuses the same both-ends pure gate
 * crdt_should_suppress_tree, but on a SEPARATE flag FEAT_CRDT_TREE_RETIRE so the SERVER
 * cutover is independently flippable from the already-live R7a SQUIT suppression
 * (FEAT_CRDT_MESHMAP_PRESENCE) — a controlled rollout for the riskiest phase.  Returns
 * nonzero IFF the caller should SKIP the SERVER emit.  While the flag is off it
 * shadow-logs the would-suppress candidates + their beacon freshness (MR-5-0 measure-
 * first), so a green board (every candidate has a fresh beacon) gates flipping it on. */
int crdt_server_intro_suppress(struct Client *peer, struct Client *subject)
{
  int peer_aware, subj_aware, primary, suppress;
  if (!shadow_on())
    return 0;
  peer_aware = peer && IsServer(peer) && IsCrdtAware(peer);
  subj_aware = subject && IsServer(subject) && IsCrdtAware(subject);
  primary    = feature_bool(FEAT_CRDT_PRIMARY);
  suppress   = crdt_should_suppress_tree(feature_bool(FEAT_CRDT_TREE_RETIRE),
                                         primary, peer_aware, subj_aware);
  /* MR-5-0 shadow: SERVER-retire flag off but the both-ends candidate holds -> measure
   * the subject's self-beacon path (the anchor fallback that replaces the SERVER intro). */
  if (!suppress && crdt_should_suppress_tree(1, primary, peer_aware, subj_aware)) {
    unsigned int n = (unsigned int)base64toint(cli_yxx(subject));
    time_t recv = (n < CRDT_MAX_SERVERS) ? crdt_beacon[n].recv_ts : 0;
    long age      = recv ? (long)(CurrentTime - recv) : -1;
    long stale_in = recv ? (long)(CRDT_BEACON_STALE - (CurrentTime - recv)) : -1;
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "MR-5-shadow SERVER subject=%s yxx=%s -> peer=%s : would-suppress; "
              "beacon present=%d age=%lds stale_in=%lds",
              cli_name(subject), cli_yxx(subject), cli_name(peer),
              recv ? 1 : 0, age, stale_in);
  }
  return suppress;
}

/* R6c: does this node have a directly-linked LEGACY (non-CRDT) P10 peer to present to? */
static int crdt_gateway_has_legacy_peer(void)
{
  struct DLink *lp;
  for (lp = cli_serv(&me)->down; lp; lp = lp->next)
    if (IsServer(lp->value.cptr) && !IsCrdtAware(lp->value.cptr))
      return 1;
  return 0;
}

/* R6c: PRESENT a mesh-stub @a srv to legacy as a P10 subtree behind this gateway, so legacy
 * can place its users and receive their channel traffic FAITHFULLY (real source).  Idempotent
 * (FLAG_CRDT_PRESENTED); a no-op when this node has no legacy peer (a pure-CRDT leaf).  Marks
 * the stub PRESENTED — crdt_user_is_mesh_only then returns false for its users, so the §17.7
 * reconcile/bridge gates emit for them.  Emits the SERVER intro to legacy-only (forbid
 * CRDT-aware; mirror server_estab's J-form), then runs the proven post-split materialize suite
 * so the now-ungated gates emit the stub's NICK/JOIN/MODE to legacy.  Forces IsIPv6 so legacy
 * accepts the server-sourced IPv6 NICK form.  Retired (SQUIT to legacy) by
 * crdt_shadow_retire_mesh_stub on relink. */
static void crdt_present_stub(struct Client *srv)
{
  if (!srv || IsPresented(srv) || !cli_serv(srv) || !crdt_gateway_has_legacy_peer())
    return;
  SetPresented(srv);
  if (!IsIPv6(srv))
    SetIPv6(srv);
  if (!Protocol(srv))
    cli_serv(srv)->prot = 10;       /* Case-B anchor default (MAJOR_PROTOCOL "10") */
  sendcmdto_flag_serv_butone(&me, CMD_SERVER, NULL, FLAG_LAST_FLAG, FLAG_CRDT_AWARE,
                             "%s 2 0 %Tu J%02u %s%s +%s%s :%s",
                             cli_name(srv), cli_serv(srv)->timestamp, Protocol(srv),
                             NumServCap(srv), IsHub(srv) ? "h" : "",
                             IsIPv6(srv) ? "6" : "", cli_info(srv));
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT mesh: presented stub %s to legacy as a P10 subtree (R6c)", cli_name(srv));
  /* Do NOT run the reconcile suite here: present() is called from make_anchor (Case B),
   * which is itself called from inside a reconcile pass — a nested reconcile would
   * intro the stub's users to legacy TWICE (numeric-collision ghost-kill).  Now that the
   * stub is marked PRESENTED, the AMBIENT reconcile (the in-progress Case-B pass, or the
   * post-split R2 block for Case A, or the 30s verify timer as a backstop) emits the
   * users/channels to legacy exactly once via the now-ungated §17.7 gates.  The SERVER
   * intro above is emitted first, so it precedes those NICKs. */
}

void crdt_shadow_convert_to_stub(struct Client *srv)
{
  unsigned int held = 0, i;
  struct Client **acptrp;
  if (!srv || !cli_serv(srv))
    return;
  /* The direct link just died (close_connection already ran): any in-flight
   * CR chunk reassembly keyed to this Client can never complete — free the
   * slots now.  This SQUIT-keep path never reaches exit_one_client (which
   * covers the cascade + overlay teardown flavors), so it must clean here. */
  s2s_chunk_cleanup_link(srv);
  acptrp = cli_serv(srv)->client_list;
  for (i = 0; i <= cli_serv(srv)->nn_mask; ++acptrp, ++i)
    if (*acptrp) held++;
  SetMeshStub(srv);
  crdt_mesh_stub_count++;            /* R6c: this node is now (partially) partitioned */
  SetFlag(srv, FLAG_MAP);            /* keep the stub's users visible in WHO */
  {                                  /* seed liveness: it was just reachable. The U6 sweep
                                      * keys retirement on seen_since_tick/miss_ticks (NOT
                                      * recv_ts), so seed THOSE — else a stub reusing a numeric
                                      * slot a prior partition left at miss_ticks>=3 is retired
                                      * on the very next tick, before its first post-split
                                      * beacon lands, dropping its held users. */
    unsigned int n = (unsigned int)base64toint(cli_yxx(srv));
    if (n < CRDT_MAX_SERVERS) {
      crdt_beacon[n].recv_ts          = CurrentTime;
      crdt_beacon[n].seen_since_tick  = 1;
      crdt_beacon[n].miss_ticks       = 0;
    }
  }
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT mesh: %s tree-split but mesh-reachable; %u user(s) held live "
            "(T2 mesh stub)", cli_name(srv), held);
  crdt_present_stub(srv);            /* R6c: present to legacy as a P10 subtree (no-op w/o legacy) */
}

/* Tier2 P2 (Case B): build a SYNTHETIC mesh anchor for a partitioned-but-mesh-
 * reachable server that THIS node has NO P10 link to (FindNServer fails), so its
 * users can be materialized + addressed here.  Unlike the Case-A converted stub it
 * owns a FRESH dead Connection (make_client(NULL): fd=-1, never socketed -> every
 * send drops, no socket hazard) and is registered in server_list[] (SetServerYXX)
 * WITHOUT a routing DLink (no add_dlink), so it is FindNServer-resolvable yet
 * excluded from the tree/burst/SQUIT/links walks (never IsServer; nothing routes
 * through it and it is not in cli_serv(&me)->down).  Retired by the beacon-staleness
 * sweep / relink pre-retire via crdt_shadow_retire_mesh_stub (updown==NULL branch).
 * @a srvnum is the 2-char server numeric (the user key's first two chars). */
static struct Client *crdt_shadow_make_anchor(const char *srvnum)
{
  struct Client *nc;
  char yxx[6];
  nc = make_client(NULL, STAT_MESH_SERVER);   /* fresh owned dead-sink Connection */
  if (!nc)
    return NULL;
  crdt_mesh_stub_count++;            /* R6c: synthetic anchor = (partial) partition here */
  make_server(nc);
  cli_serv(nc)->up = &me;          /* parent for accessors, but NOT a routing downlink */
  cli_serv(nc)->updown = NULL;     /* no DLink -> retire skips remove_dlink (asserts non-NULL) */
  cli_serv(nc)->timestamp = TStime();
  cli_hopcount(nc) = 2;            /* nominal; never used for routing */
  ircd_strncpy(cli_info(nc), "CRDT mesh anchor (partitioned server)", REALLEN + 1);
  /* #3: use the real server name + client capacity carried on the CR H beacon (the
   * beacon's recv_ts gates anchor creation, so they are normally present).  The
   * capacity right-sizes client_list: the owning server assigns client numerics
   * within its OWN nn_mask, so a matching anchor mask fits every user with no slot
   * collision — instead of always reserving the MAX 3-char mask (~2MB/anchor).
   * Fall back to a placeholder name + MAX mask only if a beacon hasn't carried them. */
  {
    unsigned int sidx = (unsigned int)base64toint(srvnum);
    const char *bname = (sidx < CRDT_MAX_SERVERS) ? crdt_beacon[sidx].name : "";
    const char *bcap  = (sidx < CRDT_MAX_SERVERS) ? crdt_beacon[sidx].nn_cap : "";
    if (bname[0])
      ircd_strncpy(cli_name(nc), bname, HOSTLEN + 1);
    else
      ircd_snprintf(0, cli_name(nc), HOSTLEN, "mesh-%s.crdt", srvnum);
    yxx[0] = srvnum[0]; yxx[1] = srvnum[1];
    if (strlen(bcap) == 3) {              /* real capacity -> right-sized mask */
      yxx[2] = bcap[0]; yxx[3] = bcap[1]; yxx[4] = bcap[2];
    } else {                             /* unknown: MAX mask so client numerics never truncate */
      inttobase64(yxx + 2, 64u * 64u * 64u - 1u, 3);
    }
    yxx[5] = '\0';
  }
  SetServerYXX(nc, nc, yxx);       /* server_list[srvnum]=nc + client_list; NO add_dlink */
  SetFlag(nc, FLAG_MAP);           /* keep its users visible in WHO */
  SetCrdtAware(nc);                /* its users are mesh-owned: from_crdt_peer self-skips */
  add_client_to_list(nc);
  hAddClient(nc);
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT mesh: synthetic anchor for server %s = %s (mesh-reachable, no P10 link)",
            srvnum, cli_name(nc));
  crdt_present_stub(nc);             /* R6c: present to legacy as a P10 subtree (no-op w/o legacy) */
  return nc;
}

/* B0/MR-3d: present ONE beacon-known CRDT mesh server (by numeric) to our legacy peer, so
 * legacy/x3 learns the leaf and a services reply (SASL/LOC/...) addressed to it routes
 * naturally over P10 to this gateway, which then tunnels CR-X to the leaf.  This is MR-3's
 * missing OUT direction (MR-3 proxy-beacons legacy INTO the mesh; this presents CRDT servers
 * OUT to legacy).  The presentation machinery is R6c's crdt_present_stub/make_anchor
 * wholesale; the only NEW bit is this beacon-driven TRIGGER — present_stub otherwise fires
 * only for a server the gateway materialized a USER for (convert_to_stub / make_anchor on a
 * user-resolve miss), so a user-less leaf (the common case: services live on x3, not the
 * leaves) was never presented and FindNServer(leaf) stayed NULL on the gateway -> the
 * services re-emit fell back to :gateway and x3 replied to the gateway with no usable origin.
 * Caller has checked the gate.  Skips: self; never-fully-seen + stale beacons; PROXIED-LEGACY
 * rows (min_fronter set -> a legacy server fronted by a gateway; never re-present a legacy
 * server toward legacy, MR-3's mirror hazard); and real STAT_SERVERs (legacy already knows
 * them via normal relay -> presenting would be a duplicate-server).  present_stub is
 * idempotent (FLAG_CRDT_PRESENTED) -> a cheap no-op once presented; its SERVER intro precedes
 * the user NICKs the ambient reconcile (the verify timer, which calls the sweep before its
 * reconcile suite) emits via the now-ungated §17.7 gates. */
static void crdt_present_one(unsigned int num)
{
  struct Client *srv;
  char yxx[4];
  unsigned int me_num = (unsigned int)base64toint(cli_yxx(&me));
  if (num >= CRDT_MAX_SERVERS || num == me_num)
    return;
  if (!crdt_beacon[num].emit_ts || !crdt_beacon[num].name[0] || !crdt_beacon[num].nn_cap[0])
    return;                                /* never fully seen this server */
  if (CurrentTime - crdt_beacon[num].recv_ts > CRDT_BEACON_STALE)
    return;                                /* stale -> don't present a server we think is gone */
  if (crdt_beacon[num].min_fronter[0])
    return;                                /* a PROXIED LEGACY server -> never present toward legacy */
  inttobase64(yxx, num, 2);
  srv = FindNServer(yxx);
  if (!srv)
    crdt_shadow_make_anchor(yxx);          /* no anchor yet -> build one (it presents) */
  else if (IsMeshStub(srv) && !IsPresented(srv))
    crdt_present_stub(srv);                 /* anchor exists, unpresented -> present it */
  /* real STAT_SERVER -> do nothing (legacy knows it via normal P10 relay) */
}

/* B0/MR-3d: proactive full sweep — present every eligible mesh server to legacy.  Proactive
 * (not on-demand) so x3 already knows every leaf BEFORE the first services-forward arrives
 * (LOC's FEAT_LOC_TIMEOUT=3 rules out presenting mid-handshake).  Gateway-only (a node with a
 * direct legacy peer).  Called from the verify timer (backstop, before its reconcile suite so
 * the presented stubs' users emit same-tick) + on CR-H beacon ingest (promptness).  Idempotent;
 * reuses FEAT_CRDT_LEGACY_PRESENCE (MR-3's flag — this is its OUT counterpart). */
void crdt_shadow_present_mesh_servers(void)
{
  unsigned int num;
  if (!crdt_shadow_active() || !feature_bool(FEAT_CRDT_LEGACY_PRESENCE) ||
      !crdt_gateway_has_legacy_peer())
    return;
  for (num = 0; num < CRDT_MAX_SERVERS; num++)
    crdt_present_one(num);
}

/* B0/MR-3d: present a single just-learned mesh server (the CR-H ingest fast path), so a fresh
 * leaf becomes presentable to legacy the moment its beacon arrives rather than up to one
 * verify interval later (matters for the 3s LOC budget on a cold leaf).  @a yxx = the 2-char
 * server numeric carried on the beacon. */
void crdt_shadow_present_one_num(const char *yxx)
{
  if (!crdt_shadow_active() || !feature_bool(FEAT_CRDT_LEGACY_PRESENCE) ||
      !crdt_gateway_has_legacy_peer() || !yxx)
    return;
  crdt_present_one((unsigned int)base64toint(yxx));
}

/* R6c gap fix: backfill — present every currently-PRESENTED mesh stub to a
 * FRESHLY-LINKED legacy peer @a cptr.  crdt_present_stub() emits the stub's
 * SERVER intro only ONCE (FLAG_CRDT_PRESENTED) and as a BROADCAST to whatever
 * legacy peers exist AT STUB-DETECTION TIME; presented stubs are also excluded
 * from the normal SERVER-tree burst.  So a legacy peer that links LATER never
 * learns the stub and cannot place its users.  This re-emits each presented
 * stub's SERVER intro TARGETED to cptr (so already-present peers are untouched);
 * called at the top of server_finish_burst's legacy path, it precedes the
 * N/BURST loops, which then place the stub's users naturally.  Iterating
 * IsPresented servers is precisely the right set: real STAT_SERVERs and
 * proxied-legacy rows never receive FLAG_CRDT_PRESENTED.  Legacy-only — a
 * CRDT-aware peer gets the CR F snapshot instead. */
void crdt_shadow_present_stubs_to(struct Client *cptr)
{
  unsigned int num;
  if (!cptr || IsCrdtAware(cptr) || !IsServer(cptr) ||
      !crdt_shadow_active() || !feature_bool(FEAT_CRDT_LEGACY_PRESENCE) ||
      !crdt_gateway_has_legacy_peer())
    return;
  for (num = 0; num < CRDT_MAX_SERVERS; num++) {
    char yxx[4];
    struct Client *srv;
    inttobase64(yxx, num, 2);
    srv = FindNServer(yxx);
    if (!srv || !IsPresented(srv) || !cli_serv(srv))
      continue;
    sendcmdto_one(&me, CMD_SERVER, cptr,
                  "%s 2 0 %Tu J%02u %s%s +%s%s :%s",
                  cli_name(srv), cli_serv(srv)->timestamp, Protocol(srv),
                  NumServCap(srv), IsHub(srv) ? "h" : "",
                  IsIPv6(srv) ? "6" : "", cli_info(srv));
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT mesh: backfilled presented stub %s to freshly-linked legacy %s (R6c)",
              cli_name(srv), cli_name(cptr));
  }
}

void crdt_shadow_topic(struct Channel *chptr, struct Client *from)
{
  if (!shadow_on())
    return;
  if (from_crdt_peer(from))            /* single-writer: peer owns this op */
    return;
  /* op-recording setter so the topic replicates (a direct crdt_lwwmap_set
   * would never enter the oplog and never sync — that was the modes/topic
   * convergence bug). */
  /* M11: pass chptr->topic_time so the mesh orders topics as a MAX-register on it
   * (legacy P10 order) — the integration already holds this wall-clock value; the
   * engine never reads a clock for it, so engine purity holds. */
  crdt_topic_set(&g_crdt, chptr->chname, chptr->topic, (uint64_t)chptr->topic_time);
  write_chanmeta(chptr);               /* topic_time/topic_nick + creationtime */
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

/* CRDT_MODE_MASK now lives in channel.h (shared with the modebuf suppression
 * predicate); +L/+U/+A excluded there — see the note at its definition. */

/** Compact, comparable snapshot of a channel's persistent mode state. */
/* S2S-audit Cluster C: fields appended AFTER the original {mode,limit,key}
 * prefix — the wire blob is parsed length-tolerantly (mode_snap_parse), so a
 * peer that predates these fields still applies the prefix and an old-format
 * blob still round-trips.  NEVER reorder or resize existing fields.
 *  - xmode: the persistent exmode word (CRDT_EXMODE_MASK).
 *  - upass/apass/redir: +U/+A/+L args.  Presence encodes the mode — a founder
 *    password / redirect target is never empty when set — so no extra mode
 *    bits are plumbed through the doc's `mode` word (keeps CRDT_MODE_MASK and
 *    the modebuf-suppression logic untouched; +A/+U/+L still ride P10 for
 *    legacy rendering pre-MR-6, per modebuf_is_crdt_only). */
struct ShadowModeSnap {
  uint32_t mode;
  uint32_t limit;
  char     key[KEYLEN + 1];
  uint32_t xmode;
  char     upass[KEYLEN + 1];
  char     apass[KEYLEN + 1];
  char     redir[CHANNELLEN + 1];
};

static void build_mode_snap(struct Channel *chptr, struct ShadowModeSnap *s)
{
  memset(s, 0, sizeof *s);
  s->mode = chptr->mode.mode & CRDT_MODE_MASK;
  if (s->mode & MODE_LIMIT)
    s->limit = chptr->mode.limit;
  if (s->mode & MODE_KEY)
    strncpy(s->key, chptr->mode.key, sizeof s->key - 1);
  s->xmode = chptr->mode.exmode & CRDT_EXMODE_MASK;
  /* +U/+A/+L store their value ONLY in the string fields — the MODE_UPASS/
   * APASS/REDIRECT bits are modebuf-transport flags, never set in mode.mode
   * (verified: channel.c sets chptr->mode.{upass,apass,redir} directly and the
   * renderer gates on *string).  So capture on STRING presence, not the bit. */
  if (chptr->mode.upass[0])
    strncpy(s->upass, chptr->mode.upass, sizeof s->upass - 1);
  if (chptr->mode.apass[0])
    strncpy(s->apass, chptr->mode.apass, sizeof s->apass - 1);
  if (chptr->mode.redir[0])
    strncpy(s->redir, chptr->mode.redir, sizeof s->redir - 1);
}

/* Length-tolerant parse of a stored mode-snap blob: memset then copy the bytes
 * present, so an OLD short blob fills only the prefix (new fields stay zeroed)
 * and a NEW full blob fills everything.  Append-only field layout makes this
 * version-safe in both directions.  Returns 1 if at least the original prefix
 * (mode+limit+key) is present, else 0 (blob too short to trust). */
static int mode_snap_parse(const void *data, uint32_t len, struct ShadowModeSnap *out)
{
  size_t prefix = offsetof(struct ShadowModeSnap, xmode);  /* {mode,limit,key} */
  size_t n = (len < sizeof *out) ? len : sizeof *out;
  if (!data || len < prefix)
    return 0;
  memset(out, 0, sizeof *out);
  memcpy(out, data, n);
  return 1;
}

/** Inverse of build_mode_snap (Phase 3e): drive the live channel's persistent
 *  modes from a snapshot, touching ONLY the CRDT_MODE_MASK bits + limit + key.
 *  Per-member status, bans, exmode, and internal flags are preserved. */
static void apply_mode_snap(struct Channel *chptr, const struct ShadowModeSnap *s)
{
  chptr->mode.mode = (chptr->mode.mode & ~CRDT_MODE_MASK) | (s->mode & CRDT_MODE_MASK);
  if (s->mode & MODE_LIMIT)
    chptr->mode.limit = s->limit;
  else
    chptr->mode.limit = 0;
  if (s->mode & MODE_KEY)
    ircd_strncpy(chptr->mode.key, s->key, KEYLEN + 1);
  else
    chptr->mode.key[0] = '\0';
  /* Cluster C: exmode word + arg-mode strings.  +U/+A/+L live ONLY in the
   * string fields (no mode.mode bit — see build_mode_snap); copy directly so
   * a materialized channel is byte-identical to a natively-set one.  An empty
   * snap string clears the live value (the mode was unset). */
  chptr->mode.exmode = (chptr->mode.exmode & ~CRDT_EXMODE_MASK)
                       | (s->xmode & CRDT_EXMODE_MASK);
  ircd_strncpy(chptr->mode.upass, s->upass, KEYLEN + 1);
  ircd_strncpy(chptr->mode.apass, s->apass, KEYLEN + 1);
  ircd_strncpy(chptr->mode.redir, s->redir, CHANNELLEN + 1);
}

void crdt_shadow_modes(struct Channel *chptr, struct Client *from)
{
  struct ShadowModeSnap snap;
  if (!shadow_on() || !chptr)
    return;
  if (from_crdt_peer(from))            /* single-writer: peer owns this op */
    return;
  build_mode_snap(chptr, &snap);
  /* op-recording setter so modes replicate (see crdt_shadow_topic). */
  crdt_modes_set(&g_crdt, chptr->chname, &snap, sizeof snap);
  /* modebuf_flush fires on every op/deop/voice — re-assert each present member's
   * status (the single choke for per-member status changes). */
  {
    struct Membership *m;
    for (m = chptr->members; m; m = m->next_member)
      write_member_status(chptr, m);
  }
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

/* ---- ban/except list-modes: OR-Sets reconciled to the real Ban lists ---- */

#define CRDT_MASKLEN (NICKLEN + USERLEN + HOSTLEN + 3)

static int mask_in_banlist(struct Ban *list, const char *mask)
{
  for (; list; list = list->next)
    if (strcmp(list->banstr, mask) == 0)
      return 1;
  return 0;
}

struct crdt_collect_ctx { char masks[64][CRDT_MASKLEN]; int n; };
static void crdt_collect_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct crdt_collect_ctx *c = ctx;
  if (c->n < 64) {
    uint32_t l = key_len < CRDT_MASKLEN - 1 ? key_len : CRDT_MASKLEN - 1;
    memcpy(c->masks[c->n], key, l);
    c->masks[c->n][l] = '\0';
    c->n++;
  }
}

/** Bring a channel's bans/excepts OR-Set into line with its real Ban list (add
 *  new masks, remove masks no longer present). Uses the op-recording
 *  crdt_chan_ban_add/remove (NOT a direct crdt_orset_add) so steady-state +b/-b
 *  replicate via delta sync, not only via the full snapshot (Phase 3i). */
static void reconcile_list(const char *chan, int is_except, struct Ban *list)
{
  struct CrdtChannel *cc = crdt_state_channel(&g_crdt, chan, 1);
  struct CrdtORSet *set = is_except ? &cc->excepts : &cc->bans;
  struct Ban *b;
  struct crdt_collect_ctx col;
  int i;
  for (b = list; b; b = b->next) {
    uint32_t len = (uint32_t)strlen(b->banstr);
    if (!crdt_orset_contains(set, b->banstr, len))
      crdt_chan_ban_add(&g_crdt, chan, b->banstr, is_except);
  }
  col.n = 0;
  crdt_orset_foreach(set, crdt_collect_cb, &col);
  for (i = 0; i < col.n; i++)
    if (!mask_in_banlist(list, col.masks[i]))
      crdt_chan_ban_remove(&g_crdt, chan, col.masks[i], CRDT_PRIORITY_USER, is_except);
}

void crdt_shadow_lists(struct Channel *chptr, struct Client *from)
{
  if (!shadow_on() || !chptr)
    return;
  if (from_crdt_peer(from))            /* single-writer: peer owns this op */
    return;
  reconcile_list(chptr->chname, 0, chptr->banlist);
  reconcile_list(chptr->chname, 1, chptr->exceptlist);
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

/* ---- Tier C F1-c: per-user SILENCE OR-Set (global, keyed usernumeric\0mask) ----
 * Under tree-retirement, the legacy P10 SILENCE broadcast (forward_silences ->
 * sendcmdto_serv_butone "* mask") reaches tree neighbours + legacy but NOT an
 * overlay-only CRDT leaf — so a sender there can't suppress a remote target's
 * messages (is_silenced checks the TARGET's list at the SENDER's server). The doc
 * fills that gap: the home server mirrors a user's silence list into the global
 * OR-Set; every node materializes it onto the (possibly remote) user's live list.
 * ADDITIVE — the P10 token is NOT suppressed, so legacy is unaffected. */

/* Collect this user's silence masks from the doc OR-Set (filter by numeric prefix).
 * Keys are usernumeric\0mask; extract the mask tail. */
struct sil_collect_ctx { const char *num; uint32_t numlen;
                         char masks[64][CRDT_MASKLEN]; int n; };
static void sil_collect_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct sil_collect_ctx *c = ctx;
  uint32_t mlen;
  if (c->n >= 64) return;
  if (key_len <= c->numlen + 1) return;
  if (memcmp(key, c->num, c->numlen) != 0 || key[c->numlen] != '\0') return;
  mlen = key_len - c->numlen - 1;
  if (mlen >= CRDT_MASKLEN) mlen = CRDT_MASKLEN - 1;
  memcpy(c->masks[c->n], key + c->numlen + 1, mlen);
  c->masks[c->n][mlen] = '\0';
  c->n++;
}

/* Doc-mask form of a silence Ban: a leading '~' marks an exception so the
 * BAN_EXCEPTION bit round-trips through the doc (else a +~mask exception would
 * materialize as a positive silence and wrongly suppress). Else the bare mask. */
static void sil_docmask(const struct Ban *b, char *out, size_t n)
{
  if ((b->flags & BAN_EXCEPTION) && n > 1) {
    out[0] = '~';
    ircd_strncpy(out + 1, b->banstr, n - 1);
  } else {
    ircd_strncpy(out, b->banstr, n);
  }
}

/* Is a doc-mask (possibly '~'-prefixed) present in a live silence list? */
static int sil_mask_in_list(struct Ban *list, const char *docmask)
{
  char dm[CRDT_MASKLEN];
  struct Ban *b;
  for (b = list; b; b = b->next) {
    sil_docmask(b, dm, sizeof dm);
    if (0 == ircd_strcmp(dm, docmask))
      return 1;
  }
  return 0;
}

/* Mirror a LOCAL user's live silence list -> the doc (single-writer = home server).
 * Op-recording add/remove so it replicates via delta. Mirrors reconcile_list. */
void crdt_shadow_silences(struct Client *cptr)
{
  char numbuf[CRDT_NUMERICLEN + 4];
  const char *num;
  struct sil_collect_ctx col;
  struct Ban *b;
  char dm[CRDT_MASKLEN];
  char key[CRDT_NUMERICLEN + 1 + CRDT_MASKLEN];
  int i;
  if (!shadow_on() || !cptr || !cli_user(cptr))
    return;
  if (!cli_user(cptr)->server || !cli_yxx(cptr)[0] || IsBouncerAlias(cptr))
    return;
  if (from_crdt_peer(cli_from(cptr)))   /* single-writer: only the home server mirrors */
    return;
  num = user_numeric(cptr, numbuf, sizeof numbuf);
  /* add: live masks not yet in the doc (doc-mask form encodes exceptions) */
  for (b = cli_user(cptr)->silence; b; b = b->next) {
    uint32_t ul = (uint32_t)strlen(num), ml;
    uint32_t klen;
    sil_docmask(b, dm, sizeof dm);
    ml = (uint32_t)strlen(dm);
    klen = ul + 1 + ml;
    if (klen > sizeof key) continue;
    memcpy(key, num, ul); key[ul] = '\0'; memcpy(key + ul + 1, dm, ml);
    if (!crdt_orset_contains(&g_crdt.silences, key, klen))
      crdt_silence_add(&g_crdt, num, dm);
  }
  /* remove: doc masks for this user no longer present live */
  col.num = num; col.numlen = (uint32_t)strlen(num); col.n = 0;
  crdt_orset_foreach(&g_crdt.silences, sil_collect_cb, &col);
  for (i = 0; i < col.n; i++)
    if (!sil_mask_in_list(cli_user(cptr)->silence, col.masks[i]))
      crdt_silence_remove(&g_crdt, num, col.masks[i], CRDT_PRIORITY_USER);
  crdt_sync_push();
}

/* Build a live silence Ban from a doc-mask (decoding the '~' exception prefix).
 * apply_ban asserts BAN_ADD|BAN_DEL is set, and BAN_EXCEPTION must be restored
 * so is_silenced treats exceptions correctly — mirrors apply_silence's flagging. */
static struct Ban *sil_make_from_docmask(const char *docmask)
{
  int is_exc = (docmask[0] == '~');
  const char *bare = is_exc ? docmask + 1 : docmask;
  struct Ban *nb;
  if (!bare[0]) return NULL;
  nb = make_ban(bare);
  if (!nb) return NULL;
  nb->flags |= BAN_ADD | (is_exc ? BAN_EXCEPTION : 0);
  return nb;
}

/* Bring a REMOTE/materialized user's live silence list into line with the doc
 * (doc is authoritative for remote users). Add missing masks, drop extras.
 * NEVER call for a local user (their live list is the source of truth -> mirror). */
void crdt_shadow_sync_user_silences(struct Client *live)
{
  char numbuf[CRDT_NUMERICLEN + 4];
  const char *num;
  struct sil_collect_ctx col;
  struct Ban *b, *next, **plast;
  char dm[CRDT_MASKLEN];
  int i;
  if (!live || !cli_user(live))
    return;
  /* Fast path: nothing in the doc AND nothing live -> the overwhelming common
   * case (no silences anywhere) is O(1), not an O(silences) scan per user/cycle. */
  if (crdt_orset_size(&g_crdt.silences) == 0 && !cli_user(live)->silence)
    return;
  num = user_numeric(live, numbuf, sizeof numbuf);
  col.num = num; col.numlen = (uint32_t)strlen(num); col.n = 0;
  crdt_orset_foreach(&g_crdt.silences, sil_collect_cb, &col);
  /* add doc masks missing from the live list */
  for (i = 0; i < col.n; i++)
    if (!sil_mask_in_list(cli_user(live)->silence, col.masks[i])) {
      struct Ban *nb = sil_make_from_docmask(col.masks[i]);
      if (nb) apply_ban(&cli_user(live)->silence, nb, 1);
    }
  /* drop live masks no longer in the doc */
  for (plast = &cli_user(live)->silence; (b = *plast) != NULL; ) {
    int keep;
    sil_docmask(b, dm, sizeof dm);
    keep = 0;
    for (i = 0; i < col.n; i++)
      if (0 == ircd_strcmp(dm, col.masks[i])) { keep = 1; break; }
    if (keep) { plast = &b->next; }
    else { next = b->next; *plast = next; free_ban(b); }
  }
}

/* ---- Tier C F2-a: read-marker (MR) doc <-> RocksDB readmarkers_cf ----
 * ADDITIVE: the P10 MR broadcast still reaches tree neighbours + legacy; the doc only
 * adds the overlay-leaf reach + backfill-on-link. The doc VALUE is the markread
 * timestamp string (lexical-max, byte-identical to metadata_readmarker_set's strcmp).
 * The key is the markread storage key (account\0target) treated as an opaque blob —
 * if per-profile markread later keys by account\0sessid\0target, this inherits it. */

/* Mirror a local account-anchored read-marker set into the doc (multi-writer; the
 * lexical-max merge is order-independent + idempotent). Hooked at the m_markread
 * account-anchored set sites (local command + S2S relay) so BOTH CRDT- and
 * legacy-origin markers enter the doc. The reconcile writes RocksDB directly (not via
 * m_markread), so there is no mirror<->reconcile loop; the guard is defensive. */
void crdt_shadow_marker_set(const char *account, const char *target, const char *ts)
{
  char key[ACCOUNTLEN + CHANNELLEN + 4];
  uint32_t al, tl, klen;
  if (!shadow_on() || g_marker_reconciling)
    return;
  if (!account || !*account || !target || !*target || !ts || !*ts)
    return;
  al = (uint32_t)strlen(account);
  tl = (uint32_t)strlen(target);
  klen = al + 1 + tl;
  if (al > ACCOUNTLEN || tl > CHANNELLEN || klen > sizeof key)
    return;
  memcpy(key, account, al); key[al] = '\0'; memcpy(key + al + 1, target, tl);
  crdt_marker_set(&g_crdt, key, klen, ts);
  crdt_sync_push();
}

struct reconcile_marker_ctx { unsigned int applied; };
static void reconcile_marker_cb(const char *key, uint32_t key_len,
                                const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_marker_ctx *c = ctx;
  const char *nul;
  char account[ACCOUNTLEN + 1], target[CHANNELLEN + 1], ts[64];
  uint32_t al, tl;
  if (!val || !val->data || !val->data_len || val->data_len >= sizeof ts)
    return;
  nul = memchr(key, '\0', key_len);          /* key = account\0target (opaque split) */
  if (!nul)
    return;
  al = (uint32_t)(nul - key);
  tl = key_len - al - 1;
  if (al == 0 || al > ACCOUNTLEN || tl == 0 || tl > CHANNELLEN)
    return;
  memcpy(account, key, al); account[al] = '\0';
  memcpy(target, nul + 1, tl); target[tl] = '\0';
  memcpy(ts, val->data, val->data_len); ts[val->data_len] = '\0';
  if (metadata_readmarker_set(account, target, ts) == 0)   /* 0 = stored (was newer) */
    c->applied++;
}

/* Tier C F3: TEMPSHUN doc->live. Only the victim's HOME server applies the
 * flag (m_tempshun's MyUser-only semantics: remote copies never carry it);
 * every other node's walk is a no-op for that key. Drift-applied with the
 * handler's own transition notices so a doc-delivered shun looks exactly like
 * a tree-delivered one to opers and the victim. Pure flag+notify — no store,
 * no doc mint (nothing here re-enters the engine). */
static void reconcile_tempshun_cb(const char *key, uint32_t key_len,
                                  const struct CrdtLWWValue *val, void *ctx)
{
  struct Client *acptr;
  const struct CrdtTempshun *ts;
  const char *reason;
  char num[8];
  (void)ctx;
  if (!val || !val->data || val->data_len != sizeof(struct CrdtTempshun))
    return;                            /* wrong-sized = other-version peer: skip */
  if (key_len >= sizeof num)
    return;
  memcpy(num, key, key_len);
  num[key_len] = '\0';
  if (!(acptr = findNUser(num)))
    return;
  if (!MyUser(acptr) || IsBouncerAlias(acptr))
    return;                            /* the HOME server is the sole flag holder */
  ts = (const struct CrdtTempshun *)val->data;
  reason = ts->reason[0] ? ts->reason : "no reason";
  if (ts->active && !IsTempShun(acptr)) {
    if (!feature_bool(FEAT_HIS_SHUN_REASON))
      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :You are shunned: %s",
                    acptr, reason);
    sendto_opmask_butone_global(&me, SNO_GLINE,
                                "Temporary shun applied to %s (%s)",
                                get_client_name(acptr, SHOW_IP), reason);
    SetTempShun(acptr);
  } else if (!ts->active && IsTempShun(acptr)) {
    sendto_opmask_butone_global(&me, SNO_GLINE,
                                "Temporary shun removed from %s (%s)",
                                get_client_name(acptr, SHOW_IP), reason);
    ClearTempShun(acptr);
  }
}

void crdt_shadow_reconcile_tempshuns(void)
{
  if (!shadow_on())
    return;
  crdt_lwwmap_foreach(&g_crdt.tempshuns, reconcile_tempshun_cb, NULL);
}

/* Tier C F3: mint a TEMPSHUN flip into the doc at the ENTRY server (the oper's
 * server for /TEMPSHUN, the §17.7 gateway edge for X3-sourced TS). LWW resolves
 * multi-origin flips to the latest; the home server applies via the reconcile
 * above. The legacy P10 relay is untouched (tree interop). */
void crdt_shadow_tempshun(struct Client *victim, int active, const char *reason)
{
  char num[16];
  if (!shadow_on() || !cli_user(victim))
    return;
  crdt_tempshun_set(&g_crdt, user_numeric(victim, num, sizeof num),
                    active, reason);
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

/* ================================================================== */
/* Tier C F2-c: WEBPUSH subscription convergence (account\0endpoint LWW) */
/* ================================================================== */
/* Endpoint cap + blob size derive from the SHARED webpush_store.h caps (no
 * drift: bumping the cap there flows here). blob = "endpoint|p256dh|auth". */
#define WEBPUSH_F2C_BLOB_MAX  (WEBPUSH_MAX_ENDPOINT_LEN + WEBPUSH_MAX_P256DH + \
                               WEBPUSH_MAX_AUTH + 8)
#define WEBPUSH_F2C_REAP_MAX  32

/* Build the account\0endpoint doc key; returns length or 0 on overflow. */
static uint32_t webpush_doc_key(const char *account, const char *endpoint,
                                char *out, size_t outsz)
{
  size_t al = strlen(account), el = strlen(endpoint);
  if (al == 0 || el == 0 || al + 1 + el > outsz)
    return 0;
  memcpy(out, account, al);
  out[al] = '\0';
  memcpy(out + al + 1, endpoint, el);
  return (uint32_t)(al + 1 + el);
}

/* Mirror a LOCAL/gateway-origin webpush REGISTER into the doc. Called from the
 * m_webpush command handler (origin) and ms_webpush's legacy-edge branch. No
 * reconciling-guard needed: the reconcile drives webpush_store_add DIRECTLY (not
 * through this mirror), so a doc-driven store write never re-enters here. */
void crdt_shadow_webpush_set(const char *account, const char *endpoint,
                             const char *blob)
{
  char dk[ACCOUNTLEN + WEBPUSH_MAX_ENDPOINT_LEN + 2];
  uint32_t klen;
  if (!shadow_on() || !account || !account[0] || !endpoint || !blob)
    return;
  klen = webpush_doc_key(account, endpoint, dk, sizeof dk);
  if (!klen)
    return;
  crdt_webpush_set(&g_crdt, dk, klen, blob, (uint32_t)strlen(blob));
  crdt_sync_push();
}

/* Mirror a webpush UNREGISTER / expiry into the doc (tombstone) — only for a
 * sub we actually converged (no spurious tombstones). */
void crdt_shadow_webpush_remove(const char *account, const char *endpoint)
{
  char dk[ACCOUNTLEN + WEBPUSH_MAX_ENDPOINT_LEN + 2];
  uint32_t klen;
  const struct CrdtLWWValue *v;
  if (!shadow_on() || !account || !account[0] || !endpoint)
    return;
  klen = webpush_doc_key(account, endpoint, dk, sizeof dk);
  if (!klen)
    return;
  v = crdt_webpush_get(&g_crdt, dk, klen);
  if (!v || !v->data)
    return;
  crdt_webpush_del(&g_crdt, dk, klen);
  crdt_sync_push();
}

/* SET-heal: drive each PRESENT doc subscription into webpush_store, echo-guarded
 * (skip if the store already holds the identical blob — no write churn on the
 * verify tick / unrelated deltas). */
struct reconcile_webpush_ctx { unsigned int applied; };
static void reconcile_webpush_set_cb(const char *key, uint32_t key_len,
                                     const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_webpush_ctx *c = ctx;
  const char *nul;
  char account[ACCOUNTLEN + 1], endpoint[WEBPUSH_MAX_ENDPOINT_LEN + 1];
  char blob[WEBPUSH_F2C_BLOB_MAX + 1], cur[WEBPUSH_F2C_BLOB_MAX + 1];
  uint32_t al, el;
  if (!val || !val->data || !val->data_len || val->data_len > WEBPUSH_F2C_BLOB_MAX)
    return;
  nul = memchr(key, '\0', key_len);            /* key = account\0endpoint */
  if (!nul)
    return;
  al = (uint32_t)(nul - key);
  el = key_len - al - 1;
  if (al == 0 || al > ACCOUNTLEN || el == 0 || el > WEBPUSH_MAX_ENDPOINT_LEN)
    return;
  memcpy(account, key, al); account[al] = '\0';
  memcpy(endpoint, nul + 1, el); endpoint[el] = '\0';
  memcpy(blob, val->data, val->data_len); blob[val->data_len] = '\0';
  if (webpush_store_get_blob(account, endpoint, cur, sizeof cur) == 0 &&
      strcmp(cur, blob) == 0)
    return;                                    /* already materialized, identical */
  if (webpush_store_add(account, blob) == 0)
    c->applied++;
}

/* Delete-walk (invariant 11): LIVE-walk the store; reap any row whose
 * account\0endpoint doc key is absent/tombstoned. Collect-then-act (no mutation
 * mid-foreach); loop to drain > REAP_MAX. Static scratch: reconcile is
 * single-threaded (verify timer / eager path). */
static struct webpush_reap_ctx {
  char acct[WEBPUSH_F2C_REAP_MAX][ACCOUNTLEN + 1];
  char ep[WEBPUSH_F2C_REAP_MAX][WEBPUSH_MAX_ENDPOINT_LEN + 1];
  int n;
} g_webpush_reap;

static int webpush_reap_collect(const char *account, const char *stored, void *data)
{
  struct webpush_reap_ctx *c = data;
  const char *bar;
  char dk[ACCOUNTLEN + WEBPUSH_MAX_ENDPOINT_LEN + 2];
  char endpoint[WEBPUSH_MAX_ENDPOINT_LEN + 1];
  uint32_t klen;
  size_t el;
  if (c->n >= WEBPUSH_F2C_REAP_MAX)
    return 0;
  bar = strchr(stored, '|');                   /* stored = endpoint|p256dh|auth */
  if (!bar)
    return 0;
  el = (size_t)(bar - stored);
  if (el == 0 || el > WEBPUSH_MAX_ENDPOINT_LEN || strlen(account) > ACCOUNTLEN)
    return 0;
  memcpy(endpoint, stored, el); endpoint[el] = '\0';
  klen = webpush_doc_key(account, endpoint, dk, sizeof dk);
  if (!klen)
    return 0;
  /* Reap ONLY on an EXPLICIT doc tombstone, never on mere absence (invariant
   * 11). The store is DUAL-populated — the P10 WP broadcast still floods the
   * tree AND the doc reconcile — so a sub that arrived over WP ahead of its CR
   * op is merely-absent-not-tombstoned; reaping it would delete a valid
   * just-registered subscription. A converged UNREGISTER leaves the tombstone
   * this gate keys on. (Matches reconcile_metadata's store-walk; a restart
   * orphan whose tombstone was GC'd lingers but self-heals on the next push's
   * HTTP-410 expiry-remove.) */
  if (!crdt_webpush_is_explicitly_removed(&g_crdt, dk, klen))
    return 0;
  ircd_strncpy(c->acct[c->n], account, ACCOUNTLEN);
  ircd_strncpy(c->ep[c->n], endpoint, WEBPUSH_MAX_ENDPOINT_LEN);
  c->n++;
  return 0;
}

/* Drive webpush_store from the doc: SET-heal present subs + reap tombstoned rows.
 * Idempotent + echo-guarded. Dispatched from the eager delta-apply, verify cycle,
 * and materialize_live (like reconcile_metadata). */
void crdt_shadow_reconcile_webpush(void)
{
  struct reconcile_webpush_ctx sc = { 0 };
  int i, removed = 0;
  if (!shadow_on() || !webpush_store_available())
    return;
  crdt_lwwmap_foreach(&g_crdt.webpush, reconcile_webpush_set_cb, &sc);
  do {
    int round = 0;
    g_webpush_reap.n = 0;
    webpush_store_foreach_all(webpush_reap_collect, &g_webpush_reap);
    for (i = 0; i < g_webpush_reap.n; i++) {
      if (webpush_store_remove(g_webpush_reap.acct[i], g_webpush_reap.ep[i]) == 0) {
        removed++;
        round++;
      }
    }
    /* stop when drained, or when a full batch made no progress (persistent
     * store error) — never spin re-collecting the same un-removable rows. */
    if (g_webpush_reap.n < WEBPUSH_F2C_REAP_MAX || round == 0)
      break;
  } while (1);
  if (sc.applied || removed)
    log_write(LS_SYSTEM, L_INFO, 0,
              "CRDT F2-c: webpush reconcile applied %u, removed %d (doc->store)",
              sc.applied, removed);
}

/* Drive the local readmarkers_cf from the doc (metadata_readmarker_set is newer-wins +
 * idempotent). Dispatched from the verify cycle + eager delta-apply, like reconcile_glines. */
void crdt_shadow_reconcile_markers(void)
{
  struct reconcile_marker_ctx c = { 0 };
  if (!shadow_on())
    return;
  g_marker_reconciling = 1;
  crdt_lwwmap_foreach(&g_crdt.markers, reconcile_marker_cb, &c);
  g_marker_reconciling = 0;
  if (c.applied)
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "CRDT marker-reconcile: %u read-marker(s) applied from doc", c.applied);
}

/* ---- Tier C F2-b: account metadata (MD) as CRDT-native doc state ---- */
/* Cap on doc-tombstoned store keys reaped per reconcile cycle (more next tick). */
#define CRDT_METADATA_REMOVE_MAX 256

/* Set by ms_metadata around a P10-relayed store write so the storage-layer mirror
 * (crdt_shadow_metadata_set, called from metadata_account_set_ts) does NOT re-enter
 * the doc — single-writer: only the ORIGIN server mirrors a SET. */
void crdt_shadow_metadata_suspend(int on)
{
  g_metadata_remote_applying = on ? 1 : 0;
}

/* Build the opaque doc key account\0metakey (byte-identical to the metadata_cf storage
 * key, KEY_SEP='\0'), or return 0 if it must not enter the doc. §B2: channel keys
 * (account is actually a "#chan" cache-key string) converge exactly like account keys
 * — same opaque composite, same generic LWW path; the doc has no notion of key shape.
 * TTL-class channel writes (today's only channel writer, the ms_metadata cache) are
 * excluded by the mirror's !permanent gate (metadata.c:534 -> crdt_shadow_metadata_set,
 * here at :2272), NOT by this function on key shape — so a pre-B2 (old) peer whose
 * reconcile writes a channel row back to the store never materializes it into live
 * memory (channel doc-reconcile doesn't exist yet); version-tolerant by construction.
 *
 * First-segment cap is CHANNELLEN, not ACCOUNTLEN: B1 (+R channel metadata,
 * metadata_set_channel's persist leg) makes this slot hold a real channel name up to
 * CHANNELLEN(200), not just an account (<=ACCOUNTLEN=15) — bounding on ACCOUNTLEN alone
 * would silently drop any channel name longer than 15 bytes from the doc (this function
 * returns 0, metadata_account_set_ts's mirror call is a no-op, no error surfaces
 * anywhere). Every buffer/check downstream that splits this same opaque key
 * (crdt_shadow_metadata_set's dk, reconcile_metadata_set_cb, crdt_shadow_reconcile_metadata's
 * DELETE pass + its del_ctx.keys collector) must size/gate on CHANNELLEN too, for the
 * same reason. */
static uint32_t metadata_doc_key(const char *account, const char *key,
                                 char *buf, size_t n)
{
  uint32_t al, kl, klen;
  if (!account || !*account || !key || !*key)
    return 0;
  al = (uint32_t)strlen(account);
  kl = (uint32_t)strlen(key);
  klen = al + 1 + kl;
  if (al > CHANNELLEN || kl > METADATA_KEY_LEN || klen > n)
    return 0;
  memcpy(buf, account, al); buf[al] = '\0'; memcpy(buf + al + 1, key, kl);
  return klen;
}

/* Mirror a permanent account-metadata write into the doc. value!=NULL && permanent ->
 * SET; value==NULL -> DELETE, but only if the key is doc-present (no spurious tombstones
 * for TTL-cache deletes). A TTL-bound set (permanent==0, value!=NULL) is a per-server
 * cache (last_present / ms_metadata remote cache) and is NOT converged. Self-skips while
 * a doc-driven reconcile or a P10-relayed apply is in flight (single-writer + loop
 * prevention). Called from metadata_account_set_ts (the storage chokepoint). */
void crdt_shadow_metadata_set(const char *account, const char *key,
                              const char *value, int permanent)
{
  char dk[CHANNELLEN + METADATA_KEY_LEN + 4];  /* account-or-channel slot; see metadata_doc_key */
  uint32_t klen;
  if (!shadow_on() || g_metadata_reconciling || g_metadata_remote_applying)
    return;
  klen = metadata_doc_key(account, key, dk, sizeof dk);
  if (!klen)
    return;
  if (value) {
    if (!permanent)
      return;                              /* TTL cache — not shared truth, skip */
    crdt_metadata_set(&g_crdt, dk, klen, value, (uint32_t)strlen(value));
    crdt_sync_push();
  } else {
    /* delete: only mint a tombstone for a key we actually converged */
    const struct CrdtLWWValue *v = crdt_metadata_get(&g_crdt, dk, klen);
    if (!v || !v->data)
      return;
    crdt_metadata_del(&g_crdt, dk, klen);
    crdt_sync_push();
  }
}

/* Raw-key variant of crdt_shadow_metadata_set's delete branch: mint a doc tombstone
 * for an already-formed storage key (account\0metakey, KEY_SEP=='\0'), rather than
 * re-deriving it from (account,key). Used by metadata_account_clear, whose bulk
 * db_writebatch_del over the store would otherwise bypass the doc-mirror chokepoint
 * and leave the doc SET intact -> reconcile_metadata_set_cb SET-heals the cleared
 * value back ~30s later (active resurrection). Same gates as the delete branch: the
 * re-entrancy guards are 0 for a user CLEAR (not a reconcile / remote apply), so the
 * mint fires; the "only tombstone a converged key" read skips TTL-cache keys that were
 * never doc-present. reconcile_metadata_del_collect (store-walk, gated on
 * crdt_metadata_is_explicitly_removed) then reaps the store copy on every node. */
void crdt_shadow_metadata_remove_key(const void *key, uint32_t klen)
{
  const struct CrdtLWWValue *v;
  if (!shadow_on() || g_metadata_reconciling || g_metadata_remote_applying)
    return;
  if (!key || !klen)
    return;
  v = crdt_metadata_get(&g_crdt, (const char *)key, klen);
  if (!v || !v->data)
    return;                                /* only tombstone a key we actually converged */
  crdt_metadata_del(&g_crdt, (const char *)key, klen);
  crdt_sync_push();
}

/* Oper diagnostic (/CRDT key <account> <metakey>): print the raw doc entry —
 * value bytes, HLC (physical/logical/node), writer, and the delta between the
 * entry's HLC physical and this node's wall clock.  Read-only.  Exists to make
 * LWW losses observable from the outside: a positive delta means the entry was
 * minted with a FUTURE clock (clockstep residue etc.) and silently beats every
 * present-time write — the draft/persistence/hold "0" reversion hunt, 2026-07-29. */
void crdt_shadow_diag_metadata_entry(struct Client *sptr, const char *account,
                                     const char *key)
{
  char dk[CHANNELLEN + METADATA_KEY_LEN + 4];
  uint32_t klen;
  const struct CrdtLWWValue *v;
  if (!shadow_on()) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :CRDT key: shadow not active", sptr);
    return;
  }
  klen = metadata_doc_key(account, key, dk, sizeof dk);
  if (!klen) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :CRDT key: bad account/key", sptr);
    return;
  }
  v = crdt_metadata_get(&g_crdt, dk, klen);
  if (v && v->data) {
    unsigned long long now_ms = (unsigned long long)CurrentTime * 1000ULL;
    long long delta = (long long)v->ts.physical_ms - (long long)now_ms;
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :CRDT key %s/%s = \"%.*s\" hlc=%llu.%u node=%u writer=%u "
                  "delta_ms=%lld%s",
                  sptr, account, key,
                  (int)(v->data_len > 64 ? 64 : v->data_len), (const char *)v->data,
                  (unsigned long long)v->ts.physical_ms, (unsigned)v->ts.logical,
                  (unsigned)v->ts.node_id, (unsigned)v->writer, delta,
                  delta > 0 ? " (FUTURE — wins over present-time writes)" : "");
  } else if (crdt_metadata_is_explicitly_removed(&g_crdt, dk, klen)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :CRDT key %s/%s = TOMBSTONE (explicitly removed)",
                  sptr, account, key);
  } else {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :CRDT key %s/%s = absent",
                  sptr, account, key);
  }
}

/* SET heal/backfill: for each PRESENT doc metadata entry, drive it into metadata_cf as a
 * permanent value if the store copy is missing or differs (echo-guarded so a
 * P10-delivered value isn't bounced back + no write churn). Runs under
 * g_metadata_reconciling so metadata_account_set_permanent's mirror self-skips. */
struct reconcile_metadata_ctx { unsigned int applied; };
static void reconcile_metadata_set_cb(const char *key, uint32_t key_len,
                                      const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_metadata_ctx *c = ctx;
  const char *nul, *docraw;
  /* account-or-channel slot; CHANNELLEN is the wider cap — see metadata_doc_key */
  char account[CHANNELLEN + 1], mkey[METADATA_KEY_LEN + 1];
  char cur[METADATA_VALUE_LEN + 1], docval[METADATA_VALUE_LEN + 1];
  uint32_t al, kl;
  int docvis, curvis;
  if (!val || !val->data || !val->data_len || val->data_len > METADATA_VALUE_LEN)
    return;
  nul = memchr(key, '\0', key_len);          /* key = account\0metakey (opaque split) */
  if (!nul)
    return;
  al = (uint32_t)(nul - key);
  kl = key_len - al - 1;
  if (al == 0 || al > CHANNELLEN || kl == 0 || kl > METADATA_KEY_LEN)
    return;
  memcpy(account, key, al); account[al] = '\0';
  memcpy(mkey, nul + 1, kl); mkey[kl] = '\0';
  memcpy(docval, val->data, val->data_len); docval[val->data_len] = '\0';
  /* A2 split: the doc value is the SAME vis-prefixed buffer set_ts wrote to the
   * store (only permanent rows reach the doc), so decode it with the single
   * store-side decoder — server-managed keys are bare/PRIVATE-by-rule, else
   * "P:"->PRIVATE, "*:"->PUBLIC, bare->PUBLIC (legacy).  docraw points into
   * docval, which stays alive for this whole callback. */
  docvis = metadata_decode_visibility(mkey, docval, &docraw);
  /* Vis-aware echo guard: get_vis returns the STRIPPED store value + its decoded
   * vis; compare BOTH against the split doc value.  The pre-A2 guard compared the
   * stripped store value against the still-prefixed docval, which mismatches every
   * private row and re-writes it each 30s tick — split first, then compare. */
  if (metadata_account_get_vis(account, mkey, cur, sizeof cur, &curvis) == 0 &&
      curvis == docvis && strcmp(cur, docraw) == 0)
    return;
  /* Heal the store with the decoded (raw, vis); set_ts re-encodes the prefix and
   * self-skips its doc mirror (g_metadata_reconciling).  On a REAL store change
   * ONLY (we are past the echo guard), materialize the converged value into every
   * local session's live cli_metadata and fire subscriber notifies — the doc-only
   * delivery half that closes the M8 staleness class.  apply_converged is memory +
   * notify only (no store write, no doc op, no umode flag-sync) so it cannot
   * re-enter set_ts / the doc mirror. */
  if (metadata_account_set_permanent(account, mkey, docraw, docvis) == 0) {
    c->applied++;
    metadata_apply_converged(account, mkey, docraw, docvis);
  }
}

/* DELETE store-walk: collect metadata_cf keys the doc has EXPLICITLY tombstoned
 * (never on mere absence — sync-lag safety; never deletes a TTL cache key, which was
 * never doc-present). Collect-then-act (metadata_account_foreach_key holds a live db
 * iterator; the deletes run after it closes). */
struct reconcile_metadata_del_ctx {
  /* account-or-channel slot; CHANNELLEN is the wider cap — see metadata_doc_key */
  char keys[CRDT_METADATA_REMOVE_MAX][CHANNELLEN + METADATA_KEY_LEN + 4];
  uint32_t klens[CRDT_METADATA_REMOVE_MAX];
  int nr;
  int capped;
};
static void reconcile_metadata_del_collect(const void *key, size_t klen, void *arg)
{
  struct reconcile_metadata_del_ctx *d = arg;
  if (d->capped || klen == 0 || klen > sizeof d->keys[0])
    return;
  if (!crdt_metadata_is_explicitly_removed(&g_crdt, key, (uint32_t)klen))
    return;
  if (d->nr >= CRDT_METADATA_REMOVE_MAX) { d->capped = 1; return; }
  memcpy(d->keys[d->nr], key, klen);
  d->klens[d->nr] = (uint32_t)klen;
  d->nr++;
}

/* Drive the local metadata_cf from the doc: SET heal (foreach present) + DELETE
 * store-walk (reap doc-tombstoned keys). Dispatched from the verify cycle + eager
 * delta-apply, like reconcile_glines/markers. The whole pass runs under
 * g_metadata_reconciling so no store write re-mints a doc op. Additive — the P10 MD
 * broadcast is untouched; this only adds overlay-leaf reach. */
void crdt_shadow_reconcile_metadata(void)
{
  struct reconcile_metadata_ctx c = { 0 };
  struct reconcile_metadata_del_ctx *d;
  unsigned int removed = 0;
  int i;
  if (!shadow_on())
    return;
  g_metadata_reconciling = 1;
  crdt_lwwmap_foreach(&g_crdt.metadata, reconcile_metadata_set_cb, &c);

  /* DELETE pass — heap-alloc the collector (large arrays; off the stack). */
  d = (struct reconcile_metadata_del_ctx *)MyCalloc(1, sizeof *d);
  if (d) {
    metadata_account_foreach_key(reconcile_metadata_del_collect, d);
    for (i = 0; i < d->nr; i++) {
      const char *k = d->keys[i];
      const char *nul = memchr(k, '\0', d->klens[i]);
      /* account-or-channel slot; CHANNELLEN is the wider cap — see metadata_doc_key */
      char account[CHANNELLEN + 1], mkey[METADATA_KEY_LEN + 1];
      char oldval[METADATA_VALUE_LEN + 1];
      uint32_t al, kl;
      int oldvis;
      if (!nul)
        continue;
      al = (uint32_t)(nul - k);
      kl = d->klens[i] - al - 1;
      if (al == 0 || al > CHANNELLEN || kl == 0 || kl > METADATA_KEY_LEN)
        continue;
      memcpy(account, k, al); account[al] = '\0';
      memcpy(mkey, nul + 1, kl); mkey[kl] = '\0';
      /* Read the row's visibility BEFORE the delete below removes it — cheap
       * (one extra get on a row we're about to write anyway; pure read, no
       * re-promotion) and lets the Task 5 notify scope a private key's
       * removal to the owner's own sessions instead of the wider PUBLIC
       * channel-share fan-out.  Default PUBLIC if the read misses (row
       * already gone/expired) — a value-less unset carries no value, so the
       * wider fan-out leaks no content either way, only delivery breadth. */
      oldvis = METADATA_VIS_PUBLIC;
      metadata_account_get_vis(account, mkey, oldval, sizeof oldval, &oldvis);
      if (metadata_account_set(account, mkey, NULL, METADATA_VIS_PUBLIC) == 0) { /* delete from store; vis ignored */
        removed++;
        /* Drop the reaped key from every local session's live cli_metadata and
         * notify (value=NULL => memory remove + unset notify).  This rides the
         * SAME tombstone guard as the store reap: the collector only enqueues
         * keys crdt_metadata_is_explicitly_removed reports (never mere absence),
         * so a merely-sync-lagging key is never de-materialized here.  memory +
         * notify only — no store write, no doc op.  Vis-aware since Task 5: a
         * private key's removal notifies only the owner's own sessions. */
        metadata_apply_converged(account, mkey, NULL, oldvis);
      }
    }
    if (d->capped)
      log_write(LS_SYSTEM, L_DEBUG, 0,
                "CRDT metadata-reconcile: remove capped at %d (more next tick)",
                CRDT_METADATA_REMOVE_MAX);
    MyFree(d);
  }
  g_metadata_reconciling = 0;

  if (c.applied || removed)
    log_write(LS_SYSTEM, L_INFO, 0,
              "CRDT metadata-reconcile: %u set, %u removed from doc",
              c.applied, removed);
}

/* ---- Global-state track: GLINEs as CRDT-native doc state (step 2 shadow-write) ---- */

/* Build the doc key (ban mask) for a G-line into @a buf, or NULL if the gline must
 * not enter the doc (local G-lines never replicate). The mask form mirrors
 * gline_propagate's wire encoding: gl_user, plus "@gl_host" for host/IP G-lines
 * ($R realname / $V version / #badchan carry their whole mask in gl_user, no host). */
static const char *gline_doc_key(const struct Gline *gl, char *buf, size_t n)
{
  if (!gl || GlineIsLocal(gl))
    return NULL;
  if (gl->gl_host)
    ircd_snprintf(0, buf, n, "%s@%s", gl->gl_user, gl->gl_host);
  else
    ircd_snprintf(0, buf, n, "%s", gl->gl_user);
  return buf;
}

/* Fill a CrdtGlineRecord from a live Gline — the fields a cutover materialize needs
 * to rebuild a faithful live G-line. gl_addr is copied raw (round-trips back). */
static void gline_to_record(const struct Gline *gl, struct CrdtGlineRecord *rec)
{
  memset(rec, 0, sizeof *rec);
  rec->expire   = (uint64_t)gl->gl_expire;
  rec->lastmod  = (uint64_t)gl->gl_lastmod;
  rec->lifetime = (uint64_t)gl->gl_lifetime;
  rec->flags    = (uint32_t)gl->gl_flags;
  if (GlineIsIpMask(gl)) {
    memcpy(rec->addr, &gl->gl_addr, sizeof rec->addr);
    rec->bits = gl->gl_bits;
  }
  ircd_strncpy(rec->reason, gl->gl_reason ? gl->gl_reason : "", sizeof rec->reason);
}

void crdt_shadow_gline_add(struct Gline *gl, struct Client *from)
{
  char key[CHANNELLEN + USERLEN + 4];   /* worst case: a #badchan mask */
  struct CrdtGlineRecord rec;
  if (!shadow_on())
    return;
  if (g_gline_reconciling)              /* step 3: doc-driven materialize — don't re-mint */
    return;
  if (from_crdt_peer(from))             /* single-writer: mesh entry server owns it */
    return;
  if (!gline_doc_key(gl, key, sizeof key))
    return;                             /* local G-line — never in the doc */
  gline_to_record(gl, &rec);
  crdt_gline_set(&g_crdt, key, &rec);
  crdt_sync_push();                     /* eager-propagate to CRDT peers */
}

void crdt_shadow_gline_remove(struct Gline *gl, struct Client *from)
{
  char key[CHANNELLEN + USERLEN + 4];
  if (!shadow_on())
    return;
  if (g_gline_reconciling)              /* step 3: doc-driven materialize — don't re-mint */
    return;
  if (from_crdt_peer(from))
    return;
  if (!gline_doc_key(gl, key, sizeof key))
    return;
  crdt_gline_del(&g_crdt, key);
  crdt_sync_push();
}

/* ---- GLINE step 3 (cutover): drive live global G-lines FROM the doc + §17.7 gateway ---- */

#define CRDT_GLINE_REMOVE_MAX 64

struct reconcile_gline_ctx { unsigned int created, removed; };

/* ADD/heal + drift pass: for each PRESENT doc gline whose live copy is missing or
 * materially stale, drive it live via gline_add/gline_modify under the re-entrancy
 * guard (so the shadow hook self-skips — no doc re-mint). gline_add derives the
 * variant ($R realname / $V version / # badchan / user@host IP) + the GLINE_*
 * flags from the mask, so we pass only the mask + record fields; its (now legacy-only
 * under FEAT_CRDT_GLINE_CUTOVER) gline_propagate IS the §17.7 gateway, and do_gline
 * kicks matching local users. Echo-guarded by a field comparison (NOT lastmod) so it
 * neither bounces a P10-delivered gline back nor churns on a lastmod-only bump. */
static void reconcile_gline_add_cb(const char *key, uint32_t key_len,
                                   const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_gline_ctx *c = ctx;
  char mask[CHANNELLEN + USERLEN + 4];
  char reason[CRDT_GLINEREASONLEN];
  const struct CrdtGlineRecord *rec;
  struct Gline *existing;
  if (key_len >= sizeof mask || !val->data ||
      val->data_len != sizeof(struct CrdtGlineRecord))
    return;                              /* tombstone / partial record */
  rec = (const struct CrdtGlineRecord *)val->data;
  if ((time_t)rec->expire <= TStime())
    return;                              /* never materialize an expired record (HQ4) */
  memcpy(mask, key, key_len); mask[key_len] = '\0';
  ircd_strncpy(reason, rec->reason, sizeof reason);
  existing = gline_find(mask, GLINE_GLOBAL | GLINE_ANY | GLINE_EXACT);
  if (existing) {
    int active_now = (existing->gl_flags & GLINE_ACTIVE) ? 1 : 0;
    int active_doc = (rec->flags & GLINE_ACTIVE) ? 1 : 0;
    if (active_now == active_doc &&
        existing->gl_expire   == (time_t)rec->expire &&
        existing->gl_lifetime == (time_t)rec->lifetime &&
        !strcmp(existing->gl_reason ? existing->gl_reason : "", reason))
      return;                            /* materially in sync — echo guard (no churn) */
    /* doc is newer/different: drive the drift (active state + expire/lifetime/reason).
     * Carry rec->lastmod (NOT TStime) so legacy ordering holds + no ping-pong (HQ1),
     * but force it past a same-second tie (M12): the gate at gline.c:812 rejects an
     * EQUAL-lastmod modify as "already have that version" even though the content here
     * differs (the echo guard above just proved it), so without the bump the doc-winner
     * would never drive live -> churn + divergence. force_lastmod is only reached in
     * this content-difference branch (not the create branch below). */
    gline_modify(&me, &me, existing,
                 active_doc ? GLINE_ACTIVATE : GLINE_DEACTIVATE, reason,
                 (time_t)rec->expire,
                 force_lastmod(GlineLastMod(existing), (time_t)rec->lastmod),
                 (time_t)rec->lifetime,
                 GLINE_EXPIRE | GLINE_LIFETIME | GLINE_REASON | GLINE_FORCE);
  } else {
    /* not live: materialize. GLINE_FORCE bypasses the expire-window check; the variant
     * + ACTIVE flags ride in (gline_add ORs the mask-derived variant bits). */
    gline_add(&me, &me, mask, reason, (time_t)rec->expire, (time_t)rec->lastmod,
              (time_t)rec->lifetime,
              GLINE_GLOBAL | GLINE_FORCE |
              ((rec->flags & GLINE_ACTIVE) ? GLINE_ACTIVE : 0));
  }
  c->created++;
}

/* GLINE step 3: drive live global G-lines FROM the doc (+ §17.7 gateway to legacy).
 * ADD/heal/drift via the foreach above; REMOVE: free any live global G-line the doc
 * has EXPLICITLY tombstoned (crdt_gline_is_explicitly_removed — NEVER on mere absence,
 * the sync-lag safety) + gateway a `-mask` to legacy. Collect-then-act (gline_free
 * unlinks; never free mid-walk). Idempotent + a no-op while P10 still delivers G-lines
 * (the field echo guard), so it is safe to enable before P10 GL suppression (3b). The
 * whole pass runs under g_gline_reconciling so no doc op is re-minted. No-op unless
 * FEAT_CRDT_GLINE_CUTOVER + FEAT_CRDT_PRIMARY. */
void crdt_shadow_reconcile_glines(void)
{
  struct reconcile_gline_ctx c = { 0, 0 };
  char masks[CRDT_GLINE_REMOVE_MAX][CHANNELLEN + USERLEN + 4];
  int nr = 0, i, capped = 0;
  struct Gline *gl;
  struct Gline *lists[2];
  int li;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_GLINE_CUTOVER) ||
      !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  g_gline_reconciling = 1;
  crdt_lwwmap_foreach(&g_crdt.glines, reconcile_gline_add_cb, &c);
  /* REMOVE pass — collect masks the doc tombstoned that are still live (both lists). */
  lists[0] = GlobalGlineList;
  lists[1] = BadChanGlineList;
  for (li = 0; li < 2 && !capped; li++) {
    for (gl = lists[li]; gl; gl = gl->gl_next) {
      char key[CHANNELLEN + USERLEN + 4];
      if (!gline_doc_key(gl, key, sizeof key))   /* skips local G-lines */
        continue;
      if (!gl->gl_lastmod)
        continue;
      if (!crdt_gline_is_explicitly_removed(&g_crdt, key))
        continue;                        /* present / absent / lagging — leave it */
      if (nr >= CRDT_GLINE_REMOVE_MAX) { capped = 1; break; }
      ircd_strncpy(masks[nr], key, sizeof masks[nr]);
      nr++;
    }
  }
  for (i = 0; i < nr; i++) {
    struct Gline *g = gline_find(masks[i], GLINE_GLOBAL | GLINE_ANY | GLINE_EXACT);
    if (!g)
      continue;                          /* already gone (e.g. P10 removed it) */
    /* §17.7 gateway: tell legacy to drop it (-mask, legacy-only). Byte-shape mirrors
     * gline_propagate. gline_free has no shadow hook -> no re-mint. */
    sendcmdto_flag_serv_butone(&me, CMD_GLINE, NULL, FLAG_LAST_FLAG, FLAG_CRDT_AWARE,
                               "* -%s%s%s %Tu %Tu %Tu :%s",
                               g->gl_user, g->gl_host ? "@" : "",
                               g->gl_host ? g->gl_host : "",
                               g->gl_expire - TStime(), g->gl_lastmod,
                               g->gl_lifetime, g->gl_reason);
    gline_free(g);
    c.removed++;
  }
  g_gline_reconciling = 0;
  if (c.created || c.removed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT gline-reconcile: drove %u, removed %u global G-line(s) from doc%s",
              c.created, c.removed, capped ? " (remove capped; more next tick)" : "");
}

/* ---- SHUN global-state track (GLINE sibling: same template, no badchan) ---- */

/* doc key for a Shun: sh_user[@sh_host] (mirrors shun_propagate's wire). NULL for
 * local Shuns (they never replicate). No badchan -> no '#' masks. */
static const char *shun_doc_key(const struct Shun *sh, char *buf, size_t n)
{
  if (!sh || ShunIsLocal(sh))
    return NULL;
  if (sh->sh_host)
    ircd_snprintf(0, buf, n, "%s@%s", sh->sh_user, sh->sh_host);
  else
    ircd_snprintf(0, buf, n, "%s", sh->sh_user);
  return buf;
}

static void shun_to_record(const struct Shun *sh, struct CrdtShunRecord *rec)
{
  memset(rec, 0, sizeof *rec);
  rec->expire   = (uint64_t)sh->sh_expire;
  rec->lastmod  = (uint64_t)sh->sh_lastmod;
  rec->lifetime = (uint64_t)sh->sh_lifetime;
  rec->flags    = (uint32_t)sh->sh_flags;
  if (ShunIsIpMask(sh)) {
    memcpy(rec->addr, &sh->sh_addr, sizeof rec->addr);
    rec->bits = sh->sh_bits;
  }
  ircd_strncpy(rec->reason, sh->sh_reason ? sh->sh_reason : "", sizeof rec->reason);
}

void crdt_shadow_shun_add(struct Shun *sh, struct Client *from)
{
  char key[USERLEN + HOSTLEN + 4];
  struct CrdtShunRecord rec;
  if (!shadow_on())
    return;
  if (g_shun_reconciling)              /* doc-driven materialize — don't re-mint */
    return;
  if (from_crdt_peer(from))            /* single-writer: mesh entry server owns it */
    return;
  if (!shun_doc_key(sh, key, sizeof key))
    return;                            /* local Shun — never in the doc */
  shun_to_record(sh, &rec);
  crdt_shun_set(&g_crdt, key, &rec);
  crdt_sync_push();
}

void crdt_shadow_shun_remove(struct Shun *sh, struct Client *from)
{
  char key[USERLEN + HOSTLEN + 4];
  if (!shadow_on())
    return;
  if (g_shun_reconciling)
    return;
  if (from_crdt_peer(from))
    return;
  if (!shun_doc_key(sh, key, sizeof key))
    return;
  crdt_shun_del(&g_crdt, key);
  crdt_sync_push();
}

/* SHUN cutover (mirror reconcile_gline_add_cb). */
static void reconcile_shun_add_cb(const char *key, uint32_t key_len,
                                  const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_gline_ctx *c = ctx;   /* same {created,removed} shape */
  char mask[USERLEN + HOSTLEN + 4];
  char reason[CRDT_SHUNREASONLEN];
  const struct CrdtShunRecord *rec;
  struct Shun *existing;
  if (key_len >= sizeof mask || !val->data ||
      val->data_len != sizeof(struct CrdtShunRecord))
    return;
  rec = (const struct CrdtShunRecord *)val->data;
  if ((time_t)rec->expire <= TStime())
    return;
  memcpy(mask, key, key_len); mask[key_len] = '\0';
  ircd_strncpy(reason, rec->reason, sizeof reason);
  existing = shun_find(mask, SHUN_GLOBAL | SHUN_ANY | SHUN_EXACT);
  if (existing) {
    int active_now = (existing->sh_flags & SHUN_ACTIVE) ? 1 : 0;
    int active_doc = (rec->flags & SHUN_ACTIVE) ? 1 : 0;
    if (active_now == active_doc &&
        existing->sh_expire   == (time_t)rec->expire &&
        existing->sh_lifetime == (time_t)rec->lifetime &&
        !strcmp(existing->sh_reason ? existing->sh_reason : "", reason))
      return;                            /* materially in sync — echo guard */
    /* M12: force lastmod past a same-second tie so shun.c:848's equal-lastmod gate
     * can't reject this content-differing modify (mirror reconcile_gline_add_cb). */
    shun_modify(&me, &me, existing,
                active_doc ? SHUN_ACTIVATE : SHUN_DEACTIVATE, reason,
                (time_t)rec->expire,
                force_lastmod(ShunLastMod(existing), (time_t)rec->lastmod),
                (time_t)rec->lifetime,
                SHUN_EXPIRE | SHUN_LIFETIME | SHUN_REASON | SHUN_FORCE);
  } else {
    shun_add(&me, &me, mask, reason, (time_t)rec->expire, (time_t)rec->lastmod,
             (time_t)rec->lifetime,
             SHUN_GLOBAL | SHUN_FORCE | ((rec->flags & SHUN_ACTIVE) ? SHUN_ACTIVE : 0));
  }
  c->created++;
}

void crdt_shadow_reconcile_shuns(void)
{
  struct reconcile_gline_ctx c = { 0, 0 };
  char masks[CRDT_GLINE_REMOVE_MAX][USERLEN + HOSTLEN + 4];
  int nr = 0, i, capped = 0;
  struct Shun *sh;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_SHUN_CUTOVER) ||
      !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  g_shun_reconciling = 1;
  crdt_lwwmap_foreach(&g_crdt.shuns, reconcile_shun_add_cb, &c);
  for (sh = GlobalShunList; sh; sh = sh->sh_next) {
    char key[USERLEN + HOSTLEN + 4];
    if (!shun_doc_key(sh, key, sizeof key))   /* skips local Shuns */
      continue;
    if (!sh->sh_lastmod)
      continue;
    if (!crdt_shun_is_explicitly_removed(&g_crdt, key))
      continue;
    if (nr >= CRDT_GLINE_REMOVE_MAX) { capped = 1; break; }
    ircd_strncpy(masks[nr], key, sizeof masks[nr]);
    nr++;
  }
  for (i = 0; i < nr; i++) {
    struct Shun *s = shun_find(masks[i], SHUN_GLOBAL | SHUN_ANY | SHUN_EXACT);
    if (!s)
      continue;
    sendcmdto_flag_serv_butone(&me, CMD_SHUN, NULL, FLAG_LAST_FLAG, FLAG_CRDT_AWARE,
                               "* -%s%s%s %Tu %Tu %Tu :%s",
                               s->sh_user, s->sh_host ? "@" : "",
                               s->sh_host ? s->sh_host : "",
                               s->sh_expire - TStime(), s->sh_lastmod,
                               s->sh_lifetime, s->sh_reason);
    shun_free(s);
    c.removed++;
  }
  g_shun_reconciling = 0;
  if (c.created || c.removed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT shun-reconcile: drove %u, removed %u global Shun(s) from doc%s",
              c.created, c.removed, capped ? " (remove capped; more next tick)" : "");
}

/* ---- ZLINE global-state track (GLINE sibling: single IP mask, no user@host) ---- */

/* doc key for a Z-line: the single zl_mask. NULL for local Z-lines. */
static const char *zline_doc_key(const struct Zline *zl, char *buf, size_t n)
{
  if (!zl || ZlineIsLocal(zl) || !zl->zl_mask)
    return NULL;
  ircd_snprintf(0, buf, n, "%s", zl->zl_mask);
  return buf;
}

static void zline_to_record(const struct Zline *zl, struct CrdtZlineRecord *rec)
{
  memset(rec, 0, sizeof *rec);
  rec->expire   = (uint64_t)zl->zl_expire;
  rec->lastmod  = (uint64_t)zl->zl_lastmod;
  rec->lifetime = (uint64_t)zl->zl_lifetime;
  rec->flags    = (uint32_t)zl->zl_flags;
  if (ZlineIsIpMask(zl)) {
    memcpy(rec->addr, &zl->zl_addr, sizeof rec->addr);
    rec->bits = zl->zl_bits;
  }
  ircd_strncpy(rec->reason, zl->zl_reason ? zl->zl_reason : "", sizeof rec->reason);
}

void crdt_shadow_zline_add(struct Zline *zl, struct Client *from)
{
  char key[HOSTLEN + 4];
  struct CrdtZlineRecord rec;
  if (!shadow_on())
    return;
  if (g_zline_reconciling)
    return;
  if (from_crdt_peer(from))
    return;
  if (!zline_doc_key(zl, key, sizeof key))
    return;
  zline_to_record(zl, &rec);
  crdt_zline_set(&g_crdt, key, &rec);
  crdt_sync_push();
}

void crdt_shadow_zline_remove(struct Zline *zl, struct Client *from)
{
  char key[HOSTLEN + 4];
  if (!shadow_on())
    return;
  if (g_zline_reconciling)
    return;
  if (from_crdt_peer(from))
    return;
  if (!zline_doc_key(zl, key, sizeof key))
    return;
  crdt_zline_del(&g_crdt, key);
  crdt_sync_push();
}

static void reconcile_zline_add_cb(const char *key, uint32_t key_len,
                                   const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_gline_ctx *c = ctx;
  char mask[HOSTLEN + 4];
  char reason[CRDT_ZLINEREASONLEN];
  const struct CrdtZlineRecord *rec;
  struct Zline *existing;
  if (key_len >= sizeof mask || !val->data ||
      val->data_len != sizeof(struct CrdtZlineRecord))
    return;
  rec = (const struct CrdtZlineRecord *)val->data;
  if ((time_t)rec->expire <= TStime())
    return;
  memcpy(mask, key, key_len); mask[key_len] = '\0';
  ircd_strncpy(reason, rec->reason, sizeof reason);
  existing = zline_find(mask, ZLINE_GLOBAL | ZLINE_ANY | ZLINE_EXACT);
  if (existing) {
    int active_now = (existing->zl_flags & ZLINE_ACTIVE) ? 1 : 0;
    int active_doc = (rec->flags & ZLINE_ACTIVE) ? 1 : 0;
    if (active_now == active_doc &&
        existing->zl_expire   == (time_t)rec->expire &&
        existing->zl_lifetime == (time_t)rec->lifetime &&
        !strcmp(existing->zl_reason ? existing->zl_reason : "", reason))
      return;                            /* materially in sync — echo guard */
    /* M12: force lastmod past a same-second tie so zline.c:621's equal-lastmod gate
     * can't reject this content-differing modify (mirror reconcile_gline_add_cb). */
    zline_modify(&me, &me, existing,
                 active_doc ? ZLINE_ACTIVATE : ZLINE_DEACTIVATE, reason,
                 (time_t)rec->expire,
                 force_lastmod(ZlineLastMod(existing), (time_t)rec->lastmod),
                 (time_t)rec->lifetime,
                 ZLINE_EXPIRE | ZLINE_LIFETIME | ZLINE_REASON | ZLINE_FORCE);
  } else {
    zline_add(&me, &me, mask, reason, (time_t)rec->expire, (time_t)rec->lastmod,
              (time_t)rec->lifetime,
              ZLINE_GLOBAL | ZLINE_FORCE | ((rec->flags & ZLINE_ACTIVE) ? ZLINE_ACTIVE : 0));
  }
  c->created++;
}

void crdt_shadow_reconcile_zlines(void)
{
  struct reconcile_gline_ctx c = { 0, 0 };
  char masks[CRDT_GLINE_REMOVE_MAX][HOSTLEN + 4];
  int nr = 0, i, capped = 0;
  struct Zline *zl;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_ZLINE_CUTOVER) ||
      !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  g_zline_reconciling = 1;
  crdt_lwwmap_foreach(&g_crdt.zlines, reconcile_zline_add_cb, &c);
  for (zl = GlobalZlineList; zl; zl = zl->zl_next) {
    char key[HOSTLEN + 4];
    if (!zline_doc_key(zl, key, sizeof key))   /* skips local Z-lines */
      continue;
    if (!zl->zl_lastmod)
      continue;
    if (!crdt_zline_is_explicitly_removed(&g_crdt, key))
      continue;
    if (nr >= CRDT_GLINE_REMOVE_MAX) { capped = 1; break; }
    ircd_strncpy(masks[nr], key, sizeof masks[nr]);
    nr++;
  }
  for (i = 0; i < nr; i++) {
    struct Zline *z = zline_find(masks[i], ZLINE_GLOBAL | ZLINE_ANY | ZLINE_EXACT);
    if (!z)
      continue;
    sendcmdto_flag_serv_butone(&me, CMD_ZLINE, NULL, FLAG_LAST_FLAG, FLAG_CRDT_AWARE,
                               "* -%s %Tu %Tu %Tu :%s", z->zl_mask,
                               z->zl_expire - TStime(), z->zl_lastmod,
                               z->zl_lifetime, z->zl_reason);
    zline_free(z);
    c.removed++;
  }
  g_zline_reconciling = 0;
  if (c.created || c.removed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT zline-reconcile: drove %u, removed %u global Z-line(s) from doc%s",
              c.created, c.removed, capped ? " (remove capped; more next tick)" : "");
}

/* ---- JUPE global-state track (NOT a ban: a juped SERVER NAME; adapted template) ----
 * Differences from gline/shun/zline: keyed by server name; no lifetime/addr; jupe has
 * NO modify -> drift is handled by recreate (jupe_free + jupe_add); jupe_add takes
 * expire as a DURATION relative to CurrentTime (not absolute/TStime); do_jupe SQUITs a
 * matching locally-linked server. A global jupe is "removed" by DEACTIVATION (a SET of
 * an inactive record), never a tombstone -> the remove pass below is dormant for global
 * jupes (kept for symmetry / a future jupe_destroy). */

static const char *jupe_doc_key(const struct Jupe *ju, char *buf, size_t n)
{
  if (!ju || JupeIsLocal(ju) || !ju->ju_server)
    return NULL;
  ircd_snprintf(0, buf, n, "%s", ju->ju_server);
  return buf;
}

static void jupe_to_record(const struct Jupe *ju, struct CrdtJupeRecord *rec)
{
  memset(rec, 0, sizeof *rec);
  rec->expire  = (uint64_t)ju->ju_expire;     /* absolute, CurrentTime-based */
  rec->lastmod = (uint64_t)ju->ju_lastmod;
  rec->flags   = (uint32_t)ju->ju_flags;
  ircd_strncpy(rec->reason, ju->ju_reason ? ju->ju_reason : "", sizeof rec->reason);
}

void crdt_shadow_jupe_add(struct Jupe *ju, struct Client *from)
{
  char key[HOSTLEN + 4];
  struct CrdtJupeRecord rec;
  if (!shadow_on())
    return;
  if (g_jupe_reconciling)
    return;
  if (from_crdt_peer(from))
    return;
  if (!jupe_doc_key(ju, key, sizeof key))
    return;
  jupe_to_record(ju, &rec);
  crdt_jupe_set(&g_crdt, key, &rec);
  crdt_sync_push();
}

void crdt_shadow_jupe_remove(struct Jupe *ju, struct Client *from)
{
  char key[HOSTLEN + 4];
  if (!shadow_on())
    return;
  if (g_jupe_reconciling)
    return;
  if (from_crdt_peer(from))
    return;
  if (!jupe_doc_key(ju, key, sizeof key))
    return;
  crdt_jupe_del(&g_crdt, key);
  crdt_sync_push();
}

static void reconcile_jupe_add_cb(const char *key, uint32_t key_len,
                                  const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_gline_ctx *c = ctx;
  char server[HOSTLEN + 4];
  char reason[CRDT_JUPEREASONLEN];
  const struct CrdtJupeRecord *rec;
  struct Jupe *existing;
  int active_doc;
  if (key_len >= sizeof server || !val->data ||
      val->data_len != sizeof(struct CrdtJupeRecord))
    return;
  rec = (const struct CrdtJupeRecord *)val->data;
  if ((time_t)rec->expire <= CurrentTime)
    return;                              /* expired (jupe_add would reject too) */
  memcpy(server, key, key_len); server[key_len] = '\0';
  ircd_strncpy(reason, rec->reason, sizeof reason);
  active_doc = (rec->flags & JUPE_ACTIVE) ? 1 : 0;
  existing = jupe_find(server);
  if (existing) {
    int active_now = JupeIsRemActive(existing) ? 1 : 0;
    if (active_now == active_doc &&
        existing->ju_expire == (time_t)rec->expire &&
        !strcmp(existing->ju_reason ? existing->ju_reason : "", reason))
      return;                            /* materially in sync — echo guard */
    jupe_free(existing);                 /* jupe has no modify -> recreate from doc */
  }
  /* (re)create: jupe_add wants a DURATION; carries rec->lastmod (no ping-pong). */
  jupe_add(&me, &me, server, reason, (time_t)rec->expire - CurrentTime,
           (time_t)rec->lastmod, active_doc ? JUPE_ACTIVE : 0);
  c->created++;
}

void crdt_shadow_reconcile_jupes(void)
{
  struct reconcile_gline_ctx c = { 0, 0 };
  char names[CRDT_GLINE_REMOVE_MAX][HOSTLEN + 4];
  int nr = 0, i, capped = 0;
  struct Jupe *ju;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_JUPE_CUTOVER) ||
      !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  g_jupe_reconciling = 1;
  crdt_lwwmap_foreach(&g_crdt.jupes, reconcile_jupe_add_cb, &c);
  /* REMOVE pass (dormant for global jupes — they deactivate, never tombstone). */
  for (ju = GlobalJupeList; ju; ju = ju->ju_next) {
    char key[HOSTLEN + 4];
    if (!jupe_doc_key(ju, key, sizeof key))   /* skips local jupes */
      continue;
    if (!ju->ju_lastmod)
      continue;
    if (!crdt_jupe_is_explicitly_removed(&g_crdt, key))
      continue;
    if (nr >= CRDT_GLINE_REMOVE_MAX) { capped = 1; break; }
    ircd_strncpy(names[nr], key, sizeof names[nr]);
    nr++;
  }
  for (i = 0; i < nr; i++) {
    struct Jupe *j = jupe_find(names[i]);
    if (!j)
      continue;
    sendcmdto_flag_serv_butone(&me, CMD_JUPE, NULL, FLAG_LAST_FLAG, FLAG_CRDT_AWARE,
                               "* -%s %Tu %Tu :%s", j->ju_server,
                               j->ju_expire - CurrentTime, j->ju_lastmod, j->ju_reason);
    jupe_free(j);
    c.removed++;
  }
  g_jupe_reconciling = 0;
  if (c.created || c.removed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT jupe-reconcile: drove %u, removed %u juped server(s) from doc%s",
              c.created, c.removed, capped ? " (remove capped; more next tick)" : "");
}

/* Emit one verify line either to the system log (timer path, @a to == NULL) or
 * as a NOTICE to an oper (the /CRDT status command).  Same text, one source. */
static void verify_emit(struct Client *to, const char *fmt, ...)
{
  char buf[512];
  va_list vl;
  va_start(vl, fmt);
  vsnprintf(buf, sizeof buf, fmt, vl);
  va_end(vl);
  if (to)
    sendcmdto_one(&me, CMD_NOTICE, to, "%C :%s", to, buf);
  else
    log_write(LS_SYSTEM, L_NOTICE, 0, "%s", buf);
}

void crdt_shadow_verify(struct Client *to)
{
  struct Channel *chptr;
  struct Client *acptr;
  unsigned int checked = 0, mismatches = 0;
  uint32_t real_users = 0, crdt_users, crdt_srvs = 1;  /* +1: ourself */

  if (!shadow_on())
    return;

  for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
    struct CrdtChannel *cc = crdt_state_channel(&g_crdt, chptr->chname, 0);
    uint32_t crdt_n = cc ? crdt_orset_size(&cc->members) : 0;
    struct Membership *m;
    char num[16];
    checked++;
    if (crdt_n != chptr->users) {
      mismatches++;
      verify_emit(to,
                "CRDT shadow count divergence: %s real=%u crdt=%u",
                chptr->chname, chptr->users, crdt_n);
    }
    /* field-level: every real non-alias member must be present in the shadow */
    for (m = chptr->members; m; m = m->next_member) {
      if (m->status & CHFL_ALIAS)
        continue;
      user_numeric(m->user, num, sizeof num);
      if (!cc || !crdt_orset_contains(&cc->members, num, strlen(num))) {
        mismatches++;
        verify_emit(to,
                  "CRDT shadow member missing: %s in %s", num, chptr->chname);
      }
    }
    /* field-level: channel topic must match */
    {
      const struct CrdtLWWValue *tv =
        crdt_lwwmap_get(&g_crdt.topics, chptr->chname, strlen(chptr->chname));
      const char *stopic = tv ? crdt_topic_value_text(tv->data, tv->data_len, NULL) : "";
      if (strcmp(stopic, chptr->topic) != 0) {
        mismatches++;
        verify_emit(to,
                  "CRDT shadow topic divergence: %s shadow=\"%s\" real=\"%s\"",
                  chptr->chname, stopic, chptr->topic);
      }
    }
    /* field-level: channel modes (bits + limit + key + exmode + A/U/L) must match */
    {
      struct ShadowModeSnap cur, stored;
      const struct CrdtLWWValue *mv =
        crdt_lwwmap_get(&g_crdt.modes, chptr->chname, strlen(chptr->chname));
      int have = mv && mode_snap_parse(mv->data, mv->data_len, &stored);
      build_mode_snap(chptr, &cur);
      /* length-tolerant compare (an old-format stored blob parses with zeroed
       * new fields); a channel with no persistent modes matches an absent entry */
      if ((have && memcmp(&stored, &cur, sizeof cur) != 0) ||
          (!have && (cur.mode != 0 || cur.xmode != 0
                     || cur.apass[0] || cur.upass[0] || cur.redir[0]))) {
        mismatches++;
        verify_emit(to,
                  "CRDT shadow mode divergence: %s real_mode=0x%x exmode=0x%x",
                  chptr->chname, cur.mode, cur.xmode);
      }
    }
    /* field-level: every real ban/except must be present in the shadow set */
    if (cc) {
      struct Ban *b;
      for (b = chptr->banlist; b; b = b->next)
        if (!crdt_orset_contains(&cc->bans, b->banstr, strlen(b->banstr))) {
          mismatches++;
          verify_emit(to,
                    "CRDT shadow ban missing: %s in %s", b->banstr, chptr->chname);
        }
      for (b = chptr->exceptlist; b; b = b->next)
        if (!crdt_orset_contains(&cc->excepts, b->banstr, strlen(b->banstr))) {
          mismatches++;
          verify_emit(to,
                    "CRDT shadow except missing: %s in %s", b->banstr, chptr->chname);
        }
    }
  }

  /* user registry: existence + nick-value check for non-alias IsUser clients */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    char num[16];
    const struct CrdtUserRecord *r;
    if (!IsUser(acptr) || IsBouncerAlias(acptr))
      continue;
    real_users++;
    user_numeric(acptr, num, sizeof num);
    r = crdt_user_get(&g_crdt, num);
    if (!r) {
      mismatches++;
      verify_emit(to,
                "CRDT shadow user missing: %s (%s)", num, cli_name(acptr));
    } else if (strcmp(r->nick, cli_name(acptr)) != 0) {
      mismatches++;
      verify_emit(to,
                "CRDT shadow nick stale: %s shadow=%s real=%s",
                num, r->nick, cli_name(acptr));
    }
  }
  crdt_users = crdt_lwwmap_size(&g_crdt.users);
  if (real_users != crdt_users) {
    mismatches++;
    verify_emit(to,
              "CRDT shadow user count divergence: real=%u crdt=%u",
              real_users, crdt_users);
  }

  /* Tier-2 S2 (was Phase 4c P10 count): report MESH-reachable CRDT servers via the
   * BEACON SET — S1 proved the beacon set is the presence oracle (BFS == beacon)
   * and that it LEADS the P10 IsCrdtAware count on a silent split (the old count
   * lagged to ping-timeout). Count beacon-fresh numerics + ourself. */
  {
    unsigned int ournum = (unsigned int)base64toint(cli_yxx(&me));
    int bi;
    for (bi = 0; bi < CRDT_MAX_SERVERS; bi++)
      if ((unsigned int)bi != ournum && crdt_beacon[bi].recv_ts &&
          (CurrentTime - crdt_beacon[bi].recv_ts) <= CRDT_BEACON_STALE)
        crdt_srvs++;
  }

  verify_emit(to,
            "CRDT shadow verify: %u channels, %u/%u users, %u servers, %u mismatch(es) "
            "oplog=%u digest=%016llx mdigest=%016llx",
            checked, crdt_users, real_users,
            crdt_srvs,                            /* Phase 4c: reachable CRDT servers */
            mismatches, g_crdt.oplog.count,
            (unsigned long long)crdt_state_digest(&g_crdt),
            (unsigned long long)crdt_state_digest_materialized(&g_crdt));

  /* NOTE: the oplog is intentionally NOT GC'd against our own state vector
   * here — Phase 2 delta sync needs ops retained until peers have caught up.
   * Causal-stability GC against the min of peer SVs (via CR V) is a later
   * increment; until then the shadow oplog grows (bounded enough for testing). */
}

/* Tier-2 Stage 1 (mesh-map -> presence input) — SHADOW ORACLE, log-only, mutates
 * nothing. Measures, per server numeric, three reachability signals and reports
 * their divergences so we can validate (before promoting anything) which is the
 * right presence oracle for R7:
 *   - BFS        : mesh-map transitive reachability (fresh adjacency path from us).
 *   - beacon-set : that server's OWN CR H beacon is fresh (the signal the staleness
 *                  sweep already uses). NB BFS is a SUBSET of this (BFS prunes the
 *                  target by its own freshness too), so "beaconOnly" = a server
 *                  whose beacon arrives but has no fresh adjacency path here
 *                  (adjacency-warmup / declared-peers gap) and "BFSonly" should be
 *                  ~empty. Steady-state beaconOnly>0 = a real adjacency gap to fix
 *                  before BFS can be trusted for presence.
 *   - P10 tree   : a live, non-stub, CRDT-aware server reachable via the P10 tree.
 *                  BFS/beacon being a SUPERSET of this is the expected overlay /
 *                  mesh-stub win (reachable via a CR overlay the tree lacks).
 * @a to == NULL -> system log (verify timer); a Client -> NOTICE'd (/CRDT status). */
void crdt_shadow_presence_diff(struct Client *to)
{
  static uint8_t bfs[CRDT_MAX_SERVERS], beacon[CRDT_MAX_SERVERS];
  static uint8_t p10[CRDT_MAX_SERVERS], diff[CRDT_MAX_SERVERS];
  const struct CrdtMeshMap *mm = crdt_shadow_meshmap();
  struct Client *acptr;
  unsigned int ournum;
  time_t now = CurrentTime, stale = CRDT_BEACON_STALE;
  int i, d_bb, d_bp, bfs_only_b = 0, beacon_only = 0, bfs_only_p = 0, p10_only = 0;

  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  ournum = (unsigned int)base64toint(cli_yxx(&me));

  crdt_meshmap_reachable(mm, (uint16_t)ournum, now, stale, bfs);

  memset(beacon, 0, sizeof beacon);
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    if (crdt_beacon[i].recv_ts && (now - crdt_beacon[i].recv_ts) <= stale)
      beacon[i] = 1;
  beacon[ournum] = 1;                    /* we are always present to ourselves */

  memset(p10, 0, sizeof p10);
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsServer(acptr) && IsCrdtAware(acptr) && !IsMeshStub(acptr)) {
      unsigned int pn = (unsigned int)base64toint(cli_yxx(acptr));
      if (pn < CRDT_MAX_SERVERS)
        p10[pn] = 1;
    }
  p10[ournum] = 1;

  d_bb = crdt_meshmap_set_diff(bfs, beacon, diff);
  for (i = 0; i < CRDT_MAX_SERVERS; i++) {
    if (diff[i] == 1) bfs_only_b++;
    else if (diff[i] == 2) beacon_only++;
  }
  d_bp = crdt_meshmap_set_diff(bfs, p10, diff);
  for (i = 0; i < CRDT_MAX_SERVERS; i++) {
    if (diff[i] == 1) bfs_only_p++;
    else if (diff[i] == 2) p10_only++;
  }

  verify_emit(to,
              "CRDT presence-diff: BFS-vs-beacon %d (BFSonly %d beaconOnly %d); "
              "BFS-vs-P10 %d (meshExtra %d treeOnly %d)",
              d_bb, bfs_only_b, beacon_only, d_bp, bfs_only_p, p10_only);
}

/* MR-0 routing shadow-oracle — see crdt_shadow.h.  Mirrors presence_diff: derive
 * the mesh next-hop table from the mesh-map, build the P10 tree's next-hop table
 * from cli_from, and diff them per CRDT-aware destination.  Log-only; mutates
 * nothing.  The "measure first" artifact the routing layer needs before MR-1
 * routes anything (scope §7a). */
void crdt_shadow_route_diff(struct Client *to)
{
  static int16_t mesh_nh[CRDT_MAX_SERVERS];
  static int16_t p10_nh[CRDT_MAX_SERVERS];
  const struct CrdtMeshMap *mm = crdt_shadow_meshmap();
  struct Client *acptr;
  unsigned int ournum;
  time_t now = CurrentTime, stale = CRDT_BEACON_STALE;
  int agree = 0, mismatch = 0, mesh_only = 0, p10_only = 0;
  int i;

  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  ournum = (unsigned int)base64toint(cli_yxx(&me));

  /* mesh next-hop: shortest-path first hop from us over the converged mesh-map */
  crdt_meshmap_nexthop(mm, (uint16_t)ournum, now, stale, mesh_nh);

  /* P10 next-hop: cli_from(d) is our direct neighbour toward d (== d if directly
   * linked).  Only CRDT-aware, non-stub servers are comparable. */
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    p10_nh[i] = -1;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    unsigned int dn;
    struct Client *via;
    if (!IsServer(acptr) || !IsCrdtAware(acptr) || IsMeshStub(acptr) || acptr == &me)
      continue;
    dn = (unsigned int)base64toint(cli_yxx(acptr));
    if (dn >= CRDT_MAX_SERVERS)
      continue;
    via = cli_from(acptr);
    if (via && IsServer(via)) {
      unsigned int vn = (unsigned int)base64toint(cli_yxx(via));
      p10_nh[dn] = (vn < CRDT_MAX_SERVERS) ? (int16_t)vn : (int16_t)dn;
    } else {
      p10_nh[dn] = (int16_t)dn;            /* directly attached */
    }
  }

  for (i = 0; i < CRDT_MAX_SERVERS; i++) {
    int hasm, hasp;
    if ((unsigned int)i == ournum)
      continue;
    hasm = (mesh_nh[i] >= 0);
    hasp = (p10_nh[i] >= 0);
    if (hasm && hasp) {
      if (mesh_nh[i] == p10_nh[i]) agree++;
      else mismatch++;
    }
    else if (hasm)
      mesh_only++;                         /* overlay/stub win (expected) */
    else if (hasp)
      p10_only++;                          /* adjacency gap to close before MR-1 */
  }

  verify_emit(to,
              "CRDT route-diff: agree %d mismatch %d meshOnly %d p10Only %d",
              agree, mismatch, mesh_only, p10_only);
}

/* MR-3a SHADOW ORACLE (log-only, mutates nothing): for every legacy (non-CRDT)
 * server this node knows via P10, report whether a FRESH proxy-beacon for it has
 * also reached us (so a Case-B anchor could be built once the SERVER intro is
 * suppressed at MR-3c). On the gateway every legacy server is P10-present (it owns
 * the link); the headline is a no-direct-link LEAF showing beacon=FRESH for a
 * legacy server it only reaches via CR — proof the proxy-beacon path works before
 * anything is suppressed. No-op unless FEAT_CRDT_LEGACY_PRESENCE. @a to==NULL ->
 * system log (verify timer); a Client -> NOTICE (/CRDT). */
void crdt_shadow_legacy_presence_diff(struct Client *to)
{
  struct Client *L;
  time_t now = CurrentTime, stale = crdt_shadow_beacon_stale_secs();
  int total = 0, fresh = 0, stalecnt = 0, absent = 0;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_LEGACY_PRESENCE))
    return;
  for (L = GlobalClientList; L; L = cli_next(L)) {
    unsigned int num;
    time_t brecv;
    struct Client *via;
    if (!IsServer(L) || IsMe(L) || IsCrdtAware(L))
      continue;                          /* legacy servers only */
    num = (unsigned int)base64toint(cli_yxx(L));
    brecv = crdt_shadow_beacon_recv(num);
    via = cli_from(L);
    total++;
    if (brecv && (now - brecv) <= stale) {
      fresh++;
      verify_emit(to, "CRDT legacy-presence: %s P10=yes beacon=FRESH age=%lds via=%s",
                  cli_name(L), (long)(now - brecv),
                  (via && via != L) ? cli_name(via) : "direct");
    } else if (brecv) {
      stalecnt++;
      verify_emit(to, "CRDT legacy-presence: %s P10=yes beacon=STALE age=%lds via=%s",
                  cli_name(L), (long)(now - brecv),
                  (via && via != L) ? cli_name(via) : "direct");
    } else {
      absent++;
      verify_emit(to, "CRDT legacy-presence: %s P10=yes beacon=ABSENT via=%s",
                  cli_name(L), (via && via != L) ? cli_name(via) : "direct");
    }
  }
  if (total)
    verify_emit(to, "CRDT legacy-presence: %d legacy server(s) — beacon fresh %d, stale %d, absent %d",
                total, fresh, stalecnt, absent);
}

/* ---- Phase 3b dry-run materialization check (doc -> live fidelity) ----
 * The inverse of crdt_shadow_verify (which walks live -> doc). For every entity
 * in the DOC, confirm a live entity exists with field-for-field fidelity over the
 * reconstruction set 3c would rebuild from. Logs "reconstruction gap"s; MUTATES
 * NOTHING. A clean run means the doc is a faithful, complete source of truth. */

#define MAT_LOG_CAP 20      /* cap logged gaps per pass to avoid log spam */

struct mat_user_ctx { unsigned int *gaps; unsigned int *logged; unsigned int *users; };

static void mat_user_cb(const char *key, uint32_t key_len,
                        const struct CrdtLWWValue *val, void *ctx)
{
  struct mat_user_ctx *c = ctx;
  char numbuf[16], miss[256];
  const struct CrdtUserRecord *rec;
  struct Client *live;
  if (key_len >= sizeof numbuf ||
      val->data_len != sizeof(struct CrdtUserRecord)) { (*c->gaps)++; return; }
  memcpy(numbuf, key, key_len); numbuf[key_len] = '\0';
  rec = (const struct CrdtUserRecord *)val->data;
  (*c->users)++;
  live = findNUser(numbuf);
  if (!live || !cli_user(live)) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: user %s (%s) in doc, not live", numbuf,
                rec->nick);
    return;
  }
  miss[0] = '\0';
#define MCK(cond, name) do { if (cond) \
    strncat(miss, name " ", sizeof miss - strlen(miss) - 1); } while (0)
  MCK(strcmp(rec->nick, cli_name(live)), "nick");
  MCK(strcmp(rec->ident, cli_user(live)->username), "ident");
  MCK(strcmp(rec->host, cli_user(live)->host), "host");
  MCK(strcmp(rec->realhost, cli_user(live)->realhost), "realhost");
  MCK(strcmp(rec->realname, cli_info(live)), "realname");
  MCK(strcmp(rec->account, cli_user(live)->account), "account");
  MCK(strcmp(rec->swhois, cli_user(live)->swhois), "swhois");
  MCK(strcmp(rec->away, cli_user(live)->away ? cli_user(live)->away : ""), "away");
  MCK(strcmp(rec->version, cli_version(live)), "version");
  MCK(strcmp(rec->sslclifp, cli_sslclifp(live)), "sslclifp");
  MCK(strcmp(rec->countrycode, cli_countrycode(live)), "countrycode");
  MCK(strcmp(rec->continentcode, cli_continentcode(live)), "continentcode");
  MCK(memcmp(rec->ip6, &cli_ip(live), sizeof rec->ip6), "ip");
  MCK(rec->nick_ts != (uint64_t)cli_lastnick(live), "ts");
  { char letters[CRDT_UMODELEN];
    umode_letters(letters, sizeof letters, umode_str(live));
    MCK(strcmp(rec->umodes, letters), "umode"); }
#undef MCK
  if (miss[0]) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: user %s (%s) fields: %s", numbuf, rec->nick,
                miss);
  }
}

struct mat_chan_ctx {
  struct Channel *live;
  const char     *chname;
  unsigned int   *gaps;
  unsigned int   *logged;
};

/* present doc member -> live membership + status fidelity */
static void mat_member_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct mat_chan_ctx *c = ctx;
  char numbuf[16], mkey[512];
  struct Client *live_u;
  struct Membership *m;
  const struct CrdtLWWValue *sv;
  const struct CrdtMemberRecord *mr;
  uint8_t live_status;
  uint32_t clen, mklen;
  if (key_len >= sizeof numbuf)
    return;
  memcpy(numbuf, key, key_len); numbuf[key_len] = '\0';
  live_u = findNUser(numbuf);
  m = live_u ? find_member_link(c->live, live_u) : NULL;
  if (!m) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: %s member %s in doc, not live", c->chname,
                numbuf);
    return;
  }
  clen = (uint32_t)strlen(c->chname);
  if (clen + 1 + key_len > sizeof mkey)
    return;
  memcpy(mkey, c->chname, clen); mkey[clen] = '\0';
  memcpy(mkey + clen + 1, key, key_len);
  mklen = clen + 1 + key_len;
  sv = crdt_lwwmap_get(&g_crdt.members_status, mkey, mklen);
  mr = (sv && sv->data_len == sizeof(struct CrdtMemberRecord))
         ? (const struct CrdtMemberRecord *)sv->data : NULL;
  live_status = compact_status(m->status);
  /* a plain member with no status entry is fine; otherwise must match */
  if ((!mr && live_status != 0) ||
      (mr && (mr->status != live_status ||
              mr->oplevel != (uint16_t)m->oplevel))) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: %s member %s status doc=%u live=%u",
                c->chname, numbuf, mr ? mr->status : 0, live_status);
  }
}

/* present doc ban/except mask -> must exist in the live ban/except list */
struct mat_ban_ctx {
  struct Ban   *live;
  const char   *chname;
  const char   *kind;
  unsigned int *gaps;
  unsigned int *logged;
};
static void mat_bancheck_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct mat_ban_ctx *c = ctx;
  char mask[CRDT_MASKLEN];
  uint32_t l = key_len < CRDT_MASKLEN - 1 ? key_len : CRDT_MASKLEN - 1;
  memcpy(mask, key, l); mask[l] = '\0';
  if (!mask_in_banlist(c->live, mask)) {
    (*c->gaps)++;
    if ((*c->logged)++ < MAT_LOG_CAP)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT mat-check gap: %s %s %s in doc, not live", c->chname,
                c->kind, mask);
  }
}

void crdt_shadow_materialize_check(void)
{
  unsigned int gaps = 0, logged = 0, users = 0, chans = 0;
  int bk;
  if (!shadow_on())
    return;

  { struct mat_user_ctx uc = { &gaps, &logged, &users };
    crdt_lwwmap_foreach(&g_crdt.users, mat_user_cb, &uc); }

  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *dc;
    for (dc = g_crdt.chan_buckets[bk]; dc; dc = dc->next) {
      char nbuf[CHANNELLEN + 1];
      struct Channel *live;
      struct mat_chan_ctx cc;
      const struct CrdtLWWValue *mv, *tv;
      struct ShadowModeSnap cur;
      if (crdt_orset_size(&dc->members) == 0)   /* empty doc channel */
        continue;
      if (dc->name_len >= sizeof nbuf)
        continue;
      memcpy(nbuf, dc->name, dc->name_len); nbuf[dc->name_len] = '\0';
      chans++;
      live = FindChannel(nbuf);
      if (!live) {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: channel %s in doc, not live", nbuf);
        continue;
      }
      /* chanmeta: creationtime + topic_nick provenance. NOT topic_time: since M11 the
       * live topic_time is materialized from the topics MAX-register value, while
       * chanmeta.topic_time is an independent HLC-LWW that legitimately diverges from
       * the MAX winner under clock skew -- comparing it here would false-flag a gap on
       * exactly the skew M11 targets. */
      mv = crdt_lwwmap_get(&g_crdt.chanmeta, nbuf, dc->name_len);
      if (mv && mv->data_len == sizeof(struct CrdtChanMeta)) {
        const struct CrdtChanMeta *meta = (const struct CrdtChanMeta *)mv->data;
        if (meta->creationtime != (uint64_t)live->creationtime ||
            strcmp(meta->topic_nick, live->topic_nick) != 0) {
          gaps++;
          if (logged++ < MAT_LOG_CAP)
            log_write(LS_SYSTEM, L_NOTICE, 0,
                      "CRDT mat-check gap: %s chanmeta doc_ts=%lu live_ts=%lu",
                      nbuf, (unsigned long)meta->creationtime,
                      (unsigned long)live->creationtime);
        }
      } else {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: %s chanmeta missing", nbuf);
      }
      /* topic string */
      tv = crdt_lwwmap_get(&g_crdt.topics, nbuf, dc->name_len);
      if (strcmp(tv ? crdt_topic_value_text(tv->data, tv->data_len, NULL) : "", live->topic) != 0) {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: %s topic mismatch", nbuf);
      }
      /* persistent modes (bits + limit + key + exmode + A/U/L) */
      build_mode_snap(live, &cur);
      mv = crdt_lwwmap_get(&g_crdt.modes, nbuf, dc->name_len);
      {
        struct ShadowModeSnap stored;
        int have = mv && mode_snap_parse(mv->data, mv->data_len, &stored);
        if ((have && memcmp(&stored, &cur, sizeof cur) != 0) ||
            (!have && (cur.mode != 0 || cur.xmode != 0
                       || cur.apass[0] || cur.upass[0] || cur.redir[0]))) {
          gaps++;
          if (logged++ < MAT_LOG_CAP)
            log_write(LS_SYSTEM, L_NOTICE, 0,
                      "CRDT mat-check gap: %s modes mismatch (mode=0x%x exmode=0x%x)",
                      nbuf, cur.mode, cur.xmode);
        }
      }
      /* members + per-member status (present doc members only) */
      cc.live = live; cc.chname = nbuf; cc.gaps = &gaps; cc.logged = &logged;
      crdt_orset_foreach(&dc->members, mat_member_cb, &cc);
      /* bans + excepts (present doc masks must be live) — required because a
       * BURST-skip cutover (3c) won't send send_channel_modes, so the doc is
       * the only source of list-modes. */
      { struct mat_ban_ctx bc;
        bc.chname = nbuf; bc.gaps = &gaps; bc.logged = &logged;
        bc.live = live->banlist;    bc.kind = "ban";
        crdt_orset_foreach(&dc->bans, mat_bancheck_cb, &bc);
        bc.live = live->exceptlist; bc.kind = "except";
        crdt_orset_foreach(&dc->excepts, mat_bancheck_cb, &bc); }
    }
  }

  log_write(LS_SYSTEM, L_NOTICE, 0,
            "CRDT mat-check: %u users, %u channels, %u reconstruction gap(s)",
            users, chans, gaps);
}

/* ---- Phase 3c: materialize live state FROM the doc (create path) ----
 * The create-analog of the dry-run: build real struct Client/struct Channel from
 * the doc instead of from P10 BURST. Idempotent + re-runnable (skips anything
 * already live). Modeled on the set_nick_name IsServer remote-create branch
 * (s_user.c:1078) — NOT register_user (which re-broadcasts NICK to the network).
 * Gated by the caller (FEAT_CRDT_PRIMARY); see crdt_shadow_materialize_live. */

/** Expand the compact member-status byte to live CHFL_* membership flags. */
static unsigned int expand_status(uint8_t s)
{
  unsigned int f = 0;
  if (s & CRDT_MEMBER_OP)     f |= CHFL_CHANOP;
  if (s & CRDT_MEMBER_VOICE)  f |= CHFL_VOICE;
  if (s & CRDT_MEMBER_HALFOP) f |= CHFL_HALFOP;
  return f;
}

struct mat_create_ctx { unsigned int *created; };

/* ---- live nick-collision resolution (§17.5) ----
 * Since 3l/3n suppress the P10 NICK to CRDT peers, P10's collision-kill no longer
 * backstops two CRDT-leaf users racing the same nick. We resolve it the §17.5 way —
 * deterministic resolver (so every server picks the SAME winner) + force-rename the
 * LOSER to its numeric (keeps the connection + channels; NOT a kill). Claims are
 * built ad-hoc from the user records/Clients (no nicks-map needed). */
static uint32_t crdt_ip_fold(const unsigned char ip6[16])
{
  uint32_t f = 2166136261u; int i;
  for (i = 0; i < 16; i++) { f ^= ip6[i]; f *= 16777619u; }
  return f;
}
static void crdt_claim_from_rec(struct CrdtNickClaim *c, const char *num,
                                const struct CrdtUserRecord *r)
{
  memset(c, 0, sizeof *c);
  ircd_strncpy(c->numeric, num, sizeof c->numeric);
  ircd_strncpy(c->ident, r->ident, sizeof c->ident);
  ircd_strncpy(c->account, r->account, sizeof c->account);
  c->ip = crdt_ip_fold(r->ip6);
  c->claimed_at.physical_ms = (uint64_t)r->nick_ts * 1000ULL;  /* nick TS = claim order */
  c->claimed_at.logical = 0;
  c->claimed_at.node_id = r->server;
}
static void crdt_claim_from_live(struct CrdtNickClaim *c, struct Client *cl)
{
  unsigned char ip6[16];
  memset(c, 0, sizeof *c);
  user_numeric(cl, c->numeric, sizeof c->numeric);
  ircd_strncpy(c->ident, cli_user(cl)->username, sizeof c->ident);
  ircd_strncpy(c->account, cli_user(cl)->account, sizeof c->account);
  memcpy(ip6, &cli_ip(cl), sizeof ip6);
  c->ip = crdt_ip_fold(ip6);
  c->claimed_at.physical_ms = (uint64_t)cli_lastnick(cl) * 1000ULL;
  c->claimed_at.logical = 0;
  c->claimed_at.node_id = (uint16_t)base64toint(cli_yxx(cli_user(cl)->server));
}

/* §17.5: may user U (numeric @a unum, record @a urec) take nick @a want?  Returns 1 if
 * yes — @a want was free, OR U won the collision and a LOSING LOCAL holder was
 * force-renamed to its numeric (freeing @a want).  Returns 0 if U must defer: U lost,
 * or the winning holder is REMOTE (its home server force-renames it and the doc then
 * converges — non-home servers never rename a remote user into a collision, so no
 * oscillation).  registered_owner=NULL: account-aware step deferred (needs X3 data).
 * NB: a force-rename's crdt_shadow_user_add hook does an in-place crdt_user_set on the
 * (already-present) holder entry — no bucket insert/delete — so a g_crdt.users foreach
 * in progress is not invalidated. */
static int crdt_nick_take(const char *want, const char *unum,
                          const struct CrdtUserRecord *urec)
{
  struct Client *holder = FindUser(want);
  struct CrdtNickClaim cu, cv;
  if (!holder || ircd_strcmp(cli_name(holder), want) != 0)
    return 1;                                  /* nobody holds this exact nick */
  crdt_claim_from_rec(&cu, unum, urec);
  crdt_claim_from_live(&cv, holder);
  if (crdt_resolve_nick_collision(&cu, &cv, NULL) == &cv)
    return 0;                                  /* U lost -> defer */
  if (!MyConnect(holder))
    return 0;                                  /* remote winner-holder: its home renames it */
  {
    char hnum[CRDT_NUMERICLEN], oldn[NICKLEN + 1], *pv[4];
    user_numeric(holder, hnum, sizeof hnum);
    if (ircd_strcmp(hnum, want) == 0)          /* holder already at its numeric */
      return 0;
    ircd_strncpy(oldn, cli_name(holder), sizeof oldn);
    cli_nextnick(holder) = 0;                  /* bypass NICKDELAY for the forced rename */
    pv[0] = oldn; pv[1] = hnum; pv[2] = (char *)"0"; pv[3] = NULL;
    set_nick_name(holder, holder, hnum, 3, pv, 1 /* svsnick: bypass ban checks */);
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT nick-collision: force-renamed local %s -> %s (lost '%s')",
              oldn, hnum, want);
  }
  return 1;
}

/* Materialize ONE doc user into a live remote Client.  Factored out of the bulk
 * mat_create_user_cb so the steady-state reconcile (crdt_shadow_reconcile_users,
 * Phase 3l) can both create the Client AND learn the resulting Client* in order
 * to §17.7-gateway a P10 NICK to legacy.  Returns the new Client, or NULL if
 * skipped (already live / bad record / owning server not in the tree yet).
 * Modeled on the set_nick_name IsServer remote-create branch (s_user.c:1078). */
static struct Client *crdt_materialize_one_user(const char *key, uint32_t key_len,
                                                const struct CrdtLWWValue *val)
{
  char numbuf[16], srvnum[4];
  const struct CrdtUserRecord *rec;
  struct Client *srv, *nc;
  if (key_len < 3 || key_len >= sizeof numbuf ||
      val->data_len != sizeof(struct CrdtUserRecord))
    return NULL;
  memcpy(numbuf, key, key_len); numbuf[key_len] = '\0';
  if (findNUser(numbuf))                  /* already live — idempotent + mandatory
                                             guard (SetRemoteNumNick kills on clash) */
    return NULL;
  rec = (const struct CrdtUserRecord *)val->data;
  srvnum[0] = numbuf[0]; srvnum[1] = numbuf[1]; srvnum[2] = '\0';
  srv = FindNServer(srvnum);
  if (!srv) {
    /* Tier2 P2 (Case B): no P10 server for this numeric HERE (we have no direct link
       to it — e.g. nef4 reaching nef5 via nef3, torn down at the SQUIT).  If the
       server is still mesh-reachable (a FRESH CR H beacon flowed to us, via an
       overlay or relay), build a SYNTHETIC anchor so its users materialize + are
       addressable; if the beacon is STALE (full partition) keep skipping -> users
       stay hidden (correct SPLIT, the reachability gate).  Idempotent: once created,
       the next pass FindNServer's the anchor and takes the IsMeshStub path below. */
    unsigned int sidx = (unsigned int)base64toint(srvnum);
    if (sidx >= CRDT_MAX_SERVERS ||
        CurrentTime - crdt_beacon[sidx].recv_ts > CRDT_BEACON_STALE)
      return NULL;
    srv = crdt_shadow_make_anchor(srvnum);
    if (!srv)
      return NULL;
  } else if (!IsServer(srv) && !IsMeshStub(srv))
    /* owning server present but not a usable parent (handshake/etc.): retry next pass.
       Tier2 P1: a STAT_MESH_SERVER stub (Case A converted, or a Case-B synthetic
       anchor above) IS a valid materialize parent — make_client(cli_from(stub))
       shares its dead-sink Connection (fd=-1; every send path skips a dead/fd<0
       parent), and it keeps cli_serv/cli_yxx.  This admits SPLIT-BORN users so they
       are visible + addressable on every mesh server.  The Q1 spike (2026-06-10)
       proved the old crash was NOT here but in the §17.7 gateway re-intro emitting a
       NICK with the stub as %C source — now skipped for mesh-only users
       (crdt_user_is_mesh_only) with %C treating a stub as a server.  On relink/full
       partition crdt_shadow_retire_mesh_stub reaps these users (cli_serv(stub)->
       client_list) before the real numeric returns. */
    return NULL;
  nc = make_client(cli_from(srv), STAT_UNKNOWN);
  if (!nc)
    return NULL;
  cli_hopcount(nc) = cli_hopcount(srv) + 1;     /* recomputed locally */
  cli_lastnick(nc) = (time_t)rec->nick_ts;
  /* §17.5: if rec->nick collides with a live user, resolve — take it (force-renaming
   * a losing local holder) or fall back to our numeric (a valid, unique nick). */
  ircd_strncpy(cli_name(nc),
               crdt_nick_take(rec->nick, numbuf, rec) ? rec->nick : numbuf,
               NICKLEN + 1);
  cli_user(nc) = make_user(nc);
  cli_user(nc)->server = srv;                    /* before SetRemoteNumNick */
  SetRemoteNumNick(nc, numbuf);
  memcpy(&cli_ip(nc), rec->ip6, sizeof cli_ip(nc));
  add_client_to_list(nc);
  hAddClient(nc);
  ircd_strncpy(cli_username(nc), rec->ident, USERLEN + 1);
  ircd_strncpy(cli_user(nc)->username, rec->ident, USERLEN + 1);
  ircd_strncpy(cli_user(nc)->host, rec->host, HOSTLEN + 1);          /* displayed host */
  ircd_strncpy(cli_user(nc)->realhost, rec->realhost, HOSTLEN + 1);  /* real host (host-rep parity) */
  ircd_strncpy(cli_info(nc), rec->realname, REALLEN + 1);
  if (rec->swhois[0])
    ircd_strncpy(cli_user(nc)->swhois, rec->swhois, BUFSIZE + 1);
  if (rec->away[0])
    user_set_away(cli_user(nc), (char *)rec->away);   /* user_set_away copies; safe */
  /* Tier C F1-b: MARK state.  GeoIP carries only the codes; geoip_apply_mark rebuilds
   * the country/continent NAMES locally + sets SetGeoIP (cheap, deterministic). */
  if (rec->version[0])
    ircd_strncpy(cli_version(nc), rec->version, VERSIONLEN + 1);
  if (rec->sslclifp[0])
    ircd_strncpy(cli_sslclifp(nc), rec->sslclifp, BUFSIZE + 1);
  if (rec->countrycode[0])
    geoip_apply_mark(nc, (char *)rec->countrycode, (char *)rec->continentcode, NULL);
  if (rec->account[0]) {
    ircd_strncpy(cli_user(nc)->account, rec->account, ACCOUNTLEN + 1);
    cli_user(nc)->acc_create = (time_t)rec->acc_create;
    SetAccount(nc);
    /* P1 A3 residue: mesh-materialized remotes need parity with normally-
     * introduced remotes (which load via the register_user chokepoint or
     * the +r stamp residue) so GET/LIST serve from memory immediately
     * instead of waiting on the lazy-fill backstop. */
    metadata_load_account(nc, cli_user(nc)->account);
  }
  user_apply_umode_str(nc, rec->umodes);         /* sets umode FLAGS only */
  SetUser(nc);
  Count_newremoteclient(UserStats, srv);
  /* user_apply_umode_str only set the FLAGS; reconcile the +o/+i counters
   * (flag-keyed source of truth, matched by userstats_count_clear at reap). */
  userstats_count_sync(nc);
  /* Tier C F1-c: populate the materialized user's silence list from the doc so
   * source-side is_silenced on this node suppresses their silenced senders. */
  crdt_shadow_sync_user_silences(nc);
  return nc;
}

static void mat_create_user_cb(const char *key, uint32_t key_len,
                               const struct CrdtLWWValue *val, void *ctx)
{
  struct mat_create_ctx *c = ctx;
  if (crdt_materialize_one_user(key, key_len, val))   /* local-only (no gateway —
                                              the bulk burst-replacement path) */
    (*c->created)++;
}

struct mat_join_ctx { struct Channel *chptr; const char *chname; };

static void mat_join_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct mat_join_ctx *c = ctx;
  char numbuf[16], mkey[512];
  struct Client *u;
  const struct CrdtLWWValue *sv;
  unsigned int flags = 0;
  int oplevel = MAXOPLEVEL + 1;     /* "no oplevel" sentinel; NOT 0 (= founder level) */
  uint32_t clen;
  if (key_len >= sizeof numbuf)
    return;
  memcpy(numbuf, key, key_len); numbuf[key_len] = '\0';
  u = findNUser(numbuf);
  if (!u)                                  /* user not materialized yet — retry */
    return;
  if (find_member_link(c->chptr, u))       /* already a member — idempotent */
    return;
  clen = (uint32_t)strlen(c->chname);
  if (clen + 1 + key_len <= sizeof mkey) {
    memcpy(mkey, c->chname, clen); mkey[clen] = '\0';
    memcpy(mkey + clen + 1, key, key_len);
    sv = crdt_lwwmap_get(&g_crdt.members_status, mkey, clen + 1 + key_len);
    if (sv && sv->data_len == sizeof(struct CrdtMemberRecord)) {
      const struct CrdtMemberRecord *mr = (const struct CrdtMemberRecord *)sv->data;
      flags = expand_status(mr->status);
      oplevel = mr->oplevel;
    }
  }
  add_user_to_channel(c->chptr, u, flags, oplevel);
}

static void mat_banbuild_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct Ban **list = ctx;
  char mask[CRDT_MASKLEN];
  uint32_t l = key_len < CRDT_MASKLEN - 1 ? key_len : CRDT_MASKLEN - 1;
  struct Ban *nb;
  memcpy(mask, key, l); mask[l] = '\0';
  nb = make_ban(mask);
  if (!nb)
    return;
  ircd_strncpy(nb->who, "*", sizeof nb->who);
  nb->when = TStime();
  nb->flags |= BAN_BURSTED;
  nb->next = *list;
  *list = nb;
}

/* Phase 3j: rebuild a freshly-created channel's creationtime/topic/modes/bans
 * from the doc. Shared by materialize_live (!existed) and reconcile_create_channels
 * so the two never drift. creationtime comes from the incarnation MIN-register
 * (NOT chanmeta — IRC is lower-TS-wins); topic_time/topic_nick stay LWW (chanmeta). */
static void rebuild_channel_from_doc(struct Channel *chptr,
                                     struct CrdtChannel *dc, const char *nbuf)
{
  const struct CrdtLWWValue *v;
  uint64_t ct = crdt_chan_ctime_get(&g_crdt, nbuf);
  if (ct)
    chptr->creationtime = (time_t)ct;
  v = crdt_lwwmap_get(&g_crdt.chanmeta, nbuf, dc->name_len);
  if (v && v->data_len == sizeof(struct CrdtChanMeta)) {
    const struct CrdtChanMeta *meta = (const struct CrdtChanMeta *)v->data;
    chptr->topic_time = (time_t)meta->topic_time;
    ircd_strncpy(chptr->topic_nick, meta->topic_nick, sizeof chptr->topic_nick - 1);
  }
  v = crdt_lwwmap_get(&g_crdt.topics, nbuf, dc->name_len);
  if (v && v->data) {
    uint64_t tt = 0;
    ircd_strncpy(chptr->topic, crdt_topic_value_text(v->data, v->data_len, &tt),
                 TOPICLEN + 1);
    /* M11: topic_time comes from the winning topic value (the MAX-register key), keeping
     * it consistent with the topic the gateway will re-emit; chanmeta above only supplies
     * topic_nick provenance now. Fall back to chanmeta's if the value carries none. */
    if (tt)
      chptr->topic_time = (time_t)tt;
  }
  v = crdt_lwwmap_get(&g_crdt.modes, nbuf, dc->name_len);
  {
    struct ShadowModeSnap sm;
    if (v && mode_snap_parse(v->data, v->data_len, &sm)) {
      chptr->mode.mode |= sm.mode;
      if (sm.mode & MODE_LIMIT) chptr->mode.limit = sm.limit;
      if (sm.mode & MODE_KEY)
        ircd_strncpy(chptr->mode.key, sm.key, sizeof chptr->mode.key);
      /* Cluster C: exmode + arg-mode strings, else a mesh-only peer rebuilding
       * this channel from the doc loses +z/+H/+P storage/persistence gates and
       * the +A/+U founder passwords (security).  +U/+A/+L are string-only (no
       * mode.mode bit — see build_mode_snap). */
      chptr->mode.exmode |= (sm.xmode & CRDT_EXMODE_MASK);
      if (sm.upass[0]) ircd_strncpy(chptr->mode.upass, sm.upass, KEYLEN + 1);
      if (sm.apass[0]) ircd_strncpy(chptr->mode.apass, sm.apass, KEYLEN + 1);
      if (sm.redir[0]) ircd_strncpy(chptr->mode.redir, sm.redir, CHANNELLEN + 1);
    }
  }
  crdt_orset_foreach(&dc->bans, mat_banbuild_cb, &chptr->banlist);
  crdt_orset_foreach(&dc->excepts, mat_banbuild_cb, &chptr->exceptlist);
}

void crdt_shadow_materialize_live(void)
{
  unsigned int created = 0, chans = 0;
  int bk;
  if (!shadow_on())
    return;

  /* users first — channels reference them by numeric */
  { struct mat_create_ctx uc = { &created };
    crdt_lwwmap_foreach(&g_crdt.users, mat_create_user_cb, &uc); }

  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *dc;
    for (dc = g_crdt.chan_buckets[bk]; dc; dc = dc->next) {
      char nbuf[CHANNELLEN + 1];
      struct Channel *chptr;
      int existed;
      struct mat_join_ctx jc;
      if (crdt_orset_size(&dc->members) == 0)
        continue;
      if (dc->name_len >= sizeof nbuf)
        continue;
      memcpy(nbuf, dc->name, dc->name_len); nbuf[dc->name_len] = '\0';
      existed = (FindChannel(nbuf) != NULL);
      /* Phase 3j: don't materialize a dead/draining channel — one with present doc
       * members but no LIVE creationtime (locally destructed, tombstone lagging).
       * An already-live (P10/BURST-built) channel is unaffected (existed). */
      if (!existed && crdt_chan_ctime_get(&g_crdt, nbuf) == 0)
        continue;
      chptr = get_channel(&me, nbuf, CGT_CREATE);
      if (!chptr)
        continue;
      if (!existed) {
        /* fresh channel: rebuild creationtime/topic/modes/bans from the doc
         * (only when WE created it — never clobber a BURST-built channel). */
        rebuild_channel_from_doc(chptr, dc, nbuf);
        chans++;
      }
      /* members — always (find_member_link guards against doubles) */
      jc.chptr = chptr; jc.chname = nbuf;
      crdt_orset_foreach(&dc->members, mat_join_cb, &jc);
    }
  }

  if (created || chans)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT materialize: created %u user(s), %u channel(s) from doc",
              created, chans);

  /* A1/F2-b (+ F2-a rider): drive the doc's account metadata and read-markers
   * into the local store/memory HERE, not only on the 30s verify tick.
   * materialize_live is the CR F snapshot apply path (m_crdt.c: the BURST
   * replacement for a joining CRDT-primary peer), which otherwise left permanent
   * account metadata + read-markers sitting in the doc for up to a full verify
   * cycle before they reached metadata_cf / readmarkers_cf and live cli_metadata
   * (the post-CR-F snapshot latency).  Both reconciles are idempotent +
   * echo-guarded, so the second run on the verify path (materialize_live runs
   * here gated !bursting, then reconcile_markers/reconcile_metadata run again a
   * few lines later) is a cheap no-op.  Each sets its own reconciling flag
   * internally, so no store write re-enters the doc mirror. */
  crdt_shadow_reconcile_markers();
  crdt_shadow_reconcile_metadata();
  crdt_shadow_reconcile_tempshuns();
  crdt_shadow_reconcile_webpush();
}

/* ---- Phase 3l: USER introduce + steady-state CREATE via CRDT (+ §17.7 gateway) ----
 * The user-level analog of 3f (channel JOIN-add): the P10 NICK introduce is
 * suppressed to CRDT peers (s_user.c register_user) so a new user rides the doc;
 * on the far side we materialize the Client AND, on a gateway node, re-introduce it
 * to the legacy P10 tree with a P10 NICK.  Removal stays on P10 (deferred 3m);
 * nick-change + umode stay on P10 (deferred 3n) — exactly as 3f's JOIN-add coexisted
 * with P10 PART until 3g. */

/* §17.7 gateway: re-introduce a freshly doc-materialized user to LEGACY peers via a
 * P10 NICK token, forbidding CRDT-aware peers (they learn it from the doc).  Mirrors
 * register_user's FLAG_IPV6 two-call split — require-IPV6 carries the real IP to v6
 * peers, forbid-IPV6 a fake IP to pre-v6 peers; every CRDT peer is v6 (literal '6',
 * s_serv.c:144) so the forbid-IPV6 call never reaches a CRDT peer (no double).
 * Sourced from the user's owning server (a server-sourced NICK is the normal remote
 * introduce form); one=NULL since the forbid mask already excludes every CRDT peer
 * (NULL one is the proven 3f gateway idiom). */
static void crdt_gateway_user_intro(struct Client *nc)
{
  char ip_base64[25];
  const char *um;
  struct Client *srv = cli_user(nc)->server;
  if (!srv)
    return;
  if (IsMeshStub(srv) && !IsPresented(srv))
                          /* Tier2 P1: a mesh-only user is NOT announced to legacy
                             P10 — those peers already SQUIT'd its server; it rides
                             the CRDT doc and the real NICK returns on relink.
                             R6c: a PRESENTED stub IS known to legacy now, so fall
                             through and introduce the user. */
    return;
  um = umode_str(nc);
  sendcmdto_flag_serv_butone(srv, CMD_NICK, NULL,
                             FLAG_IPV6, FLAG_CRDT_AWARE,
                             "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
                             cli_name(nc), cli_hopcount(nc) + 1, cli_lastnick(nc),
                             cli_user(nc)->username, cli_user(nc)->realhost,
                             *um ? "+" : "", um, *um ? " " : "",
                             iptobase64(ip_base64, &cli_ip(nc), sizeof(ip_base64), 1),
                             NumNick(nc), cli_info(nc));
  sendcmdto_flag_serv_butone(srv, CMD_NICK, NULL,
                             FLAG_LAST_FLAG, FLAG_IPV6,
                             "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
                             cli_name(nc), cli_hopcount(nc) + 1, cli_lastnick(nc),
                             cli_user(nc)->username, cli_user(nc)->realhost,
                             *um ? "+" : "", um, *um ? " " : "",
                             iptobase64(ip_base64, &cli_ip(nc), sizeof(ip_base64), 0),
                             NumNick(nc), cli_info(nc));
}

struct recon_user_ctx { unsigned int created; unsigned int renamed; unsigned int umoded; unsigned int setnamed; unsigned int attr; };

/* Build the +/- umode delta that transforms umode-letter set @from into @to.  Both
 * are umode_letters() forms (no leading sign), e.g. from="iw" to="ix" -> "+x-w". */
static void build_umode_delta(char *out, size_t outlen, const char *from, const char *to)
{
  size_t n = 0; const char *p; int pfx;
  pfx = 0;
  for (p = to; *p; p++)
    if (!strchr(from, *p)) {
      if (!pfx && n + 1 < outlen) { out[n++] = '+'; pfx = 1; }
      if (n + 1 < outlen) out[n++] = *p;
    }
  pfx = 0;
  for (p = from; *p; p++)
    if (!strchr(to, *p)) {
      if (!pfx && n + 1 < outlen) { out[n++] = '-'; pfx = 1; }
      if (n + 1 < outlen) out[n++] = *p;
    }
  out[n < outlen ? n : outlen - 1] = '\0';
}

/* Phase 3n/3o: reconcile an already-live remote user's NICK and umodes to the doc.
 * Both are driven through the real handler (set_nick_name / set_user_mode) with
 * cptr = the CRDT uplink, so the proven apply path runs (nick: common-channel NICK
 * notify, nick hash, WATCH, lastnick, WHOWAS; umode: flag-apply, UserStats,
 * host-hiding) AND its own P10 relay — now legacy-only under FEAT_CRDT_PRIMARY
 * (s_user.c:1254 / send_umode_out crdt_gate) — becomes the §17.7 gateway.  The
 * crdt_shadow_user_add hook inside both self-skips (from_crdt_peer of the CRDT
 * uplink), so no op is re-minted and g_crdt.users is NOT mutated mid-walk.  Local
 * users (state authoritative here) and bouncer aliases (follow their primary) are
 * left alone.  @a numbuf is the user's P10 numeric (for set_user_mode's findNUser). */
static void crdt_reconcile_user_update(struct Client *live,
                                       const struct CrdtUserRecord *rec,
                                       const char *numbuf,
                                       struct recon_user_ctx *c)
{
  if (!IsUser(live) || MyUser(live) || IsBouncerAlias(live))
    return;
  /* §17.5: only rename into rec->nick if it isn't contested (or we won + force-renamed
   * a losing local holder). If we must defer (lost, or a remote winner holds it), SKIP
   * — keep the current nick; the loser's home server renames it and the doc converges,
   * then this rename succeeds next tick (no oscillation: a skip is a no-op). */
  if (ircd_strcmp(cli_name(live), rec->nick) != 0
      && crdt_nick_take(rec->nick, numbuf, rec)) {
    char newn[NICKLEN + 1], oldn[NICKLEN + 1], tsbuf[24];
    char *pv[4];
    ircd_strncpy(newn, rec->nick, NICKLEN + 1);
    ircd_strncpy(oldn, cli_name(live), NICKLEN + 1);
    ircd_snprintf(0, tsbuf, sizeof tsbuf, "%Tu", (time_t)rec->nick_ts);
    pv[0] = oldn; pv[1] = newn; pv[2] = tsbuf; pv[3] = NULL;
    set_nick_name(cli_from(live), live, newn, 3, pv, 0);
    c->renamed++;
  }
  /* umode drift -> apply the +/- delta via set_user_mode (full umode_letters set;
   * suppression is all-or-nothing per MODE). set_user_mode runs the real apply and
   * re-emits to legacy via the now-gated send_umode_out (the gateway). sethost's host
   * param is NOT in umode_letters, so it is untouched here (sethost stays on P10). */
  {
    char livel[CRDT_UMODELEN], delta[CRDT_UMODELEN * 2 + 2];
    umode_letters(livel, sizeof livel, umode_str(live));
    if (strcmp(livel, rec->umodes) != 0) {
      build_umode_delta(delta, sizeof delta, livel, rec->umodes);
      if (delta[0]) {
        char nbuf[CRDT_NUMERICLEN], *pv[4];
        /* §17.7: when the reconcile delta toggles oper, force +o propagation to
         * legacy.  This user is a presented remote (no local PRIV_PROPAGATE), so
         * set_user_mode's prop stays 0 and send_umode_out would strip o via
         * SEND_UMODES_BUT_OPER — the legacy peer counted +o at the NICK intro but
         * never sees the matching transition, drifting/underflowing its
         * UserStats.opers.  CRDT peers still get the change via the doc (crdt_gate). */
        int am = ALLOWMODES_ANY;
        if (strchr(delta, 'o')) am |= ALLOWMODES_FORCE_OPER_PROP;
        ircd_strncpy(nbuf, numbuf, sizeof nbuf);
        pv[0] = cli_name(live); pv[1] = nbuf; pv[2] = delta; pv[3] = NULL;
        set_user_mode(cli_from(live), live, 3, pv, am);
        c->umoded++;
      }
    }
  }
  /* F1: realname (SETNAME) drift -> drive ms_setname with cptr = the CRDT uplink.  The
   * real handler updates cli_info, notifies local SETNAME-cap channel members, and its
   * now-legacy-only relay (skip_crdt one-shot) becomes the §17.7 gateway.  The
   * crdt_shadow_user_add hook inside ms_setname self-skips (from_crdt_peer) -> no
   * re-mint, no mid-walk doc mutation (same discipline as the nick/umode clauses). */
  if (rec->realname[0] && ircd_strcmp(cli_info(live), rec->realname) != 0) {
    char rn[REALLEN + 1], *pv[3];
    ircd_strncpy(rn, rec->realname, sizeof rn);
    pv[0] = cli_name(live); pv[1] = rn; pv[2] = NULL;
    sendcmdto_set_skip_crdt_servers();  /* doc covers CRDT peers; gateway to legacy only */
    ms_setname(cli_from(live), live, 2, pv);
    c->setnamed++;
  }
  /* F1: ident (SVSIDENT) drift -> drive ms_svsident.  SVSIDENT is SERVER-sourced (set
   * by services), so drive with sptr=&me (the gateway re-originates) — NOT live, which
   * would emit a user-sourced token legacy rejects.  skip_crdt one-shot = legacy-only
   * relay; the inner crdt_shadow_user_add self-skips (from_crdt_peer). */
  if (rec->ident[0] && ircd_strcmp(cli_user(live)->username, rec->ident) != 0) {
    char nbi[CRDT_NUMERICLEN], id[CRDT_IDENTLEN], *pv[4];
    ircd_strncpy(nbi, numbuf, sizeof nbi);
    ircd_strncpy(id, rec->ident, sizeof id);
    pv[0] = cli_name(&me); pv[1] = nbi; pv[2] = id; pv[3] = NULL;
    sendcmdto_set_skip_crdt_servers();
    ms_svsident(cli_from(live), &me, 3, pv);
    c->attr++;
  }
  /* F1: swhois (SWHOIS) drift -> drive ms_swhois (also SERVER-sourced, sptr=&me).  An
   * empty rec->swhois clears it (ms_swhois with parc==2). */
  if (ircd_strcmp(cli_user(live)->swhois, rec->swhois) != 0) {
    char nbs[CRDT_NUMERICLEN], sw[CRDT_SWHOISLEN], *pv[4];
    int pc;
    ircd_strncpy(nbs, numbuf, sizeof nbs);
    pv[0] = cli_name(&me); pv[1] = nbs;
    if (rec->swhois[0]) {
      ircd_strncpy(sw, rec->swhois, sizeof sw);
      pv[2] = sw; pv[3] = NULL; pc = 3;
    } else {
      pv[2] = NULL; pc = 2;
    }
    sendcmdto_set_skip_crdt_servers();
    ms_swhois(cli_from(live), &me, pc, pv);
    c->attr++;
  }
  /* F1: away (AWAY) drift -> drive ms_away.  AWAY is USER-sourced -> sptr=live (#8-safe;
   * contrast SVSIDENT/SWHOIS).  An empty rec->away clears (user came back).  skip_crdt
   * one-shot = legacy-only gateway; the inner crdt_shadow_user_add self-skips. */
  {
    const char *liveaway = cli_user(live)->away ? cli_user(live)->away : "";
    if (strcmp(liveaway, rec->away) != 0) {
      char aw[CRDT_AWAYLEN], *pv[3];
      ircd_strncpy(aw, rec->away, sizeof aw);
      pv[0] = cli_name(live); pv[1] = aw; pv[2] = NULL;
      sendcmdto_set_skip_crdt_servers();
      ms_away(cli_from(live), live, 2, pv);
      c->attr++;
    }
  }
  /* 3l account-prop: ACCOUNT drift -> drive ms_account (R=register / M=change),
   * SERVER-sourced (sptr=&me) like SVSIDENT/SWHOIS.  Heals a materialized user
   * whose numeric was recycled onto a different account, or whose login landed
   * after this node created it — the stale account made the bouncer alias-
   * target check refuse a CORRECT candidate (promotion scope 2026-07-29).
   * The LOGOUT direction (doc empty, live set) is deliberately NOT driven:
   * ms_account 'U' destroys bouncer sessions + clears metadata — far too
   * destructive to fire off a possibly-lagging doc read; deferred until the
   * empty-account signal is characterized (noted in the promotion scope doc).
   * Wire form matches this node's FEAT_EXTENDED_ACCOUNTS parse; the old
   * syntax has no change form, so a mismatch there heals only via R. */
  if (rec->account[0] &&
      ircd_strcmp(cli_user(live)->account, rec->account) != 0) {
    char nba[CRDT_NUMERICLEN], acct[CRDT_ACCOUNTLEN], ts[24], *pv[6];
    int pc;
    ircd_strncpy(nba, numbuf, sizeof nba);
    ircd_strncpy(acct, rec->account, sizeof acct);
    pv[0] = cli_name(&me); pv[1] = nba;
    if (feature_bool(FEAT_EXTENDED_ACCOUNTS)) {
      pv[2] = IsAccount(live) ? (char *)"M" : (char *)"R";
      if (rec->acc_create) {
        ircd_snprintf(0, ts, sizeof ts, "%Tu", (time_t)rec->acc_create);
        pv[3] = acct; pv[4] = ts; pv[5] = NULL; pc = 5;
      } else {
        pv[3] = acct; pv[4] = NULL; pc = 4;
      }
    } else if (!IsAccount(live)) {
      if (rec->acc_create) {
        ircd_snprintf(0, ts, sizeof ts, "%Tu", (time_t)rec->acc_create);
        pv[2] = acct; pv[3] = ts; pv[4] = NULL; pc = 4;
      } else {
        pv[2] = acct; pv[3] = NULL; pc = 3;
      }
    } else
      pc = 0;  /* old syntax cannot change a set account — leave it */
    if (pc) {
      sendcmdto_set_skip_crdt_servers();
      ms_account(cli_from(live), &me, pc, pv);
      c->attr++;
    }
  }
  /* F1-b: MARK state (CVERSION / SSLCLIFP / GEOIP).  All SERVER-sourced -> sptr=&me.
   * ★ ms_mark resolves its target via FindUser (by NICK), NOT findNUser (numeric) like
   * SVSIDENT/SWHOIS — so parv[1] = cli_name(live), never numbuf.  skip_crdt one-shot =
   * legacy-only gateway re-emit; the inner crdt_shadow_user_add self-skips. */
  if (ircd_strcmp(cli_version(live), rec->version) != 0) {
    char vbuf[CRDT_VERSIONLEN], *pv[5];
    ircd_strncpy(vbuf, rec->version, sizeof vbuf);
    pv[0] = cli_name(&me); pv[1] = cli_name(live);
    pv[2] = (char *)MARK_CVERSION; pv[3] = vbuf; pv[4] = NULL;
    sendcmdto_set_skip_crdt_servers();
    ms_mark(cli_from(live), &me, 4, pv);
    c->attr++;
  }
  if (ircd_strcmp(cli_sslclifp(live), rec->sslclifp) != 0) {
    char fbuf[CRDT_SSLFPLEN], *pv[5];
    ircd_strncpy(fbuf, rec->sslclifp, sizeof fbuf);
    pv[0] = cli_name(&me); pv[1] = cli_name(live);
    pv[2] = (char *)MARK_SSLCLIFP; pv[3] = fbuf; pv[4] = NULL;
    sendcmdto_set_skip_crdt_servers();
    ms_mark(cli_from(live), &me, 4, pv);
    c->attr++;
  }
  /* GeoIP: carry only the codes; ms_mark -> geoip_apply_mark rebuilds the names locally.
   * Gate on a non-empty doc code so empty-geoip users never drive a spurious MARK. */
  if (rec->countrycode[0] &&
      (ircd_strcmp(cli_countrycode(live), rec->countrycode) != 0 ||
       ircd_strcmp(cli_continentcode(live), rec->continentcode) != 0)) {
    char cc[CRDT_GEOCODELEN], cont[CRDT_GEOCODELEN], *pv[6];
    ircd_strncpy(cc, rec->countrycode, sizeof cc);
    ircd_strncpy(cont, rec->continentcode, sizeof cont);
    pv[0] = cli_name(&me); pv[1] = cli_name(live);
    pv[2] = (char *)MARK_GEOIP; pv[3] = cc; pv[4] = cont; pv[5] = NULL;
    sendcmdto_set_skip_crdt_servers();
    ms_mark(cli_from(live), &me, 5, pv);
    c->attr++;
  }
  /* Tier C F1-c: bring a remote user's live silence list into line with the doc
   * (doc-authoritative for remote users). Source-side is_silenced on this node
   * then suppresses correctly. Only for remote users (home owns local lists). */
  if (from_crdt_peer(cli_from(live)))
    crdt_shadow_sync_user_silences(live);
}

static void recon_user_cb(const char *key, uint32_t key_len,
                          const struct CrdtLWWValue *val, void *ctx)
{
  struct recon_user_ctx *c = ctx;
  char nb[16], sn[4];
  const struct CrdtUserRecord *rec;
  struct Client *srv, *via, *live, *nc;
  if (key_len < 3 || key_len >= sizeof nb ||
      val->data_len != sizeof(struct CrdtUserRecord))
    return;                       /* not a full user record (deleted / tombstoned) */
  memcpy(nb, key, key_len); nb[key_len] = '\0';
  sn[0] = nb[0]; sn[1] = nb[1]; sn[2] = '\0';
  srv = FindNServer(sn);
  /* Inbound-burst collision guard, scoped to the UPLINK we'd receive the P10 intro
   * from — NOT a global "any server in burst" gate (that wedges forever on a
   * services pseudo-server like x3.services, which sits perpetually flagged
   * BurstOrBurstAck).  A SetRemoteNumNick collision is possible ONLY if this user's
   * NICK could still arrive via P10 on THIS server, i.e. we reach its owning server
   * through a LEGACY (non-CRDT) uplink that is currently bursting.  If we reach the
   * owning server via a CRDT peer (every user on a leaf; CRDT-origin users on the
   * gateway), the user comes via the doc only → always safe.  This is also why x3's
   * perpetual burst is harmless: on a leaf we reach x3 through nef3 (CRDT), and on
   * the gateway x3's users arrive via P10 so findNUser skips them. */
  via = (srv && IsServer(srv)) ? cli_from(srv) : NULL;
  if (via && IsServer(via) && !IsCrdtAware(via) && IsBurstOrBurstAck(via))
    return;                       /* P10 intro may still be in flight on this legacy burst */
  rec = (const struct CrdtUserRecord *)val->data;
  live = findNUser(nb);
  if (live) {                     /* 3n/3o: already live — reconcile nick + umode drift */
    crdt_reconcile_user_update(live, rec, nb, c);
    return;
  }
  nc = crdt_materialize_one_user(key, key_len, val);   /* 3l: create not-yet-live */
  if (nc) {
    crdt_gateway_user_intro(nc);  /* §17.7: re-introduce to the legacy P10 tree */
    c->created++;
  }
}

/* Phase 3l: create not-yet-live doc users locally + §17.7-gateway each onward to
 * legacy.  Runs on the CR D/U eager-push path (where the gateway actually fires on
 * the gateway node, sub-second) and on the verify timer (the 2-hop anti-entropy
 * fallback).  Idempotent (findNUser inside crdt_materialize_one_user); a
 * tombstoned/deleted user is skipped (data_len mismatch) so a quit user is never
 * re-created.  The inbound-burst collision guard is PER-USER (recon_user_cb, scoped
 * to the legacy uplink toward each user's owning server) — a global gate would wedge
 * forever on a perpetually in-burst services pseudo-server (x3.services). */
void crdt_shadow_reconcile_users(void)
{
  struct recon_user_ctx c = { 0 };
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  /* The burst guard is PER-USER (in recon_user_cb, scoped to the legacy uplink
   * toward each user's owning server), not a global gate here — see the rationale
   * there (x3.services sits perpetually in burst; a global gate would wedge all
   * materialization). */
  crdt_lwwmap_foreach(&g_crdt.users, recon_user_cb, &c);
  if (c.created || c.renamed || c.umoded || c.setnamed || c.attr)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT user-reconcile: created %u, renamed %u, umode %u, setname %u, attr %u user(s) from doc",
              c.created, c.renamed, c.umoded, c.setnamed, c.attr);
}

/* ---- Phase 3m: USER delete-on-leave (QUIT) via CRDT + §17.7 gateway ----
 * The remove half of the USERS cutover (after 3l create / 3n nick / 3o umode) — the
 * genuinely risky one.  Walk LIVE remote users; exit any the doc has EXPLICITLY
 * tombstoned (crdt_user_is_explicitly_removed) — NEVER on mere absence (the 3g
 * sync-lag safety: a not-yet-materialized or lagging user is absent, not deleted).
 * Drive the exit through exit_client(cptr=CRDT uplink, victim, victim) so the real
 * teardown runs (common-channel QUIT to locals, channel/list cleanup) AND its P10
 * QUIT relay — now legacy-only under FEAT_CRDT_PRIMARY (s_misc.c) — becomes the §17.7
 * gateway; the crdt_shadow_user_remove hook inside self-skips (from_crdt_peer of the
 * uplink) so no op is re-minted.  Local users (authoritative here) and bouncer aliases
 * are left alone.  SQUIT stays on P10 (§17.3 server-SPLIT, deferred — its cascade
 * tears down materialized users, and the owning-server-absent guard in
 * crdt_materialize_one_user stops a split server's users from re-materializing).
 * No-op unless FEAT_CRDT_PRIMARY. */
#define CRDT_REMOVE_MAX 256
void crdt_shadow_reconcile_user_removes(void)
{
  struct Client *acptr;
  char victims[CRDT_REMOVE_MAX][CRDT_NUMERICLEN];
  int nv = 0, i, capped = 0;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  /* collect FIRST — exit_client frees clients; never exit mid-walk */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    char num[CRDT_NUMERICLEN];
    if (!IsUser(acptr) || MyUser(acptr) || IsBouncerAlias(acptr))
      continue;
    user_numeric(acptr, num, sizeof num);
    if (!crdt_user_is_explicitly_removed(&g_crdt, num))
      continue;                       /* present / absent / lagging — leave it (safety) */
    if (nv >= CRDT_REMOVE_MAX) { capped = 1; break; }
    ircd_strncpy(victims[nv], num, CRDT_NUMERICLEN);
    nv++;
  }
  for (i = 0; i < nv; i++) {
    struct Client *v = findNUser(victims[i]);   /* re-find: a prior exit may have freed it */
    if (v && IsUser(v) && !MyUser(v) && !IsBouncerAlias(v))
      exit_client(cli_from(v), v, v, "Quit");   /* gateway via the now-legacy-only QUIT relay */
  }
  if (nv)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT user-reconcile: removed %u user(s)%s from doc", nv,
              capped ? " (capped; more next tick)" : "");
}

/* ---- Phase 3j: channel CREATE (channel birth) via CRDT ----
 * Steady-state create-from-doc for a SINGLE not-yet-live channel (the create-half
 * of materialize, lifted to run on every CR D/U + verify tick). Births a channel
 * locally when the doc has present members for it but it isn't live here yet, so
 * the downstream reconcilers (members/modes/bans/member-status) have a channel to
 * act on. Must run BEFORE reconcile_members. LOCAL ONLY — no §17.7 gateway here:
 * legacy learns the channel via the 3f JOIN-gateway (reconcile_members re-emits the
 * founder JOIN with the doc creationtime; ms_join births it) + founder-op via the
 * 3h MODE-gateway. creationtime is the incarnation MIN-register value. */
/* §17.7 birth-modes bridge (3j gap fix, 2026-06-13): rebuild_channel_from_doc
 * applies a channel's persistent modes DIRECTLY at CRDT-birth, so
 * reconcile_mode_cb's echo guard (doc==live) never gateways them — legacy gets
 * the CREATE + member JOINs + member-ops but not the channel modes (AUTOCHANMODES
 * at birth is the motivating case). Collect channels born THIS reconcile pass
 * that carry persistent modes; AFTER reconcile_members has gatewayed their member
 * JOINs (which place the channel on legacy), emit the modes to legacy ONCE.
 * Cycle-local + channel NAMES (re-FindChannel) so a mid-pass destroy is safe;
 * modebuf_flush_nomirror routes via the channel-only suppression to legacy peers
 * only (CRDT peers have them via the doc) — a no-op on a node with no legacy peer. */
#define CRDT_BIRTH_MODES_MAX 32
static char g_birth_modes[CRDT_BIRTH_MODES_MAX][CHANNELLEN + 1];
static int  g_birth_modes_n;

static void birth_modes_record(const char *chname)
{
  if (g_birth_modes_n < CRDT_BIRTH_MODES_MAX)
    ircd_strncpy(g_birth_modes[g_birth_modes_n++], chname, CHANNELLEN + 1);
  else
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT birth-modes: >%d channels born in one pass; %s mode-bridge dropped",
              CRDT_BIRTH_MODES_MAX, chname);
}

void crdt_shadow_gateway_birth_modes(void)
{
  int i;
  for (i = 0; i < g_birth_modes_n; i++) {
    struct Channel *chptr = FindChannel(g_birth_modes[i]);
    struct ModeBuf mbuf;
    unsigned int m;
    if (!chptr)
      continue;
    /* Cluster C follow-up (gateway_birth_modes legacy-render): the bridge
     * previously emitted only CRDT_MODE_MASK bits + key/limit — the Cluster C
     * snapshot extensions (exmode bits and the STRING-ONLY +A/+U/+L, which
     * have no mode.mode bit; gate on string presence) were applied locally at
     * birth but never re-emitted to legacy.  The entry gate must consider all
     * of them, else a channel carrying ONLY extended state is skipped. */
    if (!(chptr->mode.mode & CRDT_MODE_MASK) && !chptr->mode.exmode &&
        !chptr->mode.apass[0] && !chptr->mode.upass[0] && !chptr->mode.redir[0])
      continue;
    m = chptr->mode.mode & CRDT_MODE_MASK & ~(MODE_KEY | MODE_LIMIT);
    modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER);
    if (m)
      modebuf_mode(&mbuf, MODE_ADD | m);
    if (chptr->mode.mode & MODE_LIMIT)
      modebuf_mode_uint(&mbuf, MODE_ADD | MODE_LIMIT, chptr->mode.limit);
    if (chptr->mode.mode & MODE_KEY)
      modebuf_mode_string(&mbuf, MODE_ADD | MODE_KEY, chptr->mode.key, 0);
    if (chptr->mode.apass[0])
      modebuf_mode_string(&mbuf, MODE_ADD | MODE_APASS, chptr->mode.apass, 0);
    if (chptr->mode.upass[0])
      modebuf_mode_string(&mbuf, MODE_ADD | MODE_UPASS, chptr->mode.upass, 0);
    if (chptr->mode.redir[0])
      modebuf_mode_string(&mbuf, MODE_ADD | MODE_REDIRECT, chptr->mode.redir, 0);
    if (chptr->mode.exmode)
      modebuf_exmode(&mbuf, MODE_ADD | chptr->mode.exmode);
    modebuf_flush_nomirror(&mbuf);
  }
  g_birth_modes_n = 0;
}

void crdt_shadow_reconcile_create_channels(void)
{
  unsigned int created = 0;
  int bk;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *dc;
    for (dc = g_crdt.chan_buckets[bk]; dc; dc = dc->next) {
      char nbuf[CHANNELLEN + 1];
      struct Channel *chptr;
      if (crdt_orset_size(&dc->members) == 0)
        continue;                          /* never create an empty channel (destroy-on-empty) */
      if (dc->name_len >= sizeof nbuf)
        continue;
      memcpy(nbuf, dc->name, dc->name_len); nbuf[dc->name_len] = '\0';
      if (FindChannel(nbuf))
        continue;                          /* already live (P10 BURST/CREATE or a prior pass) */
      /* Require a LIVE creationtime incarnation. A channel we locally destructed
       * (ctime_del bumped) but whose doc members haven't yet tombstoned — the
       * P10-QUIT-fast vs CRDT-tombstone-slow skew — has ctime 0; do NOT resurrect
       * it (and never birth a ts=0 channel). It stays dead until the tombstone
       * clears the member, or a genuine new create post-dates the destroy. */
      if (crdt_chan_ctime_get(&g_crdt, nbuf) == 0)
        continue;
      chptr = get_channel(&me, nbuf, CGT_CREATE);   /* &me => server, no SetAutoChanModes */
      if (!chptr)
        continue;
      rebuild_channel_from_doc(chptr, dc, nbuf);
      if (chptr->mode.mode & CRDT_MODE_MASK)
        birth_modes_record(nbuf);        /* bridge birth-modes to legacy after members */
      created++;
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT create-reconcile: created channel %s from doc (ts=%lu)",
                nbuf, (unsigned long)chptr->creationtime);
    }
  }
  if (created)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT create-reconcile: created %u channel(s) from doc", created);
}

/* ---- Phase 3d: TOPIC via CRDT + §17.7 hybrid gateway ----
 * Drive a live channel topic FROM the doc (a topic that propagated over CRDT,
 * not P10) and bridge it to the legacy P10 tree. The send-side suppression of
 * the P10 TOPIC to CRDT peers lives in m_topic.c. */

struct reconcile_topic_ctx { unsigned int *changed; };

static void reconcile_topic_cb(const char *key, uint32_t key_len,
                               const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_topic_ctx *c = ctx;
  char chname[CHANNELLEN + 1];
  struct Channel *chptr;
  const char *doc_topic;
  uint64_t doc_topic_time = 0;
  const struct CrdtLWWValue *cm;
  if (key_len >= sizeof chname || !val->data)
    return;
  memcpy(chname, key, key_len); chname[key_len] = '\0';
  chptr = FindChannel(chname);
  if (!chptr)
    return;                              /* channel not live yet (materialize/BURST) */
  doc_topic = crdt_topic_value_text(val->data, val->data_len, &doc_topic_time);
  if (strcmp(doc_topic, chptr->topic) == 0)
    return;                              /* already in sync — also the echo guard:
                                            a P10 topic sets live+doc together, so
                                            reconcile never bounces it back */
  /* Drive the live topic DIRECTLY — never via do_settopic, so crdt_shadow_topic
   * is not re-invoked and no new op is minted (loop prevention). */
  ircd_strncpy(chptr->topic, doc_topic, TOPICLEN + 1);
  /* M11: topic_time is now authoritative in the topics value (the MAX-register key),
   * so re-emit it — NOT chanmeta's (which converges independently by HLC-LWW and can
   * diverge from the winning topic's time under skew, which would keep the legacy split
   * open). chanmeta still supplies topic_nick provenance. */
  if (doc_topic_time)
    chptr->topic_time = (time_t)doc_topic_time;
  cm = crdt_lwwmap_get(&g_crdt.chanmeta, chname, key_len);
  if (cm && cm->data_len == sizeof(struct CrdtChanMeta)) {
    const struct CrdtChanMeta *meta = (const struct CrdtChanMeta *)cm->data;
    ircd_strncpy(chptr->topic_nick, meta->topic_nick, sizeof chptr->topic_nick - 1);
  }
  /* notify LOCAL clients on this server */
  sendcmdto_channel_butserv_butone(&me, CMD_TOPIC, chptr, NULL, 0, "%H :%s",
                                   chptr, chptr->topic);
  /* §17.7 GATEWAY: bridge to legacy P10 servers only (forbid CRDT-aware — they
   * already have it via CRDT). A no-op on a leaf with no legacy peers. The real
   * setter rides as the %s param so legacy records it. */
  sendcmdto_flag_serv_butone(&me, CMD_TOPIC, NULL, FLAG_LAST_FLAG, FLAG_CRDT_AWARE,
                             "%H %s %Tu %Tu :%s", chptr, chptr->topic_nick,
                             chptr->creationtime, chptr->topic_time, chptr->topic);
  (*c->changed)++;
}

void crdt_shadow_reconcile_topics(void)
{
  unsigned int changed = 0;
  struct reconcile_topic_ctx ctx = { &changed };
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  crdt_lwwmap_foreach(&g_crdt.topics, reconcile_topic_cb, &ctx);
  if (changed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT topic-reconcile: drove %u channel topic(s) from doc", changed);
}

/* ---- Phase 3e: channel MODES via CRDT + §17.7 gateway ---- */

struct reconcile_mode_ctx { unsigned int *changed; };

static void reconcile_mode_cb(const char *key, uint32_t key_len,
                              const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_mode_ctx *c = ctx;
  char chname[CHANNELLEN + 1];
  struct Channel *chptr;
  struct ShadowModeSnap doc, before;
  struct ModeBuf mbuf;
  unsigned int added, removed;
  if (key_len >= sizeof chname)
    return;
  memcpy(chname, key, key_len); chname[key_len] = '\0';
  chptr = FindChannel(chname);
  if (!chptr)
    return;                              /* channel not live yet */
  if (!mode_snap_parse(val->data, val->data_len, &doc))
    return;
  doc.mode &= CRDT_MODE_MASK;            /* mode word carries only simple bits;
                                          * +A/+U/+L ride the snap's string fields */
  build_mode_snap(chptr, &before);
  if (memcmp(&doc, &before, sizeof doc) == 0)
    return;                              /* in sync — echo guard */
  /* drive live DIRECTLY (no set_mode/modebuf -> no crdt_shadow_modes re-mirror) */
  apply_mode_snap(chptr, &doc);
  /* render the +/- delta for local clients + the legacy gateway via modebuf
   * (correct formatting); modebuf_flush_nomirror avoids the re-mirror, and the
   * channel-only suppression routes it to legacy peers only. */
  modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER);
  added   = (doc.mode & ~before.mode) & CRDT_MODE_MASK & ~(MODE_KEY | MODE_LIMIT);
  removed = (before.mode & ~doc.mode) & CRDT_MODE_MASK & ~(MODE_KEY | MODE_LIMIT);
  if (added)
    modebuf_mode(&mbuf, MODE_ADD | added);
  if (removed)
    modebuf_mode(&mbuf, MODE_DEL | removed);
  if (doc.mode & MODE_LIMIT) {
    if (!(before.mode & MODE_LIMIT) || before.limit != doc.limit)
      modebuf_mode_uint(&mbuf, MODE_ADD | MODE_LIMIT, doc.limit);
  } else if (before.mode & MODE_LIMIT)
    modebuf_mode_uint(&mbuf, MODE_DEL | MODE_LIMIT, before.limit);
  if (doc.mode & MODE_KEY) {
    if (!(before.mode & MODE_KEY) || strcmp(before.key, doc.key) != 0)
      modebuf_mode_string(&mbuf, MODE_ADD | MODE_KEY, doc.key, 0);
  } else if (before.mode & MODE_KEY)
    modebuf_mode_string(&mbuf, MODE_DEL | MODE_KEY, before.key, 0);
  modebuf_flush_nomirror(&mbuf);
  (*c->changed)++;
}

void crdt_shadow_reconcile_modes(void)
{
  unsigned int changed = 0;
  struct reconcile_mode_ctx ctx = { &changed };
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  crdt_lwwmap_foreach(&g_crdt.modes, reconcile_mode_cb, &ctx);
  if (changed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT mode-reconcile: drove %u channel(s) from doc", changed);
}

/* ---- Phase 3h: channel MEMBER-OPS (+o/+v/+h) via CRDT + §17.7 gateway ----
 * Drive live per-member status (op/voice/halfop) FROM the doc members_status LWW
 * + bridge to legacy. Send-side suppression of the P10 member-op MODE to CRDT
 * peers lives in channel.c modebuf_flush_int (the crdt_only branch). NB:
 * modebuf_mode_client only QUEUES the wire emit — it does NOT change
 * member->status (the caller does, cf. mode_process_clients) — so set it directly
 * here, then modebuf_flush_nomirror for the local-notify + legacy gateway (no
 * crdt_shadow_modes re-mirror loop). */

struct reconcile_mstatus_ctx { unsigned int *changed; };

static void reconcile_mstatus_cb(const char *key, uint32_t key_len,
                                 const struct CrdtLWWValue *val, void *ctx)
{
  struct reconcile_mstatus_ctx *c = ctx;
  char chname[CHANNELLEN + 1], numbuf[16];
  const char *nul;
  struct Channel *chptr;
  struct Client *u;
  struct Membership *m;
  const struct CrdtMemberRecord *mr;
  unsigned int chlen, numlen, doc_st, live_st, added, removed;
  struct ModeBuf mbuf;
  if (!val->data || val->data_len != sizeof(struct CrdtMemberRecord))
    return;
  /* key = chan '\0' numeric */
  nul = memchr(key, '\0', key_len);
  if (!nul)
    return;
  chlen = (unsigned int)(nul - key);
  numlen = key_len - chlen - 1;
  if (chlen == 0 || chlen >= sizeof chname || numlen == 0 || numlen >= sizeof numbuf)
    return;
  memcpy(chname, key, chlen); chname[chlen] = '\0';
  memcpy(numbuf, nul + 1, numlen); numbuf[numlen] = '\0';
  chptr = FindChannel(chname);
  if (!chptr)
    return;                              /* channel not live */
  u = findNUser(numbuf);
  if (!u)
    return;                              /* user not materialized yet — retry */
  m = find_member_link(chptr, u);
  if (!m)
    return;                              /* not a live member (3f pending / parted) */
  mr = (const struct CrdtMemberRecord *)val->data;
  doc_st  = expand_status(mr->status) & CHFL_VOICED_OR_OPPED;
  live_st = m->status & CHFL_VOICED_OR_OPPED;
  if (doc_st == live_st)
    return;                              /* in sync — echo guard */
  added   = doc_st  & ~live_st;
  removed = live_st & ~doc_st;
  /* drive live DIRECTLY (modebuf_mode_client does not set member->status) */
  m->status  = (m->status & ~CHFL_VOICED_OR_OPPED) | doc_st;
  m->oplevel = mr->oplevel;
  /* emit the +/- delta: local clients (DEST_CHANNEL) + §17.7 legacy gateway
   * (DEST_SERVER, routed legacy-only by the crdt_only branch); nomirror avoids
   * re-minting a CRDT op. */
  modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER);
  if (added & CHFL_CHANOP) modebuf_mode_client(&mbuf, MODE_ADD | MODE_CHANOP, u, m->oplevel);
  if (added & CHFL_HALFOP) modebuf_mode_client(&mbuf, MODE_ADD | MODE_HALFOP, u, m->oplevel);
  if (added & CHFL_VOICE)  modebuf_mode_client(&mbuf, MODE_ADD | MODE_VOICE,  u, m->oplevel);
  if (removed & CHFL_CHANOP) modebuf_mode_client(&mbuf, MODE_DEL | MODE_CHANOP, u, m->oplevel);
  if (removed & CHFL_HALFOP) modebuf_mode_client(&mbuf, MODE_DEL | MODE_HALFOP, u, m->oplevel);
  if (removed & CHFL_VOICE)  modebuf_mode_client(&mbuf, MODE_DEL | MODE_VOICE,  u, m->oplevel);
  modebuf_flush_nomirror(&mbuf);
  (*c->changed)++;
}

void crdt_shadow_reconcile_member_status(void)
{
  unsigned int changed = 0;
  struct reconcile_mstatus_ctx ctx = { &changed };
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  crdt_lwwmap_foreach(&g_crdt.members_status, reconcile_mstatus_cb, &ctx);
  if (changed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT member-status-reconcile: drove %u member(s) from doc", changed);
}

/* ---- Phase 3i: channel BANS/EXCEPTS (+b/+e) via CRDT + §17.7 gateway ----
 * Drive live ban/except lists FROM the doc bans/excepts OR-Sets + bridge to legacy.
 * ADD (3f pattern) for present-not-live masks; tombstone-gated REMOVE (3g pattern,
 * crdt_orset_is_explicitly_removed) for live masks the doc explicitly removed. Both
 * directions are suppressed to CRDT peers (channel.c modebuf_is_crdt_only), so there
 * is no P10-fast/CRDT-slow skew. modebuf_flush_nomirror skips crdt_shadow_lists →
 * no re-mirror loop. The doc OR-Set key == the live Ban->banstr (both normalized via
 * pretty_extmask before storage), so make_ban(key)/mask_in_banlist are idempotent. */

struct reconcile_ban_ctx { struct Ban **livehead; unsigned int modeflag;
                           struct ModeBuf *mbuf; unsigned int *changed; };

static void reconcile_ban_add_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct reconcile_ban_ctx *c = ctx;
  char mask[CRDT_MASKLEN];
  uint32_t l = key_len < CRDT_MASKLEN - 1 ? key_len : CRDT_MASKLEN - 1;
  struct Ban *nb;
  char *dup;
  memcpy(mask, key, l); mask[l] = '\0';
  if (mask_in_banlist(*c->livehead, mask))   /* already live — echo guard / idempotent */
    return;
  nb = make_ban(mask);
  if (!nb)
    return;
  ircd_strncpy(nb->who, "*", sizeof nb->who);
  nb->when = TStime();
  nb->next = *c->livehead;
  *c->livehead = nb;
  DupString(dup, mask);                       /* modebuf frees it (free=1) post-flush */
  modebuf_mode_string(c->mbuf, MODE_ADD | c->modeflag, dup, 1);
  (*c->changed)++;
}

static void reconcile_one_banlist(struct CrdtORSet *docset, struct Ban **livehead,
                                  unsigned int modeflag, struct ModeBuf *mbuf,
                                  unsigned int *changed)
{
  struct reconcile_ban_ctx ctx;
  struct Ban **pp;
  ctx.livehead = livehead; ctx.modeflag = modeflag; ctx.mbuf = mbuf; ctx.changed = changed;
  /* ADD: doc-present masks not yet live (foreach yields present-only) */
  crdt_orset_foreach(docset, reconcile_ban_add_cb, &ctx);
  /* REMOVE: live masks the doc has EXPLICITLY tombstoned (never on mere absence).
   * pointer-to-pointer unlink idiom — no destruct hazard (bans don't empty channels). */
  pp = livehead;
  while (*pp) {
    struct Ban *b = *pp;
    if (crdt_orset_is_explicitly_removed(docset, b->banstr, (uint32_t)strlen(b->banstr))) {
      char *dup;
      DupString(dup, b->banstr);
      modebuf_mode_string(mbuf, MODE_DEL | modeflag, dup, 1);
      *pp = b->next;
      free_ban(b);
      (*changed)++;
    } else {
      pp = &b->next;
    }
  }
}

void crdt_shadow_reconcile_bans(void)
{
  unsigned int changed = 0;
  int bk;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *dc;
    for (dc = g_crdt.chan_buckets[bk]; dc; dc = dc->next) {
      char nbuf[CHANNELLEN + 1];
      struct Channel *chptr;
      struct ModeBuf mbuf;
      if (dc->name_len >= sizeof nbuf)
        continue;
      memcpy(nbuf, dc->name, dc->name_len); nbuf[dc->name_len] = '\0';
      chptr = FindChannel(nbuf);
      if (!chptr)
        continue;                            /* never create a channel here */
      modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER);
      reconcile_one_banlist(&dc->bans, &chptr->banlist, MODE_BAN, &mbuf, &changed);
      reconcile_one_banlist(&dc->excepts, &chptr->exceptlist, MODE_EXCEPT, &mbuf, &changed);
      modebuf_flush_nomirror(&mbuf);
    }
  }
  if (changed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT ban-reconcile: drove %u ban/except change(s) from doc", changed);
}

/* ---- Phase 3f: channel MEMBERSHIP (JOIN-add) via CRDT + §17.7 gateway ----
 * Drive live channel membership FROM the doc (a JOIN that propagated over CRDT,
 * not P10) and bridge it to the legacy P10 tree. Send-side suppression of the
 * P10 JOIN to CRDT peers lives in channel.c joinbuf_join. ADD direction ONLY —
 * delete-on-leave (PART/KICK/QUIT) stays on P10 (deferred to 3g). The doc OR-Set
 * yields only present (non-tombstoned) members, so a parted member is never
 * re-added; find_member_link is the per-member echo/idempotency guard. */

struct reconcile_member_ctx { struct Channel *chptr; const char *chname; unsigned int *changed; };

static void reconcile_member_cb(const char *key, uint32_t key_len, void *ctx)
{
  struct reconcile_member_ctx *c = ctx;
  char numbuf[16];
  struct Client *u;
  if (key_len >= sizeof numbuf)
    return;
  memcpy(numbuf, key, key_len); numbuf[key_len] = '\0';
  u = findNUser(numbuf);
  if (!u)                                  /* user not materialized yet — retry */
    return;
  if (find_member_link(c->chptr, u))       /* already a member — echo guard / idempotent */
    return;
  /* Plain member: ops/voice/oplevel ride 3h members_status (reconcile_member_status),
   * so a 3f JOIN-add carries no status. Drive live DIRECTLY — add_user_to_channel's
   * crdt_shadow_join hook self-gates on from_crdt_peer(cli_from(u)) (true here),
   * so no op is re-minted (loop prevention; no nomirror variant needed).
   * oplevel = MAXOPLEVEL+1 ("no oplevel"); passing 0 here (the old bug) made every
   * reconciled member founder-oplevel → unkickable by ops + outranks them in apass
   * channels. An actual op's oplevel is corrected by 3h when its status reconciles. */
  add_user_to_channel(c->chptr, u, 0, MAXOPLEVEL + 1);
  /* notify LOCAL clients (same EXTJOIN-aware pair as joinbuf_join) */
  sendcmdto_channel_capab_butserv_butone(u, CMD_JOIN, c->chptr, NULL, 0,
                                         CAP_NONE, CAP_EXTJOIN, "%H", c->chptr);
  sendcmdto_channel_capab_butserv_butone(u, CMD_JOIN, c->chptr, NULL, 0,
                                         CAP_EXTJOIN, CAP_NONE, "%H %s :%s", c->chptr,
                                         IsAccount(u) ? cli_account(u) : "*", cli_info(u));
  /* §17.7 GATEWAY: re-emit JOIN onto legacy P10 servers only (forbid CRDT-aware —
   * they already have it via CRDT). A no-op on a leaf with no legacy peers.
   * Tier2 P1: skip for a mesh-only joiner — legacy SQUIT'd its server and never got
   * its NICK, so a JOIN would reference an unknown user. */
  if (!crdt_user_is_mesh_only(u))
    sendcmdto_flag_serv_butone(u, CMD_JOIN, NULL, FLAG_LAST_FLAG, FLAG_CRDT_AWARE,
                               "%H %Tu", c->chptr, c->chptr->creationtime);
  (*c->changed)++;
}

void crdt_shadow_reconcile_members(void)
{
  unsigned int changed = 0;
  int bk;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *dc;
    for (dc = g_crdt.chan_buckets[bk]; dc; dc = dc->next) {
      char nbuf[CHANNELLEN + 1];
      struct Channel *chptr;
      struct reconcile_member_ctx mc;
      if (crdt_orset_size(&dc->members) == 0)
        continue;
      if (dc->name_len >= sizeof nbuf)
        continue;
      memcpy(nbuf, dc->name, dc->name_len); nbuf[dc->name_len] = '\0';
      chptr = FindChannel(nbuf);
      if (!chptr)
        continue;                          /* 3f: never create a channel here — channel
                                              birth/death stays on P10 (CREATE/PART) */
      mc.chptr = chptr; mc.chname = nbuf; mc.changed = &changed;
      crdt_orset_foreach(&dc->members, reconcile_member_cb, &mc);
    }
  }
  if (changed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT member-reconcile: added %u member(s) from doc", changed);
}

/* ---- Phase 3g: channel MEMBERSHIP remove (PART / delete-on-leave) ---- */
/* Drive a live membership REMOVE from the doc + §17.7 gateway. Send-side
 * suppression of the P10 PART to CRDT peers lives in channel.c joinbuf_flush.
 * SAFETY: removes a live member ONLY when the doc has EXPLICITLY tombstoned it
 * (crdt_orset_is_explicitly_removed) — NEVER on mere absence (sync lag / a
 * not-yet-seen JOIN / a P10-only member). KICK/QUIT still ride P10; their
 * mirrored tombstones make this a harmless backstop (member already gone → the
 * walk finds nothing to remove). PART comment is not carried by the tombstone. */
void crdt_shadow_reconcile_removes(void)
{
  unsigned int changed = 0;
  int bk;
  if (!shadow_on() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  for (bk = 0; bk < CRDT_CHAN_BUCKETS; bk++) {
    struct CrdtChannel *dc;
    for (dc = g_crdt.chan_buckets[bk]; dc; dc = dc->next) {
      char nbuf[CHANNELLEN + 1];
      if (dc->name_len >= sizeof nbuf)
        continue;
      memcpy(nbuf, dc->name, dc->name_len); nbuf[dc->name_len] = '\0';
      /* Re-FindChannel each pass: remove_user_from_channel can SYNCHRONOUSLY
       * destruct chptr when the last member leaves (channel.c:413/424), so we
       * never hold chptr across a removal. */
      for (;;) {
        struct Channel *chptr = FindChannel(nbuf);
        struct Membership *m;
        struct Client *victim = NULL;
        char num[16];
        if (!chptr)
          break;                           /* not live, or destructed by a prior removal */
        for (m = chptr->members; m; m = m->next_member) {
          if (IsMemberAlias(m))            /* aliases aren't real members (handled elsewhere) */
            continue;
          user_numeric(m->user, num, sizeof num);
          if (!crdt_orset_is_explicitly_removed(&dc->members, num, strlen(num)))
            continue;
          /* Membership RE-ASSERT (2026-07-26): every legitimate removal of a LOCAL
           * member applies LIVE-FIRST (voluntary PART / REMOVE / SVSPART hit the
           * live state before their doc mint, so by reconcile time the member is
           * already gone) — a doc tombstone that still finds a LIVE MyUser member
           * and carries no KICK attribution is therefore presumptively reap
           * residue (decommission / orphan-members sweep of a wrongly-presumed-
           * dead server healing over its still-connected users).  I am the
           * authority for my own users' presence: refuse the de-part and re-mint
           * the membership + status instead (crdt_shadow_join — a fresh add-tag
           * beats the old tombstones by OR-Set semantics and restores the member
           * network-wide; the mainland re-JOINs the materialized copy).  A remote
           * KICK-via-doc (mesh-only kicker) still applies via the kick_info gate
           * below — fall through to victim selection for those. */
          if (MyUser(m->user)) {
            const struct CrdtLWWValue *kv = crdt_kick_info_get(&g_crdt, nbuf, num);
            const struct CrdtLWWValue *mv = crdt_member_status_get(&g_crdt, nbuf, num);
            int is_kick = kv && kv->data &&
                          kv->data_len == sizeof(struct CrdtKickInfo) &&
                          (!mv || hlc_compare(&kv->ts, &mv->ts) > 0);
            if (!is_kick) {
              log_write(LS_SYSTEM, L_NOTICE, 0,
                        "CRDT membership re-assert: re-minting %s on %s "
                        "(live local member, unattributed doc removal)",
                        num, nbuf);
              crdt_shadow_join(chptr, m->user, m->status);
              continue;                    /* not a victim — keep scanning */
            }
          }
          victim = m->user;
          break;
        }
        if (!victim)
          break;                           /* no tombstoned-but-live members remain */
        /* victim is still a member: notify locals + §17.7 gateway to legacy, THEN
         * remove. remove_user_from_channel mirrors via crdt_shadow_part, but its
         * from_crdt_peer self-gate (victim's cli_from is a CRDT peer) suppresses
         * the re-mint — no loop, no nomirror needed.
         *
         * Phase 3k: KICK-vs-PART. If there is fresh kick metadata for this victim
         * (kick_info written AFTER the member's last join — the members_status HLC
         * gate keeps a stale kick from re-tagging a later plain PART), emit a KICK
         * with attribution; otherwise a PART (3g). `num` holds the victim numeric. */
        {
          const struct CrdtLWWValue *kv = crdt_kick_info_get(&g_crdt, nbuf, num);
          const struct CrdtLWWValue *mv = crdt_member_status_get(&g_crdt, nbuf, num);
          int is_kick = kv && kv->data &&
                        kv->data_len == sizeof(struct CrdtKickInfo) &&
                        (!mv || hlc_compare(&kv->ts, &mv->ts) > 0);
          /* Tier2 P1: a mesh-only victim was never NICK'd to legacy peers (they
           * SQUIT'd its server), so skip the §17.7 legacy KICK/PART for it — local
           * clients still get the notify; CRDT peers handle it via the doc. */
          int victim_mesh_only = crdt_user_is_mesh_only(victim);
          if (is_kick) {
            const struct CrdtKickInfo *ki = (const struct CrdtKickInfo *)kv->data;
            struct Client *kicker = ki->kicker[0] ? findNUser(ki->kicker) : NULL;
            struct Client *from = kicker ? kicker : &me;   /* fall back to server-kick */
            sendcmdto_channel_butserv_butone(from, CMD_KICK, chptr, NULL, 0,
                                             "%H %C :%s", chptr, victim, ki->reason);
            if (!victim_mesh_only)
              sendcmdto_flag_serv_butone(from, CMD_KICK, NULL, FLAG_LAST_FLAG,
                                         FLAG_CRDT_AWARE, "%H %C :%s", chptr, victim,
                                         ki->reason);
          } else {
            sendcmdto_channel_butserv_butone(victim, CMD_PART, chptr, NULL, 0, "%H", chptr);
            if (!victim_mesh_only)
              sendcmdto_flag_serv_butone(victim, CMD_PART, NULL, FLAG_LAST_FLAG,
                                         FLAG_CRDT_AWARE, "%H", chptr);
          }
        }
        remove_user_from_channel(victim, chptr);   /* chptr may be freed here */
        changed++;
      }
    }
  }
  if (changed)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT member-reconcile: removed %u member(s) from doc", changed);
}

/* ---- Phase 2 wire-sync accessors ---- */

int crdt_shadow_active(void)
{
  return shadow_on();
}

int crdt_shadow_doc_ready(void)
{
  struct Client *acptr;
  uint32_t live = 0, doc;
  if (!shadow_on())
    return 0;
  /* The doc may serve as the authoritative BURST replacement only if it is a
   * COMPLETE picture of live state: non-empty AND at least as many users as we
   * have live. At cold boot the doc lags live (mirrored as P10 arrives), so this
   * is false -> the burst-skip falls back to a normal P10 BURST (no regression).
   * Once converged it is true -> peers get a full CR F snapshot to materialize. */
  doc = crdt_lwwmap_size(&g_crdt.users);
  if (doc == 0)
    return 0;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsUser(acptr) && !IsBouncerAlias(acptr))
      live++;
  return doc >= live;
}

int crdt_shadow_encode_sv(uint8_t *buf, size_t cap)
{
  if (!g_inited)
    return -1;
  return crdt_sv_encode(&g_crdt.local_sv, buf, cap);
}

int crdt_shadow_encode_delta(const uint8_t *remote_sv, size_t sv_len,
                             uint8_t *buf, size_t cap)
{
  struct CrdtStateVector rsv;
  if (!g_inited)
    return -1;
  if (crdt_sv_decode(&rsv, remote_sv, sv_len) < 0)
    return -1;
  return crdt_delta_encode(&g_crdt.oplog, &rsv, buf, cap);
}

int crdt_shadow_apply_delta(const uint8_t *buf, size_t len)
{
  if (!g_inited)
    return -1;
  return crdt_delta_apply(&g_crdt, buf, len);
}

int crdt_shadow_encode_local_unpushed(uint8_t *buf, size_t cap)
{
  static struct CrdtStateVector synth;   /* static: avoid a 32KB stack frame */
  int i, n;
  if (!g_inited)
    return -1;
  /* synthetic SV: "peer" has everything EXCEPT our own ops above the high-water
   * mark -> crdt_delta_encode emits exactly our unpushed own-origin ops. */
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    synth.seq[i] = (uint64_t)-1;
  synth.seq[g_crdt.my_numeric] = g_last_pushed_seq;
  n = crdt_delta_encode(&g_crdt.oplog, &synth, buf, cap);
  if (n > 4)                             /* ops emitted -> consume them */
    g_last_pushed_seq = g_crdt.local_sv.seq[g_crdt.my_numeric];
  return n;
}

uint64_t crdt_shadow_digest(void)
{
  return g_inited ? crdt_state_digest(&g_crdt) : 0;
}

/* Tier2 T2-b: doc lookup of a user record by numeric, for CR M source-prefix
 * reconstruction (the sender may not be live on a tree-split server, but the
 * converged doc still has its nick/ident/host). */
const struct CrdtUserRecord *crdt_shadow_user_record(const char *numeric)
{
  if (!g_inited || !numeric)
    return NULL;
  return crdt_user_get(&g_crdt, numeric);
}

int crdt_shadow_encode_snapshot(uint8_t *buf, size_t cap)
{
  return g_inited ? crdt_snapshot_encode(&g_crdt, buf, cap) : -1;
}

int crdt_shadow_apply_snapshot(const uint8_t *buf, size_t len)
{
  return g_inited ? crdt_snapshot_apply(&g_crdt, buf, len) : -1;
}

int crdt_shadow_peer_behind_floor(const uint8_t *sv, size_t len)
{
  static struct CrdtStateVector peer;   /* static: avoid a 32KB stack frame */
  int i;
  if (!g_inited)
    return 0;
  if (crdt_sv_decode(&peer, sv, len) < 0)
    return 0;
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    if (peer.seq[i] < g_crdt.gc_floor.seq[i])
      return 1;
  return 0;
}

/* Tier2 Fix A (digest-aware anti-entropy): returns 1 iff the peer's state vector
 * equals OUR local SV on every origin.  When the SVs are equal a delta would be
 * empty, so an equal-SV-but-different-DIGEST peer is the SV-invisible divergence
 * that the delta path can never repair (a pair-local CR F snapshot is the only
 * content-level reconcile, crdt_wire.c bypasses SV dedup).  Gating the snapshot
 * escalation on SV-equality keeps it from firing during normal op-lag, when the
 * SVs differ and the ordinary delta already heals the gap. */
int crdt_shadow_sv_equal(const uint8_t *sv, size_t len)
{
  static struct CrdtStateVector peer;   /* static: avoid a 32KB stack frame */
  int i;
  if (!g_inited)
    return 0;
  if (crdt_sv_decode(&peer, sv, len) < 0)
    return 0;
  for (i = 0; i < CRDT_MAX_SERVERS; i++)
    if (peer.seq[i] != g_crdt.local_sv.seq[i])
      return 0;
  return 1;
}

void crdt_shadow_record_peer_sv(uint16_t origin, const uint8_t *sv, size_t len)
{
  int i, slot = -1;
  if (!g_inited)
    return;
  for (i = 0; i < CRDT_MAX_PEERS; i++) {
    if (g_peers[i].used && g_peers[i].origin == origin) { slot = i; break; }
    if (slot < 0 && !g_peers[i].used) slot = i;
  }
  if (slot < 0)
    return;                                  /* table full */
  if (crdt_sv_decode(&g_peers[slot].sv, sv, len) < 0)
    return;
  g_peers[slot].used = 1;
  g_peers[slot].origin = origin;
  g_peers[slot].when = CurrentTime;
}

/* SV cached for a peer numeric (from CR S / CR V), or NULL if not yet reported. */
static const struct CrdtStateVector *peer_sv_lookup(uint16_t origin)
{
  int i;
  for (i = 0; i < CRDT_MAX_PEERS; i++)
    if (g_peers[i].used && g_peers[i].origin == origin)
      return &g_peers[i].sv;
  return NULL;
}

/* Causal-stability GC: reclaim everything below the component-wise min of (our
 * SV, each CONNECTED CRDT peer's SV). Inclusion is by live connection state, not
 * by last-CR-S timestamp: a peer that is currently linked is always counted
 * (with its best-known SV, or all-zero if it hasn't reported yet -> conservative,
 * blocks GC of its component until it does). A peer that has SQUIT simply isn't
 * in the list, so GC advances past it and a CR F snapshot catches it up on
 * rejoin. (The old timestamp-staleness flapped whenever stale_timeout fell below
 * the CR S broadcast interval, risking reclaiming ops a live-but-quiet peer
 * still needed.) This is correct for ANY connected topology, not just a star:
 * a server only ever sends deltas to its direct peers and retains each op until
 * ALL of them have it, and received ops relay hop-by-hop (crdt_state_apply_op
 * re-appends to the oplog). So an op always survives on the frontier between the
 * has-it and lacks-it regions until it finishes propagating -- no transitive
 * (CR V) SV flooding is needed. Proven by test_multihop_relay_gc_converges. */
static void crdt_shadow_gc(void)
{
  static struct CrdtStateVector gmin;        /* static: avoid a 32KB stack frame */
  static struct CrdtStateVector zero;        /* all-zero, for an unreported peer */
  const struct CrdtStateVector *vecs[CRDT_MAX_PEERS + 1];
  int n = 0, npeers = 0, freed;
  struct Client *acptr;
  if (!shadow_on())
    return;
  vecs[n++] = &g_crdt.local_sv;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    /* Phase 4b: include CR-only overlay peers, not just P10 server links — the
     * GC floor must account for EVERY transport that could still owe a peer an
     * op (esp. a peer reachable only via the overlay during a P10 split).  A
     * peer reachable via both transports resolves to the same numeric-keyed SV
     * slot, so the duplicate vecs[] entry is idempotent under crdt_sv_global_min. */
    if (IsCrdtSyncTarget(acptr)) {
      const struct CrdtStateVector *sv =
        peer_sv_lookup((uint16_t)base64toint(cli_yxx(acptr)));
      vecs[n++] = sv ? sv : &zero;
      npeers++;
      if (n > CRDT_MAX_PEERS)
        break;
    }
  }
  if (npeers < 1)
    return;                                  /* no connected CRDT peer */
  crdt_sv_global_min(&gmin, vecs, n);
  /* reclaim orphaned per-member metadata (members_status/kick_info for fully-departed
   * members) by minting DELETE ops FIRST, so this pass's GC can already start
   * reclaiming any that became causally stable. */
  {
    int orph = crdt_state_reclaim_orphan_member_meta(&g_crdt);
    if (orph > 0)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT GC: reclaimed %d orphan member-meta entr(ies) (departed members)",
                orph);
  }
  {
    int orph = crdt_state_reclaim_orphan_chan_meta(&g_crdt);
    if (orph > 0)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT GC: reclaimed %d orphan chan-meta entr(ies) (gone channels)",
                orph);
  }
  {
    /* M9 backstop: departed-user silence masks the synchronous crdt_user_remove reap
     * never saw (home SQUIT/crash with the user still live). */
    int orph = crdt_state_reclaim_orphan_silences(&g_crdt);
    if (orph > 0)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT GC: reclaimed %d orphan silence mask(s) (departed users)",
                orph);
  }
  {
    /* Orphan-reap 2026-07-26: partition-cycle member residue — membership add-tags
     * of users wholly gone from the users collection (their member-remove tombstones
     * were GC'd across a partition; the healed node's still-present adds re-merged
     * network-wide).  GC-cycle-only like its sibling reclaims: the residue is inert
     * doc state, no live gate races it (the F3 eager-suite rule is for new
     * collections, not sweeps). */
    int orph = crdt_state_reclaim_orphan_members(&g_crdt);
    if (orph > 0)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT GC: reclaimed %d orphan channel member(s) (departed users)",
                orph);
  }
  {
    /* Tier C F3: same backstop for tempshun registers (departed victims). */
    int orph = crdt_state_reclaim_orphan_tempshuns(&g_crdt);
    if (orph > 0)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT GC: reclaimed %d orphan tempshun register(s) (departed users)",
                orph);
  }
  freed = crdt_state_gc(&g_crdt, &gmin);
  if (freed > 0)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT GC: reclaimed %d op/tombstone(s) (causally stable)", freed);
}

/** Periodic timer callback. */
static void crdt_shadow_verify_cb(struct Event *ev)
{
  if (ev_type(ev) != ET_EXPIRE)
    return;
  /* Phase 4c: no servers-map self-assert — reachability is a local determination
   * (FindNServer at the materialize gate), not replicated doc state. */
  crdt_shadow_verify(NULL);         /* NULL -> the system log (timer path) */
  crdt_shadow_materialize_check();  /* Phase 3b dry-run: doc -> live fidelity */
  /* B0/MR-3d: present every fresh mesh server to legacy BEFORE the reconcile suite, so the
   * SERVER intros precede the user NICKs the now-ungated §17.7 gates emit below (same tick).
   * Backstop for the CR-H ingest fast path; gateway-only + flag-gated internally. */
  crdt_shadow_present_mesh_servers();
  /* Phase 3l: create+gateway users BEFORE materialize_live (the bulk path creates
   * users locally but never gateways; running reconcile_users first lets it §17.7-
   * introduce a not-yet-live user to legacy, after which materialize_live no-ops it).
   * Self-guards against a concurrent burst. */
  crdt_shadow_reconcile_users();
  /* Phase 3c: idempotent create-from-doc. Run it only when NO inbound burst is
   * in progress, so we never pre-create a user that a P10 BURST is still about
   * to deliver (which would collide). In steady state every entity is already
   * live so this creates nothing (Stage-1 crash-free proof); it is also the
   * post-burst retry that heals SERVER-tree-race skips once the cutover is on.
   * The during-burst create path (when BURST was skipped) is the CR F trigger. */
  {
    struct Client *acptr;
    int bursting = 0;
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
      if (IsServer(acptr) && IsBurstOrBurstAck(acptr)) { bursting = 1; break; }
    if (!bursting)
      crdt_shadow_materialize_live();
  }
  crdt_shadow_reconcile_topics();  /* Phase 3d: drive live topics from CRDT (+gateway) —
                                      catches 2-hop foreign-origin topics via anti-entropy */
  crdt_shadow_reconcile_modes();   /* Phase 3e: same for persistent channel modes */
  crdt_shadow_reconcile_create_channels(); /* Phase 3j: birth channels from doc before members */
  crdt_shadow_reconcile_members(); /* Phase 3f: same for channel membership (JOIN-add) */
  crdt_shadow_gateway_birth_modes(); /* 3j gap fix: bridge birth-modes AFTER members place the channel on legacy */
  crdt_shadow_reconcile_removes(); /* Phase 3g: membership remove (PART / delete-on-leave) */
  crdt_shadow_reconcile_member_status(); /* Phase 3h: per-member status (+o/+v/+h) */
  crdt_shadow_reconcile_bans();    /* Phase 3i: channel bans/excepts (+b/+e) */
  crdt_shadow_reconcile_user_removes(); /* Phase 3m: QUIT / delete-on-leave (after channel cleanup) */
  crdt_shadow_stale_user_scan();   /* orphan-reap Inc 1: detect-and-log stale-materialization ghosts (absent-from-doc) the tombstone-only reap left behind */
  crdt_shadow_own_user_sweep();    /* orphan-reap owner sweep: reap MY-origin doc records with no live client (resurrection zombies / restart residue / hookless teardowns) */
  crdt_shadow_own_user_reassert(); /* recovery completion: re-mint records of live local users the doc lost (wrong-decommission heal) */
  crdt_shadow_ch_storage_publish(); /* 5-5f B2: publish our CH storage capability (change-gated, so idle ticks are free) */
  crdt_shadow_ch_storage_synth_to(NULL); /* 5-5f B4: synth doc-known stores to legacy links (change-gated per leaf — covers stores that appear AFTER the legacy link's EOB) */
  crdt_shadow_decomm_sweep();      /* decommission standing sweep: reap residue of operator-asserted-dead servers; auto-dissolve on return */
  crdt_shadow_reconcile_glines();  /* GLINE step 3: drive global G-lines from doc (+gateway) */
  crdt_shadow_reconcile_shuns();   /* SHUN: drive global Shuns from doc (+gateway) */
  crdt_shadow_reconcile_markers(); /* Tier C F2-a: drive read-markers from doc -> RocksDB */
  crdt_shadow_reconcile_metadata(); /* Tier C F2-b: drive account metadata from doc -> metadata_cf */
  crdt_shadow_reconcile_tempshuns(); /* Tier C F3: apply tempshun flips on the victim's home server */
  crdt_shadow_reconcile_webpush(); /* Tier C F2-c: drive webpush subs from doc -> LMDB */
  crdt_shadow_reconcile_zlines();  /* ZLINE: drive global Z-lines from doc (+gateway) */
  crdt_shadow_reconcile_jupes();   /* JUPE: drive juped servers from doc (+gateway) */
  bounce_crdt_bsess_sweep();       /* 5-5e M2: mirror local-holder bouncer sessions -> doc (shadow) */
  crdt_shadow_reconcile_bouncer(); /* 5-5e M6a: doc -> live replica sessions (FEAT_CRDT_BOUNCER_DOC; inert while relay flows) */
  { uint32_t bs = crdt_lwwmap_size(&g_crdt.bsessions);   /* M2 convergence signal: same on every node */
    uint32_t bc = crdt_lwwmap_size(&g_crdt.bconns);      /* M4 convergence signal */
    uint32_t bl = crdt_lwwmap_size(&g_crdt.bleases);     /* M5 convergence signal (per-node, incl. non-holders) */
    if (bs || bc || bl)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "CRDT bouncer doc: %u session(s), %u connection(s), %u lease(s)", bs, bc, bl); }
  crdt_sync_broadcast();   /* periodic anti-entropy: pull deltas from peers */
  crdt_shadow_gc();        /* reclaim causally-stable ops/tombstones */

  /* Tier2 full-partition liveness: emit our beacon, then retire any mesh stub
   * whose beacon has gone stale (no CR H for CRDT_BEACON_STALE s -> the peer is
   * unreachable via ANY CRDT path -> full/permanent partition).  Collect-then-
   * retire (retire frees the stub + its users -> can't free a live iterator). */
  crdt_gossip_beacon();
  crdt_shadow_presence_diff(NULL);  /* Tier-2 S1 shadow oracle: log signal divergences (no mutation) */
  crdt_shadow_route_diff(NULL);     /* MR-0 routing oracle: mesh next-hop vs P10 tree (no mutation) */
  crdt_shadow_legacy_presence_diff(NULL); /* MR-3a oracle: legacy P10-present vs proxy-beacon-fresh */
  {
    struct Client *acptr, *stale[16];
    int ns = 0, k;
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      if (IsMeshStub(acptr)) {
        /* U6 (Design B): tick-counted liveness.  A CR H beacon seen since the last
         * tick (seen_since_tick, set in crdt_shadow_beacon_record above the relay
         * gate) resets the miss counter; CRDT_BEACON_MISS_TICKS consecutive silent
         * ticks (90s) = the peer is unreachable via ANY CRDT path -> retire.  This
         * replaces the CurrentTime-recv_ts delta that a forward wall-clock step made
         * exceed the window for every stub in a single tick (the U6 mass-reap). */
        unsigned int n = (unsigned int)base64toint(cli_yxx(acptr));
        int seen;
        if (n >= CRDT_MAX_SERVERS)
          continue;
        seen = crdt_beacon[n].seen_since_tick;
        crdt_beacon[n].seen_since_tick = 0;          /* consume for the next window */
        if (crdt_beacon_tick_stale(seen, &crdt_beacon[n].miss_ticks) && ns < 16)
          stale[ns++] = acptr;
      } else if (IsCrdtOverlay(acptr) && MyConnect(acptr) && !IsDead(acptr)) {
        /* U6 overlay change-detector: an overlay has no server numeric (never
         * SetServerYXX) so it cannot key crdt_beacon[]; its liveness signal is
         * socket-read activity (cli_lasttime, refreshed by read_packet on every CR).
         * Compare two same-epoch reads for INEQUALITY (step-robust, no CurrentTime
         * delta): a read since the last tick moved cli_lasttime -> reset; no read ->
         * ++miss.  crdt_overlay_is_stale (check_pings) reads the con_ov_miss verdict. */
        struct Connection *con = cli_connect(acptr);
        int seen = (cli_lasttime(acptr) != con_ov_lastseen(con));
        if (seen)
          con_ov_lastseen(con) = cli_lasttime(acptr);
        crdt_beacon_tick_stale(seen, &con_ov_miss(con));
      }
    }
    for (k = 0; k < ns; k++)
      crdt_shadow_retire_mesh_stub(stale[k], "mesh beacon stale (full partition)");
  }
}

void crdt_shadow_init(uint16_t my_numeric)
{
  if (g_inited)
    return;
  crdt_state_init(&g_crdt, my_numeric);
  /* Restart-epoch defense: seed next_seq from the wall clock (ms) so a restarted
   * server's freshly-reset op sequence never reuses seqs from a previous
   * incarnation that peers still remember in their state vectors (which would
   * dedup the post-restart ops via crdt_sv_has_seen).  crdt_state_resume_seq()
   * additionally lifts next_seq past any SV adopted from a peer snapshot/delta.
   * (Engine crdt_state_init keeps next_seq=1 so the cmocka suite stays
   * deterministic; the wall-clock seed is a live-integration concern.) */
  {
    struct HLC seed = hlc_local_event(&g_crdt.clock);
    if (seed.physical_ms > g_crdt.next_seq)
      g_crdt.next_seq = seed.physical_ms;
  }
  g_inited = 1;
  timer_add(timer_init(&g_verify_timer), crdt_shadow_verify_cb, 0,
            TT_PERIODIC, CRDT_VERIFY_INTERVAL);
}
