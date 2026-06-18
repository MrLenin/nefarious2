/*
 * m_crdt.c - CR (CRDT sync) P10 token handler (Phase 2)
 *
 * Wires together the pieces built earlier: the 'C' capability flag
 * (negotiation), s2s_chunk (reassembly), crdt_wire (serialization), and the
 * shadow document (via crdt_shadow_* accessors). Additive and non-authoritative
 * — P10 BURST stays the source of truth; CR only flows between CRDT-aware peers
 * and only when FEAT_CRDT_ENABLED.
 *
 * Wire shapes (S2S):
 *   <src> CR S :<b64(state_vector)>            request: my SV, send me the delta
 *   <src> CR D <id> <+|.> :<b64_chunk>         delta chunk (+ = more follows)
 *   <src> CR U <id> <+|.> :<b64_chunk>         incremental update chunk
 *   <src> CR F <id> <+|.> :<b64_chunk>         full-snapshot chunk (CR F)
 *   <src> CR V :<b64(state_vector)>            version broadcast (GC)
 */

#include "config.h"

#include "capab.h"        /* Tier2 T2-b: CAP_MSGTAGS gate for CR M TAGMSG delivery */
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"  /* MR-1: ircd_snprintf (route target numeric) */
#include "handlers.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"
#include "crdt_state.h"   /* Tier2 T2-b: struct CrdtUserRecord (CR M source prefix) */
#include "ircd_string.h"  /* Tier2 T2-b: ircd_strncpy (msgid dedup ring) */
#include "channel.h"      /* Tier2 T2-b: Membership (CR M channel deliver); MR-5-1 add_invite */
#include "hash.h"         /* Tier2 T2-b: FindChannel (CR M channel deliver) */
#include "s_misc.h"       /* MR-5-1: exit_client_msg (mesh-routed KILL home delivery) */

#include "crdt_shadow.h"
#include "crdt_meshmap.h"  /* MR-1: crdt_meshmap_nexthop + crdt_route_action */
#include "crdt_wire.h"
#include "s2s_chunk.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define CR_DELTA_MAX  65536     /* max raw delta we encode in one exchange */
#define CR_SNAP_MAX   262144    /* max raw full snapshot (CR F) */
#define CR_CHUNK_LEN  400       /* base64 chars per CR D/U/F line */

static unsigned int crdt_stream_ctr = 0;

/** Send base64 @a b64 (length @a b64len) to @a to as a series of CR <sub>
 *  chunks, each carrying a stream id so the receiver can reassemble. */
static void send_crdt_chunks(struct Client *to, char sub,
                             const char *b64, int b64len)
{
  char id[24];
  int off = 0;
  snprintf(id, sizeof id, "%s%u", cli_yxx(&me), ++crdt_stream_ctr);
  do {
    int n = (b64len - off > CR_CHUNK_LEN) ? CR_CHUNK_LEN : (b64len - off);
    int more = (off + n < b64len);
    char piece[CR_CHUNK_LEN + 1];
    memcpy(piece, b64 + off, (size_t)n);
    piece[n] = '\0';
    sendcmdto_one(&me, CMD_CRDT_REPLICATION, to, "%c %s %s :%s",
                  sub, id, more ? "+" : ".", piece);
    off += n;
  } while (off < b64len);
}

/** Base64-encode a raw CRDT op blob and send it to @a to as CR <sub> chunks. */
static void send_crdt_blob(struct Client *to, char sub, const uint8_t *bin,
                           int n)
{
  size_t bcap = (size_t)n * 4 / 3 + 8;
  char *b64 = MyMalloc(bcap);
  int bn = crdt_b64_encode(bin, (size_t)n, b64, bcap);
  if (bn > 0)
    send_crdt_chunks(to, sub, b64, bn);
  MyFree(b64);
}

/** Compute the delta of ops @a to lacks (given its encoded state vector) and
 *  send it as CR D chunks. */
static void send_crdt_delta(struct Client *to, const uint8_t *remote_sv,
                            int sv_len)
{
  uint8_t *delta = MyMalloc(CR_DELTA_MAX);
  int dn = crdt_shadow_encode_delta(remote_sv, (size_t)sv_len, delta,
                                    CR_DELTA_MAX);
  if (dn > 4)                   /* 4 bytes = empty op count; nothing to send */
    send_crdt_blob(to, 'D', delta, dn);
  MyFree(delta);
}

/** Encode the full document as a snapshot and send it as CR F chunks. Used
 *  when the peer has fallen behind the GC floor (a delta would be incomplete). */
static void send_crdt_snapshot(struct Client *to)
{
  uint8_t *snap = MyMalloc(CR_SNAP_MAX);
  int sn = crdt_shadow_encode_snapshot(snap, CR_SNAP_MAX);
  if (sn > 0) {
    size_t bcap = (size_t)sn * 4 / 3 + 8;
    char *b64 = MyMalloc(bcap);
    int bn = crdt_b64_encode(snap, (size_t)sn, b64, bcap);
    if (bn > 0)
      send_crdt_chunks(to, 'F', b64, bn);
    MyFree(b64);
  }
  MyFree(snap);
}

void crdt_sync_request(struct Client *peer)
{
  uint8_t sv[8192];
  char b64[12000];
  int n, bn;
  if (!crdt_shadow_active() || !IsCrdtAware(peer) ||
      (!IsServer(peer) && !IsCrdtOverlay(peer)))
    return;
  n = crdt_shadow_encode_sv(sv, sizeof sv);
  if (n < 0)
    return;
  bn = crdt_b64_encode(sv, (size_t)n, b64, sizeof b64);
  if (bn < 0)
    return;
  /* Tier2 Fix A: carry our doc digest alongside the SV. A peer whose SV equals
   * ours but whose digest differs is an SV-invisible divergence the delta path
   * can't repair; the receiver escalates such a case to a CR F snapshot. */
  sendcmdto_one(&me, CMD_CRDT_REPLICATION, peer, "S %016llx :%s",
                (unsigned long long)crdt_shadow_digest(), b64);
}

void crdt_sync_broadcast(void)
{
  struct Client *acptr;
  if (!crdt_shadow_active())
    return;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsCrdtSyncTarget(acptr))
      crdt_sync_request(acptr);
}

void crdt_sync_push(void)
{
  struct Client *acptr;
  uint8_t *delta;
  int dn;
  if (!crdt_shadow_active())
    return;
  /* Encode our own-origin ops created since the last push ONCE, then fan the
   * same CR U out to every directly-connected CRDT peer. Foreign-origin ops we
   * received are eager-RELAYED separately (crdt_relay_delta from the apply path),
   * so 2-hop peers no longer wait for the periodic anti-entropy pull. */
  delta = MyMalloc(CR_DELTA_MAX);
  dn = crdt_shadow_encode_local_unpushed(delta, CR_DELTA_MAX);
  if (dn > 4)
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
      if (IsCrdtSyncTarget(acptr))
        send_crdt_blob(acptr, 'U', delta, dn);
  MyFree(delta);
}

/* Phase 4 foundation — eager multi-hop relay.  Forward a just-applied delta blob to
 * every directly-connected CRDT-aware peer EXCEPT the source, so foreign-origin ops
 * propagate sub-second across hops instead of waiting for the 30s anti-entropy pull.
 * Gossip flood with state-vector dedup for termination: a peer that already has the
 * ops applies 0 and so does NOT re-relay (the applied>0 guard at the call site), so
 * the cascade dies out.  This is the gossip substrate Phase 4's redundant (mesh)
 * paths need — under multiple paths the same dedup makes duplicate arrivals harmless.
 * Relaying the whole received blob (not just new ops) is intentional: SV dedup skips
 * any the target already has; correctness over a few redundant bytes at PoC scale. */
static void crdt_relay_delta(struct Client *from, const uint8_t *bin, int bn)
{
  struct Client *acptr;
  if (!crdt_shadow_active() || bn <= 0)
    return;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (acptr != from && IsCrdtSyncTarget(acptr))
      send_crdt_blob(acptr, 'D', bin, bn);
}

void crdt_send_snapshot(struct Client *to)
{
  send_crdt_snapshot(to);              /* Phase 3c: CRDT-authoritative BURST */
}

/* ================================================================== */
/* Tier2 T2-b — ephemeral live-message gossip (CR M)                  */
/*                                                                    */
/* A PRIVMSG to a user on a mesh stub (its P10 tree path is down but it */
/* is mesh-reachable, T2-a) is gossiped as an EPHEMERAL CR M line over  */
/* the CRDT transports — it NEVER enters the doc/oplog/snapshot.  Each  */
/* receiver delivers it if the target is local and relays it onward;    */
/* a small msgid ring dedups so a message arriving via multiple mesh    */
/* paths is delivered/relayed exactly once.  Wire:                      */
/*   :<srv> CR M <msgid> <srcYXX> <tgtYXX> :<text>                       */
/* ================================================================== */
/* R3 (dedup-at-scale): a TIME-WINDOWED dedup set (crdt_dedup_*, engine-tested)
 * replaces the old 256-entry count-bounded ring.  At steady-state CR M volume the
 * ring would evict a msgid before its duplicate arrived via a slower mesh path
 * (double-delivery); the windowed set keeps each msgid "seen" for ~the max mesh
 * propagation latency regardless of volume, and (unlike the ring) never spuriously
 * dedupes two distinct msgid-less ("*") messages against each other. */
#define CRDT_M_SEEN_WINDOW 90        /* s; > worst-case mesh propagation latency */
static struct CrdtMsgidDedup crdt_m_seen;   /* static zero-init => all slots empty */

/* MR-4a: the CR-M -> legacy unicast dead-sink counter (INERT instrumentation).  A
 * CR-M unicast addressed to a legacy user that THIS node fronts (a real legacy user
 * reached via our own non-CRDT link) cannot be delivered by the 'M' handler — it only
 * delivers to MyConnect() targets, and there is no CR->P10 re-emit yet.  The flood
 * still reaches this gateway, resolves the target via findNUser(), then silently
 * drops.  MR-4b adds the bridge HERE; MR-4a just measures the gap so the live bed can
 * confirm the drop count (nef7 PM AuthServ -> bumps on the gateway nef3). */
static unsigned long crdt_dead_sink_dropped = 0;
/* MR-4b: the matching success counter — a CR-M unicast we re-emitted as real P10
 * toward the fronted legacy user (the bridge fired). */
static unsigned long crdt_cr_to_p10_bridged = 0;
/* MR-4d: a CR-M unicast we did NOT re-emit because a lower-numeric gateway also
 * fronts the legacy server (the double-delivery election stood us down). */
static unsigned long crdt_gateway_standby_suppressed = 0;

/* MR-1: TTL/hop-limit on every routed CR M frame (the §0 prerequisite).  A
 * storm-backstop, NOT a delivery limiter — set far above any realistic mesh
 * diameter so no deliverable message is ever dropped; it only bounds a loop over a
 * transiently-inconsistent next-hop graph (esp. msgid-less "*" unicast, which the
 * dedup set cannot catch).  Carried as an optional positional before the trailing
 * text: "M <msgid> <cmd> <src> <tgt> <ttl> :<text>" (parc>=8); an old-form frame
 * (parc==7) has no ttl and defaults here, and an old relayer simply strips it. */
#define CRDT_M_TTL_DEFAULT 32

/* return 1 if msgid was already seen within the window (dup), else record it -> 0. */
static int crdt_m_seen_check_add(const char *msgid)
{
  return crdt_dedup_check_add(&crdt_m_seen, msgid, (uint64_t)CurrentTime,
                              CRDT_M_SEEN_WINDOW);
}

/* MR-2: forward a channel CR M along the canonical shared tree (declared here,
 * defined below crdt_peer_by_num). @a except_num is the receive-edge peer numeric
 * to skip (-1 at the origin). */
static void crdt_tree_forward_chan(int except_num, const char *msgid, char cmd,
                                   const char *srcfull, const char *target,
                                   int ttl, const char *text);

/* Gossip a live message via ephemeral CR M.
 *   cmd    'P' (PRIVMSG) / 'N' (NOTICE) / 'T' (TAGMSG)
 *   target a 5-char user numeric (unicast) OR a #channel name
 * Wire: :<srv> CR M <msgid> <cmd> <srcYXX> <target> <ttl> :<text>
 * MR-2: a CHANNEL target forwards over the canonical mesh tree (N-1) when
 * FEAT_CRDT_ROUTE_BCAST and the mesh is stable; otherwise (and for unicast, the
 * MR-1 flood-fallback) it floods to all CRDT peers (TTL+dedup terminate it). */
void crdt_gossip_message(struct Client *from, char cmd, const char *target,
                         const char *msgid, const char *text)
{
  struct Client *acptr;
  const char *mid;
  if (!crdt_shadow_active() || !from || !target || !text)
    return;
  mid = (msgid && *msgid) ? msgid : "*";
  crdt_m_seen_check_add(msgid);        /* record so an echo/relay-back is deduped */

  if ((target[0] == '#' || target[0] == '&' || target[0] == '*') &&
      feature_bool(FEAT_CRDT_ROUTE_BCAST) && crdt_shadow_mesh_bcast_stable(CurrentTime)) {
    char srcfull[16];
    ircd_snprintf(0, srcfull, sizeof srcfull, "%s%s", NumNick(from));
    crdt_tree_forward_chan(-1, mid, cmd, srcfull, target, CRDT_M_TTL_DEFAULT, text);
    return;
  }
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsCrdtSyncTarget(acptr))
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, acptr, "M %s %c %s%s %s %d :%s",
                    mid, cmd, NumNick(from), target, CRDT_M_TTL_DEFAULT, text);
}

/* MR-1: the direct CRDT peer (server link or overlay) whose numeric == @a num,
 * i.e. the link to forward a next-hop-routed frame on.  NULL if no such peer is
 * currently a sync target (its link dropped -> caller flood-falls-back). */
static struct Client *crdt_peer_by_num(unsigned int num)
{
  struct Client *p;
  for (p = GlobalClientList; p; p = cli_next(p))
    if (IsCrdtSyncTarget(p) && (unsigned int)base64toint(cli_yxx(p)) == num)
      return p;
  return NULL;
}

/* MR-2: forward a channel CR M to this node's canonical-tree neighbours (the N-1
 * broadcast), skipping @a except_num (the receive edge; -1 at the origin).  The
 * caller has already gated on stability; here we just compute the shared tree and
 * send.  Per-message canon_tree recompute is microseconds at PoC scale (cache opt
 * deferred to scale). */
static void crdt_tree_forward_chan(int except_num, const char *msgid, char cmd,
                                   const char *srcfull, const char *target,
                                   int ttl, const char *text)
{
  static uint16_t tu[CRDT_MAX_SERVERS], tv[CRDT_MAX_SERVERS];
  static uint16_t nbrs[CRDT_MESH_MAXDEG];
  static struct Client *resolved[CRDT_MESH_MAXDEG];
  unsigned int ournum = (unsigned int)base64toint(cli_yxx(&me));
  int nedges, nn, i, np = 0, gap = 0;
  struct Client *p;

  if (ttl <= 0)
    return;
  nedges = crdt_meshmap_canon_tree(crdt_shadow_meshmap(), CurrentTime,
                                   crdt_shadow_beacon_stale_secs(),
                                   tu, tv, CRDT_MAX_SERVERS);
  nn = crdt_meshmap_tree_neighbors(tu, tv, nedges, (uint16_t)ournum,
                                   nbrs, CRDT_MESH_MAXDEG);
  /* resolve every tree-neighbour (except the receive edge) to a direct peer first.
   * If any tree edge is NOT a directly-sendable link here (an asymmetric/stale
   * adjacency the stability gate didn't catch), forwarding it would silently gap
   * that subtree -> flood-fallback instead (dedup makes the redundancy harmless). */
  for (i = 0; i < nn; i++) {
    if ((int)nbrs[i] == except_num)
      continue;
    resolved[np] = crdt_peer_by_num(nbrs[i]);
    if (!resolved[np]) { gap = 1; break; }
    np++;
  }
  if (!gap) {
    for (i = 0; i < np; i++)
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, resolved[i], "M %s %c %s %s %d :%s",
                    msgid, cmd, srcfull, target, ttl, text);
    return;
  }
  for (p = GlobalClientList; p; p = cli_next(p))     /* gap -> flood (gap-safe) */
    if (IsCrdtSyncTarget(p) && (int)base64toint(cli_yxx(p)) != except_num)
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "M %s %c %s %s %d :%s",
                    msgid, cmd, srcfull, target, ttl, text);
}

/* MR-1: try to deliver a user-unicast over the CRDT mesh instead of the P10 tree.
 * Returns 1 if handled over CR (caller MUST skip the P10 send), 0 to use P10.
 *  - target on a mesh STUB -> always over CR (its P10 path is a dead-sink): the
 *    proven partition fallback, flag-independent.
 *  - target on a live CRDT-aware server -> over CR only when FEAT_CRDT_ROUTE_UNICAST
 *    (the MR-1 primary path); else 0 -> P10 (today's behaviour).
 * Send shape: flag on -> next-hop toward the owner (crdt_meshmap_nexthop), the one
 * peer, flood-fallback if the next-hop is unknown/stale; flag off (stub only) ->
 * the proven flood.  @a cmd 'P'/'N'/'T'; @a text is the body (or client-tag string
 * for 'T'). */
int crdt_route_unicast_try(struct Client *from, char cmd, struct Client *tgt,
                           const char *msgid, const char *text)
{
  static int16_t nh[CRDT_MAX_SERVERS];
  struct Client *tsrv, *peer;
  char tyxx[6];
  const char *mid;
  unsigned int owner, ournum;
  int known = 0;

  if (!crdt_shadow_active() || !from || !tgt || !cli_user(tgt) || !text)
    return 0;
  tsrv = cli_user(tgt)->server;
  if (!tsrv)
    return 0;
  if (!IsMeshStub(tsrv) &&
      !(feature_bool(FEAT_CRDT_ROUTE_UNICAST) && IsServer(tsrv) && IsCrdtAware(tsrv)))
    return 0;                            /* live CRDT target + flag off -> use P10 */

  ircd_snprintf(0, tyxx, sizeof tyxx, "%s%s", NumNick(tgt));
  mid = (msgid && *msgid) ? msgid : "*";

  /* flag off (only reachable for a mesh stub here) -> the proven flood */
  if (!feature_bool(FEAT_CRDT_ROUTE_UNICAST)) {
    crdt_gossip_message(from, cmd, tyxx, mid, text);
    return 1;
  }

  /* flag on -> next-hop route toward the owner */
  owner  = (unsigned int)base64toint(cli_yxx(tsrv));
  ournum = (unsigned int)base64toint(cli_yxx(&me));
  if (owner < CRDT_MAX_SERVERS) {
    crdt_meshmap_nexthop(crdt_shadow_meshmap(), (uint16_t)ournum, CurrentTime,
                         crdt_shadow_beacon_stale_secs(), nh);
    known = (nh[owner] >= 0);
  }
  switch (crdt_route_action(owner == ournum, known, CRDT_M_TTL_DEFAULT)) {
  case CRDT_ROUTE_NEXTHOP:
    peer = crdt_peer_by_num((unsigned int)nh[owner]);
    if (peer) {
      crdt_m_seen_check_add(mid);        /* dedup our own relay-back */
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, peer, "M %s %c %s%s %s %d :%s",
                    mid, cmd, NumNick(from), tyxx, CRDT_M_TTL_DEFAULT, text);
      break;
    }
    /* fallthrough: next-hop peer vanished -> flood */
  case CRDT_ROUTE_FLOOD:
    crdt_gossip_message(from, cmd, tyxx, mid, text);
    break;
  case CRDT_ROUTE_DELIVER:              /* owner is us (remote target can't be) -> let the
                                          caller deliver locally via the normal path */
    return 0;
  case CRDT_ROUTE_DROP:                 /* full TTL: never here */
    break;
  }
  return 1;
}

/* Tier2 full-partition liveness: gossip our ephemeral liveness beacon
 * (CR H <ourYXX> <CurrentTime> <nn_capacity> <peers> :<name>) to all CRDT
 * transports.  Receivers track the last beacon per server; a mesh stub whose
 * beacon goes stale is retired (full partition).  #3: the appended capacity +
 * name let a receiver build a right-sized, real-named synthetic anchor for us.
 * <peers> (append-only, mesh-map) is our comma-joined direct-CRDT-peer numerics
 * for the gossiped topology map — observability-only, never touches the doc. */
/* MR-3a: the gateway PROXY-beacons each legacy (non-CRDT) server in its own legacy
 * subtree, so a no-direct-P10-link CRDT leaf can anchor it from the beacon (Case-B)
 * once the legacy SERVER intro is suppressed (MR-3c). SINGLE-WRITER by construction:
 * only the node that reaches the legacy server via a NON-CRDT link (cli_from is a
 * legacy server, not a CRDT peer) beacons it — a leaf reaches the same legacy server
 * via a CRDT uplink, so its cli_from is CRDT-aware and it self-skips. peers="*" (a
 * legacy server has no CRDT peers; keeps it out of the mesh-map). Existing wire form
 * (the proxy-row lease marker is the MR-3c append-only addition). No-op unless
 * FEAT_CRDT_LEGACY_PRESENCE. */
static void crdt_proxy_beacon_legacy_to(struct Client *only)
{
  struct Client *L, *p;
  for (L = GlobalClientList; L; L = cli_next(L)) {
    if (!IsServer(L) || IsMe(L) || IsCrdtAware(L))
      continue;                          /* legacy servers only */
    if (!cli_from(L) || IsCrdtAware(cli_from(L)))
      continue;                          /* reached via OUR legacy link only (single-writer) */
    for (p = GlobalClientList; p; p = cli_next(p))
      if (IsCrdtSyncTarget(p) && (!only || p == only))
        /* MR-4d: append our own numeric as fronted_by (after peers, before name) so
         * leaves/peer-gateways learn WHICH CRDT node fronts this legacy server — the
         * double-delivery election input + the proxy-row marker.  Append-only: an old
         * binary reads name=parv[parc-1] and ignores the extra positional. */
        sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "H %s %ld %s %s %s :%s",
                      cli_yxx(L), (long)CurrentTime,
                      cli_serv(L)->nn_capacity, "*", cli_yxx(&me), cli_name(L));
  }
}

/* Emit our own liveness set.  @a only==NULL -> all CRDT sync targets (the periodic
 * flood); @a only!=NULL -> just that one peer (the MR-5 event-driven beacon-burst at
 * link time — see crdt_shadow_beacon_burst). */
void crdt_gossip_beacon_to(struct Client *only)
{
  struct Client *acptr;
  char peers[256];
  if (!crdt_shadow_active() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  /* build our own direct-peer set (also records our own mesh-map row); "*" when
   * we have no CRDT peers, so the positional param is always present. */
  if (crdt_shadow_local_peers(peers, sizeof peers) == 0)
    strcpy(peers, "*");
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsCrdtSyncTarget(acptr) && (!only || acptr == only))
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, acptr, "H %s %ld %s %s :%s",
                    cli_yxx(&me), (long)CurrentTime,
                    cli_serv(&me)->nn_capacity, peers, cli_name(&me));
  if (feature_bool(FEAT_CRDT_LEGACY_PRESENCE))
    crdt_proxy_beacon_legacy_to(only);   /* MR-3a: proxy-beacon our legacy subtree */
}

void crdt_gossip_beacon(void)
{
  crdt_gossip_beacon_to(NULL);
}

int ms_crdt(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *sub;

  if (!crdt_shadow_active() || parc < 3)
    return 0;
  sub = parv[1];

  if (sub[0] == 'S' && !sub[1]) {
    /* peer's state vector -> record it (for GC) + reply with the delta it lacks.
     * Fix A form: "S <digest> :<sv>" (parc>=4); legacy "S :<sv>" (parc==3) carries
     * no digest -> escalation is skipped (degrades to delta/floor behaviour). The
     * SV blob is always the LAST param. */
    uint8_t svbytes[8192];
    int svn = crdt_b64_decode(parv[parc - 1], svbytes, sizeof svbytes);
    if (svn >= 0) {
      crdt_shadow_record_peer_sv((uint16_t)base64toint(cli_yxx(cptr)),
                                 svbytes, (size_t)svn);
      /* if the peer is behind the GC floor, the ops it lacks are gone from the
       * oplog -> send a full snapshot instead of an incomplete delta */
      if (crdt_shadow_peer_behind_floor(svbytes, (size_t)svn))
        send_crdt_snapshot(cptr);
      /* Fix A: equal SV but different doc digest = SV-invisible divergence the
       * delta path cannot repair (an empty delta) -> escalate to a CR F snapshot,
       * whose HLC-merge is the only content-level reconcile. Both peers broadcast
       * CR S each cycle, so the commutative merge converges both in one round. The
       * SV-equal gate keeps this from firing during normal op-lag. */
      else if (parc >= 4 && crdt_shadow_sv_equal(svbytes, (size_t)svn)
               && (uint64_t)strtoull(parv[2], NULL, 16) != crdt_shadow_digest()) {
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT sync: digest mismatch at equal SV (peer=%s local=%016llx)"
                  " -> full snapshot to %s", parv[2],
                  (unsigned long long)crdt_shadow_digest(), cli_name(cptr));
        send_crdt_snapshot(cptr);
      }
      else
        send_crdt_delta(cptr, svbytes, svn);
    }
  } else if ((sub[0] == 'D' || sub[0] == 'U') && !sub[1]) {
    /* delta / incremental chunk: <id> <+|.> :<b64> */
    char *full = NULL;
    size_t flen = 0;
    int r;
    if (parc < 5)
      return 0;
    r = s2s_chunk_feed(cptr, parv[2], parv[parc - 1], parv[3][0] == '+',
                       &full, &flen);
    if (r == 1) {
      uint8_t *bin = MyMalloc(flen ? flen : 1);
      int bn = crdt_b64_decode(full, bin, flen ? flen : 1);
      MyFree(full);
      if (bn > 0) {
        int applied = crdt_shadow_apply_delta(bin, (size_t)bn);
        if (applied > 0) {
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT sync: applied %d op(s) from %s", applied,
                    cli_name(cptr));
          /* Phase 4 foundation: eager multi-hop relay — forward the just-applied
           * ops onward to our OTHER CRDT peers (gossip flood; the applied>0 guard +
           * SV dedup terminate the cascade) so 2-hop peers converge sub-second. */
          crdt_relay_delta(cptr, bin, bn);
          /* Phase 3d/3e/3f: drive live topics + channel modes + membership that just
           * arrived via CRDT (+ gateway to legacy). Idempotent; no-op unless
           * FEAT_CRDT_PRIMARY. */
          crdt_shadow_reconcile_users(); /* Phase 3l: create+gateway users before channels */
          crdt_shadow_reconcile_topics();
          crdt_shadow_reconcile_modes();
          crdt_shadow_reconcile_create_channels(); /* Phase 3j: birth channels before members */
          crdt_shadow_reconcile_members();
          crdt_shadow_gateway_birth_modes(); /* 3j gap fix: bridge birth-modes after members place the channel on legacy */
          crdt_shadow_reconcile_removes();
          crdt_shadow_reconcile_member_status();
          crdt_shadow_reconcile_bans();
          crdt_shadow_reconcile_user_removes(); /* Phase 3m: QUIT / delete-on-leave (after channel cleanup) */
          crdt_shadow_reconcile_glines();  /* GLINE step 3: drive global G-lines from doc (+gateway) */
          crdt_shadow_reconcile_shuns();   /* SHUN: drive global Shuns from doc (+gateway) */
          crdt_shadow_reconcile_zlines();  /* ZLINE: drive global Z-lines from doc (+gateway) */
          crdt_shadow_reconcile_jupes();   /* JUPE: drive juped servers from doc (+gateway) */
        }
      }
      MyFree(bin);
    }
  } else if (sub[0] == 'F' && !sub[1]) {
    /* full-snapshot chunk: <id> <+|.> :<b64> -> apply once fully reassembled */
    char *full = NULL;
    size_t flen = 0;
    int r;
    if (parc < 5)
      return 0;
    r = s2s_chunk_feed(cptr, parv[2], parv[parc - 1], parv[3][0] == '+',
                       &full, &flen);
    if (r == 1) {
      uint8_t *bin = MyMalloc(flen ? flen : 1);
      int bn = crdt_b64_decode(full, bin, flen ? flen : 1);
      MyFree(full);
      if (bn > 0 && crdt_shadow_apply_snapshot(bin, (size_t)bn) == 0) {
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT sync: applied full snapshot (%d bytes) from %s", bn,
                  cli_name(cptr));
        /* Phase 3c cutover: if WE are CRDT-primary and this peer skipped its P10
         * BURST in favor of the snapshot (we're still mid-burst from it), build
         * live state from the doc NOW — the authoritative replacement for BURST.
         * Idempotent; the verify timer re-runs post-burst to heal SERVER-tree
         * race skips. No-op when the peer sent a normal BURST (this never fires
         * because no CR F is received in that case). */
        if (feature_bool(FEAT_CRDT_PRIMARY) && IsBurstOrBurstAck(cptr))
          crdt_shadow_materialize_live();
      }
      MyFree(bin);
    }
  } else if (sub[0] == 'V' && !sub[1]) {
    /* version broadcast: record the peer's SV for causal-stability GC */
    uint8_t svbytes[8192];
    int svn = crdt_b64_decode(parv[parc - 1], svbytes, sizeof svbytes);
    if (svn >= 0)
      crdt_shadow_record_peer_sv((uint16_t)base64toint(cli_yxx(cptr)),
                                 svbytes, (size_t)svn);
  } else if (sub[0] == 'M' && !sub[1]) {
    /* Tier2 T2-b: ephemeral live message —
     *   M <msgid> <cmd> <srcYXX> <target> :<payload>
     * cmd='P'(PRIVMSG)/'N'(NOTICE) -> payload is the message text; cmd='T'(TAGMSG)
     * -> payload is the client-only tag string (rides the @-prefix, no body, and is
     * delivered only to message-tags-capable recipients).  target = a 5-char user
     * numeric (unicast) or a #channel.  Deliver to the LOCAL target (a user, or all
     * local members of a channel) with the source prefix reconstructed from the
     * converged doc (the sender may not be live on this split server), then relay
     * onward; msgid-deduped so multi-path arrivals deliver/relay once.  NEVER
     * touches the doc/oplog. */
    const char *m_msgid, *m_cmd, *srcyxx, *target, *m_text, *cmdstr;
    const struct CrdtUserRecord *src;
    struct Client *p;
    int is_tag, ttl, ttl_next;
    if (parc < 7)
      return 0;
    m_msgid = parv[2]; m_cmd = parv[3]; srcyxx = parv[4]; target = parv[5];
    m_text = parv[parc - 1];
    /* MR-1: optional TTL positional before the trailing text (new form parc>=8);
     * an old-form frame (parc==7) carries none and defaults. */
    ttl = (parc >= 8) ? atoi(parv[6]) : CRDT_M_TTL_DEFAULT;
    ttl_next = ttl - 1;
    if (crdt_m_seen_check_add(m_msgid))
      return 0;                        /* already handled via another mesh path */
    is_tag = (m_cmd[0] == 'T');
    cmdstr = (m_cmd[0] == 'N') ? "NOTICE" : (m_cmd[0] == 'K') ? "KILL"
             : (m_cmd[0] == 'I') ? "INVITE" : (is_tag ? "TAGMSG" : "PRIVMSG");
    src = crdt_shadow_user_record(srcyxx);
    /* R4a (channel-over-mesh): per-server local-delivery dedup.  If the TREE plane
     * already delivered this msgid to our locals (the channel relay marked it), skip the
     * redundant CR-M LOCAL delivery — but still relay the flood onward below.  Distinct
     * from crdt_m_seen (the flood dedup at the top), which gates relay too; sharing it
     * would let a tree-first delivery suppress the CR-M relay and break the flood. */
    if (!crdt_shadow_chan_local_check_add(m_msgid)) {
    if (m_cmd[0] == 'W') {                                /* MR-2b: all-server WALLOPS */
      struct Client *wsrc = findNUser(srcyxx);
      if (wsrc)
        sendwallto_local(wsrc, WALL_WALLOPS, m_text);    /* deliver to local +w opers */
    } else if (target[0] == '#' || target[0] == '&') {    /* channel delivery */
      struct Channel *ch = FindChannel(target);
      struct Membership *memb;
      if (ch)
        for (memb = ch->members; memb; memb = memb->next_member) {
          if (!MyConnect(memb->user))
            continue;
          if (is_tag) {                /* TAGMSG: @tags prefix, no body, cap-gated */
            if (!CapActive(memb->user, CAP_MSGTAGS))
              continue;
            if (src && src->nick[0])
              sendrawto_one(memb->user, "@%s :%s!%s@%s TAGMSG %s", m_text,
                            src->nick, src->ident,
                            src->host[0] ? src->host : "mesh", target);
            else
              sendrawto_one(memb->user, "@%s :%s TAGMSG %s", m_text, srcyxx, target);
          } else if (src && src->nick[0])
            sendrawto_one(memb->user, ":%s!%s@%s %s %s :%s", src->nick,
                          src->ident, src->host[0] ? src->host : "mesh",
                          cmdstr, target, m_text);
          else
            sendrawto_one(memb->user, ":%s %s %s :%s", srcyxx, cmdstr, target,
                          m_text);
        }
      /* R6b (gateway CR-M -> legacy bridge): re-emit this channel message to LEGACY P10
       * peers (forbid CRDT-aware — they got the CR-M flood).  Being inside the !dup_local
       * block means CR-M was the FIRST arrival here, i.e. the TREE did not carry this msgid
       * to us (R6a demoted the tree among CRDT peers), so legacy members reachable only via
       * us still receive it, exactly once (no tree copy to double with; a legacy-origin
       * message arrives via the tree, is dedup-marked, and skips this block).  A no-op on a
       * node with no legacy peers.  Skip a MESH-ONLY source: legacy SQUIT'd its server and
       * cannot place it (the partition case = R6c).  TAGMSG ('T') deferred (its @-tag legacy
       * form differs + its tree leg is not yet demoted). */
      if (ch && !is_tag) {
        struct Client *srcc = findNUser(srcyxx);
        if (srcc && !crdt_user_is_mesh_only(srcc))
          sendcmdto_flag_serv_butone(srcc, (m_cmd[0] == 'N') ? CMD_NOTICE : CMD_PRIVATE,
                                     NULL, FLAG_LAST_FLAG, FLAG_CRDT_AWARE,
                                     "%H :%s", ch, m_text);
      }
      /* R6b TAGMSG bridge: same gateway CR-M -> legacy bridge for TAGMSG.  The @tags v3 form
       * goes via sendcmdto_serv_butone_v3 (which targets IRCv3-aware downlinks); with skip_crdt
       * set it skips CRDT-aware peers -> legacy IRCv3 peers only.  m_text is the client-only
       * tag string. */
      if (ch && is_tag) {
        struct Client *srcc = findNUser(srcyxx);
        if (srcc && !crdt_user_is_mesh_only(srcc)) {
          sendcmdto_set_skip_crdt_servers();
          sendcmdto_serv_butone_v3(srcc, CMD_TAGMSG, NULL, "@%s %s", m_text, ch->chname);
        }
      }
    } else {                                              /* unicast delivery */
      struct Client *tgt = findNUser(target);
      if (tgt && MyConnect(tgt) && m_cmd[0] == 'K') {
        /* MR-5-1: a mesh-routed KILL reached the victim's HOME -> execute it locally.
         * Fires once a CRDT server is mesh-anchored (post-MR-5-2, so the KILL routes over
         * CR-M instead of the now-suppressed P10 tree); a legacy victim takes the gateway
         * re-emit branch below instead.  The resulting exit writes the doc tombstone, so
         * the removal propagates to every materialized copy (the single teardown
         * authority — same as the MR-4c gateway-KILL path). */
        struct Client *ksrc = findNUser(srcyxx);
        struct Client *ksh  = (feature_bool(FEAT_HIS_KILLWHO) || !ksrc) ? &me : ksrc;
        const char *kn = feature_bool(FEAT_HIS_KILLWHO) ? feature_str(FEAT_HIS_SERVERNAME)
                         : (ksrc ? cli_name(ksrc) : "mesh");
        sendcmdto_one(ksh, CMD_KILL, tgt, "%C :%s %s", tgt, kn, m_text);
        exit_client_msg(cptr, tgt, ksh, "Killed (%s %s)", kn, m_text);
      } else if (tgt && MyConnect(tgt) && m_cmd[0] == 'I') {
        /* MR-5-1: a mesh-routed INVITE reached the target's HOME -> add the invite + notify
         * the local target (mirrors m_invite's MyConnect branch).  m_text = the channel. */
        struct Client *isrc = findNUser(srcyxx);
        struct Channel *ich = FindChannel(m_text);
        if (ich) {
          add_invite(tgt, ich);
          sendcmdto_one(isrc ? isrc : &me, CMD_INVITE, tgt, "%s %H", cli_name(tgt), ich);
        }
      } else if (tgt && MyConnect(tgt)) {            /* local CRDT user — message delivery (P/N/T) */
        if (is_tag) {                  /* TAGMSG: @tags prefix, no body, cap-gated */
          if (CapActive(tgt, CAP_MSGTAGS)) {
            if (src && src->nick[0])
              sendrawto_one(tgt, "@%s :%s!%s@%s TAGMSG %s", m_text, src->nick,
                            src->ident, src->host[0] ? src->host : "mesh",
                            cli_name(tgt));
            else
              sendrawto_one(tgt, "@%s :%s TAGMSG %s", m_text, srcyxx, cli_name(tgt));
          }
        } else if (src && src->nick[0])
          sendrawto_one(tgt, ":%s!%s@%s %s %s :%s", src->nick, src->ident,
                        src->host[0] ? src->host : "mesh", cmdstr, cli_name(tgt),
                        m_text);
        else
          sendrawto_one(tgt, ":%s %s %s :%s", srcyxx, cmdstr, cli_name(tgt), m_text);
      } else if (tgt && cli_user(tgt) && cli_user(tgt)->server) {
        /* MR-4b: the CR-M -> legacy unicast bridge.  tgt resolved but is not local.  If
         * it is a real legacy user THIS node fronts — its owning server is a non-CRDT P10
         * server reached over our OWN non-CRDT link (an anchor would be SetCrdtAware, so
         * !IsCrdtAware excludes anchors) — then we are the gateway and the message IS
         * deliverable: re-emit the CR-M as a real P10 PRIVMSG/NOTICE toward the legacy
         * user (the direct-message analog of the R6b channel bridge).  Source = the
         * originating CRDT user; gated by crdt_user_is_mesh_only exactly as R6b (a
         * partitioned mesh-only sender can't be placed by legacy -> drop, R6c).  Exactly
         * once: only the fronting gateway passes !IsCrdtAware(tsrv), and crdt_m_seen has
         * already deduped the flood per-node.  TAGMSG deferred (its @tags unicast legacy
         * form differs).  When the bridge flag is off / source unplaceable, count the
         * drop (the MR-4a behaviour) with the reason. */
        struct Client *tsrv = cli_user(tgt)->server;
        if (IsServer(tsrv) && !IsCrdtAware(tsrv) && cli_from(tsrv) &&
            !IsCrdtAware(cli_from(tsrv)) && feature_bool(FEAT_CRDT_GATEWAY_BRIDGE) &&
            crdt_shadow_should_standby((unsigned int)base64toint(cli_yxx(tsrv)),
                                       cli_yxx(&me))) {
          /* MR-4d: a lower-numeric gateway also fronts this legacy server — stand down
           * so only it re-emits (no double-delivery on legacy).  Not a loss: the active
           * gateway delivers; if it departs, its beacon goes stale and we promote. */
          crdt_gateway_standby_suppressed++;
          log_write(LS_SYSTEM, L_INFO, 0, "MR-4d standby: CR-M %s for legacy user %s "
                    "(on %s) NOT re-emitted — a lower-numeric gateway fronts it "
                    "(count=%lu)", cmdstr, cli_name(tgt), cli_name(tsrv),
                    crdt_gateway_standby_suppressed);
        } else if (IsServer(tsrv) && !IsCrdtAware(tsrv) && cli_from(tsrv) &&
            !IsCrdtAware(cli_from(tsrv))) {
          struct Client *srcc = findNUser(srcyxx);
          int is_kill = (m_cmd[0] == 'K');                 /* MR-4c */
          int is_inv  = (m_cmd[0] == 'I');
          if (feature_bool(FEAT_CRDT_GATEWAY_BRIDGE) && srcc &&
              !crdt_user_is_mesh_only(srcc) &&
              (m_cmd[0] == 'P' || m_cmd[0] == 'N' || is_kill || is_inv)) {
            if (is_kill)
              /* MR-4c: re-emit a real P10 KILL toward the legacy user.  Path
               * mirrors do_kill's S2S relay (m_kill.c): <gateway>!<killer> <reason>.
               * The resulting legacy QUIT comes back over our legacy link and the
               * observe-and-mirror crdt_user_remove tombstones the user -> reconcile
               * tears down every materialized copy (the single teardown authority). */
              sendcmdto_one(srcc, CMD_KILL, tgt, "%C :%s!%s %s", tgt,
                            cli_name(&me), cli_name(srcc), m_text);
            else if (is_inv) {
              /* MR-4c: re-emit a real P10 INVITE toward the legacy user.  m_text is
               * the channel name; reconstruct %Tu from the gateway's OWN live channel
               * (legacy's invite_ts > creationtime guard needs the gateway's view, not
               * the originating leaf's).  If the channel isn't live here, fall back to
               * the non-existent-channel form (mirrors ms_invite.c).  legacy's
               * ms_invite runs add_invite since the target is local there. */
              struct Channel *ichp = FindChannel(m_text);
              if (ichp)
                sendcmdto_one(srcc, CMD_INVITE, tgt, "%s %H %Tu", cli_name(tgt),
                              ichp, ichp->creationtime);
              else
                sendcmdto_one(srcc, CMD_INVITE, tgt, "%C :%s", tgt, m_text);
            } else
              sendcmdto_one(srcc, (m_cmd[0] == 'N') ? CMD_NOTICE : CMD_PRIVATE, tgt,
                            "%C :%s", tgt, m_text);
            crdt_cr_to_p10_bridged++;
            log_write(LS_SYSTEM, L_INFO, 0, "MR-4 bridge: CR-M %s %s -> legacy user %s "
                      "(on %s) re-emitted (count=%lu)", cmdstr, srcyxx, cli_name(tgt),
                      cli_name(tsrv), crdt_cr_to_p10_bridged);
          } else {
            crdt_dead_sink_dropped++;
            log_write(LS_SYSTEM, L_NOTICE, 0, "MR-4 dead-sink: CR-M %s for legacy user %s "
                      "(on %s) dropped — %s (count=%lu)", cmdstr, cli_name(tgt),
                      cli_name(tsrv),
                      !feature_bool(FEAT_CRDT_GATEWAY_BRIDGE) ? "bridge off" :
                      is_tag ? "TAGMSG deferred" : !srcc ? "source unknown" :
                      "mesh-only source (R6c)", crdt_dead_sink_dropped);
          }
        }
      }
    }
    }  /* R4a: end local-delivery dedup guard (the relay below always runs) */
    /* MR-1/MR-2 relay (TTL-bounded): a CHANNEL ('#'/'&') or all-server ('*', the
     * MR-2b WALLOPS) target is a broadcast -> forward over the canonical tree when
     * stable (N-1), else flood; a UNICAST target is routed next-hop toward its owner
     * (flood-fallback), DROP on TTL exhaustion. */
    if (target[0] == '#' || target[0] == '&' || target[0] == '*') {
      if (ttl_next > 0) {
        /* MR-2: forward over the canonical mesh tree (N-1) when stable; else flood */
        if (feature_bool(FEAT_CRDT_ROUTE_BCAST) &&
            crdt_shadow_mesh_bcast_stable(CurrentTime))
          crdt_tree_forward_chan((int)base64toint(cli_yxx(cptr)), m_msgid, m_cmd[0],
                                 srcyxx, target, ttl_next, m_text);
        else
          for (p = GlobalClientList; p; p = cli_next(p))
            if (p != cptr && IsCrdtSyncTarget(p))
              sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "M %s %s %s %s %d :%s",
                            m_msgid, m_cmd, srcyxx, target, ttl_next, m_text);
      }
    } else {
      struct Client *tgt2 = findNUser(target);
      int owner_self = (tgt2 && MyConnect(tgt2));
      int route_on = feature_bool(FEAT_CRDT_ROUTE_UNICAST);
      int known = 0, do_flood = 0;
      int16_t nhp = -1;
      if (route_on && tgt2 && cli_user(tgt2) && cli_user(tgt2)->server) {
        unsigned int owner = (unsigned int)base64toint(cli_yxx(cli_user(tgt2)->server));
        unsigned int ournum = (unsigned int)base64toint(cli_yxx(&me));
        if (owner < CRDT_MAX_SERVERS) {
          static int16_t nh[CRDT_MAX_SERVERS];
          crdt_meshmap_nexthop(crdt_shadow_meshmap(), (uint16_t)ournum, CurrentTime,
                               crdt_shadow_beacon_stale_secs(), nh);
          nhp = nh[owner]; known = (nhp >= 0);
        }
      }
      /* flag off -> flood (today's proven partition path); flag on -> route_action */
      switch (route_on ? crdt_route_action(owner_self, known, ttl_next)
                       : (owner_self ? CRDT_ROUTE_DELIVER
                                     : (ttl_next > 0 ? CRDT_ROUTE_FLOOD : CRDT_ROUTE_DROP))) {
      case CRDT_ROUTE_NEXTHOP: {
        struct Client *peer = crdt_peer_by_num((unsigned int)nhp);
        if (peer && peer != cptr)
          sendcmdto_one(&me, CMD_CRDT_REPLICATION, peer, "M %s %s %s %s %d :%s",
                        m_msgid, m_cmd, srcyxx, target, ttl_next, m_text);
        else if (!peer)
          do_flood = 1;                  /* next-hop peer vanished -> flood */
        break;
      }
      case CRDT_ROUTE_FLOOD:  do_flood = 1; break;
      case CRDT_ROUTE_DELIVER:           /* owner is us: delivered locally above */
      case CRDT_ROUTE_DROP:              /* TTL exhausted */
        break;
      }
      if (do_flood)
        for (p = GlobalClientList; p; p = cli_next(p))
          if (p != cptr && IsCrdtSyncTarget(p))
            sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "M %s %s %s %s %d :%s",
                          m_msgid, m_cmd, srcyxx, target, ttl_next, m_text);
    }
  } else if (sub[0] == 'H' && !sub[1]) {
    /* Tier2 full-partition liveness beacon — H <srvYXX> <emit_ts> [<nn_cap> :<name>].
     * Record + relay if FRESH (newer emit_ts); a dup/old beacon drops, terminating
     * the flood.  #3: nn_cap + name are append-only; an old-form beacon (parc==4)
     * omits them and is relayed in old form (mixed-version safe).  Ephemeral. */
    struct Client *p;
    const char *bcap = "", *bname = "", *bpeers = "", *bfronted = "";
    if (parc < 4)
      return 0;
    /* name is always the trailing param (parv[parc-1]); peers (parc>=7) and the MR-4d
     * fronted_by (parc>=8) are optional positionals inserted before it, so an old
     * binary's read of cap=parv[4]+name=parv[parc-1] stays correct and just ignores
     * the extras. */
    if (parc >= 6) { bcap = parv[4]; bname = parv[parc - 1]; }
    if (parc >= 7) { bpeers = parv[5]; }
    if (parc >= 8) { bfronted = parv[6]; }
    if (!crdt_shadow_beacon_record((unsigned int)base64toint(parv[2]),
                                   (time_t)atol(parv[3]), bcap, bname, bpeers, bfronted))
      return 0;
    for (p = GlobalClientList; p; p = cli_next(p))
      if (p != cptr && IsCrdtSyncTarget(p)) {
        if (bname[0] && bpeers[0] && bfronted[0])
          sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "H %s %s %s %s %s :%s",
                        parv[2], parv[3], bcap, bpeers, bfronted, bname);
        else if (bname[0] && bpeers[0])
          sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "H %s %s %s %s :%s",
                        parv[2], parv[3], bcap, bpeers, bname);
        else if (bname[0])
          sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "H %s %s %s :%s",
                        parv[2], parv[3], bcap, bname);
        else
          sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "H %s %s", parv[2], parv[3]);
      }
  }
  return 0;
}

/* Phase 4b: UNREGISTERED-state CR handler.  A CRDT mesh overlay link
 * (mr_crdtmesh) stays in STAT_HANDSHAKE / UNREGISTERED_HANDLER permanently and
 * carries ONLY CR tokens — never a P10 SERVER/BURST and never the routing tree.
 * Its CR lines arrive via the normal connect_dopacket -> parse_client path (which
 * ignores the sender prefix), so they dispatch through this UNREG slot instead of
 * ms_crdt's SERVER slot.  ms_crdt keys the peer numeric off cli_yxx(cptr), which
 * mr_crdtmesh stored at handshake, so SV recording + dedup are correct.  Gate
 * strictly on IsCrdtOverlay so an ordinary unregistered/handshake connection can
 * never inject CRDT state. */
int mr_crdt(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  if (!IsCrdtOverlay(cptr))
    return 0;
  return ms_crdt(cptr, sptr, parc, parv);
}
