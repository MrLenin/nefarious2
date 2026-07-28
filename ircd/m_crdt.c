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
#include "sasl_auth.h"    /* sasl_cache_invalidate_user (CR M cmd I — CI over mesh) */
#include "ircd_relay.h"   /* 5-5f B1: store_channel_history (CR-M witness store) */
#include "history.h"      /* 5-5f B1: HISTORY_PRIVMSG/NOTICE type enum */

#include "crdt_shadow.h"
#include "crdt_meshmap.h"  /* MR-1: crdt_meshmap_nexthop + crdt_route_action */
#include "crdt_wire.h"
#include "s2s_chunk.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>     /* 5-5f B1: gettimeofday (witness-store timestamp) */

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

/** The document does not fit in CR_SNAP_MAX, so no CR F snapshot can be built.
 *  A peer below our gc_floor NEEDS a snapshot (the ops it lacks are GC'd, so a
 *  delta is incomplete) — without it that peer stays permanently DIVERGENT.
 *  Surface it as an operator warning instead of a silent drop.  Rate-limited:
 *  anti-entropy re-attempts every cycle, so an uncorrectable overflow must not
 *  turn into a log flood.  @a need is the byte count the full snapshot requires
 *  (the magnitude the engine returned). */
static void crdt_snapshot_overflow_warn(struct Client *to, size_t need)
{
  static time_t last_warn;
  if (CurrentTime == last_warn)
    return;
  last_warn = CurrentTime;
  log_write(LS_SYSTEM, L_WARNING, 0,
            "CRDT sync: full snapshot for %s does not fit CR_SNAP_MAX "
            "(doc needs %lu bytes, cap %d) — peer below gc_floor stays DIVERGENT; "
            "raise CR_SNAP_MAX or chunk the snapshot",
            cli_name(to), (unsigned long)need, CR_SNAP_MAX);
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
  } else if (sn < 0 && crdt_shadow_active()) {
    /* engine signalled encode overflow (magnitude = bytes needed); shadow_active
     * implies g_inited, so a negative here is a real doc-too-big, not "CRDT off". */
    crdt_snapshot_overflow_warn(to, (size_t)(-(long)sn));
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

/* CR M source token for @a from: a user's 5-char YXX, or — for a USERLESS
 * source (a real server, a mesh stub, or &me: nick-collision / services
 * KILLs, server-sourced WALLOPS/NOTICEs) — its 2-char server numeric.
 * NumNick() on a userless source derefs cli_user(from)->server (NULL) ->
 * SIGSEGV (invariant 2: user-branch formatters crash on a server/stub
 * source).  The receiver discriminates the two forms by token length. */
static void crdt_m_source_token(struct Client *from, char *buf, size_t cap)
{
  if (IsServer(from) || IsMeshStub(from) || IsMe(from) || !cli_user(from))
    /* Canonical 2-char server numeric.  cli_yxx is only 1 char for a server
     * configured with a 1-char P10 numeric; the receiver discriminates the
     * server form as EXACTLY 2 chars (srcyxx[0] && srcyxx[1] && !srcyxx[2]),
     * so a 1-char token would be misread as user-form and misresolved by
     * findNUser.  Re-encode to a fixed 2-char width (buf/cap is always >= 3):
     * base64toint recovers the value for a 1- or 2-char yxx, and a server
     * numeric is 0..4095, so inttobase64(,2) reproduces it exactly. */
    inttobase64(buf, base64toint(cli_yxx(from)), 2);
  else
    ircd_snprintf(0, buf, cap, "%s%s", NumNick(from));
}

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
  char srcfull[16];
  if (!crdt_shadow_active() || !from || !target || !text)
    return;
  mid = (msgid && *msgid) ? msgid : "*";
  crdt_m_seen_check_add(msgid);        /* record so an echo/relay-back is deduped */
  crdt_m_source_token(from, srcfull, sizeof srcfull);

  if ((target[0] == '#' || target[0] == '&' || target[0] == '*') &&
      feature_bool(FEAT_CRDT_ROUTE_BCAST) && crdt_shadow_mesh_bcast_stable(CurrentTime)) {
    crdt_tree_forward_chan(-1, mid, cmd, srcfull, target, CRDT_M_TTL_DEFAULT, text);
    return;
  }
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsCrdtSyncTarget(acptr))
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, acptr, "M %s %c %s %s %d :%s",
                    mid, cmd, srcfull, target, CRDT_M_TTL_DEFAULT, text);
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
  char tyxx[6], srcfull[16];
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
      crdt_m_source_token(from, srcfull, sizeof srcfull);  /* server/stub-safe */
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, peer, "M %s %c %s %s %d :%s",
                    mid, cmd, srcfull, tyxx, CRDT_M_TTL_DEFAULT, text);
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

/* ===== Tier B: the services-anchor bridge (CR X carrier) =====
 * x3.services (and other services pseudo-servers) is reachable on a far CRDT leaf ONLY as a
 * dead-sink anchor, so every P10 command to/from it drops.  CR X is a payload-agnostic,
 * SERVER-numeric-routed opaque carrier (vs CR M's user-routed unicast): it tunnels the verbatim
 * P10 body of a SASL/ACCOUNT/REGISTER/XQUERY/... command across the mesh.  STATELESS — the
 * <srvnum>!fd.cookie auth token in the body already encodes origin+fd+cookie, so the bridge
 * never parses auth.  Wire: `X <msgid> <dstSrvYXX> <p10cmd> <ttl> :<P10 body>`.  Flood + dedup
 * (low-volume services traffic; flood is robust + avoids the next-hop-stale latency risk against
 * FEAT_SASL_TIMEOUT).  See crdt-mesh-services-bridge.md. */

/* Flood a CR X frame toward server numeric @a dstyxx, carrying the ORIGINATING server numeric
 * @a srcyxx so the gateway re-emits to the service with that source (the service then replies
 * to the real origin, not the gateway).  @a body = the verbatim P10 param tail (what
 * sendcmdto_one would have produced after the routing target). */
static void crdt_services_emit(const char *srcyxx, const char *dstyxx, char p10cmd,
                               const char *body)
{
  struct Client *p;
  char mid[64];
  if (!crdt_shadow_active() || !srcyxx || !dstyxx || !body)
    return;
  generate_msgid(mid, sizeof mid);
  crdt_m_seen_check_add(mid);             /* dedup our own relay-back */
  for (p = GlobalClientList; p; p = cli_next(p))
    if (IsCrdtSyncTarget(p))
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "X %s %s %s %c %d :%s",
                    mid, srcyxx, dstyxx, p10cmd, CRDT_M_TTL_DEFAULT, body);
}

/* FORWARD (leaf -> x3): route a services command over the mesh when its target SERVER is
 * reachable only as an anchor (crdt_server_is_mesh_only — x3 is never presented on a leaf).
 * Returns 1 if tunneled (caller skips the P10 send), 0 to fall back to P10. */
int crdt_route_services_try(struct Client *dstsrv, char p10cmd, const char *body)
{
  log_write(LS_SYSTEM, L_INFO, 0,
            "Tier B FWD-try: tgt=%s cmd=%c flag=%d meshstub=%d presented=%d",
            dstsrv ? cli_name(dstsrv) : "(null)", p10cmd,
            feature_bool(FEAT_CRDT_SERVICES_BRIDGE),
            dstsrv ? IsMeshStub(dstsrv) : -1,
            (dstsrv && IsMeshStub(dstsrv)) ? IsPresented(dstsrv) : -1);
  if (!feature_bool(FEAT_CRDT_SERVICES_BRIDGE) || !dstsrv || !body ||
      !crdt_server_is_mesh_only(dstsrv))
    return 0;
  crdt_services_emit(cli_yxx(&me), cli_yxx(dstsrv), p10cmd, body);  /* origin = us (the leaf) */
  log_write(LS_SYSTEM, L_INFO, 0, "Tier B FWD: CR-X emitted dst=%s cmd=%c", cli_yxx(dstsrv), p10cmd);
  return 1;
}

/* REVERSE (gateway: x3-reply -> originating leaf): the reply's target (@a tgt = a server, or a
 * user/anchor on it) is mesh-only on the gateway, so a P10 send would dead-sink.  Tunnel CR X
 * toward the owning server.  Uses IsMeshStub directly (NOT crdt_server_is_mesh_only): on the
 * gateway a leaf stub may be PRESENTED, which still dead-sinks — the presented-stub trap from
 * the INVITE fix.  Returns 1 if tunneled, 0 to fall back to P10. */
int crdt_route_services_reply_try(struct Client *tgt, char p10cmd, const char *body)
{
  struct Client *owner;
  if (!feature_bool(FEAT_CRDT_SERVICES_BRIDGE) || !tgt || !body)
    return 0;
  owner = (IsServer(tgt) || IsMeshStub(tgt)) ? tgt
          : (cli_user(tgt) ? cli_user(tgt)->server : NULL);
  log_write(LS_SYSTEM, L_INFO, 0,
            "Tier B REV-try: tgt=%s owner=%s ownermeshstub=%d cmd=%c",
            cli_name(tgt), owner ? cli_name(owner) : "(null)",
            owner ? IsMeshStub(owner) : -1, p10cmd);
  if (!owner || !IsMeshStub(owner))
    return 0;
  crdt_services_emit(cli_yxx(&me), cli_yxx(owner), p10cmd, body);  /* origin = us (the gateway) */
  log_write(LS_SYSTEM, L_INFO, 0, "Tier B REV: CR-X emitted dst=%s cmd=%c", cli_yxx(owner), p10cmd);
  return 1;
}

/* REVERSE by numeric (gateway-as-proxy): the services reply landed on THIS gateway (x3 only
 * knows the gateway under tree-retirement) but its session token belongs to another server
 * @a srvnum (the originating mesh-only leaf).  Tunnel CR-X toward srvnum.  Routes when srvnum
 * is a mesh anchor here OR is unknown here (reachable only via the mesh); declines a real local
 * P10 server.  Returns 1 if tunneled, 0 to fall through. */
int crdt_route_services_reply_by_num(const char *srvnum, char p10cmd, const char *body)
{
  struct Client *owner;
  if (!feature_bool(FEAT_CRDT_SERVICES_BRIDGE) || !srvnum || !body)
    return 0;
  owner = FindNServer(srvnum);
  if (owner && !IsMeshStub(owner))
    return 0;                            /* a real P10 server reachable here -> not our case */
  crdt_services_emit(cli_yxx(&me), srvnum, p10cmd, body);
  log_write(LS_SYSTEM, L_INFO, 0, "Tier B REV(num): CR-X emitted dst=%s cmd=%c", srvnum, p10cmd);
  return 1;
}

/* Gateway: re-emit a tunneled services command as REAL P10 toward the live server @a dsrv
 * (x3).  The body is the verbatim P10 param tail; %s passes it literally (auth payloads have
 * no '%').  Dumb pipe — the auth handler on x3 parses it. */
static void crdt_services_reemit(struct Client *srcsrv, struct Client *dsrv, char p10cmd,
                                 const char *body)
{
  struct Client *src = srcsrv ? srcsrv : &me;   /* origin so the service replies to the real
                                                   originating server, not this gateway */
  switch (p10cmd) {
    case 'A': sendcmdto_one(src, CMD_SASL,     dsrv, "%s", body); break;
    case 'C': sendcmdto_one(src, CMD_ACCOUNT,  dsrv, "%s", body); break;
    case 'G': sendcmdto_one(src, CMD_REGISTER, dsrv, "%s", body); break;
    case 'V': sendcmdto_one(src, CMD_VERIFY,   dsrv, "%s", body); break;
    case 'R': sendcmdto_one(src, CMD_REGREPLY, dsrv, "%s", body); break;
    case 'Q': sendcmdto_one(src, CMD_XQUERY,   dsrv, "%s", body); break;
    case 'Y': sendcmdto_one(src, CMD_XREPLY,   dsrv, "%s", body); break;
    /* 5-5f B3: chathistory federation frame (query or reply) leaving the mesh
     * for a legacy server we hold a live P10 link to.  This IS the return leg
     * of the gateway slice: the owner tunnels its replies addressed to the
     * requesting legacy server, and they land here as ordinary P10 CH lines
     * sourced from the real owner, so the requester's find_fed_request()
     * matches exactly as if the two had been directly linked. */
    case 'H': sendcmdto_one(src, CMD_CHATHISTORY, dsrv, "%s", body); break;
    default: break;
  }
}

/* 5-5f B3 (gateway slice): hand a chathistory federation frame to the CR-X
 * carrier, addressed to server @a dstyxx (cmd 'H').  Routing, msgid dedup,
 * TTL, the destination's local re-inject and the gateway's re-emit-to-legacy
 * leg are all existing CR-X machinery — this only selects the carrier.
 *
 * Returns 1 if the mesh accepted it, 0 if the carrier is unavailable.  A 0 is
 * load-bearing for the caller: a query that cannot be tunnelled MUST still be
 * accounted for (the 5-5c invariant — never leave servers_pending uncredited,
 * or the pre-Phase-0 wedge returns). */
int crdt_ch_tunnel_try(const char *dstyxx, const char *body)
{
  if (!crdt_ch_tunnel_avail() || !dstyxx || !dstyxx[0] || !body || !body[0])
    return 0;
  crdt_services_emit(cli_yxx(&me), dstyxx, 'H', body);
  return 1;
}

/* 5-5f B2 part 2: is the CR-X carrier usable at all?  Deterministic within a
 * tick, so the federation dispatcher can decide at COUNT time whether a
 * mesh-stub storage server is reachable — count and dispatch then agree by
 * construction and servers_pending never carries a target that tunnel_try
 * would refuse (the 5-5c never-uncredited invariant, settled up front instead
 * of by post-hoc decrement). */
int crdt_ch_tunnel_avail(void)
{
  return feature_bool(FEAT_CRDT_SERVICES_BRIDGE) && crdt_shadow_active();
}

/* Reply leg of the above — fire-and-forget: a reply that cannot be tunnelled
 * has no second carrier to try, and falls to the requester's fed timeout. */
void crdt_ch_tunnel_reply(const char *dstyxx, const char *body)
{
  crdt_ch_tunnel_try(dstyxx, body);
}

/* Destination leaf: re-inject the tunneled body into the LOCAL services handler (the token in
 * the body resolves the local client).  Splits @a body (mutated in place) into a parv — P10
 * arg rules: space-separated, a leading ':' begins the trailing param (rest of line).  parv[0]
 * is a prefix placeholder (the ms_ handlers route by the body, not the prefix). */
static void crdt_services_reinject(char p10cmd, char *body)
{
  char *parv[MAXPARA + 3];
  int parc = 0;
  char *s = body;
  parv[parc++] = cli_name(&me);
  while (*s && parc < MAXPARA + 2) {
    while (*s == ' ') *s++ = '\0';
    if (!*s)
      break;
    if (*s == ':') { parv[parc++] = ++s; break; }   /* trailing param: rest of line verbatim */
    parv[parc++] = s;
    while (*s && *s != ' ')
      s++;
  }
  parv[parc] = NULL;
  switch (p10cmd) {
    case 'A': ms_sasl(&me, &me, parc, parv); break;
    case 'C': ms_account(&me, &me, parc, parv); break;
    case 'R': ms_regreply(&me, &me, parc, parv); break;
    case 'Q': ms_xquery(&me, &me, parc, parv); break;
    case 'Y': ms_xreply(&me, &me, parc, parv); break;
    /* 'G'/'V' (REGISTER/VERIFY) are forward-only to services -> never re-injected at a leaf */
    default: break;
  }
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

/* s2s_chunk_feed failure (reassembly cap exceeded / table full / alloc): the
 * transfer is dropped; anti-entropy re-serves the state later.  Rate-limited —
 * a hostile endless stream must not turn the abort itself into log flood. */
static void crdt_chunk_feed_failed(struct Client *cptr, const char *id)
{
  static time_t last_warn;
  if (CurrentTime == last_warn)
    return;
  last_warn = CurrentTime;
  log_write(LS_SYSTEM, L_WARNING, 0,
            "CRDT sync: chunk reassembly aborted (id %s from %s) — transfer dropped",
            id, cli_name(cptr));
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
    if (r < 0)
      crdt_chunk_feed_failed(cptr, parv[2]);
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
          crdt_shadow_reconcile_markers(); /* Tier C F2-a: drive read-markers from doc -> RocksDB */
          crdt_shadow_reconcile_metadata(); /* Tier C F2-b: drive account metadata from doc -> metadata_cf */
          crdt_shadow_reconcile_tempshuns(); /* Tier C F3: apply tempshun flips on the delta, not the 30s tick */
          crdt_shadow_reconcile_webpush(); /* Tier C F2-c: converge webpush subs on the delta */
          /* M6c-1 Increment 2: reconcile bouncer sessions EAGERLY on the delta that
           * carries the change, not on the 30s verify timer.  Without this the
           * gateway's HOLDING<->ACTIVE state-apply (and its BS A/D synth toward
           * legacy) lagged ~120s (verify timer + holder sweep + lease claim),
           * missing fast revive/hold transitions.  Runs LAST so reconcile_users +
           * members + member_status have already materialized the user + its
           * memberships -> chans resolves for the synth.  Idempotent: the state-
           * apply emit is gated on hs_state != doc state, so repeated eager calls
           * after convergence are no-ops (no BS A/D storm).  NO local-holder sweep
           * here -- eager ingest is doc->live only; the sweep stays verify-timer. */
          crdt_shadow_reconcile_bouncer();
          crdt_shadow_decomm_sweep();      /* decommission markers reap eagerly on the delta that carries them (F3 lesson); empty-map early-out makes this ~free */
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
    if (r < 0)
      crdt_chunk_feed_failed(cptr, parv[2]);
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
        /* Orphan-reap owner sweep, eager pass: a CR F merge is the ONLY path a
         * stale OWN-origin record can re-import (merge-keep; deltas are SV-deduped
         * ops), so sweep right after each steady-state apply — the Fix-A exchange
         * storm typically applies 2+ snapshots within seconds, completing the
         * 2-pass debounce near-instantly.  Self-gates on !bursting (the mid-burst
         * apply defers to the EOB call). */
        crdt_shadow_own_user_sweep();
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
    struct Client *p, *srcsrv, *srcu;
    int is_tag, ttl, ttl_next, src_is_srv;
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
    /* Source-form discrimination: a 2-char token is the SERVER-form source
     * (server / mesh stub / &me — a userless origin has no user YXX, see
     * crdt_m_source_token).  findNUser() on a 2-char token MISRESOLVES:
     * FindNServer() reads both chars as the server numeric, then the char at
     * yxx+1 indexes that server's client_list -> an arbitrary user would get
     * attributed as the source.  Resolve each form explicitly, once. */
    src_is_srv = (srcyxx[0] && srcyxx[1] && !srcyxx[2]);
    srcsrv = src_is_srv ? FindNServer(srcyxx) : NULL;
    srcu = src_is_srv ? NULL : findNUser(srcyxx);
    /* R4a (channel-over-mesh): per-server local-delivery dedup.  If the TREE plane
     * already delivered this msgid to our locals (the channel relay marked it), skip the
     * redundant CR-M LOCAL delivery — but still relay the flood onward below.  Distinct
     * from crdt_m_seen (the flood dedup at the top), which gates relay too; sharing it
     * would let a tree-first delivery suppress the CR-M relay and break the flood. */
    if (!crdt_shadow_chan_local_check_add(m_msgid)) {
    if (m_cmd[0] == 'W') {                                /* MR-2b: all-server WALLOPS */
      struct Client *wsrc = srcu ? srcu : srcsrv;   /* server-form: server WALLOPS
                                                     * (%:#C handles server + stub) */
      if (wsrc)
        sendwallto_local(wsrc, WALL_WALLOPS, m_text);    /* deliver to local +w opers */
    } else if (m_cmd[0] == 'I' && target[0] == '*') {  /* CI (target "*") — NOT INVITE.
                                            * INVITE also rides cmd 'I' but always carries a
                                            * USER numeric target; CI always "*".  Without
                                            * this target guard the CI branch (added by the
                                            * gap-B fix `2b1283d`, ordered before the unicast
                                            * INVITE handler below) swallowed EVERY mesh
                                            * INVITE into sasl_cache_invalidate_user(channel)
                                            * — a bogus no-op that also dead-sank the invite
                                            * (proven live: nef3 INVITE -> nef7 logged "CRDT
                                            * CI ... for #invchan", target got nothing).
                                            * SASL auth-cache invalidation (S2S-audit
                                            * gap B, SECURITY — the tree-only CI token
                                            * never reached overlay-only / tree-retired
                                            * nodes, whose POSITIVE cache then served a
                                            * revoked credential for up to pos_ttl).
                                            * LOCAL invalidate only, MR-2b W precedent:
                                            * no legacy re-emit (legacy rides the
                                            * origin's tree copy; re-emitting here would
                                            * open a dual-plane echo loop), no channel
                                            * delivery.  The shared flood relay below
                                            * carries it mesh-wide, msgid-deduped. */
      log_write(LS_SYSTEM, L_INFO, 0,
                "CRDT CI: mesh auth-cache invalidation for %s", m_text);
      sasl_cache_invalidate_user(m_text);
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
              sendrawto_one(memb->user, "@%s :%s TAGMSG %s", m_text,
                            srcsrv ? cli_name(srcsrv) : srcyxx, target);
          } else if (src && src->nick[0])
            sendrawto_one(memb->user, ":%s!%s@%s %s %s :%s", src->nick,
                          src->ident, src->host[0] ? src->host : "mesh",
                          cmdstr, target, m_text);
          else
            sendrawto_one(memb->user, ":%s %s %s :%s",
                          srcsrv ? cli_name(srcsrv) : srcyxx, cmdstr, target,
                          m_text);
        }
#ifdef USE_ROCKSDB
      /* 5-5f B1: witness-store the mesh-delivered message with the SAME
       * semantics as the P10 relay path — store_channel_history applies the
       * local-interest walk, +P, REQUIRE_AUTH and +Y gates internally — so
       * mesh steady state keeps a copy on every node with a local member,
       * restoring pre-R6a storage redundancy (without this, R6a tree-demote
       * leaves exactly ONE stored copy network-wide: the origin's).
       * First-arrival only (we are inside the chan_local dedup, so a
       * tree-first double-arrival never double-stores); the origin msgid on
       * the frame keys storage network-consistently (exact federation
       * dedup); arrival-time timestamp mirrors server_relay_channel_message.
       * Skip TAGMSG (tree parity: never stored) and mesh-stub sources — a
       * stub's cli_from is itself, so MyConnect(stub) is true and would
       * defeat store_channel_history's local-interest gate. */
      if (ch && !is_tag && (m_cmd[0] == 'P' || m_cmd[0] == 'N')
          && m_msgid[0] && strcmp(m_msgid, "*") != 0) {
        struct Client *wsptr = srcu ? srcu
            : ((srcsrv && !MyConnect(srcsrv)) ? srcsrv : NULL);
        if (wsptr) {
          char wts[32];
          struct timeval wtv;
          gettimeofday(&wtv, NULL);
          ircd_snprintf(0, wts, sizeof(wts), "%lu.%03lu",
                        (unsigned long)wtv.tv_sec,
                        (unsigned long)(wtv.tv_usec / 1000));
          store_channel_history(wsptr, ch, m_text,
                                (m_cmd[0] == 'N') ? HISTORY_NOTICE
                                                  : HISTORY_PRIVMSG,
                                m_msgid, wts, NULL);
        }
      }
#endif
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
        struct Client *srcc = srcu;   /* USER sources only: legacy can't place a
                                       * server-form (2-char) source in a channel */
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
        struct Client *srcc = srcu;   /* USER sources only (as above) */
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
        struct Client *ksrc = srcu;
        /* server-form source (collision / services kill): attribute the kill
         * to the ORIGIN SERVER by name; the emitting client stays &me (a mesh
         * stub must never become an exit/emit source — invariant 2). */
        struct Client *ksh  = (feature_bool(FEAT_HIS_KILLWHO) || !ksrc) ? &me : ksrc;
        const char *kn = feature_bool(FEAT_HIS_KILLWHO) ? feature_str(FEAT_HIS_SERVERNAME)
                         : (ksrc ? cli_name(ksrc)
                                 : (srcsrv ? cli_name(srcsrv) : "mesh"));
        sendcmdto_one(ksh, CMD_KILL, tgt, "%C :%s %s", tgt, kn, m_text);
        exit_client_msg(cptr, tgt, ksh, "Killed (%s %s)", kn, m_text);
      } else if (tgt && MyConnect(tgt) && m_cmd[0] == 'I') {
        /* MR-5-1: a mesh-routed INVITE reached the target's HOME -> add the invite + notify
         * the local target (mirrors m_invite's MyConnect branch).  m_text = the channel. */
        struct Client *isrc = srcu;   /* INVITE sources are users; server-form -> &me */
        struct Channel *ich = FindChannel(m_text);
        if (ich) {
          add_invite(tgt, ich);
          sendcmdto_one(isrc ? isrc : &me, CMD_INVITE, tgt, "%s %H", cli_name(tgt), ich);
        } else
          /* audit-A2: invite to a non-existent channel (ms_invite :341 form) — no chptr to
           * add_invite; relay the bare-name INVITE (legacy "allow invites to non existent
           * channels"; mirrors the gateway 'I' re-emit fallback at the CR->P10 bridge). */
          sendcmdto_one(isrc ? isrc : &me, CMD_INVITE, tgt, "%C :%s", tgt, m_text);
      } else if (tgt && MyConnect(tgt)) {            /* local CRDT user — message delivery (P/N/T) */
        if (is_tag) {                  /* TAGMSG: @tags prefix, no body, cap-gated */
          if (CapActive(tgt, CAP_MSGTAGS)) {
            if (src && src->nick[0])
              sendrawto_one(tgt, "@%s :%s!%s@%s TAGMSG %s", m_text, src->nick,
                            src->ident, src->host[0] ? src->host : "mesh",
                            cli_name(tgt));
            else
              sendrawto_one(tgt, "@%s :%s TAGMSG %s", m_text,
                            srcsrv ? cli_name(srcsrv) : srcyxx, cli_name(tgt));
          }
        } else if (src && src->nick[0])
          sendrawto_one(tgt, ":%s!%s@%s %s %s :%s", src->nick, src->ident,
                        src->host[0] ? src->host : "mesh", cmdstr, cli_name(tgt),
                        m_text);
        else
          sendrawto_one(tgt, ":%s %s %s :%s",
                        srcsrv ? cli_name(srcsrv) : srcyxx, cmdstr, cli_name(tgt),
                        m_text);
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
          struct Client *srcc = srcu;
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
          } else if (feature_bool(FEAT_CRDT_GATEWAY_BRIDGE) && !srcc && srcsrv &&
                     is_kill) {
            /* MR-4c, server-form source: a server/stub-sourced mesh KILL of a
             * legacy-fronted victim (collision / services kill during a
             * partition).  Re-emit from the GATEWAY itself — always placeable
             * by legacy, and a mesh-stub srcsrv must never be an S2S message
             * source (invariant 2) — naming the true origin in the path. */
            sendcmdto_one(&me, CMD_KILL, tgt, "%C :%s!%s %s", tgt,
                          cli_name(&me), cli_name(srcsrv), m_text);
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
    /* B0/MR-3d fast path: a FRESH beacon for a mesh server just arrived -> if we're a
     * gateway, present that leaf to legacy NOW (don't wait up to a verify interval), so x3
     * knows it before a cold-leaf services-forward arrives under the 3s LOC budget.  Skips
     * proxied-legacy rows + real servers internally; no-op off-gateway / flag-off. */
    crdt_shadow_present_one_num(parv[2]);
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
  } else if (sub[0] == 'X' && !sub[1]) {
    /* Tier B services-anchor bridge: `X <msgid> <srcSrvYXX> <dstSrvYXX> <p10cmd> <ttl> :<P10 body>`.
     * Routed toward the SERVER numeric dstSrvYXX (flood + dedup); srcSrvYXX = the originating
     * server (so the gateway re-emits to the service with that source -> the service replies to
     * the origin, not the gateway).  Three outcomes:
     *  (a) dstSrvYXX == us  -> re-inject the body into the local ms_ handler;
     *  (b) we hold a LIVE legacy P10 link to dstSrvYXX (the gateway) -> re-emit real P10;
     *  (c) else relay onward (TTL-bounded).  Dumb pipe; flag-gated FEAT_CRDT_SERVICES_BRIDGE. */
    const char *x_msgid, *srcyxx, *dstyxx, *x_body;
    char x_cmd;
    int x_ttl;
    unsigned int dstnum, ournum;
    struct Client *dsrv, *ssrv, *p;
    if (parc < 8 || !feature_bool(FEAT_CRDT_SERVICES_BRIDGE))
      return 0;
    x_msgid = parv[2]; srcyxx = parv[3]; dstyxx = parv[4]; x_cmd = parv[5][0];
    x_ttl = atoi(parv[6]); x_body = parv[parc - 1];
    if (crdt_m_seen_check_add(x_msgid))
      return 0;                            /* already handled via another mesh path */
    dstnum = (unsigned int)base64toint(dstyxx);
    ournum = (unsigned int)base64toint(cli_yxx(&me));
    dsrv = FindNServer(dstyxx);
    log_write(LS_SYSTEM, L_INFO, 0,
              "Tier B CR-X recv: src=%s dst=%s cmd=%c ttl=%d self=%d resolved=%s gwbridge=%d",
              srcyxx, dstyxx, x_cmd, x_ttl, dstnum == ournum,
              dsrv ? cli_name(dsrv) : "(none)", feature_bool(FEAT_CRDT_GATEWAY_BRIDGE));
    if (dstnum == ournum) {                /* (a) we are the destination -> local re-inject */
      char bodybuf[BUFSIZE];
      ircd_strncpy(bodybuf, x_body, sizeof bodybuf);
      if (x_cmd == 'H')                  /* 5-5f B3: chathistory needs the reply
                                          * tunnel armed around its dispatch */
        crdt_ch_tunnel_dispatch(bodybuf);
      else
        crdt_services_reinject(x_cmd, bodybuf);
      log_write(LS_SYSTEM, L_INFO, 0, "Tier B CR-X: re-injected locally cmd=%c", x_cmd);
      return 0;
    }
    if (dsrv && IsServer(dsrv) && cli_from(dsrv) && !IsCrdtAware(cli_from(dsrv)) &&
        feature_bool(FEAT_CRDT_GATEWAY_BRIDGE) &&
        !crdt_shadow_should_standby(dstnum, cli_yxx(&me))) {
      ssrv = FindNServer(srcyxx);          /* the originating server (anchor/real) for the source prefix */
      crdt_services_reemit(ssrv, dsrv, x_cmd, x_body);   /* (b) gateway -> real P10 to the service */
      log_write(LS_SYSTEM, L_INFO, 0, "Tier B CR-X: re-emitted P10 to %s (src %s) cmd=%c",
                cli_name(dsrv), ssrv ? cli_name(ssrv) : "&me", x_cmd);
      return 0;
    }
    if (x_ttl > 1)                          /* (c) relay onward (dedup above terminates loops) */
      for (p = GlobalClientList; p; p = cli_next(p))
        if (p != cptr && IsCrdtSyncTarget(p))
          sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "X %s %s %s %c %d :%s",
                        x_msgid, srcyxx, dstyxx, x_cmd, x_ttl - 1, x_body);
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
