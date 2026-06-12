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
#include "handlers.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"
#include "crdt_state.h"   /* Tier2 T2-b: struct CrdtUserRecord (CR M source prefix) */
#include "ircd_string.h"  /* Tier2 T2-b: ircd_strncpy (msgid dedup ring) */
#include "channel.h"      /* Tier2 T2-b: Membership (CR M channel deliver) */
#include "hash.h"         /* Tier2 T2-b: FindChannel (CR M channel deliver) */

#include "crdt_shadow.h"
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

/* return 1 if msgid was already seen within the window (dup), else record it -> 0. */
static int crdt_m_seen_check_add(const char *msgid)
{
  return crdt_dedup_check_add(&crdt_m_seen, msgid, (uint64_t)CurrentTime,
                              CRDT_M_SEEN_WINDOW);
}

/* Gossip a live message to a mesh-only target via ephemeral CR M.
 *   cmd    'P' (PRIVMSG) or 'N' (NOTICE)
 *   target a 5-char user numeric (unicast) OR a #channel name
 * Wire: :<srv> CR M <msgid> <cmd> <srcYXX> <target> :<text> */
void crdt_gossip_message(struct Client *from, char cmd, const char *target,
                         const char *msgid, const char *text)
{
  struct Client *acptr;
  if (!crdt_shadow_active() || !from || !target || !text)
    return;
  crdt_m_seen_check_add(msgid);        /* record so an echo/relay-back is deduped */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsCrdtSyncTarget(acptr))
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, acptr, "M %s %c %s%s %s :%s",
                    msgid && *msgid ? msgid : "*", cmd,
                    NumNick(from), target, text);
}

/* Tier2 full-partition liveness: gossip our ephemeral liveness beacon
 * (CR H <ourYXX> <CurrentTime> <nn_capacity> :<name>) to all CRDT transports.
 * Receivers track the last beacon per server; a mesh stub whose beacon goes stale
 * is retired (full partition).  #3: the appended capacity + name let a receiver
 * build a right-sized, real-named synthetic anchor for us.  Ephemeral — never
 * touches the doc. */
void crdt_gossip_beacon(void)
{
  struct Client *acptr;
  if (!crdt_shadow_active() || !feature_bool(FEAT_CRDT_PRIMARY))
    return;
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
    if (IsCrdtSyncTarget(acptr))
      sendcmdto_one(&me, CMD_CRDT_REPLICATION, acptr, "H %s %ld %s :%s",
                    cli_yxx(&me), (long)CurrentTime,
                    cli_serv(&me)->nn_capacity, cli_name(&me));
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
          crdt_shadow_reconcile_removes();
          crdt_shadow_reconcile_member_status();
          crdt_shadow_reconcile_bans();
          crdt_shadow_reconcile_user_removes(); /* Phase 3m: QUIT / delete-on-leave (after channel cleanup) */
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
    int is_tag;
    if (parc < 7)
      return 0;
    m_msgid = parv[2]; m_cmd = parv[3]; srcyxx = parv[4]; target = parv[5];
    m_text = parv[parc - 1];
    if (crdt_m_seen_check_add(m_msgid))
      return 0;                        /* already handled via another mesh path */
    is_tag = (m_cmd[0] == 'T');
    cmdstr = (m_cmd[0] == 'N') ? "NOTICE" : (is_tag ? "TAGMSG" : "PRIVMSG");
    src = crdt_shadow_user_record(srcyxx);
    /* R4a (channel-over-mesh): per-server local-delivery dedup.  If the TREE plane
     * already delivered this msgid to our locals (the channel relay marked it), skip the
     * redundant CR-M LOCAL delivery — but still relay the flood onward below.  Distinct
     * from crdt_m_seen (the flood dedup at the top), which gates relay too; sharing it
     * would let a tree-first delivery suppress the CR-M relay and break the flood. */
    if (!crdt_shadow_chan_local_check_add(m_msgid)) {
    if (target[0] == '#' || target[0] == '&') {           /* channel delivery */
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
    } else {                                              /* unicast delivery */
      struct Client *tgt = findNUser(target);
      if (tgt && MyConnect(tgt)) {
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
      }
    }
    }  /* R4a: end local-delivery dedup guard (the flood relay below always runs) */
    for (p = GlobalClientList; p; p = cli_next(p))   /* gossip relay (excl source) */
      if (p != cptr && IsCrdtSyncTarget(p))
        sendcmdto_one(&me, CMD_CRDT_REPLICATION, p, "M %s %s %s %s :%s",
                      m_msgid, m_cmd, srcyxx, target, m_text);
  } else if (sub[0] == 'H' && !sub[1]) {
    /* Tier2 full-partition liveness beacon — H <srvYXX> <emit_ts> [<nn_cap> :<name>].
     * Record + relay if FRESH (newer emit_ts); a dup/old beacon drops, terminating
     * the flood.  #3: nn_cap + name are append-only; an old-form beacon (parc==4)
     * omits them and is relayed in old form (mixed-version safe).  Ephemeral. */
    struct Client *p;
    const char *bcap = "", *bname = "";
    if (parc < 4)
      return 0;
    if (parc >= 6) { bcap = parv[4]; bname = parv[parc - 1]; }
    if (!crdt_shadow_beacon_record((unsigned int)base64toint(parv[2]),
                                   (time_t)atol(parv[3]), bcap, bname))
      return 0;
    for (p = GlobalClientList; p; p = cli_next(p))
      if (p != cptr && IsCrdtSyncTarget(p)) {
        if (bname[0])
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
