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
#include "s_misc.h"          /* exit_client (Phase 3m user delete-on-leave) */
#include "s_user.h"          /* umode_str, make_user, user_apply_umode_str */
#include "send.h"            /* sendcmdto_* (Phase 3d topic gateway) */
#include "handlers.h"        /* crdt_sync_broadcast */

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
  if (num >= CRDT_MAX_SERVERS || emit_ts <= crdt_beacon[num].emit_ts)
    return 0;
  crdt_beacon[num].emit_ts = emit_ts;
  crdt_beacon[num].recv_ts = CurrentTime;
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
  acptrp = cli_serv(srv)->client_list;
  for (i = 0; i <= cli_serv(srv)->nn_mask; ++acptrp, ++i)
    if (*acptrp) held++;
  SetMeshStub(srv);
  crdt_mesh_stub_count++;            /* R6c: this node is now (partially) partitioned */
  SetFlag(srv, FLAG_MAP);            /* keep the stub's users visible in WHO */
  {                                  /* seed the liveness clock: it was just reachable */
    unsigned int n = (unsigned int)base64toint(cli_yxx(srv));
    if (n < CRDT_MAX_SERVERS) crdt_beacon[n].recv_ts = CurrentTime;
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

void crdt_shadow_topic(struct Channel *chptr, struct Client *from)
{
  if (!shadow_on())
    return;
  if (from_crdt_peer(from))            /* single-writer: peer owns this op */
    return;
  /* op-recording setter so the topic replicates (a direct crdt_lwwmap_set
   * would never enter the oplog and never sync — that was the modes/topic
   * convergence bug). */
  crdt_topic_set(&g_crdt, chptr->chname, chptr->topic);
  write_chanmeta(chptr);               /* topic_time/topic_nick + creationtime */
  crdt_sync_push();                    /* eager-propagate to CRDT peers */
}

/* CRDT_MODE_MASK now lives in channel.h (shared with the modebuf suppression
 * predicate); +L/+U/+A excluded there — see the note at its definition. */

/** Compact, comparable snapshot of a channel's persistent mode state. */
struct ShadowModeSnap {
  uint32_t mode;
  uint32_t limit;
  char     key[KEYLEN + 1];
};

static void build_mode_snap(struct Channel *chptr, struct ShadowModeSnap *s)
{
  memset(s, 0, sizeof *s);
  s->mode = chptr->mode.mode & CRDT_MODE_MASK;
  if (s->mode & MODE_LIMIT)
    s->limit = chptr->mode.limit;
  if (s->mode & MODE_KEY)
    strncpy(s->key, chptr->mode.key, sizeof s->key - 1);
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
     * Carry rec->lastmod (NOT TStime) so legacy ordering holds + no ping-pong (HQ1). */
    gline_modify(&me, &me, existing,
                 active_doc ? GLINE_ACTIVATE : GLINE_DEACTIVATE, reason,
                 (time_t)rec->expire, (time_t)rec->lastmod, (time_t)rec->lifetime,
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
    shun_modify(&me, &me, existing,
                active_doc ? SHUN_ACTIVATE : SHUN_DEACTIVATE, reason,
                (time_t)rec->expire, (time_t)rec->lastmod, (time_t)rec->lifetime,
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
    zline_modify(&me, &me, existing,
                 active_doc ? ZLINE_ACTIVATE : ZLINE_DEACTIVATE, reason,
                 (time_t)rec->expire, (time_t)rec->lastmod, (time_t)rec->lifetime,
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
      const char *stopic = tv ? (const char *)tv->data : "";
      if (strcmp(stopic, chptr->topic) != 0) {
        mismatches++;
        verify_emit(to,
                  "CRDT shadow topic divergence: %s shadow=\"%s\" real=\"%s\"",
                  chptr->chname, stopic, chptr->topic);
      }
    }
    /* field-level: channel modes (bits + limit + key) must match */
    {
      struct ShadowModeSnap cur;
      const struct CrdtLWWValue *mv =
        crdt_lwwmap_get(&g_crdt.modes, chptr->chname, strlen(chptr->chname));
      build_mode_snap(chptr, &cur);
      /* a channel with no persistent modes matches an absent shadow entry */
      if ((mv && (mv->data_len != sizeof cur ||
                  memcmp(mv->data, &cur, sizeof cur) != 0)) ||
          (!mv && cur.mode != 0)) {
        mismatches++;
        verify_emit(to,
                  "CRDT shadow mode divergence: %s real_mode=0x%x",
                  chptr->chname, cur.mode);
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
      /* chanmeta: creationtime + topic provenance */
      mv = crdt_lwwmap_get(&g_crdt.chanmeta, nbuf, dc->name_len);
      if (mv && mv->data_len == sizeof(struct CrdtChanMeta)) {
        const struct CrdtChanMeta *meta = (const struct CrdtChanMeta *)mv->data;
        if (meta->creationtime != (uint64_t)live->creationtime ||
            meta->topic_time != (uint64_t)live->topic_time ||
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
      if (strcmp(tv ? (const char *)tv->data : "", live->topic) != 0) {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: %s topic mismatch", nbuf);
      }
      /* persistent modes */
      build_mode_snap(live, &cur);
      mv = crdt_lwwmap_get(&g_crdt.modes, nbuf, dc->name_len);
      if ((mv && (mv->data_len != sizeof cur ||
                  memcmp(mv->data, &cur, sizeof cur) != 0)) ||
          (!mv && cur.mode != 0)) {
        gaps++;
        if (logged++ < MAT_LOG_CAP)
          log_write(LS_SYSTEM, L_NOTICE, 0,
                    "CRDT mat-check gap: %s modes mismatch (mode=0x%x)", nbuf,
                    cur.mode);
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
  if (rec->account[0]) {
    ircd_strncpy(cli_user(nc)->account, rec->account, ACCOUNTLEN + 1);
    cli_user(nc)->acc_create = (time_t)rec->acc_create;
    SetAccount(nc);
  }
  user_apply_umode_str(nc, rec->umodes);         /* sets umode FLAGS only */
  SetUser(nc);
  Count_newremoteclient(UserStats, srv);
  if (IsInvisible(nc))                            /* user_apply_umode_str doesn't */
    ++UserStats.inv_clients;                      /* bump these — exit asserts >0  */
  if (IsOper(nc) && !IsHideOper(nc) && !IsChannelService(nc) && !IsBot(nc))
    ++UserStats.opers;
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
  if (v && v->data)
    ircd_strncpy(chptr->topic, (const char *)v->data, TOPICLEN + 1);
  v = crdt_lwwmap_get(&g_crdt.modes, nbuf, dc->name_len);
  if (v && v->data_len == sizeof(struct ShadowModeSnap)) {
    const struct ShadowModeSnap *s = (const struct ShadowModeSnap *)v->data;
    chptr->mode.mode |= s->mode;
    if (s->mode & MODE_LIMIT) chptr->mode.limit = s->limit;
    if (s->mode & MODE_KEY)
      ircd_strncpy(chptr->mode.key, s->key, sizeof chptr->mode.key);
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

struct recon_user_ctx { unsigned int created; unsigned int renamed; unsigned int umoded; };

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
        ircd_strncpy(nbuf, numbuf, sizeof nbuf);
        pv[0] = cli_name(live); pv[1] = nbuf; pv[2] = delta; pv[3] = NULL;
        set_user_mode(cli_from(live), live, 3, pv, ALLOWMODES_ANY);
        c->umoded++;
      }
    }
  }
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
  if (c.created || c.renamed || c.umoded)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "CRDT user-reconcile: created %u, renamed %u, umode %u user(s) from doc",
              c.created, c.renamed, c.umoded);
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
    if (!chptr || !(chptr->mode.mode & CRDT_MODE_MASK))
      continue;
    m = chptr->mode.mode & CRDT_MODE_MASK & ~(MODE_KEY | MODE_LIMIT);
    modebuf_init(&mbuf, &me, NULL, chptr, MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER);
    if (m)
      modebuf_mode(&mbuf, MODE_ADD | m);
    if (chptr->mode.mode & MODE_LIMIT)
      modebuf_mode_uint(&mbuf, MODE_ADD | MODE_LIMIT, chptr->mode.limit);
    if (chptr->mode.mode & MODE_KEY)
      modebuf_mode_string(&mbuf, MODE_ADD | MODE_KEY, chptr->mode.key, 0);
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
  const struct CrdtLWWValue *cm;
  if (key_len >= sizeof chname || !val->data)
    return;
  memcpy(chname, key, key_len); chname[key_len] = '\0';
  chptr = FindChannel(chname);
  if (!chptr)
    return;                              /* channel not live yet (materialize/BURST) */
  doc_topic = (const char *)val->data;
  if (strcmp(doc_topic, chptr->topic) == 0)
    return;                              /* already in sync — also the echo guard:
                                            a P10 topic sets live+doc together, so
                                            reconcile never bounces it back */
  /* Drive the live topic DIRECTLY — never via do_settopic, so crdt_shadow_topic
   * is not re-invoked and no new op is minted (loop prevention). */
  ircd_strncpy(chptr->topic, doc_topic, TOPICLEN + 1);
  cm = crdt_lwwmap_get(&g_crdt.chanmeta, chname, key_len);
  if (cm && cm->data_len == sizeof(struct CrdtChanMeta)) {
    const struct CrdtChanMeta *meta = (const struct CrdtChanMeta *)cm->data;
    chptr->topic_time = (time_t)meta->topic_time;
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
  if (key_len >= sizeof chname || !val->data ||
      val->data_len != sizeof(struct ShadowModeSnap))
    return;
  memcpy(chname, key, key_len); chname[key_len] = '\0';
  chptr = FindChannel(chname);
  if (!chptr)
    return;                              /* channel not live yet */
  memcpy(&doc, val->data, sizeof doc);
  doc.mode &= CRDT_MODE_MASK;            /* defensive: ignore any stale +L/U/A bits */
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
          if (crdt_orset_is_explicitly_removed(&dc->members, num, strlen(num))) {
            victim = m->user;
            break;
          }
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
  crdt_shadow_reconcile_glines();  /* GLINE step 3: drive global G-lines from doc (+gateway) */
  crdt_shadow_reconcile_shuns();   /* SHUN: drive global Shuns from doc (+gateway) */
  crdt_shadow_reconcile_zlines();  /* ZLINE: drive global Z-lines from doc (+gateway) */
  crdt_shadow_reconcile_jupes();   /* JUPE: drive juped servers from doc (+gateway) */
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
    for (acptr = GlobalClientList; acptr && ns < 16; acptr = cli_next(acptr))
      if (IsMeshStub(acptr)) {
        unsigned int n = (unsigned int)base64toint(cli_yxx(acptr));
        if (n < CRDT_MAX_SERVERS &&
            CurrentTime - crdt_beacon[n].recv_ts > CRDT_BEACON_STALE)
          stale[ns++] = acptr;
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
