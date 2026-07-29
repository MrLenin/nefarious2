/*
 * IRC - Internet Relay Chat, ircd/m_crdtinfo.c
 *
 * Oper-facing CRDT mesh introspection: /CRDT [map|peers|status|route].
 *
 * Reads the gossiped mesh-topology map (crdt_meshmap, fed by CR H beacon
 * adjacency) plus locally-known server state.  Observability-only — it inspects,
 * it never mutates doc/routing state.  The S2S replication token is "CR"
 * (ms_crdt/mr_crdt); opers reach this handler via the full "CRDT" command name
 * (the OPER slot of the same msgtab entry; non-opers get m_not_oper).
 *
 *   /CRDT map     - BFS spanning tree of the mesh from this node (ASCII, like
 *                   /MAP), each node annotated with role + beacon age; mesh
 *                   cross-links and direct legacy peers listed as footers.
 *   /CRDT peers   - adjacency list (one row per reachable node -> its declared
 *                   direct peers); shows true mesh cross-links a tree can't.
 *   /CRDT status  - on-demand shadow-verify line + server-role census +
 *                   partition state.
 *   /CRDT route   - MR-0 routing table: unicast next-hop per destination + the
 *                   canonical (root-free) broadcast tree + the routing
 *                   shadow-oracle (derived mesh next-hop vs the P10 tree).
 *
 * Reachability here is DERIVED locally (BFS over single-writer adjacency rows,
 * pruning beacon-stale nodes) — never replicated.  See crdt_meshmap.h.
 */
#include "config.h"

#include "client.h"
#include "crdt_hlc.h"
#include "crdt_meshmap.h"
#include "crdt_shadow.h"
#include "handlers.h"
#include "hash.h"
#include "ircd_string.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "list.h"
#include "msg.h"
#include "numnicks.h"
#include "s_bsd.h"    /* MR-6-0: connect_overlay (/CRDT link) */
#include "s_conf.h"   /* MR-6-0: GlobalConfList / CONF_CRDTMESH */
#include "send.h"
#include "struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- helpers ---------------------------------------------------------- */

/* Locate a locally-known server Client by its integer numeric (robust to numeric
 * width — avoids reconstructing the base64 yxx for FindNServer). */
static struct Client *srv_by_num(unsigned int num)
{
  struct Client *a;
  for (a = GlobalClientList; a; a = cli_next(a))
    if (IsServer(a) && (unsigned int)base64toint(cli_yxx(a)) == num)
      return a;
  return NULL;
}

static const char *name_of(unsigned int num, unsigned int ournum)
{
  const char *bn;
  struct Client *s;
  if (num == ournum)
    return cli_name(&me);
  bn = crdt_shadow_beacon_name(num);
  if (bn && bn[0])
    return bn;
  s = srv_by_num(num);
  return s ? cli_name(s) : "?";
}

static const char *role_of(unsigned int num, unsigned int ournum)
{
  struct Client *s;
  if (num == ournum)
    return IsHub(&me) ? "self/hub" : "self";
  s = srv_by_num(num);
  if (!s)
    return "mesh";                       /* known only via beacon (beyond a stub) */
  if (IsMeshStub(s))
    return IsPresented(s) ? "stub/presented" : "stub";
  if (IsCrdtAware(s))
    return "crdt";
  if (IsServer(s))
    return "legacy";
  return "?";
}

/* one rendered node line: <prefix><branch> <name>  [<role>] <beacon age> */
static void mesh_print(struct Client *to, const char *prefix, const char *branch,
                       unsigned int num, unsigned int ournum, time_t now)
{
  char age[24];
  time_t rt = crdt_shadow_beacon_recv(num);
  if (num == ournum)
    strcpy(age, "-");
  else if (rt == 0)
    strcpy(age, "beacon ?");
  else
    ircd_snprintf(0, age, sizeof age, "beacon %lds", (long)(now - rt));
  sendcmdto_one(&me, CMD_NOTICE, to, "%C :%s%s %s  [%s] %s",
                to, prefix, branch, name_of(num, ournum),
                role_of(num, ournum), age);
}

/* DFS the spanning tree, printing children of @a node with /MAP-style glyphs */
static void map_children(struct Client *to, const int16_t *parent,
                         const uint16_t *order, int n, unsigned int node,
                         const char *prefix, unsigned int ournum, time_t now)
{
  uint16_t kids[CRDT_MESH_MAXDEG];
  int i, nk = 0;

  for (i = 0; i < n; i++) {
    uint16_t v = order[i];               /* ascending within a parent's batch */
    if (v != node && parent[v] == (int16_t)node && nk < CRDT_MESH_MAXDEG)
      kids[nk++] = v;
  }
  for (i = 0; i < nk; i++) {
    int last = (i == nk - 1);
    char np[256];
    mesh_print(to, prefix, last ? "`-" : "|-", kids[i], ournum, now);
    ircd_snprintf(0, np, sizeof np, "%s%s", prefix, last ? "   " : "|  ");
    map_children(to, parent, order, n, kids[i], np, ournum, now);
  }
}

/* --- subviews --------------------------------------------------------- */

static void render_map(struct Client *to)
{
  static int16_t  parent[CRDT_MAX_SERVERS];
  static uint16_t order[CRDT_MAX_SERVERS];
  static uint8_t  depth[CRDT_MAX_SERVERS];
  const struct CrdtMeshMap *mm = crdt_shadow_meshmap();
  unsigned int ournum = (unsigned int)base64toint(cli_yxx(&me));
  time_t now = CurrentTime, stale = crdt_shadow_beacon_stale_secs();
  uint16_t cu[16], cv[16];
  char buf[400];
  struct DLink *lp;
  int n, nc, i, w;

  n = crdt_meshmap_spanning(mm, (uint16_t)ournum, now, stale, parent, depth, order);
  sendcmdto_one(&me, CMD_NOTICE, to,
                "%C :CRDT mesh (local view from %s) - %d node%s reachable",
                to, cli_name(&me), n, (n == 1) ? "" : "s");
  mesh_print(to, "", "", ournum, ournum, now);
  map_children(to, parent, order, n, ournum, "", ournum, now);

  nc = crdt_meshmap_crossedges(mm, now, stale, parent, cu, cv, 16);
  if (nc > 0) {
    w = 0; buf[0] = '\0';
    for (i = 0; i < nc && i < 16; i++)
      w += ircd_snprintf(0, buf + w, sizeof buf - w, "%s%s-%s", w ? " " : "",
                         name_of(cu[i], ournum), name_of(cv[i], ournum));
    sendcmdto_one(&me, CMD_NOTICE, to, "%C :  mesh x-links: %s%s",
                  to, buf, (nc > 16) ? " ..." : "");
  }

  /* direct legacy peers are NOT in the mesh map (they don't beacon) */
  w = 0; buf[0] = '\0';
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *d = lp->value.cptr;
    if (IsServer(d) && !IsCrdtAware(d))
      w += ircd_snprintf(0, buf + w, sizeof buf - w, "%s%s", w ? " " : "",
                         cli_name(d));
  }
  if (w)
    sendcmdto_one(&me, CMD_NOTICE, to, "%C :  legacy peers: %s", to, buf);

  sendcmdto_one(&me, CMD_NOTICE, to, "%C :End of /CRDT map", to);
}

static void render_peers(struct Client *to)
{
  static uint8_t reach[CRDT_MAX_SERVERS];
  const struct CrdtMeshMap *mm = crdt_shadow_meshmap();
  unsigned int ournum = (unsigned int)base64toint(cli_yxx(&me));
  time_t now = CurrentTime, stale = crdt_shadow_beacon_stale_secs();
  char buf[400];
  int rc, i, j, w;

  rc = crdt_meshmap_reachable(mm, (uint16_t)ournum, now, stale, reach);
  sendcmdto_one(&me, CMD_NOTICE, to,
                "%C :CRDT mesh adjacency (%d reachable):", to, rc);
  for (i = 0; i < CRDT_MAX_SERVERS; i++) {
    if (!reach[i])
      continue;
    w = 0; buf[0] = '\0';
    for (j = 0; j < mm->npeers[i]; j++)
      w += ircd_snprintf(0, buf + w, sizeof buf - w, "%s%s", w ? " " : "",
                         name_of(mm->peers[i][j], ournum));
    sendcmdto_one(&me, CMD_NOTICE, to, "%C :  %s -> %s",
                  to, name_of((unsigned int)i, ournum), buf[0] ? buf : "(none)");
  }
  sendcmdto_one(&me, CMD_NOTICE, to, "%C :End of /CRDT peers", to);
}

static void render_status(struct Client *to)
{
  static uint8_t reach[CRDT_MAX_SERVERS];
  const struct CrdtMeshMap *mm = crdt_shadow_meshmap();
  unsigned int ournum = (unsigned int)base64toint(cli_yxx(&me));
  time_t now = CurrentTime, stale = crdt_shadow_beacon_stale_secs();
  struct Client *a;
  int crdt = 0, legacy = 0, stub = 0, presented = 0, rc;

  crdt_shadow_verify(to);                /* the canonical verify line(s) on demand */
  crdt_shadow_presence_diff(to);         /* Tier-2 S1: mesh-map BFS vs beacon-set vs P10 divergences */

  for (a = GlobalClientList; a; a = cli_next(a)) {
    /* IsServer is exact STAT_SERVER — a mesh stub is STAT_MESH_SERVER, so it
     * must be admitted here too or the stub branch below is unreachable
     * (the count read "0 stub" even mid-partition). */
    if (!IsServer(a) && !IsMeshStub(a))
      continue;
    if (IsMeshStub(a)) {
      stub++;
      if (IsPresented(a))
        presented++;
    } else if (IsCrdtAware(a))
      crdt++;
    else
      legacy++;
  }
  rc = crdt_meshmap_reachable(mm, (uint16_t)ournum, now, stale, reach);
  sendcmdto_one(&me, CMD_NOTICE, to,
                "%C :CRDT servers: %d crdt, %d legacy, %d stub (%d presented); "
                "mesh reachable=%d; partitioned=%s",
                to, crdt, legacy, stub, presented, rc,
                crdt_have_mesh_stub() ? "YES" : "no");
  sendcmdto_one(&me, CMD_NOTICE, to, "%C :End of /CRDT status", to);
}

/* MR-0 routing-table view: the unicast next-hop table + the canonical broadcast
 * tree (the inputs mesh-native routing will run on) + the routing shadow-oracle.
 * Observability-only — derives, measures, routes nothing. */
static void render_route(struct Client *to)
{
  static int16_t nh[CRDT_MAX_SERVERS];
  static uint8_t reach[CRDT_MAX_SERVERS];
  const struct CrdtMeshMap *mm = crdt_shadow_meshmap();
  unsigned int ournum = (unsigned int)base64toint(cli_yxx(&me));
  time_t now = CurrentTime, stale = crdt_shadow_beacon_stale_secs();
  uint16_t tu[64], tv[64];
  char buf[400];
  int nt, i, rc, w;

  /* unicast next-hop table (per-viewpoint shortest path — the MR-1 input) */
  rc = crdt_meshmap_nexthop(mm, (uint16_t)ournum, now, stale, nh);
  crdt_meshmap_reachable(mm, (uint16_t)ournum, now, stale, reach);
  sendcmdto_one(&me, CMD_NOTICE, to,
                "%C :CRDT unicast routes from %s (%d dest%s):",
                to, cli_name(&me), rc - 1, (rc - 1 == 1) ? "" : "s");
  for (i = 0; i < CRDT_MAX_SERVERS; i++) {
    if (!reach[i] || (unsigned int)i == ournum)
      continue;
    sendcmdto_one(&me, CMD_NOTICE, to, "%C :  %s  via %s",
                  to, name_of((unsigned int)i, ournum),
                  (nh[i] >= 0) ? name_of((unsigned int)nh[i], ournum) : "-");
  }

  /* canonical broadcast tree (root-free Kruskal-lex — IDENTICAL on every node;
   * the MR-2 input).  Rendered as the edge set so it is directly diffable. */
  nt = crdt_meshmap_canon_tree(mm, now, stale, tu, tv, 64);
  w = 0; buf[0] = '\0';
  for (i = 0; i < nt && i < 64; i++)
    w += ircd_snprintf(0, buf + w, sizeof buf - w, "%s%s-%s", w ? " " : "",
                       name_of(tu[i], ournum), name_of(tv[i], ournum));
  sendcmdto_one(&me, CMD_NOTICE, to,
                "%C :CRDT broadcast tree (canonical, %d edge%s): %s%s",
                to, nt, (nt == 1) ? "" : "s", buf[0] ? buf : "(none)",
                (nt > 64) ? " ..." : "");

  crdt_shadow_route_diff(to);            /* mesh next-hop vs P10 tree (oracle) */
  sendcmdto_one(&me, CMD_NOTICE, to, "%C :End of /CRDT route", to);
}

/* --- handler ---------------------------------------------------------- */

/** mo_crdt - oper /CRDT [map|peers|status|route] mesh introspection.
 * parv[1] = optional subcommand (first letter dispatched; default map).
 * In DEBUG builds ONLY, "/CRDT clockstep <±secs>" (case 'c') relatively steps this
 * node's fake wall-clock offset for the timing-race test harness; the subcommand
 * is compiled out entirely in a release build. */
int mo_crdt(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char c = (parc > 1 && parv[1][0]) ? parv[1][0] : 'm';
  (void)cptr;

  if (c >= 'A' && c <= 'Z')
    c = (char)(c + ('a' - 'A'));

  if (!crdt_shadow_active()) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :CRDT mesh: shadow not active on this server", sptr);
    return 0;
  }

  switch (c) {
    case 'p': render_peers(sptr);  break;
    case 's': render_status(sptr); break;
    case 'r': render_route(sptr);  break;
    case 'd': {
      /* decommission <server|2char-numeric> [remove|<reason...>] — operator-
       * asserted permanent absence ("jupe without the jupe part"): licenses the
       * standing decomm-sweep to reap the server's doc residue, never blocks
       * relink, auto-dissolves if the server returns.  Refused while the target
       * is reachable (present or beacon-fresh) so it cannot be fat-fingered
       * onto a live server. */
      const char *arg = (parc > 2 && parv[2][0]) ? parv[2] : NULL;
      struct Client *asrv;
      char srvnum[3];
      int rc;
      if (!arg) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Usage: CRDT decommission <server|2char-numeric> "
                      "[remove|<reason>]", sptr);
        break;
      }
      asrv = FindServer(arg);
      if (asrv) {
        srvnum[0] = cli_yxx(asrv)[0];
        srvnum[1] = cli_yxx(asrv)[1];
        srvnum[2] = '\0';
      } else if (strlen(arg) == 2) {
        srvnum[0] = arg[0]; srvnum[1] = arg[1]; srvnum[2] = '\0';
      } else {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :CRDT decommission: no such server '%s' — for a "
                      "long-gone server use its 2-char numeric", sptr, arg);
        break;
      }
      if (parc > 3 && 0 == ircd_strcmp(parv[3], "remove")) {
        rc = crdt_shadow_decomm_unmark(srvnum);
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      rc == 0 ? "%C :CRDT decommission: marker for %s removed"
                              : "%C :CRDT decommission: no marker for %s",
                      sptr, srvnum);
        break;
      }
      rc = crdt_shadow_decomm_mark(srvnum, cli_name(sptr),
                                   (parc > 3) ? parv[parc - 1] : "");
      if (rc == 0) {
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CRDT decommission: %s marked by %s (%s)",
                  srvnum, cli_name(sptr), (parc > 3) ? parv[parc - 1] : "-");
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :CRDT decommission: %s marked — residue will be "
                      "reaped; marker auto-dissolves if the server returns",
                      sptr, srvnum);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :CRDT decommission: refused — %s is %s", sptr, srvnum,
                      rc == 1 ? "present/linked" : "mesh-reachable (beacon fresh)");
      }
      break;
    }
    case 'l': {   /* link <server> — force an overlay (re)connect NOW (MR-6-0):
                   * try_connections only retries overlays on the CONNECTFREQUENCY
                   * cycle (up to ~10 min), and oper CONNECT can't target one (it
                   * resolves the canonical P10 server of the same name). */
      const char *arg = (parc > 2 && parv[2][0]) ? parv[2] : NULL;
      struct ConfItem *aconf;
      struct Client *ov;
      if (!arg) {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Usage: CRDT link <server>",
                      sptr);
        break;
      }
      for (aconf = GlobalConfList; aconf; aconf = aconf->next)
        if ((aconf->status & CONF_SERVER) && (aconf->flags & CONF_CRDTMESH) &&
            0 == ircd_strcmp(aconf->name, arg))
          break;
      if (!aconf) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :CRDT link: no overlay Connect block for '%s'", sptr,
                      arg);
        break;
      }
      /* Dedupe like try_connections: the canonical P10 server of this name
       * legitimately exists (the overlay is a redundant, unhashed edge) — scan
       * for a live/in-progress overlay instead of FindServer. */
      for (ov = GlobalClientList; ov; ov = cli_next(ov))
        if (IsCrdtOverlay(ov) && MyConnect(ov) && !IsDead(ov) &&
            0 == ircd_strcmp(cli_name(ov), aconf->name))
          break;
      if (ov) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :CRDT link: overlay to %s already up/connecting",
                      sptr, arg);
        break;
      }
      aconf->hold = 0;                        /* cancel autoconnect backoff */
      if (connect_overlay(aconf, 0)) {
        sendto_opmask_butone(0, SNO_OLDSNO,
                             "CRDT mesh overlay to %s activated by %s.",
                             aconf->name, cli_name(sptr));
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :CRDT link: connecting overlay to %s", sptr, arg);
      } else
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :CRDT link: connect to %s did not start "
                      "(DNS pending or connect failure — see server notices)",
                      sptr, arg);
      break;
    }
    case 'k': {   /* key <account> <metakey> — raw doc metadata entry + HLC */
      if (parc < 4) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Usage: CRDT key <account> <metakey>", sptr);
        break;
      }
      crdt_shadow_diag_metadata_entry(sptr, parv[2], parv[3]);
      break;
    }
#ifdef DEBUGMODE
    case 'c': {   /* clockstep <±secs> — DEBUG-only relative wall-clock step */
      int step = (parc > 2 && parv[2]) ? atoi(parv[2]) : 0;
      ircd_fake_clock_offset += (time_t)step;
      log_write(LS_SYSTEM, L_WARNING, 0,
                "*** CRDT clockstep %+d s by %s -> fake clock offset now %+ld s "
                "-- DEBUG BUILD ONLY ***",
                step, cli_name(sptr), (long)ircd_fake_clock_offset);
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :CRDT clockstep: %+d s applied; fake clock offset now "
                    "%+ld s (DEBUG build only)", sptr, step,
                    (long)ircd_fake_clock_offset);
      break;
    }
#endif
    case 'm':
    default:  render_map(sptr);    break;
  }
  return 0;
}
