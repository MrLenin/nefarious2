/*
 * IRC - Internet Relay Chat, ircd/m_privs.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Report operators' privileges to others
 * @version $Id: m_privs.c 1810 2007-05-20 14:15:58Z entrope $
 */

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "handlers.h"
#include "crdt_shadow.h"

/** Handle a local operator's privilege query.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @see \ref m_functions
 */
int mo_privs(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *name;
  char *p = 0;
  int i;

  if (parc < 2)
    return client_report_privs(sptr, sptr);

  for (i = 1; i < parc; i++) {
    for (name = ircd_strtok(&p, parv[i], " "); name;
	 name = ircd_strtok(&p, 0, " ")) {
      if (!(acptr = FindUser(name)))
        send_reply(sptr, ERR_NOSUCHNICK, name);
      else if (MyUser(acptr))
	client_report_privs(sptr, acptr);
      else
        sendcmdto_one(cptr, CMD_PRIVS, acptr, "%s%s", NumNick(acptr));
    }
  }

  return 0;
}

/** Handle a remote user's privilege query.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @see \ref m_functions
 */
/* M8: 0 = normal P10 relay; 1 = apply only (mesh copy from a tree-present
 * origin: legacy rides the origin's tree copy); 2 = apply + re-emit to
 * legacy links only (mesh copy from a tree-absent origin). */
static int privs_relay_mode = 0;

void privs_apply_from_mesh(const char *numeric, const char *privlist, int relay_legacy)
{
  char buf[BUFSIZE];
  char *pv[MAXPARA + 2];
  char *q;
  int pc = 0;
  ircd_strncpy(buf, privlist, sizeof buf);
  pv[pc++] = "PRIVS";
  pv[pc++] = (char *)numeric;
  for (q = buf; *q && pc < MAXPARA; ) {
    while (*q == ' ') *q++ = '\0';
    if (!*q) break;
    pv[pc++] = q;
    while (*q && *q != ' ') q++;
  }
  pv[pc] = NULL;
  privs_relay_mode = relay_legacy ? 2 : 1;
  ms_privs(&me, &me, pc, pv);
  privs_relay_mode = 0;
}

int ms_privs(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *numnick, *p = 0;
  char buf[512] = "";
  int i;
  int what = PRIV_ADD;
  int modified = 0;
  char *tmp;

  /* A beyond-horizon mesh anchor is a server source: without it a stub falls
   * into the query branch below and X3's PRIVS grants are silently never
   * applied on tree-retired leaves. */
  if (IsServer(sptr) || IsMeshStub(sptr) || IsMe(sptr)) {   /* IsMe: the CR M re-inject (invariant 2) */
    acptr = parc > 1 ? findNUser(parv[1]) : NULL;

    if (!acptr)
      return 0;

    if (parc < 3) {
      if (acptr) {
        memset(&cli_privs(acptr), 0, sizeof(struct Privs));
        clear_privs(acptr);
      }
      return 0;
    }

    for (i=2; i<parc; i++) {
      strcat(buf, parv[i]);
      strcat(buf, " ");
    }

    for (i = 2; i < parc; i++) {
      if (*parv[i] == '+') { what = PRIV_ADD; parv[i]++; }
      if (*parv[i] == '-') { what = PRIV_DEL; parv[i]++; }
      /* sigh, this can be simplified in 1.4 */
      if (strstr(parv[i], ",")) {
        for (tmp = ircd_strtok(&p, parv[i], ","); tmp;
             tmp = ircd_strtok(&p, 0, ",")) {
          if (!strcmp(tmp, "PRIV_NONE")) {
            memset(&cli_privs(acptr), 0, sizeof(struct Privs));
            clear_privs(acptr);
            break;
          } else {
            client_modify_priv_by_name(acptr, tmp, what);
          }
          if (!modified)
            modified = 1;
        }
      } else {
        for (tmp = ircd_strtok(&p, parv[i], " "); tmp;
             tmp = ircd_strtok(&p, 0, " ")) {
          if (!strcmp(tmp, "PRIV_NONE")) {
            memset(&cli_privs(acptr), 0, sizeof(struct Privs));
            clear_privs(acptr);
            break;
          } else {
            client_modify_priv_by_name(acptr, tmp, what);
          }
          if (!modified)
            modified = 1;
        }
      }
    }

    if (MyConnect(acptr) && modified)
      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :Your privileges were modified", acptr);

    /* Alias→primary privilege sync: the PRIVS message targets the alias
     * numeric, but the primary needs the same privileges so oper
     * capabilities (CHECK, KILL, etc.) work from the primary too. */
    if (IsBouncerAlias(acptr) && cli_user(acptr)
        && cli_user(acptr)->alias_primary) {
      memcpy(&cli_privs(cli_user(acptr)->alias_primary),
             &cli_privs(acptr), sizeof(struct Privs));
    }

    if (privs_relay_mode == 1)
      return 0;                             /* mesh receiver: apply only */
    /* Gateway edge (CI precedent): a PRIVS that arrived over a LEGACY link
     * is minted into the mesh once here; the tree relay then goes to
     * legacy links only.  privs_relay_mode 2 = the mesh receiver asked for
     * a legacy re-emit (the origin has no tree presence here). */
    if ((IsServer(cptr) && !IsCrdtAware(cptr) && client_privs_mesh_mint(acptr, buf))
        || privs_relay_mode == 2)
      sendcmdto_set_skip_crdt_servers();
    sendcmdto_serv_butone(sptr, CMD_PRIVS, cptr, "%C %s", acptr, buf);
  } else {
    if (parc < 2)
      return protocol_violation(cptr, "PRIVS with no arguments");

    for (i = 1; i < parc; i++) {
      for (numnick = ircd_strtok(&p, parv[i], " "); numnick;
        numnick = ircd_strtok(&p, 0, " ")) {
        if (!(acptr = findNUser(numnick)))
          continue;
        else if (MyUser(acptr))
          client_report_privs(sptr, acptr);
        else
          sendcmdto_one(sptr, CMD_PRIVS, acptr, "%s%s", NumNick(acptr));
      }
    }
  }

  return 0;
}
