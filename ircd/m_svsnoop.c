/*
 * IRC - Internet Relay Chat, ircd/m_svsnoop.c
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
 *
 * $Id: m_tmpl.c 1271 2004-12-11 05:14:07Z klmitch $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "client.h"
#include "crdt_shadow.h"  /* crdt_shadow_active */
#include "handlers.h"     /* crdt_gossip_message, svsnoop_apply_local */
#include "ircd_snprintf.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_conf.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 *  ms_svsnoop
 *
 *  parv[0] = sender prefix
 *  parv[1] = server
 *  parv[2] = +/-
 *
 *  Ported From Ultimate IRCd
 */
/* Apply an SVSNOOP aimed at @a mask on THIS server (no-op unless we match).
 * Shared by the P10 handler and the CR M 'Z' receiver (mesh copy). */
void svsnoop_apply_local(const char *mask, const char *pm)
{
  struct ConfItem *aconf;
  struct Client *server;

  /* this could be done with hunt_server_cmd but its a bucket of shit */
  if (!string_has_wildcards(mask))
    server = FindServer(mask);
  else
    server = find_match_server((char *)mask);
  if (server != &me)
    return;

  if (*pm == '+') {
    for(aconf = GlobalConfList; aconf; aconf = aconf->next) {
      if (aconf->status & CONF_OPERATOR)
        aconf->status |= CONF_ILLEGAL;
    }
    SetServerNoop(&me);
  } else {
    rehash (&me, 2);
    ClearServerNoop(&me);
  }
}

int ms_svsnoop(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int mesh;

  if (!IsServer(sptr) || parc < 3)
    return 0;

  svsnoop_apply_local(parv[1], parv[2]);

  /* Services reach us over a legacy link; mint the mesh copy once at that
   * edge (CR M 'Z', target "*", every mesh node applies it against itself)
   * and keep the tree relay to legacy links -- a CRDT-aware downlink gets the
   * mesh copy.  Mesh off / arrived from a CRDT peer: plain tree relay. */
  mesh = IsServer(cptr) && !IsCrdtAware(cptr) && crdt_shadow_active();
  if (mesh) {
    char body[BUFSIZE], msgidbuf[64];
    sendcmdto_flag_serv_butone(sptr, CMD_SVSNOOP, cptr, FLAG_LAST_FLAG,
                               FLAG_CRDT_AWARE, "%s %s", parv[1], parv[2]);
    ircd_snprintf(0, body, sizeof body, "%s %s", parv[1], parv[2]);
    generate_msgid(msgidbuf, sizeof msgidbuf);
    crdt_gossip_message(&me, 'Z', "*", msgidbuf, body);
  } else
    sendcmdto_serv_butone(sptr, CMD_SVSNOOP, cptr, "%s %s", parv[1], parv[2]);
  return 0;
}

