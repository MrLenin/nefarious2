/*
 * IRC - Internet Relay Chat, ircd/m_smo.c
 * Copyright (C) 2003-2008 Neil Spierling
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
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
 * @brief SMO command
 * @version $Id: m_smo.c 2480 2009-05-20 09:33:32Z sirvulcan $
 */

 #include "config.h"

#include "client.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "ircd_snprintf.h"
#include "ircd.h"          /* me */
#include "handlers.h"   /* crdt_gossip_message */
#include "crdt_shadow.h" /* crdt_shadow_active */

#include <stdlib.h>

/*
 * ms_smo
 *
 * parv[1] = mask
 * parv[2] = msg
 */
int ms_smo(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *message = parc > 2 ? parv[2] : 0;
  const char *mask = parc > 1 ? parv[1] : "o"; /* default to opers only if not specified */

  if (EmptyString(message) || !mask)
    return need_more_params(sptr, "SMO");

  /* Gateway edge (CI precedent): minted into the mesh once, where the
   * notice entered from a LEGACY link (letter 'M'); the tree relay then
   * goes to legacy links only (see ms_sno). */
  int mesh = IsServer(cptr) && !IsCrdtAware(cptr) && crdt_shadow_active();

  sendto_mode_butone(cptr, sptr, mask, "%s", message);
  if (mesh) {
    char body[BUFSIZE], msgidbuf[64];
    sendcmdto_flag_serv_butone(sptr, CMD_SMO, cptr, FLAG_LAST_FLAG,
                               FLAG_CRDT_AWARE, "%s :%s", mask, message);
    ircd_snprintf(0, body, sizeof body, "%s %s", mask, message);
    generate_msgid(msgidbuf, sizeof msgidbuf);
    crdt_gossip_message(&me, 'M', "*", msgidbuf, body);
  } else
    sendcmdto_serv_butone(sptr, CMD_SMO, cptr, "%s :%s", mask, message);
  return 0;
}
