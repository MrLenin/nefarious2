/*
 * IRC - Internet Relay Chat, ircd/m_sno.c
 * Copyright (C) 2003-2005 Progs
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
 * @brief SNO command
 * @version $Id: m_sno.c 2480 2009-05-20 09:33:32Z sirvulcan $
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
 * ms_sno - ircoderz2
 *
 * parv[1] = mask
 * parv[2] = msg
 */
int ms_sno(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *message = parc > 2 ? parv[2] : 0;
  int mask = parc > 1 ? atoi(parv[1]) : 0;

  if (EmptyString(message) || !mask)
    return need_more_params(sptr, "SNO");

  /* Gateway edge (CI precedent): a notice that arrived over a LEGACY link
   * is minted into the mesh once here (letter 'O'); one from a CRDT peer
   * already rode the mesh.  When minted, the tree relay goes to legacy
   * links only -- a CRDT-aware downlink would otherwise get both copies
   * (the tree copy has no msgid to dedup on). */
  int mesh = IsServer(cptr) && !IsCrdtAware(cptr) && crdt_shadow_active();

  sendto_opmask_butone_from(sptr, sptr, mask, "%s", message);
  if (mesh) {
    char body[BUFSIZE], msgidbuf[64];
    sendcmdto_flag_serv_butone(sptr, CMD_SNO, cptr, FLAG_LAST_FLAG,
                               FLAG_CRDT_AWARE, "%d :%s", mask, message);
    ircd_snprintf(0, body, sizeof body, "%d %s", mask, message);
    generate_msgid(msgidbuf, sizeof msgidbuf);
    crdt_gossip_message(&me, 'O', "*", msgidbuf, body);
  } else
    sendcmdto_serv_butone(sptr, CMD_SNO, cptr, "%d :%s", mask, message);
  return 0;
}

