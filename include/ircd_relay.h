#ifndef INCLUDED_IRCD_RELAY_H
#define INCLUDED_IRCD_RELAY_H
/*
 * IRC - Internet Relay Chat, include/ircd_relay.h
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
 * @brief Interface to functions for relaying messages.
 * @version $Id: ircd_relay.h 1231 2004-10-05 04:21:37Z entrope $
 */

#include <stddef.h>            /* size_t — this header is the first include
                                  in some translation units (e.g. ircd_relay.c),
                                  so it cannot rely on a later header for this. */

struct Client;

extern void relay_channel_message(struct Client* sptr, const char* name, const char* text, int targets);
extern void relay_channel_notice(struct Client* sptr, const char* name, const char* text, int targets);
extern void relay_directed_message(struct Client* sptr, char* name, char* server, const char* text);
extern void relay_directed_notice(struct Client* sptr, char* name, char* server, const char* text);
extern void relay_masked_message(struct Client* sptr, const char* mask, const char* text);
extern void relay_masked_notice(struct Client* sptr, const char* mask, const char* text);
extern void relay_private_message(struct Client* sptr, const char* name, const char* text);
extern void relay_private_notice(struct Client* sptr, const char* name, const char* text);

extern void server_relay_channel_message(struct Client* sptr, const char* name, const char* text);
extern void server_relay_channel_notice(struct Client* sptr, const char* name, const char* text);
extern void server_relay_masked_message(struct Client* sptr, const char* mask, const char* text);
extern void server_relay_masked_notice(struct Client* sptr, const char* mask, const char* text);
extern void server_relay_private_message(struct Client* sptr, const char* name, const char* text);
extern void server_relay_private_notice(struct Client* sptr, const char* name, const char* text);

/* DM chathistory identity keying (F-CH1): account when authenticated,
 * else the per-connection session id.  NEVER the nick. */
extern void history_pm_identity(struct Client *cli, char *buf, size_t buflen);
extern int  history_pm_identity_matches(struct Client *cli,
                                        const char *half, size_t half_len);

#ifdef USE_ROCKSDB
struct Channel;
enum HistoryMessageType;
/* Store a channel message with the standard witness gate (local-interest,
 * +P, REQUIRE_AUTH, +Y gap).  Exported for 5-5f B1: the CR-M mesh-delivery
 * path witness-stores with the SAME semantics as the P10 relay path, so
 * every node with a local member keeps a copy (restoring pre-mesh storage
 * redundancy under R6a tree-demote). */
extern void store_channel_history(struct Client *sptr, struct Channel *chptr,
                                   const char *text, enum HistoryMessageType type,
                                   const char *msgid, const char *timestamp,
                                   const char *client_tags);
#endif

#endif /* INCLUDED_IRCD_RELAY_H */
