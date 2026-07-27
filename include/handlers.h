/*
 * IRC - Internet Relay Chat, include/handlers.h
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Declarations for all protocol message handler functions.
 * @version $Id: handlers.h 1925 2010-01-02 20:33:10Z klmitch $
 */
#ifndef INCLUDED_handlers_h
#define INCLUDED_handlers_h

/** @page m_functions Protocol Message Handlers
 *
 * m_functions execute protocol messages on this server:
 * int m_func(struct Client* cptr, struct Client* sptr, int parc, char* parv[]);
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

#include <time.h>

struct Channel;
struct Client;
struct StatDesc;

extern int m_admin(struct Client*, struct Client*, int, char*[]);
extern int m_authenticate(struct Client*, struct Client*, int, char*[]);
extern int m_away(struct Client*, struct Client*, int, char*[]);
extern int mu_away(struct Client*, struct Client*, int, char*[]);
extern int m_cap(struct Client*, struct Client*, int, char*[]);
extern int m_cnotice(struct Client*, struct Client*, int, char*[]);
extern int m_cprivmsg(struct Client*, struct Client*, int, char*[]);
extern int m_fingerprint(struct Client*, struct Client*, int, char*[]);
extern int m_gline(struct Client*, struct Client*, int, char*[]);
extern int m_help(struct Client*, struct Client*, int, char*[]);
extern int m_ignore(struct Client*, struct Client*, int, char*[]);
extern int m_info(struct Client*, struct Client*, int, char*[]);
extern int m_isupport(struct Client*, struct Client*, int, char*[]);
extern int m_invite(struct Client*, struct Client*, int, char*[]);
extern int m_ircops(struct Client*, struct Client*, int, char*[]);
extern int m_isnef(struct Client*, struct Client*, int, char*[]);
extern int m_ison(struct Client*, struct Client*, int, char*[]);
extern int m_join(struct Client*, struct Client*, int, char*[]);
extern int m_jupe(struct Client*, struct Client*, int, char*[]);
extern int m_kick(struct Client*, struct Client*, int, char*[]);
extern int m_links(struct Client*, struct Client*, int, char*[]);
extern int m_links_redirect(struct Client*, struct Client*, int, char*[]);
extern int m_list(struct Client*, struct Client*, int, char*[]);
extern int m_lusers(struct Client*, struct Client*, int, char*[]);
extern int m_map(struct Client*, struct Client*, int, char*[]);
extern int m_map_redirect(struct Client*, struct Client*, int, char*[]);
extern int m_mkpasswd(struct Client*, struct Client*, int, char*[]);
extern int m_mode(struct Client*, struct Client*, int, char*[]);
extern int m_motd(struct Client*, struct Client*, int, char*[]);
extern int m_names(struct Client*, struct Client*, int, char*[]);
extern int m_nick(struct Client*, struct Client*, int, char*[]);
extern int m_not_oper(struct Client*, struct Client*, int, char*[]);
extern int m_notice(struct Client*, struct Client*, int, char*[]);
extern int mr_notice(struct Client*, struct Client*, int, char*[]);
extern int m_oper(struct Client*, struct Client*, int, char*[]);
extern int m_opermotd(struct Client*, struct Client*, int, char*[]);
extern int m_part(struct Client*, struct Client*, int, char*[]);
extern int mr_pass(struct Client*, struct Client*, int, char*[]);
extern int m_ping(struct Client*, struct Client*, int, char*[]);
extern int m_pong(struct Client*, struct Client*, int, char*[]);
extern int m_private(struct Client*, struct Client*, int, char*[]);
extern int m_privmsg(struct Client*, struct Client*, int, char*[]);
extern int m_proto(struct Client*, struct Client*, int, char*[]);
extern int m_protoctl(struct Client*, struct Client*, int, char*[]);
extern int m_pseudo(struct Client*, struct Client*, int, char*[]);
extern int m_quit(struct Client*, struct Client*, int, char*[]);
extern int m_registered(struct Client*, struct Client*, int, char*[]);
extern int m_rules(struct Client*, struct Client*, int, char*[]);
extern int m_sethost(struct Client*, struct Client*, int, char*[]);
extern int m_setname(struct Client*, struct Client*, int, char*[]);
extern int m_tagmsg(struct Client*, struct Client*, int, char*[]);
extern int m_shun(struct Client*, struct Client*, int, char*[]);
extern int m_silence(struct Client*, struct Client*, int, char*[]);
extern int m_starttls(struct Client*, struct Client*, int, char*[]);
extern int m_stats(struct Client*, struct Client*, int, char*[]);
extern int m_time(struct Client*, struct Client*, int, char*[]);
extern int m_topic(struct Client*, struct Client*, int, char*[]);
extern int m_trace(struct Client*, struct Client*, int, char*[]);
extern int m_unregistered(struct Client*, struct Client*, int, char*[]);
extern int m_unsupported(struct Client*, struct Client*, int, char*[]);
extern int m_user(struct Client*, struct Client*, int, char*[]);
extern int m_userhost(struct Client*, struct Client*, int, char*[]);
extern int m_userip(struct Client*, struct Client*, int, char*[]);
extern int m_version(struct Client*, struct Client*, int, char*[]);
extern int m_wallchops(struct Client*, struct Client*, int, char*[]);
extern int m_wallhops(struct Client*, struct Client*, int, char*[]);
extern int m_wallvoices(struct Client*, struct Client*, int, char*[]);
extern int m_watch(struct Client*, struct Client*, int, char*[]);
extern int m_monitor(struct Client*, struct Client*, int, char*[]);
extern int m_webirc(struct Client*, struct Client*, int, char*[]);
extern int m_who(struct Client*, struct Client*, int, char*[]);
extern int m_whois(struct Client*, struct Client*, int, char*[]);
extern int m_whowas(struct Client*, struct Client*, int, char*[]);
extern int m_zline(struct Client*, struct Client*, int, char*[]);
extern int mo_admin(struct Client*, struct Client*, int, char*[]);
extern int mo_asll(struct Client*, struct Client*, int, char*[]);
extern int mo_check(struct Client*, struct Client*, int, char*[]);
extern int mo_clearmode(struct Client*, struct Client*, int, char*[]);
extern int mo_close(struct Client*, struct Client*, int, char*[]);
extern int mo_connect(struct Client*, struct Client*, int, char*[]);
extern int mo_die(struct Client*, struct Client*, int, char*[]);
extern int mo_get(struct Client*, struct Client*, int, char*[]);
extern int mo_gline(struct Client*, struct Client*, int, char*[]);
extern int mo_info(struct Client*, struct Client*, int, char*[]);
extern int mo_jupe(struct Client*, struct Client*, int, char*[]);
extern int mo_kill(struct Client*, struct Client*, int, char*[]);
#ifdef USE_LIBGIT2
extern int mo_gitsync(struct Client*, struct Client*, int, char*[]);
#endif
extern int mo_notice(struct Client*, struct Client*, int, char*[]);
extern int mo_oper(struct Client*, struct Client*, int, char*[]);
extern int mo_opmode(struct Client*, struct Client*, int, char*[]);
extern int mo_ping(struct Client*, struct Client*, int, char*[]);
extern int mo_privmsg(struct Client*, struct Client*, int, char*[]);
extern int mo_privs(struct Client*, struct Client*, int, char*[]);
extern int mo_rehash(struct Client*, struct Client*, int, char*[]);
extern int mo_remove(struct Client*, struct Client*, int, char*[]);
extern int mo_reset(struct Client*, struct Client*, int, char*[]);
extern int mo_restart(struct Client*, struct Client*, int, char*[]);
extern int mo_rping(struct Client*, struct Client*, int, char*[]);
extern int mo_set(struct Client*, struct Client*, int, char*[]);
extern int mo_sethost(struct Client*, struct Client*, int, char*[]);
extern int mo_settime(struct Client*, struct Client*, int, char*[]);
extern int mo_shun(struct Client*, struct Client*, int, char*[]);
extern int mo_squit(struct Client*, struct Client*, int, char*[]);
extern int mo_stats(struct Client*, struct Client*, int, char*[]);
extern int mo_store(struct Client*, struct Client*, int, char*[]);
extern int mo_tempshun(struct Client*, struct Client*, int, char*[]);
extern int mo_trace(struct Client*, struct Client*, int, char*[]);
extern int mo_uping(struct Client*, struct Client*, int, char*[]);
extern int mo_version(struct Client*, struct Client*, int, char*[]);
extern int mo_wallops(struct Client*, struct Client*, int, char*[]);
extern int mo_wallusers(struct Client*, struct Client*, int, char*[]);
extern int mo_xquery(struct Client*, struct Client*, int, char*[]);
extern int mo_zline(struct Client*, struct Client*, int, char*[]);
extern int mr_error(struct Client*, struct Client*, int, char*[]);
extern int mr_error(struct Client*, struct Client*, int, char*[]);
extern int mr_pong(struct Client*, struct Client*, int, char*[]);
extern int mr_server(struct Client*, struct Client*, int, char*[]);
extern int mr_crdtmesh(struct Client*, struct Client*, int, char*[]);
extern int mr_crdt(struct Client*, struct Client*, int, char*[]);
extern int ms_account(struct Client*, struct Client*, int, char*[]);
extern int ms_cacheinval(struct Client*, struct Client*, int, char*[]);
extern int ms_admin(struct Client*, struct Client*, int, char*[]);
extern int ms_asll(struct Client*, struct Client*, int, char*[]);
extern int ms_away(struct Client*, struct Client*, int, char*[]);
extern int ms_bouncer_transfer(struct Client*, struct Client*, int, char*[]);
extern int ms_burst(struct Client*, struct Client*, int, char*[]);
extern int ms_clearmode(struct Client*, struct Client*, int, char*[]);
extern int ms_connect(struct Client*, struct Client*, int, char*[]);
extern int ms_create(struct Client*, struct Client*, int, char*[]);
extern int ms_destruct(struct Client*, struct Client*, int, char*[]);
extern int ms_desynch(struct Client*, struct Client*, int, char*[]);
extern int ms_end_of_burst(struct Client*, struct Client*, int, char*[]);
extern int ms_end_of_burst_ack(struct Client*, struct Client*, int, char*[]);
extern int ms_error(struct Client*, struct Client*, int, char*[]);
extern int ms_fake(struct Client*, struct Client*, int, char*[]);
extern int ms_gline(struct Client*, struct Client*, int, char*[]);
extern int ms_info(struct Client*, struct Client*, int, char*[]);
extern int ms_invite(struct Client*, struct Client*, int, char*[]);
extern int ms_join(struct Client*, struct Client*, int, char*[]);
extern int ms_jupe(struct Client*, struct Client*, int, char*[]);
extern int ms_kick(struct Client*, struct Client*, int, char*[]);
extern int ms_kill(struct Client*, struct Client*, int, char*[]);
extern int ms_links(struct Client*, struct Client*, int, char*[]);
#ifdef USE_LIBGIT2
extern int ms_gitsync(struct Client*, struct Client*, int, char*[]);
#endif
extern int ms_lusers(struct Client*, struct Client*, int, char*[]);
extern int ms_mark(struct Client*, struct Client*, int, char*[]);
extern int ms_mode(struct Client*, struct Client*, int, char*[]);
extern int ms_motd(struct Client*, struct Client*, int, char*[]);
extern int ms_names(struct Client*, struct Client*, int, char*[]);
extern int ms_nick(struct Client*, struct Client*, int, char*[]);
extern int ms_notice(struct Client*, struct Client*, int, char*[]);
extern int ms_oper(struct Client*, struct Client*, int, char*[]);
extern int ms_opermotd(struct Client*, struct Client*, int, char*[]);
extern int ms_opmode(struct Client*, struct Client*, int, char*[]);
extern int ms_part(struct Client*, struct Client*, int, char*[]);
extern int ms_ping(struct Client*, struct Client*, int, char*[]);
extern int ms_pong(struct Client*, struct Client*, int, char*[]);
extern int ms_privmsg(struct Client*, struct Client*, int, char*[]);
extern int ms_privs(struct Client*, struct Client*, int, char*[]);
extern int ms_quit(struct Client*, struct Client*, int, char*[]);
extern int ms_rehash(struct Client*, struct Client*, int, char*[]);
extern int ms_remove(struct Client*, struct Client*, int, char*[]);
extern int ms_rping(struct Client*, struct Client*, int, char*[]);
extern int ms_rpong(struct Client*, struct Client*, int, char*[]);
extern int ms_rules(struct Client*, struct Client*, int, char*[]);
extern int ms_sasl(struct Client*, struct Client*, int, char*[]);
extern int ms_server(struct Client*, struct Client*, int, char*[]);
extern int ms_setname(struct Client*, struct Client*, int, char*[]);
extern int ms_tagmsg(struct Client*, struct Client*, int, char*[]);
extern int ms_settime(struct Client*, struct Client*, int, char*[]);
extern int ms_shun(struct Client*, struct Client*, int, char*[]);
extern int ms_silence(struct Client*, struct Client*, int, char*[]);
extern int ms_smo(struct Client*, struct Client*, int, char*[]);
extern int ms_sno(struct Client*, struct Client*, int, char*[]);
extern int ms_squit(struct Client*, struct Client*, int, char*[]);
extern int ms_stats(struct Client*, struct Client*, int, char*[]);
extern int ms_svsident(struct Client*, struct Client*, int, char*[]);
extern int ms_svsinfo(struct Client*, struct Client*, int, char*[]);
extern int ms_svsjoin(struct Client*, struct Client*, int, char*[]);
extern int ms_svsmode(struct Client*, struct Client*, int, char*[]);
extern int ms_svsnick(struct Client*, struct Client*, int, char*[]);
extern int ms_svsnoop(struct Client*, struct Client*, int, char*[]);
extern int ms_svspart(struct Client*, struct Client*, int, char*[]);
extern int ms_svsquit(struct Client*, struct Client*, int, char*[]);
extern int ms_swhois(struct Client*, struct Client*, int, char*[]);
extern int ms_tempshun(struct Client*, struct Client*, int, char*[]);
extern int ms_topic(struct Client*, struct Client*, int, char*[]);
extern int ms_trace(struct Client*, struct Client*, int, char*[]);
extern int ms_uping(struct Client*, struct Client*, int, char*[]);
extern int ms_version(struct Client*, struct Client*, int, char*[]);
extern int ms_wallchops(struct Client*, struct Client*, int, char*[]);
extern int ms_wallhops(struct Client*, struct Client*, int, char*[]);
extern int ms_wallops(struct Client*, struct Client*, int, char*[]);
extern int ms_wallusers(struct Client*, struct Client*, int, char*[]);
extern int ms_wallvoices(struct Client*, struct Client*, int, char*[]);
extern int ms_whois(struct Client*, struct Client*, int, char*[]);
extern int ms_xquery(struct Client*, struct Client*, int, char*[]);
extern int ms_xreply(struct Client*, struct Client*, int, char*[]);
extern int ms_zline(struct Client*, struct Client*, int, char*[]);
extern int ms_batch(struct Client*, struct Client*, int, char*[]);
extern int m_batch(struct Client*, struct Client*, int, char*[]);
extern int check_client_batch_timeout(struct Client*);
extern int ms_multiline(struct Client*, struct Client*, int, char*[]);
extern int m_chathistory(struct Client*, struct Client*, int, char*[]);
extern int ms_chathistory(struct Client*, struct Client*, int, char*[]);
extern int m_history(struct Client*, struct Client*, int, char*[]);
extern int has_chathistory_advertisement(struct Client*);
extern int server_retention_days(struct Client*);
extern int server_retention_covers(struct Client*, time_t);
extern void clear_server_ad(struct Client*);
extern void chathistory_report_ads(struct Client*, const struct StatDesc*, char*);
extern void forward_history_write(struct Channel*, struct Client*, const char*, const char*, int, const char*);
extern int send_channel_advertisements(struct Client*);
extern void broadcast_channel_advertisement(const char*);
extern void chathistory_init_callbacks(void);
extern int m_redact(struct Client*, struct Client*, int, char*[]);
extern int ms_redact(struct Client*, struct Client*, int, char*[]);
extern int m_register(struct Client*, struct Client*, int, char*[]);
extern int m_verify(struct Client*, struct Client*, int, char*[]);
extern int ms_regreply(struct Client*, struct Client*, int, char*[]);
extern int m_markread(struct Client*, struct Client*, int, char*[]);
extern int ms_markread(struct Client*, struct Client*, int, char*[]);
extern void send_markread_on_join(struct Client*, const char*);
extern int m_rename(struct Client*, struct Client*, int, char*[]);
extern int ms_rename(struct Client*, struct Client*, int, char*[]);
extern int m_metadata(struct Client*, struct Client*, int, char*[]);
extern int ms_metadata(struct Client*, struct Client*, int, char*[]);
extern int m_webpush(struct Client*, struct Client*, int, char*[]);
extern int ms_webpush(struct Client*, struct Client*, int, char*[]);
extern int m_bouncer(struct Client*, struct Client*, int, char*[]);
extern int ms_bouncer_session(struct Client*, struct Client*, int, char*[]);
extern int ms_crdt(struct Client*, struct Client*, int, char*[]);
/** Oper /CRDT [map|peers|status]: introspect the gossiped CRDT mesh state. */
extern int mo_crdt(struct Client*, struct Client*, int, char*[]);
/** Send our CRDT state vector to a CRDT-aware peer to kick off delta sync. */
extern void crdt_sync_request(struct Client* peer);
/** Periodic anti-entropy: send CR S to every directly-connected CRDT peer. */
extern void crdt_sync_broadcast(void);
/** Eager push (CR U): after a local CRDT write, send each directly-connected
 *  CRDT peer the ops it lacks, using its last-reported state vector. Peers with
 *  no cached SV yet are skipped (the periodic anti-entropy catches them up). */
extern void crdt_sync_push(void);
/** Phase 3c: send the full CRDT document as a CR F snapshot to @a to — the
 *  CRDT-authoritative replacement for P10 BURST on a CRDT-primary link. */
extern void crdt_send_snapshot(struct Client* to);
/** Tier2 T2-b: gossip a live message to a mesh-only target (its tree path is down
 *  but it is mesh-reachable) as an ephemeral CR M line over the CRDT transports —
 *  delivered on the target's home server, deduped by @a msgid; never the doc.
 *  @a cmd is 'P' (PRIVMSG) or 'N' (NOTICE); @a target is a 5-char user numeric
 *  (unicast) or a #channel name (deliver to local channel members). */
extern void crdt_gossip_message(struct Client* from, char cmd, const char* target,
                                const char* msgid, const char* text);
/** MR-1: try to route a user-unicast over the CRDT mesh instead of the P10 tree.
 *  Returns 1 if handled over CR (caller MUST skip the P10 send), 0 to use P10.
 *  Mesh-stub target -> always CR (partition fallback); live CRDT-aware target ->
 *  CR only under FEAT_CRDT_ROUTE_UNICAST.  @a cmd 'P'/'N'/'T'. */
extern int crdt_route_unicast_try(struct Client* from, char cmd, struct Client* tgt,
                                  const char* msgid, const char* text);
/** Tier B services-anchor bridge (CR X carrier).  FORWARD: route a services command (SASL/
 *  ACCOUNT/REGISTER/...) over the mesh when its target SERVER @a dstsrv is reachable only as a
 *  dead-sink anchor; @a body = the verbatim P10 param tail.  REPLY: same, for the x3-reply
 *  reverse leg on the gateway (target may be a user/anchor; uses IsMeshStub directly).  Each
 *  returns 1 if tunneled (skip the P10 send) / 0 to fall back to P10.  @a p10cmd is the one-letter
 *  code (A=SASL C=ACCOUNT G=REGISTER V=VERIFY R=REGREPLY Q=XQUERY Y=XREPLY). */
extern int crdt_route_services_try(struct Client* dstsrv, char p10cmd, const char* body);
extern int crdt_route_services_reply_try(struct Client* tgt, char p10cmd, const char* body);
extern int crdt_route_services_reply_by_num(const char* srvnum, char p10cmd, const char* body);

/* 5-5f B3 (gateway slice): chathistory federation over the CR-X carrier.
 * _try tunnels a frame toward a server numeric (0 = carrier unavailable, the
 * caller must then account for the request itself); _reply is the fire-and-
 * forget reply leg; _dispatch re-injects a tunnelled frame locally with the
 * reply tunnel armed. */
extern int  crdt_ch_tunnel_try(const char* dstyxx, const char* body);
extern void crdt_ch_tunnel_reply(const char* dstyxx, const char* body);
extern void crdt_ch_tunnel_dispatch(char* body);
/** Tier2 full-partition liveness: gossip an ephemeral CR H liveness beacon
 *  (CR H <ourYXX> <CurrentTime>) over every CRDT transport.  Receivers track
 *  the last beacon per server; a mesh stub whose beacon goes stale is retired. */
extern void crdt_gossip_beacon(void);
/** MR-5 beacon-burst: emit our liveness set to a single peer @a only (link-time
 *  bringup), instead of the periodic all-peer flood.  @a only==NULL == the flood. */
extern void crdt_gossip_beacon_to(struct Client *only);
extern int ms_bouncer_transfer(struct Client*, struct Client*, int, char*[]);
extern int m_persistence(struct Client*, struct Client*, int, char*[]);
extern void persistence_send_status(struct Client *to);
extern int persistence_replay_enabled_for(struct Client *cptr);

#endif /* INCLUDED_handlers_h */

