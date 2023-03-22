#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <gio/gnetworking.h>

#include "sctp.h"
#include "dtls_transport.h"
#include "nice_agent_bio.h"
#include "rtp_packet.h"
#include "rtcp_packet.h"
#include "utils.h"
#include "peer_connection.h"

static const gchar *STATE_NAME[] = {"disconnected", "gathering", "connecting",
 "connected", "ready", "failed"};
static const gchar *CANDIDATE_TYPE_NAME[] = {"host", "srflx", "prflx", "relay"};
//static const gchar *STUN_ADDR = "18.191.223.12";
//static const guint STUN_PORT = 3478;

//static const gchar *STUN_ADDR = "stun.l.google.com";
//static const guint STUN_PORT = 19302;

static const gchar *STUN_ADDR = ""; //"127.0.0.1";
static const guint STUN_PORT = 10001; //3478;

//static const gchar *STUN_ADDR = "192.168.0.84";
//static const guint STUN_PORT = 3478;

typedef struct {

  uint8_t h264:1;
  uint8_t vp8:1;
  uint8_t opus:1;
  uint8_t pcma:1;
  uint8_t pcmu:1;

} CodecCapability;

struct PeerConnection {

  NiceAgent *nice_agent;
  gboolean controlling;
  guint stream_id;
  guint component_id;
  GMainLoop *gloop;
  GThread *gthread;

  CodecCapability codec_capability;
  gboolean mdns_enabled;

  uint32_t audio_ssrc, video_ssrc;

  SessionDescription *remote_sdp;
  SessionDescription *local_sdp;

  Sctp *sctp;
  DtlsTransport *dtls_transport;
  MediaStream *media_stream;
  RtpMap rtp_map;

  onicecandidate_cb_t onicecandidate;
  oniceconnectionstatechange_cb_t oniceconnectionstatechange;
  ontrack_cb_t ontrack;
  
  get_rtpmap_handler_t get_rtpmap_handler; 

  on_connected_cb_t on_connected;
  on_receiver_loss on_receiver_packet_loss;

  void *userdata;

  GMutex mutex;

  /*on_transport_ready_cb_t on_transport_ready;
  void *on_transport_ready_userdata;*/
};


void* peer_connection_gather_thread(void *data) {

  PeerConnection *pc = (PeerConnection*)data;

  g_main_loop_run(pc->gloop);

  return NULL;

}

static int hostname_to_ip(const char *hostname, char *ip)
{
	struct hostent *he = NULL;
	struct in_addr **addr_list = NULL;
		
    he = gethostbyname(hostname);
	if(he == NULL)
	{
		return 0;
	}

	addr_list = (struct in_addr **) he->h_addr_list;
	
    if(addr_list[0] != NULL)
    {
        strcpy(ip, inet_ntoa(*addr_list[0]));
		return 1;
    }
	
	return 0;
}

static void peer_connection_new_selected_pair_full_cb(NiceAgent* agent, guint stream_id,
 guint component_id, NiceCandidate *lcandidate, NiceCandidate* rcandidate, gpointer data) {

  PeerConnection *pc = (PeerConnection*)data;
  dtls_transport_do_handshake(pc->dtls_transport);
}

static void* peer_connection_component_state_chanaged_cb(NiceAgent *agent,
 guint stream_id, guint component_id, guint state, gpointer data) {

  PeerConnection *pc = (PeerConnection*)data;
  LOG_INFO("SIGNAL: state changed %d %d %s[%d]",
   stream_id, component_id, STATE_NAME[state], state);
  if(pc->oniceconnectionstatechange != NULL) {
    pc->oniceconnectionstatechange(pc, state, pc->userdata);
  }

}

static void peer_connection_candidates_to_sdp(PeerConnection *pc, SessionDescription *sdp) {

  GSList *nice_candidates = NULL;
  NiceCandidate *nice_candidate;
  char nice_candidate_addr[INET6_ADDRSTRLEN];
  int i = 0;

  nice_candidates = nice_agent_get_local_candidates(pc->nice_agent,
   pc->stream_id, pc->component_id);

  for(i = 0; i < g_slist_length(nice_candidates); ++i) {

    nice_candidate = (NiceCandidate *)g_slist_nth(nice_candidates, i)->data;
    nice_address_to_string(&nice_candidate->addr, nice_candidate_addr);
    if(utils_is_valid_ip_address(nice_candidate_addr) > 0) {
      nice_candidate_free(nice_candidate);
      continue;
    }

    session_description_append(sdp, "a=candidate:%s 1 udp %u %s %d typ host",
     nice_candidate->foundation,
     nice_candidate->priority,
     nice_candidate_addr,
     nice_address_get_port(&nice_candidate->addr));

    nice_candidate_free(nice_candidate);
  }

  if(nice_candidates)
    g_slist_free(nice_candidates);
}

static void peer_connection_video_to_sdp(PeerConnection *pc, SessionDescription *sdp, uint32_t ssrc) {

  session_description_append(sdp, "m=video 9 UDP/TLS/RTP/SAVPF 96 102");

  if(pc->codec_capability.h264) {

    session_description_append(sdp, "a=rtcp-fb:102 nack");
    session_description_append(sdp, "a=rtcp-fb:102 nack pli");
    session_description_append(sdp, "a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1");
    session_description_append(sdp, "a=fmtp:102 profile-level-id=42e01f;packetization-mode=1;level-asymmetry-allowed=1");
    session_description_append(sdp, "a=fmtp:102 x-google-max-bitrate=6000;x-google-min-bitrate=2000;x-google-start-bitrate=4000");
    session_description_append(sdp, "a=rtpmap:96 H264/90000");
    session_description_append(sdp, "a=rtpmap:102 H264/90000");
  }

  //session_description_append(sdp, "a=ssrc:%d cname:pear", ssrc);
  session_description_append(sdp, "a=sendrecv");

}

static void peer_connection_audio_to_sdp(PeerConnection *pc, SessionDescription *sdp, uint32_t ssrc) {

  session_description_append(sdp, "m=audio 9 UDP/TLS/RTP/SAVP 111");

  if(pc->codec_capability.opus) {

    session_description_append(sdp, "a=rtcp-fb:111 nack");
    session_description_append(sdp, "a=rtpmap:111 opus/48000/2");
  }
  else if(pc->codec_capability.pcma) {

    session_description_append(sdp, "a=rtpmap:8 PCMA/8000");
  }

  session_description_append(sdp, "a=ssrc:%d cname:pear", ssrc);
  session_description_append(sdp, "a=sendrecv");
}

static void peer_connection_datachannel_to_sdp(PeerConnection *pc, SessionDescription *sdp) {

  session_description_append(sdp, "m=application 50712 UDP/DTLS/SCTP webrtc-datachannel");
  session_description_append(sdp, "a=sctp-port:5000");
  session_description_append(sdp, "a=max-message-size:262144");
}

static void* peer_connection_candidate_gathering_done_cb(NiceAgent *agent, guint stream_id,
 gpointer data) {
    LOG_INFO("%s", __PRETTY_FUNCTION__);

  PeerConnection *pc = (PeerConnection*)data;

  MediaDescription *media_descriptions;

  gchar *local_ufrag = NULL;
  gchar *local_password = NULL;
  GSList *nice_candidates = NULL;

  int i = 0;
  NiceCandidate *nice_candidate;
  char nice_candidate_addr[INET6_ADDRSTRLEN];

  int num = 0;
  char attribute_text[128];
  char bundle_text[64];

  if(pc->local_sdp) {
    session_description_destroy(pc->local_sdp);
  }

  pc->local_sdp = session_description_create(NULL);
  SessionDescription *sdp = pc->local_sdp;

  if(!nice_agent_get_local_credentials(pc->nice_agent,
   pc->stream_id, &local_ufrag, &local_password)) {
    LOG_ERROR("get local credentials failed");
    return NULL;
  }
  
  GRand *rand = g_rand_new();

  session_description_append(sdp, "v=0");
  // 1495799811084970
  uint32_t ss_id = g_rand_int(rand);
  session_description_append(sdp, "o=- %u %u IN IP4 0.0.0.0", ss_id, ss_id + 1);
  g_rand_free(rand);
  session_description_append(sdp, "s=-");
  session_description_append(sdp, "t=0 0");
  session_description_append(sdp, "a=msid-semantic: WMS");

  media_descriptions = session_description_get_media_descriptions(pc->remote_sdp, &num);

  memset(attribute_text, 0, sizeof(attribute_text));
  for(i = 0; i < num; i++) {

    memset(bundle_text, 0, sizeof(bundle_text));
    sprintf(bundle_text, " %d", i);
#warning
    strcat(attribute_text, bundle_text);
  }

  session_description_append(sdp, "a=group:BUNDLE%s", attribute_text);

  for(i = 0; i < num; i++) {

    switch(media_descriptions[i]) {
      case MEDIA_VIDEO:
        peer_connection_video_to_sdp(pc, sdp, (i+1));
        break;
      case MEDIA_AUDIO:
        peer_connection_audio_to_sdp(pc, sdp, (i+1));
        break;
      case MEDIA_DATACHANNEL:
        peer_connection_datachannel_to_sdp(pc, sdp);
        break;
      default:
        break;
    }

    session_description_append(sdp, "a=mid:%d", i);
    session_description_append(sdp, "c=IN IP4 0.0.0.0");
    session_description_append(sdp, "a=rtcp-mux");
    session_description_append(sdp, "a=ice-ufrag:%s", local_ufrag);
    session_description_append(sdp, "a=ice-pwd:%s", local_password);
    session_description_append(sdp, "a=ice-options:trickle");
    session_description_append(sdp, "a=fingerprint:sha-256 %s",
     dtls_transport_get_fingerprint(pc->dtls_transport));
    session_description_append(sdp, "a=setup:passive");
    peer_connection_candidates_to_sdp(pc, sdp);
  }

  if(local_ufrag)
    free(local_ufrag);

  if(local_password)
    free(local_password);


  nice_candidates = nice_agent_get_local_candidates(pc->nice_agent,
   pc->stream_id, pc->component_id);

  for(i = 0; i < g_slist_length(nice_candidates); ++i) {

    nice_candidate = (NiceCandidate *)g_slist_nth(nice_candidates, i)->data;
    nice_address_to_string(&nice_candidate->addr, nice_candidate_addr);
    if(utils_is_valid_ip_address(nice_candidate_addr) > 0) {
      nice_candidate_free(nice_candidate);
      continue;
    }

    char *template = "a=candidate:%s 1 udp %u %s %d typ %s";
    
    if(nice_candidate->type == NICE_CANDIDATE_TYPE_RELAYED)
    {
        template = "a=candidate:%s 1 udp %u %s %d typ %s raddr 0.0.0.0 rport 777";
    }

    session_description_append(sdp, template,
     nice_candidate->foundation,
     nice_candidate->priority,
     nice_candidate_addr,
     nice_address_get_port(&nice_candidate->addr),
     CANDIDATE_TYPE_NAME[nice_candidate->type]);

    nice_candidate_free(nice_candidate);
  }

  if(pc->onicecandidate != NULL) {

    char *sdp_content = session_description_get_content(pc->local_sdp);
    pc->onicecandidate(pc, sdp_content, pc->userdata);
  }

  if(nice_candidates)
    g_slist_free(nice_candidates);

}

int peer_connection_send_rtcp_pil(PeerConnection *pc, uint32_t ssrc) {

  int ret = -1;
  guint size = 12;
  uint8_t plibuf[128];
  rtcp_packet_get_pli(plibuf, 12, ssrc);

  dtls_transport_encrypt_rctp_packet(pc->dtls_transport, plibuf, &size);
  ret = nice_agent_send(pc->nice_agent, pc->stream_id, pc->component_id, size, (gchar*)plibuf);

  return ret;
}

void peer_connection_incomming_rtcp(PeerConnection *pc, uint8_t *buf, size_t len) {

  RtcpHeader rtcp_header = {0};
  memcpy(&rtcp_header, buf, sizeof(rtcp_header));
  switch(rtcp_header.type) {
    case RTCP_RR:
      if(rtcp_header.rc > 0) {
        RtcpRr rtcp_rr = rtcp_packet_parse_rr(buf);
        uint32_t fraction = ntohl(rtcp_rr.report_block[0].flcnpl) >> 24;
        uint32_t total = ntohl(rtcp_rr.report_block[0].flcnpl) & 0x00FFFFFF;
        uint32_t extended_highest_sequence_number_received = htonl(rtcp_rr.report_block[0].ehsnr);
        if(pc->on_receiver_packet_loss/* && fraction > 0*/) {
          pc->on_receiver_packet_loss(pc, (float)fraction / 256.0, total, extended_highest_sequence_number_received, pc->userdata);
        }
      }
      break;
    default:
      break;
  }
}

static void peer_connection_ice_recv_cb(NiceAgent *agent, guint stream_id, guint component_id,
 guint len, gchar *buf, gpointer data) {

  PeerConnection *pc = (PeerConnection*)data;
  int ret;
  char decrypted_data[3000];
  if(rtcp_packet_validate(buf, len)) {

    dtls_transport_decrypt_rtcp_packet(pc->dtls_transport, buf, &len);
    peer_connection_incomming_rtcp(pc, buf, len);
  }
  else if(dtls_transport_validate(buf)) {

    if(!dtls_transport_get_srtp_initialized(pc->dtls_transport)) {

      dtls_transport_incomming_msg(pc->dtls_transport, buf, len);

      if(dtls_transport_get_srtp_initialized(pc->dtls_transport) && pc->on_connected) {
        pc->on_connected(pc, pc->userdata);
      }

      if(pc->remote_sdp->datachannel_enabled) {
        sctp_create_socket(pc->sctp);
      }

    }
    else {

      ret = dtls_transport_decrypt_data(pc->dtls_transport, buf, len, decrypted_data, sizeof(decrypted_data));
      sctp_incoming_data(pc->sctp, decrypted_data, ret);
    }

  }
  else if(rtp_packet_validate(buf, len)) {

    dtls_transport_decrypt_rtp_packet(pc->dtls_transport, buf, &len);

    if(pc->ontrack != NULL) {
      pc->ontrack(pc, buf, len, pc->userdata);
    }
  }
}

static char *get_env_str(const char *name, const char *default_value)
{
    char *v = getenv(name);
    if(v)
    {
        return strdup(v);
    }
    return strdup(default_value);
}

static int get_env_int(const char *name, int default_value)
{
    char *v = getenv(name);
    if(v)
    {
        int rv = default_value;
        char *endptr = NULL;
        rv = strtol(v, &endptr, 10);
        if(v == endptr)
        {
            return default_value;
        }        
        return rv;
    }
    return default_value;
}

gboolean peer_connection_nice_agent_setup(PeerConnection *pc) {

  pc->gloop = g_main_loop_new(NULL, FALSE);

  pc->nice_agent = nice_agent_new(g_main_loop_get_context(pc->gloop),
   NICE_COMPATIBILITY_RFC5245);

  if(pc->nice_agent == NULL) {
    LOG_ERROR("Failed to create agent");
    return FALSE;
  }

  g_object_set(pc->nice_agent, "stun-server", STUN_ADDR, NULL);
  g_object_set(pc->nice_agent, "stun-server-port", STUN_PORT, NULL);
  g_object_set(pc->nice_agent, "controlling-mode", FALSE, NULL);
  g_object_set(pc->nice_agent, "keepalive-conncheck", TRUE, NULL);

  g_signal_connect(pc->nice_agent, "candidate-gathering-done",
   G_CALLBACK(peer_connection_candidate_gathering_done_cb), pc);

  g_signal_connect(pc->nice_agent, "component-state-changed",
   G_CALLBACK(peer_connection_component_state_chanaged_cb), pc);

  g_signal_connect(pc->nice_agent, "new-selected-pair-full",
   G_CALLBACK(peer_connection_new_selected_pair_full_cb), pc);

  pc->component_id = 1;
  pc->stream_id = nice_agent_add_stream(pc->nice_agent, pc->component_id);

  if(pc->stream_id == 0) {
    LOG_ERROR("Failed to add stream");
    return FALSE;
  }

  nice_agent_set_stream_name(pc->nice_agent, pc->stream_id, "video");
  
  char *relay_host = get_env_str("PEAR_RELAY_HOST", "127.0.0.1");
  char relay_ip[100] = {0};
  int ip_ok = hostname_to_ip(relay_host, relay_ip);
  if(ip_ok)
  {
      char *relay_user = get_env_str("PEAR_RELAY_USERNAME", "test");
      char *relay_password = get_env_str("PEAR_RELAY_PASSWORD", "test");
      int relay_port = get_env_int("PEAR_RELAY_PORT", 3478);
      NiceRelayType relay_type = NICE_RELAY_TYPE_TURN_TCP;
      char *relay_type_env = get_env_str("PEAR_RELAY_TYPE", "tcp");
      if(!strcmp(relay_type_env, "udp"))
      {
          relay_type = NICE_RELAY_TYPE_TURN_UDP;
      }
      
      nice_agent_set_relay_info(pc->nice_agent, pc->stream_id, pc->component_id, relay_ip, relay_port, relay_user, relay_password, relay_type);

      free(relay_type_env);
      free(relay_user);
      free(relay_password);
  }
  free(relay_host);

  nice_agent_attach_recv(pc->nice_agent, pc->stream_id, pc->component_id,
   g_main_loop_get_context(pc->gloop), peer_connection_ice_recv_cb, pc);

  pc->gthread = g_thread_new("ice gather thread", peer_connection_gather_thread, pc);

  return TRUE;
}

int peer_connection_init(PeerConnection *pc)
{
    pc->mdns_enabled = FALSE;
  
    pc->audio_ssrc = 0;
    pc->video_ssrc = 0;
  
    pc->onicecandidate = NULL;
  
    pc->oniceconnectionstatechange = NULL;
        
    pc->get_rtpmap_handler = session_description_parse_rtpmap_default;
  
    if(peer_connection_nice_agent_setup(pc) == FALSE)
    {
        peer_connection_destroy(pc);
        return 0;
    }
  
    pc->dtls_transport = dtls_transport_create(nice_agent_bio_new(pc->nice_agent, pc->stream_id, pc->component_id));
    
#warning
    //pc->sdp = session_description_create();
    
    return 1;
}

PeerConnection* peer_connection_create(void *userdata) {
  PeerConnection *pc = NULL;
  pc = (PeerConnection*)calloc(1, sizeof(PeerConnection));
  memset(pc, 0, sizeof(*pc));
  if(pc == NULL)
    return pc;

  pc->codec_capability.h264 = 1;
  pc->codec_capability.opus = 1;

  pc->audio_ssrc = 0;
  pc->video_ssrc = 0;

  if(peer_connection_nice_agent_setup(pc) == FALSE) {
    peer_connection_destroy(pc);
    return NULL;
  }

  pc->dtls_transport = dtls_transport_create(nice_agent_bio_new(pc->nice_agent, pc->stream_id, pc->component_id));

  pc->sctp = sctp_create(pc->dtls_transport);

  return pc;
}

void peer_connection_enable_mdns(PeerConnection *pc, gboolean b_enabled) {

  if(pc->remote_sdp) {
    session_description_set_mdns_enabled(pc->remote_sdp, b_enabled);
  }
}

void peer_connection_destroy(PeerConnection *pc) {

  if(pc == NULL)
    return;

  g_main_loop_quit(pc->gloop);

  g_thread_join(pc->gthread);

  g_main_loop_unref(pc->gloop);

  if(pc->nice_agent)
    g_object_unref(pc->nice_agent);

  if(pc->dtls_transport)
    dtls_transport_destroy(pc->dtls_transport);

  if(pc->local_sdp)
    session_description_destroy(pc->local_sdp);

  if(pc->remote_sdp)
    session_description_destroy(pc->remote_sdp);

  free(pc);
  pc = NULL;
}

void peer_connection_add_stream(PeerConnection *pc, MediaStream *media_stream) {

  pc->media_stream = media_stream;
}

int peer_connection_create_answer(PeerConnection *pc) {

  if(!nice_agent_gather_candidates(pc->nice_agent, pc->stream_id)) {
    LOG_ERROR("Failed to start candidate gathering");
    return -1;
  }
  return 0;
}

void peer_connection_set_remote_description(PeerConnection *pc, const char *sdp)
{
    peer_connection_set_remote_description_a(pc, sdp);
    peer_connection_set_remote_description_b(pc, sdp);
}
        
void peer_connection_set_remote_description_a(PeerConnection *pc, const char *sdp_text) {

  if(!sdp_text) {

    LOG_WARN("Remote SDP is empty");
    return;
  }

  pc->audio_ssrc = session_description_find_ssrc("audio", sdp_text);
  pc->video_ssrc = session_description_find_ssrc("video", sdp_text);

  if(pc->remote_sdp) {
    session_description_destroy(pc->remote_sdp);
  }

  /*// Remove mDNS
  SessionDescription *sdp = NULL;
  if(strstr(remote_sdp, "local") != NULL) {

    sdp = session_description_create();
    gchar **splits;

    splits = g_strsplit(remote_sdp, "\r\n", 256);
    for(i = 0; splits[i] != NULL; i++) {

      if(strstr(splits[i], "candidate") != NULL && strstr(splits[i], "local") != NULL) {

        if(pc->mdns_enabled) {
          char buf[256] = {0};
          if(session_description_update_mdns_of_candidate(splits[i], buf, sizeof(buf)) != -1) {
            session_description_append_newline(sdp, buf);
          }
        }
      }
      else {
        session_description_append_newline(sdp, splits[i]);
      }
    }

    remote_sdp = session_description_get_content(sdp);
  }*/

  pc->remote_sdp = session_description_create(sdp_text);

  sdp_text = session_description_get_content(pc->remote_sdp);

  pc->rtp_map = pc->get_rtpmap_handler(sdp_text);

  /*if(sdp)
    session_description_destroy(sdp);*/
}
        
void peer_connection_set_remote_description_b(PeerConnection *pc, const char *sdp_text) {

  gchar* ufrag = NULL;
  gchar* pwd = NULL;
  GSList *plist;
  
  sdp_text = session_description_get_content(pc->remote_sdp);
  plist = nice_agent_parse_remote_stream_sdp(pc->nice_agent, pc->component_id, sdp_text, &ufrag, &pwd);

  if(ufrag && pwd && g_slist_length(plist) > 0) {

    ufrag[strlen(ufrag) - 1] = '\0';
    pwd[strlen(pwd) - 1] = '\0';
    NiceCandidate* c = (NiceCandidate*)g_slist_nth(plist, 0)->data;

    if(!nice_agent_set_remote_credentials(pc->nice_agent, 1, ufrag, pwd)) {

      LOG_WARN("failed to set remote credentials");
    }

    if(nice_agent_set_remote_candidates(pc->nice_agent, pc->stream_id,
     pc->component_id, plist) < 1) {
 
     LOG_WARN("failed to set remote candidates");
    }

    g_free(ufrag);
    g_free(pwd);
    g_slist_free_full(plist, (GDestroyNotify)&nice_candidate_free);
  }

  /*if(sdp)
    session_description_destroy(sdp);*/
}

int peer_connection_datachannel_send(PeerConnection *pc, char *message, size_t len) {

  if(sctp_is_connected(pc->sctp))
    return sctp_outgoing_data(pc->sctp, message, len);

  return -1;
}

int peer_connection_send_rtp_packet(PeerConnection *pc, uint8_t *packet, int bytes) {

  dtls_transport_encrypt_rtp_packet(pc->dtls_transport, packet, &bytes);
  int sent = nice_agent_send(pc->nice_agent, pc->stream_id, pc->component_id, bytes, (gchar*)packet);
  if(sent < bytes) {
    //LOG_ERROR("only sent %d bytes? (was %d)\n", sent, bytes);
  }
  return sent;

}

void peer_connection_on_connected(PeerConnection *pc, on_connected_cb_t on_connected) {

  pc->on_connected = on_connected;
}

void peer_connection_on_receiver_packet_loss(PeerConnection *pc, on_receiver_loss on_receiver_packet_loss)
{
    pc->on_receiver_packet_loss = on_receiver_packet_loss;
}

void peer_connection_onicecandidate(PeerConnection *pc, onicecandidate_cb_t onicecandidate) {

  pc->onicecandidate = onicecandidate;
}

void peer_connection_oniceconnectionstatechange(PeerConnection *pc,
  oniceconnectionstatechange_cb_t oniceconnectionstatechange) {

  pc->oniceconnectionstatechange = oniceconnectionstatechange;

}

void peer_connection_ontrack(PeerConnection *pc, ontrack_cb_t ontrack) {

  pc->ontrack = ontrack;
}


uint32_t peer_connection_get_ssrc(PeerConnection *pc, const char *type) {

  if(strcmp(type, "audio") == 0) {
    return pc->audio_ssrc;
  }
  else if(strcmp(type, "video") == 0) {
    return pc->video_ssrc;
  }

  return 0;
}

int peer_connection_get_rtpmap(PeerConnection *pc, MediaCodec codec) {

  switch(codec) {

    case CODEC_H264:
      return pc->rtp_map.pt_h264;
    case CODEC_OPUS:
      return pc->rtp_map.pt_opus;
    case CODEC_PCMA:
      return pc->rtp_map.pt_pcma;
    default:
     return -1;
  }

   return -1;
}
            
void peer_connection_set_rtpmap_handler(PeerConnection *pc, get_rtpmap_handler_t handler)
{
    pc->get_rtpmap_handler = handler;
}


void peer_connection_ondatachannel(PeerConnection *pc,
 void (*onmessasge)(char *msg, size_t len, void *userdata),
 void (*onopen)(void *userdata),
 void (*onclose)(void *userdata)) {

  if(pc) {

    sctp_onopen(pc->sctp, onopen);
    sctp_onclose(pc->sctp, onclose);
    sctp_onmessage(pc->sctp, onmessasge);
  }
}
