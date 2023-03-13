/**
 * @file peer_connection.h
 * @brief Struct PeerConnection
 */
#ifndef PEER_CONNECTION_H_
#define PEER_CONNECTION_H_

#ifdef __cplusplus
extern "C" {
#endif

//#include <agent.h>

#include "utils.h"
#include "session_description.h"
#include "dtls_transport.h"
#include "media_stream.h"

typedef enum IceConnectionState {

  DISCONNECTED,
  GATHERING,
  CONNECTING,
  CONNECTED,
  READY,
  FAILED,

} IceConnectionState;

struct PeerConnection;

typedef struct PeerConnection PeerConnection;

typedef void (*onicecandidate_cb_t)(PeerConnection *pc, char *sdp, void *userdata);
typedef void (*oniceconnectionstatechange_cb_t)(PeerConnection *pc, IceConnectionState state, void *userdata);
typedef void (*ontrack_cb_t)(PeerConnection *pc, uint8_t *packet, size_t bytes, void *userdata);
typedef void (*on_transport_ready_cb_t)(PeerConnection *pc, void *userdata);
typedef void (*on_connected_cb_t)(PeerConnection *pc, void *userdata);
typedef RtpMap (*get_rtpmap_handler_t)(const char *sdp);

/**
 * @brief Create a struct PeerConnection and initialize it.
 * @return Pointer of PeerConnection.
 */
PeerConnection* peer_connection_create(void *userdata);
int peer_connection_init(PeerConnection *pc);

/**
 * @brief Destory a struct PeerConnection.
 */
void peer_connection_destroy(PeerConnection *pc);

/**
 * @brief Let PeerConnection send RTCP PIL.
 * @param PeerConnection
 * @param RTP ssrc
 */
int peer_connection_send_rtcp_pil(PeerConnection *pc, uint32_t ssrc);

/**
 * @brief Add audio or video stream to PeerConnection.
 * @param A PeerConnection.
 * @param A MediaStream.
 */
void peer_connection_add_stream(PeerConnection *pc, MediaStream *media_stream);

/**
 * @brief Set the callback function to handle onicecandidate event.
 * @param A PeerConnection.
 * @param A callback function to handle onicecandidate event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_onicecandidate(PeerConnection *pc, onicecandidate_cb_t onicecandidate);

/**
 * @brief Set the callback function to handle oniceconnectionstatechange event.
 * @param A PeerConnection.
 * @param A callback function to handle oniceconnectionstatechange event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_oniceconnectionstatechange(PeerConnection *pc,
 oniceconnectionstatechange_cb_t oniceconnectionstatechange);

/**
 * @brief Set the callback function to handle ontrack event.
 * @param A PeerConnection.
 * @param A callback function to handle ontrack event.
 * @param A userdata which is pass to callback function. 
 */
void peer_connection_ontrack(PeerConnection *pc, ontrack_cb_t ontrack);

/**
 * @brief sets the specified session description as the remote peer's current offer or answer.
 * @param PeerConnection.
 * @param SDP string.
 */
void peer_connection_set_remote_description(PeerConnection *pc, const char *sdp);
void peer_connection_set_remote_description_a(PeerConnection *pc, const char *sdp);
void peer_connection_set_remote_description_b(PeerConnection *pc, const char *sdp);

/**
 * @brief PeerConnection creates an answer.
 * @param PeerConnection.
 */
int peer_connection_create_answer(PeerConnection *pc);

/**
 * @brief Get audio and video ssrc from a PeerConnection after set remote description.
 * @param PeerConnection.
 * @param Media type of audio and video.
 */
uint32_t peer_connection_get_ssrc(PeerConnection *pc, const char *type);

/**
 * @brief Get payload type of codec in SDP.
 * @param PeerConnection.
 * @param Media Codec of audio or video.
 */
int peer_connection_get_rtpmap(PeerConnection *pc, MediaCodec codec);

/**
 * @brief Support to resolve mDNS candidate.
 * @param PeerConnection.
 * @param Boolean. Default is FALSE.
 */
void peer_connection_enable_mdns(PeerConnection *pc, int b_enabled);

/**
 * @brief register callback function to handle packet loss from RTCP receiver report
 * @param[in] peer connection
 * @param[in] callback function void (*cb)(float fraction_loss, uint32_t total_loss, void *userdata)
 * @param[in] userdata for callback function
 */
void peer_connection_on_receiver_packet_loss(PeerConnection *pc,
 void (*on_receiver_packet_loss)(float fraction_loss, uint32_t total_loss, void *userdata));

/**
 * @brief register callback function to handle event when the connection is established
 * @param[in] peer connection
 * @param[in] callback function void (*cb)(void *userdata)
 * @param[in] userdata for callback function
 */
void peer_connection_on_connected(PeerConnection *pc, on_connected_cb_t on_connected);

/**
 * @brief register callback function to handle event of datachannel
 * @param[in] peer connection
 * @param[in] callback function when message received
 * @param[in] callback function when connection is opened
 * @param[in] callback function when connection is closed
 */
void peer_connection_ondatachannel(PeerConnection *pc,
 void (*onmessasge)(char *msg, size_t len, void *userdata),
 void (*onopen)(void *userdata),
 void (*onclose)(void *userdata));

/**
 * @brief send message to data channel
 * @param[in] peer connection
 * @param[in] message buffer
 * @param[in] length of message
 */
int peer_connection_datachannel_send(PeerConnection *pc, char *message, size_t len);

// To confirm:
int peer_connection_send_rtp_packet(PeerConnection *pc, uint8_t *packet, int bytes);

void peer_connection_set_rtpmap_handler(PeerConnection *pc, get_rtpmap_handler_t handler);

#ifdef __cplusplus
}
#endif

#endif // PEER_CONNECTION_H_
