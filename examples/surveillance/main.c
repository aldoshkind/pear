#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <gst/gst.h>

#include "index_html.h"
#include "peer_connection.h"
#include "signaling.h"

const char PIPE_LINE[] = "videotestsrc pattern=ball ! video/x-raw,width=1280,height=720,framerate=30/1 ! x264enc bitrate=6000 speed-preset=ultrafast tune=zerolatency key-int-max=15 ! video/x-h264,profile=constrained-baseline ! rtph264pay name=rtp config-interval=-1 ssrc=1 ! appsink name=peer-connection-sink";

typedef struct Surveillance {

  GstElement *rtp;
  GstElement *pipeline;
  GstElement *sink;

  GCond cond;
  GMutex mutex;

  PeerConnection *pc;
  Signaling *signaling;

} Surveillance;

Surveillance g_surveillance = {0};


static void on_iceconnectionstatechange(IceConnectionState state, void *data) {
    printf("%s %d\n", __PRETTY_FUNCTION__, state);
  if(state == FAILED) {
    printf("Disconnect with browser... Stop streaming");
    gst_element_set_state(g_surveillance.pipeline, GST_STATE_PAUSED);
  }
}

static void on_icecandidate(char *sdp, void *data) {
    printf("%s\n", __PRETTY_FUNCTION__);
  signaling_send_answer_to_call(g_surveillance.signaling, sdp);
  g_cond_signal(&g_surveillance.cond);
}

void on_receiver_packet_loss(float fration_loss, uint32_t total_loss, void *data) {

  LOG_INFO("Get receiver report. packet loss %f, %u", fration_loss, total_loss);
}

static void on_connected(void *data) {

  static int pt = -1;
  // Update payload type of rtph264pay
  int gst_pt = gst_pt = peer_connection_get_rtpmap(g_surveillance.pc, CODEC_H264);
  if(pt != gst_pt) {
    pt = gst_pt;
    g_object_set(g_surveillance.rtp, "pt", pt, NULL);
  }
  gst_element_set_state(g_surveillance.pipeline, GST_STATE_PLAYING);
}

void on_call_event(SignalingEvent signaling_event, char *msg, void *data) {

  if(signaling_event == SIGNALING_EVENT_GET_OFFER) {

    printf("Get offer from singaling\n");
    g_mutex_lock(&g_surveillance.mutex);
    gst_element_set_state(g_surveillance.pipeline, GST_STATE_PAUSED);

    peer_connection_destroy(g_surveillance.pc);

    g_surveillance.pc = peer_connection_create(NULL);

    peer_connection_onicecandidate(g_surveillance.pc, on_icecandidate);
    peer_connection_oniceconnectionstatechange(g_surveillance.pc, on_iceconnectionstatechange);
    peer_connection_on_connected(g_surveillance.pc, on_connected);
    peer_connection_on_receiver_packet_loss(g_surveillance.pc, on_receiver_packet_loss);
    peer_connection_set_remote_description(g_surveillance.pc, msg);
    peer_connection_create_answer(g_surveillance.pc);

    g_cond_wait(&g_surveillance.cond, &g_surveillance.mutex);
    g_mutex_unlock(&g_surveillance.mutex);
  }
}

static GstFlowReturn new_sample(GstElement *sink, void *data) {

  static uint8_t rtp_packet[1400] = {0};
  int bytes;

  GstSample *sample;
  GstBuffer *buffer;
  GstMapInfo info;

  g_signal_emit_by_name(sink, "pull-sample", &sample);

  if(sample) {

    buffer = gst_sample_get_buffer(sample);
    gst_buffer_map(buffer, &info, GST_MAP_READ);

    memset(rtp_packet, 0, sizeof(rtp_packet));
    memcpy(rtp_packet, info.data, info.size);
    bytes = info.size;

    peer_connection_send_rtp_packet(g_surveillance.pc, rtp_packet, bytes);

    gst_buffer_unmap(buffer, &info);
    gst_sample_unref(sample);

    return GST_FLOW_OK;
  }
  return GST_FLOW_ERROR;
}

void signal_handler(int signal) {

  gst_element_set_state(g_surveillance.pipeline, GST_STATE_PAUSED);
  gst_object_unref(g_surveillance.sink);
  gst_object_unref(g_surveillance.pipeline);
 
  if(g_surveillance.signaling)
    signaling_destroy(g_surveillance.signaling);

  if(g_surveillance.pc)
    peer_connection_destroy(g_surveillance.pc);

  exit(0);
}

int main(int argc, char *argv[]) {

  gst_init(&argc, &argv);
  signal(SIGINT, signal_handler);

  SignalingOption signaling_option = {SIGNALING_PROTOCOL_HTTP, "0.0.0.0", "demo", 8000, index_html};

  g_surveillance.signaling = signaling_create(signaling_option);
  if(!g_surveillance.signaling) {
    printf("Create signaling service failed\n");
    return 0;
  }

  signaling_on_call_event(g_surveillance.signaling, &on_call_event, NULL);

  g_surveillance.pipeline = gst_parse_launch(PIPE_LINE, NULL);
  g_surveillance.sink = gst_bin_get_by_name(GST_BIN(g_surveillance.pipeline), "peer-connection-sink");
  g_surveillance.rtp = gst_bin_get_by_name(GST_BIN(g_surveillance.pipeline), "rtp");
  g_signal_connect(g_surveillance.sink, "new-sample", G_CALLBACK(new_sample), NULL);
  g_object_set(g_surveillance.sink, "emit-signals", TRUE, NULL);

  signaling_dispatch(g_surveillance.signaling);

  return 0;
}
