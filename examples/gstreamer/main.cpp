#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <gst/gst.h>

#include <sstream>
#include <fstream>

extern "C"
{
#include "utils.h"
#include "peer_connection.h"
}

#include <httplib.h>
#include <base64.h>
#include <json.hpp>

#define MTU 1400

GstElement *gst_element;
static GCond g_cond;
static GMutex g_mutex;
PeerConnection *g_peer_connection = NULL;

//const char PIPE_LINE[] = "v4l2src ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! "
const char PIPE_LINE[] = "videotestsrc pattern=ball ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! "
                        "x264enc bitrate=1000 speed-preset=ultrafast tune=zerolatency key-int-max=10 ! video/x-h264,profile=constrained-baseline ! "
                        "queue ! h264parse ! queue ! rtph264pay config-interval=-1 pt=102 seqnum-offset=0 timestamp-offset=0 mtu=1400 ! appsink name=pear-sink";

        //"queue ! h264parse ! queue ! rtph264pay config-interval=-1 pt=102 seqnum-offset=0 timestamp-offset=0 mtu=1400 ! appsink name=pear-sink";

//const char PIPE_LINE[] = "videotestsrc pattern=ball ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! vp9enc ! queue ! rtpvp9pay mtu=1400 ! appsink name=pear-sink";

int sending = 0;

static void on_iceconnectionstatechange(IceConnectionState state, void *data) {
    printf("%s %d\n", __PRETTY_FUNCTION__, state);
  if(state == FAILED) {
    LOG_INFO("Disconnect with browser... Stop streaming");
    sending = 0;
    gst_element_set_state(gst_element, GST_STATE_PAUSED);
  }
}

std::string answer;

static void on_icecandidate(PeerConnection *pc, char *sdp, void *data) {
    printf("%s\n", __PRETTY_FUNCTION__);

  answer = sdp;
  g_cond_signal(&g_cond);
}

static void on_transport_ready(void *data)
{
    //printf("%s\n", __PRETTY_FUNCTION__);
    if(!sending)
    {
        printf("%s\n", __PRETTY_FUNCTION__);
        sending = 1;
        gst_element_set_state(gst_element, GST_STATE_PLAYING);
    }
}

void process_offer(const std::string &offer)
{
    printf("%s\n", __PRETTY_FUNCTION__);

  gst_element_set_state(gst_element, GST_STATE_PAUSED);
  sending = 0;

  printf("%s get offer\n", __PRETTY_FUNCTION__);

  g_mutex_lock(&g_mutex);
  peer_connection_destroy(g_peer_connection);
  g_peer_connection = peer_connection_create();

  MediaStream *media_stream = media_stream_new();
  media_stream_add_track(media_stream, CODEC_H264);

  peer_connection_add_stream(g_peer_connection, media_stream);

  peer_connection_onicecandidate(g_peer_connection, (void *)&on_icecandidate, NULL);
  peer_connection_oniceconnectionstatechange(g_peer_connection, (void *)&on_iceconnectionstatechange, NULL);
  peer_connection_set_on_transport_ready(g_peer_connection, (void *)&on_transport_ready, NULL);
  peer_connection_create_answer(g_peer_connection);

  g_cond_wait(&g_cond, &g_mutex);
  peer_connection_set_remote_description(g_peer_connection, (char *)offer.c_str());
  g_mutex_unlock(&g_mutex);

  return;
}

static GstFlowReturn new_sample(GstElement *sink, void *data) {
  //printf("%s\n", __PRETTY_FUNCTION__);
  static uint8_t rtp_packet[MTU] = {0};
  int bytes;

  GstSample *sample;
  GstBuffer *buffer;
  GstMapInfo info;

  g_signal_emit_by_name (sink, "pull-sample", &sample);
  if(sample) {

    buffer = gst_sample_get_buffer(sample);
    gst_buffer_map(buffer, &info, GST_MAP_READ);

    memset(rtp_packet, 0, sizeof(rtp_packet));
    memcpy(rtp_packet, info.data, info.size);
    bytes = info.size;

    peer_connection_send_rtp_packet(g_peer_connection, rtp_packet, bytes);

    gst_sample_unref(sample);
    gst_buffer_unmap(buffer,&info);
    return GST_FLOW_OK;
  }
  return GST_FLOW_ERROR;
}

static void print_usage(const char *prog) {

  printf("Usage: %s \n"
   " -p      - port (default: 8080)\n"
   " -H      - address to bind (default: 0.0.0.0)\n"
   " -r      - document root\n"
   " -h      - print help\n", prog);

}

int main(int argc, char **argv)
{
    std::ifstream t("/home/dmitry/downloads/vcs/pear/examples/gstreamer/index.html");
    std::stringstream buf;
    buf << t.rdbuf();
    std::string index_html = buf.str();
    
    httplib::Server s;
    
    s.Get("/", [&index_html](const httplib::Request &/*req*/, httplib::Response &res)
    {
        res.set_content(index_html, "text/html");
    });
    
    s.Post("/call/demo", [](const httplib::Request &req, httplib::Response &res)
    {
        std::string body = req.body;
        if(body.empty())
        {
            res.status = 400;
            return;
        }
        std::string decoded = base64::decode(body);
        auto json = nlohmann::json::parse(decoded);
        std::string type = json["type"];
        std::string sdp = json["sdp"];
        process_offer(sdp);         // тут блокируемся в ожидании answer
        nlohmann::json response = {{"type", "answer"}, {"sdp", answer}};
        std::string resp_str = response.dump();
        printf("%s\n", resp_str.c_str());
        auto response_encoded = httplib::detail::base64_encode(resp_str);
        res.set_content(response_encoded, "text/plain");
        printf("%s\n", response_encoded.c_str());
        //char *enc = g_base64_encode((const guchar *)resp_str.c_str(), resp_str.length());
        //res.set_content(enc, strlen(enc), "text/plain");
        res.status = 200;
    });
    
    
  GstElement *pear_sink;

  gst_init(&argc, &argv);

  gst_element = gst_parse_launch(PIPE_LINE, NULL);
  pear_sink = gst_bin_get_by_name(GST_BIN(gst_element), "pear-sink");
  g_signal_connect(pear_sink, "new-sample", G_CALLBACK(new_sample), NULL);
  g_object_set(pear_sink, "emit-signals", TRUE, NULL);
 
  s.listen("0.0.0.0", 8000);

  gst_element_set_state(gst_element, GST_STATE_NULL);
  gst_object_unref(gst_element);

  return 0;
}
