#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <set>
#include <sstream>
#include <fstream>
#include <regex>

#include <gst/gst.h>

extern "C"
{
#include "utils.h"
#include "peer_connection.h"
}

#include <httplib.h>
#include <base64.h>
#include <json.hpp>

#define MTU 1400

static GCond g_cond;
static GMutex g_mutex;

std::string answer;

//const char PIPE_LINE[] = "v4l2src ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! "
//const char PIPE_LINE[] = "videotestsrc pattern=ball ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! "
const char PIPE_LINE[] = " ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! "
                        "x264enc bitrate=100 speed-preset=ultrafast tune=zerolatency key-int-max=10 ! video/x-h264,profile=constrained-baseline ! "
                        "queue ! h264parse ! queue ! rtph264pay config-interval=-1 pt=102 seqnum-offset=0 timestamp-offset=0 mtu=1400 ! appsink name=pear-sink";

        //"queue ! h264parse ! queue ! rtph264pay config-interval=-1 pt=102 seqnum-offset=0 timestamp-offset=0 mtu=1400 ! appsink name=pear-sink";

//const char PIPE_LINE[] = "videotestsrc pattern=ball ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! vp9enc ! queue ! rtpvp9pay mtu=1400 ! appsink name=pear-sink";

int sending = 0;


class encoder
{
public:
    encoder()
    {
        //
    }
    
    GstElement *gst_element = nullptr;
    GstElement *sink = nullptr;
    
    std::set<PeerConnection *> connections;
};

typedef std::shared_ptr<encoder> encoder_ptr;

std::map<std::string, encoder_ptr> encoders;

encoder_ptr get_enc_by_pc(PeerConnection *pc)
{
    for(auto &e : encoders)
    {
        if(e.second->connections.count(pc) > 0)
        {
            return e.second;
        }
    }
    return nullptr;
}

static void on_iceconnectionstatechange(PeerConnection *pc, IceConnectionState state, void */*data*/)
{
    printf("%s %d\n", __PRETTY_FUNCTION__, state);
    if(state == FAILED)
    {
        LOG_INFO("Disconnect with browser... Stop streaming");
        sending = 0;
        auto enc = get_enc_by_pc(pc);
        if(enc)
        {
            gst_element_set_state(enc->gst_element, GST_STATE_PAUSED);
        }
    }
}

static void on_icecandidate(PeerConnection *pc, char *sdp, void */*data*/)
{
    printf("%s\n", __PRETTY_FUNCTION__);

    answer = sdp;
    g_cond_signal(&g_cond);
}

static void on_transport_ready(PeerConnection *pc, void */*data*/)
{
    //printf("%s\n", __PRETTY_FUNCTION__);
    
    auto enc = get_enc_by_pc(pc);
    GstState state;
    GstState pending;
    gst_element_get_state(enc->gst_element, &state, &pending, 0);
    if(state != GST_STATE_PLAYING && pending != GST_STATE_PLAYING)
    {
        printf("%s\n", __PRETTY_FUNCTION__);
        auto enc = get_enc_by_pc(pc);
        if(enc)
        {
            gst_element_set_state(enc->gst_element, GST_STATE_PLAYING);
        }
    }
}

static GstFlowReturn new_sample(GstElement *sink, void *data);

void create_encoder(const std::string &camid, const std::string &pipeline)
{
    encoders[camid] = std::make_shared<encoder>();
    auto &e = encoders[camid];
    e->gst_element = gst_parse_launch(pipeline.c_str(), NULL);
    e->sink = gst_bin_get_by_name(GST_BIN(e->gst_element), "pear-sink");
    g_signal_connect(e->sink, "new-sample", G_CALLBACK(new_sample), NULL);
    g_object_set(e->sink, "emit-signals", TRUE, NULL);
}

void process_offer(const std::string &camid, const std::string &offer)
{
    printf("%s: \n%s\n", __PRETTY_FUNCTION__, offer.c_str());

    //gst_element_set_state(gst_element, GST_STATE_PAUSED);
    sending = 0;
    
    printf("%s get offer\n", __PRETTY_FUNCTION__);
    
    
    if(encoders.count(camid) == 0)
    {
        //create_encoder(camid);
        return;
    }    
    
    g_mutex_lock(&g_mutex);

    PeerConnection *g_peer_connection = nullptr;
    g_peer_connection = peer_connection_create();
    peer_connection_enable_mdns(g_peer_connection, true);
    
    MediaStream *media_stream = media_stream_new();
    media_stream_add_track(media_stream, CODEC_H264);
    
    peer_connection_add_stream(g_peer_connection, media_stream);
    
    peer_connection_onicecandidate(g_peer_connection, on_icecandidate, NULL);
    peer_connection_oniceconnectionstatechange(g_peer_connection, on_iceconnectionstatechange, NULL);
    peer_connection_set_on_transport_ready(g_peer_connection, on_transport_ready, NULL);
    
    peer_connection_create_answer(g_peer_connection);
    
    g_cond_wait(&g_cond, &g_mutex);
    peer_connection_set_remote_description(g_peer_connection, (char *)offer.c_str());
    g_mutex_unlock(&g_mutex);
    encoders[camid]->connections.insert(g_peer_connection);
    
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

    encoder_ptr enc;
    for(auto &e : encoders)
    {
        if(e.second->sink == sink)
        {
            enc = e.second;
            break;
        }
    }
    
    if(enc)
    {
        for(auto &peer : enc->connections)
        {
            static uint8_t rtp_packet_per_peer[MTU] = {0};
            memcpy(rtp_packet_per_peer, rtp_packet, MTU);
            peer_connection_send_rtp_packet(peer, rtp_packet_per_peer, bytes);
        }
    }

    gst_sample_unref(sample);
    gst_buffer_unmap(buffer,&info);
    return GST_FLOW_OK;
  }
  return GST_FLOW_ERROR;
}

int main(int argc, char **argv)
{
    gst_init(&argc, &argv);

    std::ifstream t("/home/dmitry/downloads/vcs/pear/examples/gstreamer/index.html");
    std::stringstream buf;
    buf << t.rdbuf();
    std::string index_html = buf.str();
    
    httplib::Server s;
    
    
    create_encoder("i-1", (std::string("videotestsrc") + PIPE_LINE).c_str());
    create_encoder("i-2", (std::string("videotestsrc pattern=ball") + PIPE_LINE).c_str());
    create_encoder("i-3", (std::string("v4l2src") + PIPE_LINE).c_str());
    
    
    s.Get("/", [&index_html](const httplib::Request &/*req*/, httplib::Response &res)
    {
        res.set_content(index_html, "text/html");
    });
    
    s.Get("/(\\w+-\\d+)/?", [&index_html](const httplib::Request &req, httplib::Response &res)
    {
        std::string html = std::regex_replace(index_html, std::regex("###camid###"), (std::string)req.matches[1]);
        res.set_content(html, "text/html");
    });
    
    
    s.Post("/call/(\\w+-\\d+)/?", [](const httplib::Request &req, httplib::Response &res)
    {
        std::string camid = req.matches[1];
        
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
        process_offer(camid, sdp);                              // тут блокируемся в ожидании answer
        nlohmann::json response = {{"type", "answer"}, {"sdp", answer}};
        std::string resp_str = response.dump();
        printf("%s\n", resp_str.c_str());
        auto response_encoded = httplib::detail::base64_encode(resp_str);
        res.set_content(response_encoded, "text/plain");
        printf("%s\n", response_encoded.c_str());
        res.status = 200;
    });
    
    

    
    s.listen("0.0.0.0", 8000);
    
    //gst_element_set_state(gst_element, GST_STATE_NULL);
    //gst_object_unref(gst_element);
    
    return 0;
}
