#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <set>
#include <sstream>
#include <fstream>
#include <regex>
#include <optional>

#include <gst/gst.h>

extern "C"
{
#include "utils.h"
#include "peer_connection.h"
}

#include <httplib.h>
#include <base64.h>
#include <json.hpp>

#include "SessionDescription.h"

#define MTU 1400

static GCond g_cond;
static GMutex g_mutex;

std::string answer;

//const char PIPE_LINE[] = "v4l2src ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! "
//const char PIPE_LINE[] = "videotestsrc pattern=ball ! videorate ! video/x-raw,width=640,height=480,framerate=30/1 ! videoconvert ! queue ! "


/*
const char PIPE_LINE[] = " ! videoconvert ! clockoverlay ! queue "
                         " ! x264enc bitrate=1000 speed-preset=ultrafast tune=zerolatency key-int-max=10 "
                         //" ! video/x-h264,profile=constrained-baseline "
                         " ! video/x-h264,packetization-mode=1,profile-level-id=42e01f,level-asymmetry-allowed=1"
//                         ",stream-format=byte-stream"
//                         ",byte-stream=true"
//                         ",alignment=nal "
                         //" ! video/x-h264,packetization-mode=1,profile-level-id=42c01e,level-asymmetry-allowed=1 "
                         //" ! queue ! rtph264parse ! queue "
                         " ! rtph264pay config-interval=-1 pt=102 seqnum-offset=0 timestamp-offset=0 mtu=1400"
                         //" ! application/x-rtp,packetization-mode=0,profile-level-id=42e01f,level-asymmetry-allowed=1 "
                         " ! appsink name=pear-sink";
*/


const char PIPE_LINE[] = " ! videoconvert ! video/x-raw, format=I420 ! clockoverlay ! queue "
                         " ! x264enc bitrate=1000 speed-preset=ultrafast tune=zerolatency key-int-max=10 "
                         " ! video/x-h264,packetization-mode=1,profile-level-id=42e01f,level-asymmetry-allowed=1"
                         " ! rtph264pay config-interval=-1 pt=102 seqnum-offset=0 timestamp-offset=0 mtu=1400"
                         " ! appsink name=pear-sink";

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

static void on_icecandidate(PeerConnection */*pc*/, char *sdp, void */*data*/)
{
    printf("%s\n", __PRETTY_FUNCTION__);

    g_mutex_lock(&g_mutex);
    answer = sdp;
    g_mutex_unlock(&g_mutex);
    g_cond_signal(&g_cond);
}

static void on_transport_ready(PeerConnection *pc, void */*data*/)
{
    printf("%s\n", __PRETTY_FUNCTION__);
    
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
            GstState a, b;
            gst_element_get_state(enc->gst_element, &a, &b, GST_CLOCK_TIME_NONE);
            GST_DEBUG_BIN_TO_DOT_FILE(GST_BIN(enc->gst_element), GST_DEBUG_GRAPH_SHOW_ALL, "graph.dot");
        }
    }
}

static GstFlowReturn new_sample(GstElement *sink, void *data);

void create_encoder(const std::string &camid, const std::string &pipeline)
{
    encoders[camid] = std::make_shared<encoder>();
    auto &e = encoders[camid];
    e->gst_element = gst_parse_launch(pipeline.c_str(), NULL);
    printf("pipeline is %s\n", pipeline.c_str());
    e->sink = gst_bin_get_by_name(GST_BIN(e->gst_element), "pear-sink");
    g_signal_connect(e->sink, "new-sample", G_CALLBACK(new_sample), NULL);
    g_object_set(e->sink, "emit-signals", TRUE, NULL);
}

RtpMap extract_rtpmap(const char *sdp_string)
{
    RtpMap rtp_map;
    
    std::shared_ptr<sdp::SessionDescription> sdp;
	try
    {
		sdp = sdp::SessionDescription::parse(sdp_string);
	}
    catch (const std::exception& e)
    { 
		std::cout << e.what();
        return session_description_parse_rtpmap_default(sdp_string);
	}
    
    uint64_t pt_pcma = 0;
    uint64_t pt_opus = 0;
    uint64_t pt_h264 = 0;
    
    for(auto &m : sdp->getMedias())
    {
        for (auto &f : m->getFormats())
        {
            int pt = std::atoi(f.c_str());
            auto rtpmap = m->getRTPMap(pt);
            std::string name = rtpmap->getName();
            
            if(name == "PCMA")
            {
                pt_pcma = pt;
            }
            else if(name == "opus")
            {
                pt_opus = pt;
            }
            else if(name == "H264")
            {
                pt_h264 = pt;
            }
            
            if(pt_h264 > 0 and pt_pcma > 0 and pt_opus > 0)
            {
                break;
            }
        }
    }
    
    rtp_map.pt_h264 = pt_h264;
    rtp_map.pt_pcma = pt_pcma;
    rtp_map.pt_opus = pt_opus;
    
    return rtp_map;
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
    g_peer_connection = peer_connection_create(nullptr);
    peer_connection_set_rtpmap_handler(g_peer_connection, extract_rtpmap);
    //peer_connection_enable_mdns(g_peer_connection, true);
    peer_connection_enable_mdns(g_peer_connection, false);
    
    peer_connection_onicecandidate(g_peer_connection, on_icecandidate);
    peer_connection_oniceconnectionstatechange(g_peer_connection, on_iceconnectionstatechange);
    peer_connection_on_connected(g_peer_connection, on_transport_ready);
    
    peer_connection_set_remote_description_a(g_peer_connection, (char *)offer.c_str());
    answer = "";
    peer_connection_create_answer(g_peer_connection);
    sleep(1);

    g_cond_wait(&g_cond, &g_mutex);
    peer_connection_set_remote_description_b(g_peer_connection, (char *)offer.c_str());
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
            // количество добавочных байт из документации не понятно, похоже что должно быть 10, берём с запасом 100
            const int additional_buf_space = 100;
            const int buf_size = MTU + additional_buf_space;
            uint8_t rtp_packet_per_peer[buf_size] = {0};
            size_t sz = std::min<size_t>(bytes, MTU);
            memcpy(rtp_packet_per_peer, rtp_packet, sz);
            uint32_t &fw = *(uint32_t*)rtp_packet_per_peer;
            auto pt = peer_connection_get_rtpmap(peer, CODEC_H264);
            fw = (fw & (~(127 << 8))) | (pt << 8);
            auto &pack_ssrc = ((uint32_t*)rtp_packet_per_peer)[2];
            pack_ssrc = htonl(peer_connection_get_ssrc(peer, "video"));
            peer_connection_send_rtp_packet(peer, rtp_packet_per_peer, sz);
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
    
    //nice_debug_enable(true);
    
    httplib::Server s;
    
    
    create_encoder("i-1", (std::string("videotestsrc ! videorate ! videoconvert ! video/x-raw,format=I420,width=640,height=480,framerate=30/1") + PIPE_LINE).c_str());
    create_encoder("i-2", (std::string("videotestsrc pattern=ball ! videorate ! video/x-raw,width=640,height=480,framerate=30/1") + PIPE_LINE).c_str());
    //create_encoder("i-3", (std::string("v4l2src") + PIPE_LINE).c_str());
    //create_encoder("i-4", (std::string("filesrc location=/home/dmitry/video/vizorlabs/nordgold_2.avi ! decodebin ") + PIPE_LINE).c_str());
    
    std::string index_path = "index.html";
    char *index_path_cstr = getenv("INDEX_PATH");
    if(index_path_cstr)
    {
        index_path = index_path_cstr;
    }
    
    
    s.Get("/", [=](const httplib::Request &/*req*/, httplib::Response &res)
    {
        std::ifstream t(index_path);
        std::stringstream buf;
        buf << t.rdbuf();
        std::string index_html = buf.str();
        res.set_content(index_html, "text/html");
    });
    
    s.Get("/(\\w+-\\d+)/?", [=](const httplib::Request &req, httplib::Response &res)
    {
        std::ifstream t(index_path);
        std::stringstream buf;
        buf << t.rdbuf();
        std::string index_html = buf.str();
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
    
    

    
    s.listen("0.0.0.0", 7000);
    
    //gst_element_set_state(gst_element, GST_STATE_NULL);
    //gst_object_unref(gst_element);
    
    return 0;
}
