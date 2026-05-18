from __future__ import annotations

#!/usr/bin/env python3
"""
mininet/ryu_collector.py: Ryu SDN Controller + Flow Stats Collector

This Ryu app does two main jobs:
1. Acts as a basic learning L2 switch (so hosts in Mininet can ping each other)
2. Periodically collects OpenFlow flow statistics from all switches and saves 
   them as CSV files for our anomaly detection tool.

The collected data is written to:
data/live_client1.csv
data/live_client2.csv

Usage (run from project root):
ryu-manager mininet/ryu_collector.py --observe-links
"""

import csv
import os
import time
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, ipv6, packet, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3



# Configuration
POLL_INTERVAL = 5  # How often to poll switches for flow stats (seconds)
OUTPUT_DIR = "data"  # Where to save the live CSV files
MAX_ROWS = 5000  # Future: rotate files after this many rows

# Map switch DPID to client name (easy to extend for bigger topologies)
DPID_TO_CLIENT = {
    1: "live_client1",
    2: "live_client2",
    3: "live_client3",
}

# Columns in our output CSV files
CSV_FIELDNAMES = [
    "timestamp", "dpid",
    "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "bytes", "packets", "duration", "flags", "label"
]



# main Ryu Application
class SDNFlowCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        self.mac_to_port = {}  # MAC address learning table per switch
        self.datapaths = {}  # Connected switches
        self._writers = {}  # CSV writers
        self._files = {}  # File handles
        self._row_counts = defaultdict(int)
        
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        # Start background thread for polling flow stats
        self.monitor_thread = hub.spawn(self._monitor_loop)
        
        self.logger.info("[Collector] SDN Flow Collector started!")
        self.logger.info(f"           Polling every {POLL_INTERVAL} seconds -> {OUTPUT_DIR}/")

    
    # Called when a switch connects to the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.datapaths[datapath.id] = datapath
        self.logger.info(f"[Collector] Switch connected -> dpid={datapath.id}")
        
        # Install table-miss flow: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)


    
    # Packet-In Handler (Learning Switch)
    # Handle packet-in messages and learn MAC addresses
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return

        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src
        dpid = datapath.id

        # Learn the source MAC
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        # Decide output port
        out_port = self.mac_to_port[dpid].get(dst_mac) or ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install forwarding rule if we know the destination
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_dst=dst_mac,
                                    eth_src=src_mac)
            self._add_flow(datapath, priority=1, match=match, actions=actions)

        # Send the packet out
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

 
    # Process flow statistics received from switches.
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        
        client = DPID_TO_CLIENT.get(dpid, f"live_client{dpid}")
        writer = self._get_writer(client)
        
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        rows_written = 0
        
        for stat in body:
            row = self._stat_to_row(stat, dpid, ts)
            if row:
                writer.writerow(row)
                rows_written += 1
                self._row_counts[client] += 1
        
        if rows_written:
            self._files[client].flush()
            self.logger.info(f"[Collector] dpid={dpid} ({client}): "
                           f"+{rows_written} flows (total={self._row_counts[client]})")


    
    # Background Monitoring
    # Background thread: poll switches for flow stats periodically
    def _monitor_loop(self):

        while True:
            hub.sleep(POLL_INTERVAL)
            for datapath in list(self.datapaths.values()):
                self._request_flow_stats(datapath)

    # Send a flow stats request to a switch
    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        req = parser.OFPFlowStatsRequest(
            datapath,
            flags=0,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=0,
            cookie_mask=0,
        )
        datapath.send_msg(req)


    # Helper Functions
    # Install a flow entry on the switch.
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=30, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    #Convert OpenFlow flow stat into a CSV row
    # Extract counters from an OFPFlowStats entry
    # Uses MAC addresses since L2 flows don't have IP match fields
    # Skips table-miss entries (priority=0, no src/dst)
    def _stat_to_row(self, stat, dpid, ts) -> dict:
    	match = stat.match

    	src_mac = match.get("eth_src", "")
    	dst_mac = match.get("eth_dst", "")

    	# Skip table-miss entries
    	if not src_mac or not dst_mac:
            return None

    	duration = stat.duration_sec + stat.duration_nsec / 1e9

    	return {
            "timestamp": ts,
            "dpid":      dpid,
            "src_ip":    src_mac,   # MAC used in place of IP for L2 flows
            "dst_ip":    dst_mac,
            "src_port":  match.get("in_port", 0),
            "dst_port":  0,
            "protocol":  "ethernet",
            "bytes":     stat.byte_count,
            "packets":   stat.packet_count,
            "duration":  round(duration, 6),
            "flags":     "",
            "label":     0,
        }

    # Get or create a CSV writer for a specific client
    def _get_writer(self, client: str):
        if client not in self._writers:
            path = os.path.join(OUTPUT_DIR, f"{client}.csv")
            file_exists = os.path.isfile(path)
            
            f = open(path, "a", newline="")
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
            
            if not file_exists:
                writer.writeheader()
            
            self._writers[client] = writer
            self._files[client] = f
            self.logger.info(f"[Collector] Opened/created CSV: {path}")
        
        return self._writers[client]
