from __future__ import annotations
#!/usr/bin/env python3

""" sdn_mininet/ryu_collector.py
This is the Ryu SDN Controller with Flow Stats Collector, 
with Byzantine-Robust Model Poisoning Defense
This Ryu app:
1. Learns all MAC to Port mappings. Hosts in Mininet should ping each other.
2. Collects OpenFlow flow stats from all switches and saves them as CSV files
for my anomaly detection tool.
3. Provides REST endpoints so FL clients can upload local model metrics and 
then sanitizes aggregation to thwart model poisoning attacks.

The collected data is written to:
data/live_client1.csv
data/live_client2.csv
data/live_client3.csv

REST API (runs on port 8080):
POST /fl/upload -> client pushes local model metric
GET /fl/aggregate -> trigger sanitized aggregation
GET /fl/status -> query current global model state
GET /fl/reset -> clear upload queue for next FL round
Usage:
ryu-manager sdn_mininet/ryu_collector.py --observe-links
"""

import csv
import json
import os
import sys
import time
from collections import defaultdict
from typing import Dict, Optional

# Add project root to path so src/ is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, ipv6, packet, tcp, udp, icmp
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

# Tool 2: import sanitizer
from src.sanitizer import aggregate_with_sanitizer, SanitizationReport
from src.features import load_flows  # available for live scoring

# Configuration
POLL_INTERVAL = 5  # How often to poll switches for flow stats (seconds)
OUTPUT_DIR = "data"  # Where to save the live CSV files
MAX_ROWS = 5000  # Future: rotate files after this many rows

# Map switch DPID to client name (easy to extend for bigger topologies) -------- update and check for now, use 3 switches only ---------
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

# Tool 2: REST API configuration
REST_APP_NAME = "fl_sanitizer_api"
Z_THRESHOLD = float(os.environ.get("Z_THRESHOLD", "1.5"))
SANITIZER_LOG_PATH = os.environ.get("SANITIZER_LOG_PATH", "results/ryu_sanitizer.log")

# Tool 2: in memory upload queue (cleared each FL round)
_upload_queue: Dict[str, float] = {}
_last_global_model: Optional[float] = None
_last_report: Optional[SanitizationReport] = None


# Main Ryu Application
class SDNSanitizerController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Tool 1: switch learning and monitoring state
        self.mac_to_port = {}  # MAC address learning table per switch
        self.datapaths = {}  # Connected switches
        self._writers = {}  # CSV writers
        self._files = {}  # File handles
        self._row_counts = defaultdict(int)

        # Tool 2: register REST API
        wsgi = kwargs["wsgi"]
        wsgi.register(FLSanitizerAPI, {REST_APP_NAME: self})

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        os.makedirs("results", exist_ok=True)

        # Start background thread for polling flow stats
        self.monitor_thread = hub.spawn(self._monitor_loop)

        self.logger.info("[Ryu] SDN Sanitizer Controller started!")
        self.logger.info(f"      Polling every {POLL_INTERVAL} seconds -> {OUTPUT_DIR}/")
        self.logger.info(f"[Ryu] Zero-trust FL aggregation active — Z threshold: {Z_THRESHOLD}")


	
    # Called when a switch connects to the controller
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.logger.info(f"[Ryu] Switch {datapath.id} connected — table-miss flow installed")

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

	
    # Helper Functions that installs a flow entry on the switch.
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

	
    # Convert OpenFlow flow stat into a CSV row
    # Extract counters from an OFPFlowStats entry
    # Uses MAC addresses since L2 flows don't have IP match fields -----------------------
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
            "src_ip":    src_mac,   # MAC used in place of IP for L2 flows -------------------
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

	
    # Tool 2: sanitizer trigger called by REST API
    def run_sanitized_aggregation(self, z_threshold: float = Z_THRESHOLD):
        # Consume the current upload queue, apply the Z-score sanitizer,
        # and update the global model.
        global _last_global_model, _last_report

        if not _upload_queue:
            self.logger.warning("[Sanitizer] Aggregation triggered with empty queue")
            return None, None

        self.logger.info(
            "[Sanitizer] Aggregating %d hosts: %s",
            len(_upload_queue), list(_upload_queue.keys()),
        )

        global_model, report = aggregate_with_sanitizer(
            dict(_upload_queue), z_threshold=z_threshold
        )

        _last_global_model = global_model
        _last_report = report

        # Write to sanitizer alert log
        with open(SANITIZER_LOG_PATH, "a") as logf:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            for line in report.summary_lines():
                logf.write(f"[{ts}] {line}\n")
            if report.poisoning_detected:
                logf.write(
                    f"[{ts}] ALERT: Rejected hosts -> {report.rejected_hosts}\n"
                )
            logf.write("\n")

        return global_model, report


# Tool 2: REST API Handler
# REST API for FL clients to upload local model metrics and start
# sanitized aggregation.
"""
REST API controller for handling Federated Learning client uploads.
This provides an endpoint for FL clients to submit their local model metrics, 
e.g., accuracy, loss, etc., which are then queued for sanitized aggregation.
"""
class FLSanitizerAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
		# Reference the main sanitizer controller that manages aggregation
        self.controller: SDNSanitizerController = data[REST_APP_NAME]

    @route("fl", "/fl/upload", methods=["POST"])
    def upload_metric(self, req, **kwargs):
		# Client pushes its local model metric.
        # Body: {"host_id": "h1", "metric": 0.12}
        try:
            # Parse JSON request body
			body = json.loads(req.body)
			# Extract and validate fields
            host_id = str(body["host_id"])  # ensure host_id is string
            metric = float(body["metric"])  # ensure metric is float
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
			# return error message for malformed requests
            return Response(
                status=400,
                content_type="application/json",
				charset="utf-8",
                body=json.dumps({"error": str(exc)}),
            )
		# store the metric in the upload queue that is shared with aggregator
        _upload_queue[host_id] = metric
		# return success response
        return Response(
            content_type="application/json",
			charset="utf-8",
            body=json.dumps({
                "status": "queued",
                "host_id": host_id,
                "queue_size": len(_upload_queue)
            }),
        )

	# Trigger sanitized aggregation over all queued uploads
    @route("fl", "/fl/aggregate", methods=["GET"])
    def trigger_aggregation(self, req, **kwargs):
        global_model, report = self.controller.run_sanitized_aggregation()
        if report is None:
            return Response(
                status=400,
                content_type="application/json",
				charset="utf-8",
                body=json.dumps({"error": "Upload queue is empty"}),
            )
        result = {
            "global_model": global_model,
            "accepted": report.accepted_hosts,
            "rejected": report.rejected_hosts,
            "poisoning_detected": report.poisoning_detected,
            "n_submitted": report.n_submitted,
        }
        return Response(
            content_type="application/json",
			charset="utf-8",
            body=json.dumps(result),
        )
	
	# Return current queue and last known global model
    @route("fl", "/fl/status", methods=["GET"])
    def get_status(self, req, **kwargs):    
        return Response(
            content_type="application/json",
			charset="utf-8",
            body=json.dumps({
                "queued_hosts": list(_upload_queue.keys()),
                "queue_size": len(_upload_queue),
                "last_global_model": _last_global_model,
                "poisoning_detected_last_round": (
                    _last_report.poisoning_detected if _last_report else None
                ),
            }),
        )

	# Clear the upload queue to start a new FL round
    @route("fl", "/fl/reset", methods=["GET"])
    def reset_queue(self, req, **kwargs):
        _upload_queue.clear()
        return Response(
            content_type="application/json",
			charset="utf-8",
            body=json.dumps({"status": "queue cleared"}),
        )
