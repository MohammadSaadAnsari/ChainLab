#!/usr/bin/env python3
"""Ryu OpenFlow 1.3 controller: h1 -> firewall -> IDS -> policer -> h2.

s1 ports: 1=h1, 2=s2, 3/4=firewall, 5/6=IDS, 7/8=policer.
s2 ports: 1=s1, 2=h2. VLANs 101/102/103 mark chain stages.
Set SFC_API_TOKEN before starting ryu-manager; WSGI runs on port 8080.
"""

from collections import defaultdict
import hmac
import json
import math
import os
from pathlib import Path

from ryu.app.wsgi import ControllerBase, Response, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, DEAD_DISPATCHER,
                                    MAIN_DISPATCHER, set_ev_cls)
from ryu.lib import hub
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

from sfc_policy import PolicyState


S1, S2 = 1, 2
H1_IP, H2_IP = "10.0.0.1", "10.0.0.2"
H1, UPLINK, FW_IN, FW_OUT, IDS_IN, IDS_OUT, POL_IN, POL_OUT = range(1, 9)
S2_UPLINK, H2 = 1, 2
VLAN_FW, VLAN_IDS, VLAN_POL = 101, 102, 103
FLOW_LIFETIME = 120

# Top 24 bits identify this app. The next two flags separate base rules,
# quarantine rules, and reactive 5-tuple rules for safe policy updates.
APP_COOKIE = 0x5346430000000000
APP_MASK = 0xFFFFFF0000000000
QUARANTINE_FLAG = 1 << 39
BASE_FLAG = 1 << 38
BASE_COOKIE = APP_COOKIE | BASE_FLAG
QUARANTINE_COOKIE = APP_COOKIE | QUARANTINE_FLAG
REACTIVE_MASK = APP_MASK | QUARANTINE_FLAG | BASE_FLAG


class SFCController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_token = os.environ.get("SFC_API_TOKEN", "")
        if not self.api_token:
            raise RuntimeError("Set SFC_API_TOKEN before starting Ryu")
        self.policy = PolicyState()
        self.datapaths = {}
        self.next_flow_id = 1
        self.flows = {}  # cookie base -> {five_tuple, action}
        self.counters = {}  # cookie base -> per-stage packet counters
        self.pending = {}  # (dpid, barrier xid) -> queued first packets
        self.pending_keys = {}  # five_tuple -> (dpid, barrier xid)
        kwargs["wsgi"].register(SFCApi, {"sfc_app": self})
        self.monitor = hub.spawn(self._monitor)

    @staticmethod
    def _add_flow(dp, priority, match, actions, *, cookie, timeout=0,
                  removed=False):
        p, ofp = dp.ofproto_parser, dp.ofproto
        instruction = p.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)
        dp.send_msg(p.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=[instruction], cookie=cookie, hard_timeout=timeout,
            flags=ofp.OFPFF_SEND_FLOW_REM if removed else 0))

    @staticmethod
    def _delete_flows(dp, cookie, mask):
        p, ofp = dp.ofproto_parser, dp.ofproto
        dp.send_msg(p.OFPFlowMod(datapath=dp, command=ofp.OFPFC_DELETE,
                                cookie=cookie, cookie_mask=mask,
                                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                match=p.OFPMatch()))

    def _flush_reactive(self):
        dp = self.datapaths.get(S1)
        if dp is not None:
            self._delete_flows(dp, APP_COOKIE, REACTIVE_MASK)
        self.flows.clear()
        self.counters.clear()
        self.pending.clear()
        self.pending_keys.clear()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        if dp.id not in (S1, S2):
            self.logger.warning("Unexpected switch DPID %s", dp.id)
            return
        p, ofp = dp.ofproto_parser, dp.ofproto
        self.datapaths[dp.id] = dp
        self._delete_flows(dp, APP_COOKIE, APP_MASK)
        self._add_flow(dp, 0, p.OFPMatch(),
                       [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)],
                       cookie=BASE_COOKIE)
        if dp.id == S1:
            self._flush_reactive()
            # ARP, ICMP, UDP and replies follow the direct physical path.
            for ingress, egress in ((H1, UPLINK), (UPLINK, H1)):
                self._add_flow(dp, 10, p.OFPMatch(in_port=ingress),
                               [p.OFPActionOutput(egress)], cookie=BASE_COOKIE)
            # A host cannot inject a tag and impersonate a VNF return port.
            self._add_flow(dp, 250,
                           p.OFPMatch(in_port=H1,
                                      vlan_vid=(ofp.OFPVID_PRESENT, ofp.OFPVID_PRESENT)),
                           [], cookie=BASE_COOKIE)
            # First packet of each h1 -> h2 TCP flow reaches the policy engine.
            self._add_flow(dp, 200,
                           p.OFPMatch(in_port=H1, eth_type=ether_types.ETH_TYPE_IP,
                                      vlan_vid=ofp.OFPVID_NONE, ipv4_src=H1_IP,
                                      ipv4_dst=H2_IP, ip_proto=6),
                           [p.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)],
                           cookie=BASE_COOKIE)
            for source, remaining in self.policy.snapshot()["quarantined"].items():
                self._install_quarantine(source, max(1, math.ceil(remaining)))
        else:
            for ingress, egress in ((S2_UPLINK, H2), (H2, S2_UPLINK)):
                self._add_flow(dp, 10, p.OFPMatch(in_port=ingress),
                               [p.OFPActionOutput(egress)], cookie=BASE_COOKIE)
        self.policy.record("switch", f"s{dp.id} connected")
        self.logger.info("Base rules installed on s%s", dp.id)

    @set_ev_cls(ofp_event.EventOFPStateChange,
               [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        if ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(ev.datapath.id, None)
            self.policy.record("switch", f"s{ev.datapath.id} disconnected")

    @staticmethod
    def _match(dp, five_tuple, ingress, vlan=None):
        src, dst, src_port, dst_port, protocol = five_tuple
        fields = dict(in_port=ingress, eth_type=ether_types.ETH_TYPE_IP,
                      ipv4_src=src, ipv4_dst=dst, ip_proto=protocol,
                      tcp_src=src_port, tcp_dst=dst_port)
        fields["vlan_vid"] = (dp.ofproto.OFPVID_NONE if vlan is None else
                              dp.ofproto.OFPVID_PRESENT | vlan)
        return dp.ofproto_parser.OFPMatch(**fields)

    def _install_decision(self, dp, five_tuple, action):
        p = dp.ofproto_parser
        base = APP_COOKIE | (self.next_flow_id << 4)
        self.next_flow_id += 1
        if action == "direct":
            first_actions = [p.OFPActionOutput(UPLINK)]
            self._add_flow(dp, 300, self._match(dp, five_tuple, H1),
                           first_actions, cookie=base | 5,
                           timeout=FLOW_LIFETIME, removed=True)
        else:
            # Reverse installation plus a barrier prevents a first-packet race.
            stages = (
                (POL_OUT, VLAN_POL,
                 [p.OFPActionPopVlan(), p.OFPActionOutput(UPLINK)], 4),
                (IDS_OUT, VLAN_IDS,
                 [p.OFPActionSetField(vlan_vid=dp.ofproto.OFPVID_PRESENT | VLAN_POL),
                  p.OFPActionOutput(POL_IN)], 3),
                (FW_OUT, VLAN_FW,
                 [p.OFPActionSetField(vlan_vid=dp.ofproto.OFPVID_PRESENT | VLAN_IDS),
                  p.OFPActionOutput(IDS_IN)], 2),
            )
            for ingress, vlan, actions, stage in stages:
                self._add_flow(dp, 300, self._match(dp, five_tuple, ingress, vlan),
                               actions, cookie=base | stage, timeout=FLOW_LIFETIME)
            first_actions = [p.OFPActionPushVlan(0x8100),
                             p.OFPActionSetField(vlan_vid=dp.ofproto.OFPVID_PRESENT | VLAN_FW),
                             p.OFPActionOutput(FW_IN)]
            self._add_flow(dp, 300, self._match(dp, five_tuple, H1),
                           first_actions, cookie=base | 1,
                           timeout=FLOW_LIFETIME, removed=True)
        self.flows[base] = {"five_tuple": five_tuple, "action": action}
        self.policy.record("flow", f"TCP/{five_tuple[3]} from {five_tuple[0]} -> {action}")
        self.logger.info("Flow %s classified %s", five_tuple, action)
        return first_actions

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg, dp = ev.msg, ev.msg.datapath
        if dp.id != S1 or msg.match.get("in_port") != H1:
            self.logger.warning("Unexpected PacketIn s%s port=%s",
                                dp.id, msg.match.get("in_port"))
            return
        pkt = packet.Packet(msg.data)
        eth, ip, seg = (pkt.get_protocol(ethernet.ethernet),
                        pkt.get_protocol(ipv4.ipv4), pkt.get_protocol(tcp.tcp))
        if (eth is None or eth.ethertype != ether_types.ETH_TYPE_IP or
                ip is None or seg is None or ip.proto != 6 or
                ip.src != H1_IP or ip.dst != H2_IP):
            self.logger.warning("Unexpected packet from h1; dropped")
            return
        five_tuple = (ip.src, ip.dst, seg.src_port, seg.dst_port, ip.proto)
        existing = self.pending_keys.get(five_tuple)
        if existing is not None:
            self.pending[existing]["packets"].append(msg.data)
            return
        action = self.policy.classify_tcp(ip.src, seg.dst_port)
        if action == "drop":
            return
        actions = self._install_decision(dp, five_tuple, action)
        barrier = dp.ofproto_parser.OFPBarrierRequest(dp)
        dp.send_msg(barrier)
        key = (dp.id, barrier.xid)
        self.pending[key] = {"five_tuple": five_tuple,
                             "packets": [msg.data], "actions": actions}
        self.pending_keys[five_tuple] = key

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, ev):
        msg = ev.msg
        pending = self.pending.pop((msg.datapath.id, msg.xid), None)
        if pending is None:
            return
        self.pending_keys.pop(pending["five_tuple"], None)
        dp = msg.datapath
        for data in pending["packets"]:
            dp.send_msg(dp.ofproto_parser.OFPPacketOut(
                datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
                in_port=H1, actions=pending["actions"], data=data))

    def _install_quarantine(self, source, seconds):
        dp = self.datapaths.get(S1)
        if dp is None:
            return
        self._add_flow(dp, 400,
                       dp.ofproto_parser.OFPMatch(
                           in_port=H1, eth_type=ether_types.ETH_TYPE_IP,
                           ipv4_src=source), [], cookie=QUARANTINE_COOKIE,
                       timeout=seconds, removed=True)

    def receive_alert(self, source, signature):
        if source != H1_IP:
            raise ValueError(f"Only demo source {H1_IP} can be quarantined")
        self.policy.quarantine(source, 60)
        self._install_quarantine(source, 60)
        detail = f"IDS detected {signature} from {source}; s1 quarantine installed"
        self.policy.record("quarantine", detail)
        self.logger.warning(detail)
        return self.status()

    def release(self):
        sources = self.policy.clear_quarantine()
        dp = self.datapaths.get(S1)
        if dp is not None:
            p, ofp = dp.ofproto_parser, dp.ofproto
            for source in sources:
                dp.send_msg(p.OFPFlowMod(
                    datapath=dp, command=ofp.OFPFC_DELETE_STRICT,
                    priority=400, cookie=QUARANTINE_COOKIE,
                    cookie_mask=APP_MASK | QUARANTINE_FLAG,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    match=p.OFPMatch(in_port=H1,
                                     eth_type=ether_types.ETH_TYPE_IP,
                                     ipv4_src=source)))
        self._flush_reactive()
        return self.status()

    def set_tcp_policy(self, port, action):
        self.policy.set_tcp_policy(port, action)
        self._flush_reactive()  # Active connections are reclassified.
        return self.status()

    def status(self):
        state = self.policy.snapshot()
        state.update({
            "switches": sorted(self.datapaths),
            "flows": [{"five_tuple": list(info["five_tuple"]),
                       "action": info["action"],
                       "packets": self.counters.get(base, {})}
                      for base, info in self.flows.items()],
            "chain": ["firewall", "IDS", "policer"],
            "vlans": [VLAN_FW, VLAN_IDS, VLAN_POL],
        })
        return state

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, ev):
        cookie = ev.msg.cookie
        if cookie & APP_MASK != APP_COOKIE:
            return
        if cookie == QUARANTINE_COOKIE:
            if ev.msg.reason == ev.msg.datapath.ofproto.OFPRR_HARD_TIMEOUT:
                self.policy.clear_quarantine(ev.msg.match.get("ipv4_src"))
            return
        if cookie & 0xF in (1, 5):
            base = cookie & ~0xF
            self.flows.pop(base, None)
            self.counters.pop(base, None)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
               [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, ev):
        self.logger.error("OpenFlow error s%s type=%s code=%s data=%r",
                          ev.msg.datapath.id, ev.msg.type, ev.msg.code, ev.msg.data)

    def _monitor(self):
        while True:
            hub.sleep(2)
            self.policy.expire()
            dp = self.datapaths.get(S1)
            if dp is not None:
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats(self, ev):
        if ev.msg.datapath.id != S1:
            return
        counts = defaultdict(dict)
        labels = {1: "ingress", 2: "after_firewall", 3: "after_ids",
                  4: "after_policer", 5: "direct"}
        for flow in ev.msg.body:
            cookie = flow.cookie
            if cookie & REACTIVE_MASK == APP_COOKIE and cookie & 0xF in labels:
                counts[cookie & ~0xF][labels[cookie & 0xF]] = flow.packet_count
        for base, current in counts.items():
            if current != self.counters.get(base):
                self.counters[base] = current
                if base in self.flows:
                    self.logger.info("Flow %s counters=%s",
                                     self.flows[base]["five_tuple"], current)


def json_response(data, status=200):
    return Response(status=status, content_type="application/json",
                    body=json.dumps(data))


class SFCApi(ControllerBase):
    """Read-only dashboard plus token-protected policy and alert endpoints."""

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data["sfc_app"]

    def _authorized(self, req):
        return hmac.compare_digest(req.headers.get("X-SFC-Token", ""),
                                   self.app.api_token)

    @staticmethod
    def _body(req):
        if len(req.body) > 4096:
            raise ValueError("request body is too large")
        try:
            body = json.loads(req.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("expected a JSON object") from exc
        if not isinstance(body, dict):
            raise ValueError("expected a JSON object")
        return body

    @route("sfc", "/sfc", methods=["GET"])
    def dashboard(self, req, **kwargs):
        html = (Path(__file__).resolve().parent / "dashboard.html").read_text()
        return Response(content_type="text/html", body=html)

    @route("sfc", "/sfc/status", methods=["GET"])
    def status(self, req, **kwargs):
        return json_response(self.app.status())

    @route("sfc", "/sfc/alerts", methods=["POST"])
    def alert(self, req, **kwargs):
        if not self._authorized(req):
            return json_response({"error": "invalid X-SFC-Token"}, 403)
        try:
            body = self._body(req)
            source, signature = body["src_ip"], body.get("signature", "unspecified")
            if not isinstance(source, str) or not isinstance(signature, str):
                raise ValueError("src_ip and signature must be strings")
            result = self.app.receive_alert(source, signature[:120])
        except (ValueError, KeyError) as exc:
            return json_response({"error": str(exc)}, 400)
        return json_response(result, 202)

    @route("sfc", "/sfc/policy", methods=["POST"])
    def policy(self, req, **kwargs):
        if not self._authorized(req):
            return json_response({"error": "invalid X-SFC-Token"}, 403)
        try:
            body = self._body(req)
            result = self.app.set_tcp_policy(body["dst_port"], body["action"])
        except (ValueError, KeyError) as exc:
            return json_response({"error": str(exc)}, 400)
        return json_response(result)

    @route("sfc", "/sfc/release", methods=["POST"])
    def release(self, req, **kwargs):
        if not self._authorized(req):
            return json_response({"error": "invalid X-SFC-Token"}, 403)
        return json_response(self.app.release())
