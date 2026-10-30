"""Serialize the real Ryu FlowMods used for the direct and chained paths.

This test skips on hosts without Ryu; run it inside the controller image with
``docker run --rm -v "$PWD:/project:ro" -e PYTHONPATH=/project
sfc-controller:latest python3 -m unittest discover -s /project/tests -v``.
"""

import logging
import unittest

try:
    import eventlet.wsgi

    if not hasattr(eventlet.wsgi, "ALREADY_HANDLED"):
        eventlet.wsgi.ALREADY_HANDLED = object()
    from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
    from sfc_controller import SFCController
except ImportError:
    SFCController = None

from sfc_policy import PolicyState


class FakeDatapath:
    ofproto = None
    ofproto_parser = None

    def __init__(self):
        self.ofproto = ofproto_v1_3
        self.ofproto_parser = ofproto_v1_3_parser
        self.messages = []

    def send_msg(self, message):
        message.serialize()  # Real Ryu parser checks match/action encoding.
        self.messages.append(message)


@unittest.skipUnless(SFCController is not None, "Ryu is installed in controller image")
class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.dp = FakeDatapath()
        self.controller = object.__new__(SFCController)
        self.controller.next_flow_id = 1
        self.controller.flows = {}
        self.controller.policy = PolicyState()
        self.controller.logger = logging.getLogger("pipeline-test")
        self.five_tuple = ("10.0.0.1", "10.0.0.2", 53000, 80, 6)

    def test_chain_rules_serialize_in_stage_order(self):
        self.controller._install_decision(self.dp, self.five_tuple, "chain")
        self.assertEqual(len(self.dp.messages), 4)
        self.assertEqual([m.match.get("in_port") for m in self.dp.messages],
                         [8, 6, 4, 1])
        self.assertEqual([m.cookie & 0xF for m in self.dp.messages],
                         [4, 3, 2, 1])
        actions = self.dp.messages[-1].instructions[0].actions
        self.assertEqual(actions[0].__class__.__name__, "OFPActionPushVlan")
        self.assertEqual(actions[-1].port, 3)

    def test_trusted_rule_serializes_as_direct_output(self):
        self.controller._install_decision(self.dp, self.five_tuple, "direct")
        self.assertEqual(len(self.dp.messages), 1)
        actions = self.dp.messages[0].instructions[0].actions
        self.assertEqual(actions[0].port, 2)


if __name__ == "__main__":
    unittest.main()
