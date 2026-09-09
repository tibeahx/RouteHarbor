"""No Docker needed: rejected evidence must never become a blanket RST filter."""
import copy
import hashlib
import ipaddress
import pathlib
import struct
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import capture


def packet(at, src, dst, sport, dport, **changes):
    value = {'at': at, 'src': src, 'dst': dst, 'sport': sport, 'dport': dport,
             'source_mac': capture.ROUTER_MAC, 'ttl': 64, 'protocol': 6,
             'seq': 100, 'ack': 0, 'flags': 2, 'window': 100, 'tcp_header': 20,
             'payload_length': 0, 'payload_sha256': hashlib.sha256(b'').hexdigest()}
    value.update(changes)
    return value


def fixture():
    wan, lan, protected, connections = [], [], [], []
    for index, (version, port) in enumerate([(4, 53), (4, 18080), (6, 53), (6, 18080)]):
        local = '10.44.0.20' if version == 4 else 'fd44:1::20'
        outside = '198.18.0.2' if version == 4 else local
        server = '8.8.8.8' if version == 4 else '2001:4860:4860::8888'
        sport, moment = 40000 + index, index / 100
        connections.append({'local': [local, sport], 'remote': [server, port],
                            'family': 2 if version == 4 else 10})
        lan.append(packet(1 + moment, local, server, sport, port))
        wan.append(packet(1.001 + moment, outside, server, sport, port, ttl=63))
        old = packet(1.5 + moment, server, outside, port, sport, seq=200, ack=123,
                     flags=24, payload_length=23, payload_sha256=hashlib.sha256(b'old synthetic data').hexdigest())
        wan.append(old)
        trigger = copy.deepcopy(old)
        trigger['at'] = 3 + moment
        wan.append(trigger)
        reset = packet(3.001 + moment, outside, server, sport, port, flags=4, seq=123, window=0)
        wan.append(reset)
        protected.append(copy.deepcopy(reset))
    lan.append(packet(4, '10.44.0.20', '8.8.8.8', 55555, 18081, protocol=17))
    return wan, lan, protected, 2, connections


def logs(wan, lan, protected):
    return {key: f'{len(value)} packets captured\n{len(value)} packets received by filter\n0 packets dropped by kernel\n'
            for key, value in [('wan', wan), ('lan', lan), ('protected', protected)]}


class CaptureProofTest(unittest.TestCase):
    def verify(self, values):
        return capture.verify(*values, logs(*values[:3]))

    def test_all_four_control_responses_are_reported_not_hidden(self):
        result = self.verify(fixture())
        self.assertEqual(result['router_generated_resets'], 4)
        self.assertEqual(result['total_outgoing_wan_packets'], 4)
        self.assertEqual(result['protected_client_packets'], 0)
        self.assertEqual(len(result['proofs']), 4)

    def test_zero_outgoing_is_also_valid(self):
        values = list(fixture())
        values[0] = [p for p in values[0] if not p['flags'] & 4]
        values[2] = []
        self.assertEqual(self.verify(values)['router_generated_resets'], 0)

    def test_outgoing_safety_requirements(self):
        for changes in [{'ttl': 63}, {'flags': 2}, {'payload_length': 1}, {'seq': 999},
                        {'window': 1}, {'ack': 1}, {'tcp_header': 24}, {'protocol': 17},
                        {'source_mac': '00:00:00:00:00:01'}, {'sport': 45000}]:
            with self.subTest(changes=changes):
                values = list(fixture())
                values[0][3].update(changes)
                with self.assertRaises(AssertionError):
                    self.verify(values)

    def test_missing_inbound_match(self):
        values = list(fixture())
        del values[0][2]
        with self.assertRaisesRegex(AssertionError, 'matching inbound ACK'):
            self.verify(values)

    def test_inbound_packet_must_have_old_identical_retransmission(self):
        values = list(fixture())
        values[0][1]['payload_sha256'] = 'different'
        with self.assertRaisesRegex(AssertionError, 'old server retransmission'):
            self.verify(values)

    def test_lan_origin_reset_is_not_router_control(self):
        values = list(fixture())
        reset = copy.deepcopy(values[2][0])
        reset['src'] = '10.44.0.20'
        values[1].append(reset)
        with self.assertRaisesRegex(AssertionError, 'transmitted by the LAN client'):
            self.verify(values)

    def test_trigger_must_not_reach_lan(self):
        values = list(fixture())
        trigger = copy.deepcopy(values[0][2])
        trigger['dst'] = '10.44.0.20'
        values[1].append(trigger)
        with self.assertRaisesRegex(AssertionError, 'reached the protected LAN'):
            self.verify(values)

    def test_earlier_retransmission_copy_is_not_the_reset_trigger(self):
        values = list(fixture())
        earlier = copy.deepcopy(values[0][2])
        earlier.update(at=0.5, dst='10.44.0.20')
        values[1].append(earlier)
        self.assertEqual(self.verify(values)['router_generated_resets'], 4)

    def test_lan_capture_must_cover_reset_time(self):
        values = list(fixture())
        values[1][-1]['at'] = 2.5
        with self.assertRaisesRegex(AssertionError, 'ended before reset'):
            self.verify(values)

    def test_capture_drop_or_count_ambiguity_is_rejected(self):
        values = fixture()
        for key in ['wan', 'lan', 'protected']:
            for bad in ['1 packets dropped by kernel\n', '0 packets captured\n0 packets dropped by kernel\n', '']:
                with self.subTest(capture=key, log=bad):
                    counts = logs(*values[:3])
                    counts[key] = bad
                    with self.assertRaisesRegex(AssertionError, 'Capture incomplete'):
                        capture.verify(*values, counts)

    def test_received_but_unwritten_or_interface_drop_is_rejected(self):
        values = fixture()
        for change in ['1 packets dropped by interface\n', '1 packets received by filter\n']:
            counts = logs(*values[:3])
            counts['wan'] += change
            with self.assertRaisesRegex(AssertionError, 'Capture incomplete'):
                capture.verify(*values, counts)

    def test_no_unproven_packet_in_independent_capture(self):
        values = list(fixture())
        values[2][0]['seq'] += 1
        with self.assertRaisesRegex(AssertionError, 'unproven packet'):
            self.verify(values)

    def test_source_port_filter_match_is_not_silently_ignored(self):
        values = list(fixture())
        values[0].append(packet(2.01, '198.18.0.2', '8.8.8.8', 53, 444, protocol=17))
        with self.assertRaisesRegex(AssertionError, 'Protected traffic escaped'):
            self.verify(values)

    def test_each_old_connection_can_only_explain_one_reset(self):
        values = list(fixture())
        values[0].append(copy.deepcopy(values[2][0]))
        with self.assertRaisesRegex(AssertionError, 'one recorded old connection'):
            self.verify(values)

    def test_missing_calibrated_client_syn_is_rejected(self):
        values = list(fixture())
        values[1][0]['ttl'] = 65
        with self.assertRaisesRegex(AssertionError, 'calibrated initial'):
            self.verify(values)


class DecoderTest(unittest.TestCase):
    @staticmethod
    def binary(version=4, cooked=False):
        tcp = struct.pack('!HHIIBBHHH', 40000, 53, 123, 0, 0x50, 4, 0, 0, 0)
        if version == 4:
            data = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0x4000, 64, 6, 0,
                               ipaddress.ip_address('198.18.0.2').packed,
                               ipaddress.ip_address('8.8.8.8').packed) + tcp
            ethertype = 0x0800
        else:
            data = struct.pack('!IHBB16s16s', 6 << 28, 20, 6, 64,
                               ipaddress.ip_address('fd44:1::20').packed,
                               ipaddress.ip_address('2001:4860:4860::8888').packed) + tcp
            ethertype = 0x86dd
        mac = bytes.fromhex(capture.ROUTER_MAC.replace(':', ''))
        link = (struct.pack('!HHIHBB8s', ethertype, 0, 1, 1, 0, 6, mac + b'\0\0') if cooked else
                bytes(6) + mac + struct.pack('!H', ethertype))
        frame = link + data
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 276 if cooked else 1)
        return header + struct.pack('<IIII', 3, 1000, len(frame), len(frame)) + frame

    def test_actual_link_and_family_shapes(self):
        for version in [4, 6]:
            for cooked in [False, True]:
                with self.subTest(version=version, cooked=cooked):
                    result = capture.decode(self.binary(version, cooked))[0]
                    self.assertEqual(result['source_mac'], capture.ROUTER_MAC)
                    self.assertEqual(result['ttl'], 64)
                    self.assertEqual(result['flags'], 4)
                    self.assertEqual(result['seq'], 123)
                    self.assertEqual(result['payload_length'], 0)

    def test_truncated_or_fragmented_capture_fails(self):
        original = self.binary()
        for amount in [1, 10, 50]:
            with self.assertRaises(AssertionError):
                capture.decode(original[:-amount])
        fragmented = bytearray(original)
        fragmented[24 + 16 + 14 + 6] = 0x20
        with self.assertRaisesRegex(AssertionError, 'Fragmented'):
                capture.decode(bytes(fragmented))


if __name__ == '__main__':
    unittest.main()
