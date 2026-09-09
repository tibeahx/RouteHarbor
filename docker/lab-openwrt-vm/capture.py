#!/usr/bin/env python3
"""Strict evidence checks for this lab's closed-policy packet captures.

This is not a production firewall rule or a general RST exception. Every packet
leaving toward the synthetic servers after confirmation must either be absent,
or be proven to be the router rejecting one recorded pre-policy TCP connection.
"""
import argparse
import hashlib
import ipaddress
import json
import pathlib
import struct

SERVERS = {'8.8.8.8', '2001:4860:4860::8888'}
ROUTER_MAC = '52:54:00:44:00:02'


def require(value, message):
    if not value:
        raise AssertionError(message)


def decode(raw):
    """Decode complete Ethernet/Linux cooked pcaps; reject ambiguous packets."""
    require(24 <= len(raw) <= 256 * 1024 * 1024, 'Capture size outside bounds')
    formats = {
        b'\xd4\xc3\xb2\xa1': ('<', 1_000_000),
        b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
        b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000),
        b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000),
    }
    require(raw[:4] in formats, 'Unsupported capture format')
    order, scale = formats[raw[:4]]
    major, minor = struct.unpack(order + 'HH', raw[4:8])
    require((major, minor) == (2, 4), 'Unsupported pcap version')
    link = struct.unpack(order + 'I', raw[20:24])[0]
    require(link in (1, 276), 'Expected Ethernet or Linux cooked v2 capture')
    position, result = 24, []
    while position < len(raw):
        require(position + 16 <= len(raw), 'Truncated pcap record')
        seconds, fraction, length, original = struct.unpack(order + 'IIII', raw[position:position+16])
        position += 16
        require(length == original and length <= 262144 and position + length <= len(raw), 'Truncated packet')
        frame = raw[position:position+length]
        position += length
        offset = 14 if link == 1 else 20
        require(len(frame) >= offset, 'Truncated link header')
        protocol = struct.unpack('!H', frame[12:14] if link == 1 else frame[:2])[0]
        mac = frame[6:12] if link == 1 else frame[12:18]
        packet = {'at': seconds + fraction / scale, 'source_mac': mac.hex(':')}
        data = frame[offset:]
        if protocol == 0x0800:
            require(len(data) >= 20 and data[0] >> 4 == 4, 'Malformed IPv4')
            header = (data[0] & 15) * 4
            total = struct.unpack('!H', data[2:4])[0]
            require(20 <= header <= total <= len(data), 'Truncated IPv4')
            require(struct.unpack('!H', data[6:8])[0] & 0x3fff == 0, 'Fragmented IPv4 is not classifiable')
            packet.update(src=str(ipaddress.ip_address(data[12:16])),
                          dst=str(ipaddress.ip_address(data[16:20])), ttl=data[8], protocol=data[9])
        elif protocol == 0x86dd:
            require(len(data) >= 40 and data[0] >> 4 == 6, 'Malformed IPv6')
            header, total = 40, 40 + struct.unpack('!H', data[4:6])[0]
            require(total <= len(data), 'Truncated IPv6')
            packet.update(src=str(ipaddress.ip_address(data[8:24])),
                          dst=str(ipaddress.ip_address(data[24:40])), ttl=data[7], protocol=data[6])
        else:
            raise AssertionError('Unexpected non-IP packet in filtered capture')
        transport = data[header:total]
        require(packet['protocol'] in (6, 17), 'Unsupported IP extension or transport')
        require(len(transport) >= 8, 'Truncated transport')
        packet['sport'], packet['dport'] = struct.unpack('!HH', transport[:4])
        if packet['protocol'] == 6:
            require(len(transport) >= 20, 'Truncated TCP')
            tcp_header = (transport[12] >> 4) * 4
            require(20 <= tcp_header <= len(transport), 'Invalid TCP header')
            packet.update(seq=struct.unpack('!I', transport[4:8])[0],
                          ack=struct.unpack('!I', transport[8:12])[0],
                          flags=((transport[12] & 15) << 8) | transport[13],
                          window=struct.unpack('!H', transport[14:16])[0], tcp_header=tcp_header)
            payload = transport[tcp_header:]
        else:
            require(struct.unpack('!H', transport[4:6])[0] == len(transport), 'Invalid UDP length')
            payload = transport[8:]
        packet.update(payload_length=len(payload), payload_sha256=hashlib.sha256(payload).hexdigest())
        result.append(packet)
        require(len(result) <= 1_000_000, 'Packet count outside bounds')
    return result


def signature(packet):
    return tuple(packet.get(key) for key in (
        'src', 'dst', 'protocol', 'sport', 'dport', 'seq', 'ack', 'flags',
        'window', 'tcp_header', 'payload_length', 'payload_sha256',
    ))


def zero_drops(log, count):
    import re
    captured = re.findall(r'(?m)^(\d+) packets? captured$', log)
    received = re.findall(r'(?m)^(\d+) packets? received by filter$', log)
    dropped = re.findall(r'(?m)^(\d+) packets dropped by kernel$', log)
    interface_dropped = re.findall(r'(?m)^(\d+) packets dropped by interface$', log)
    require(captured == [str(count)] and received == [str(count)] and dropped == ['0'] and
            interface_dropped in ([], ['0']), 'Capture incomplete or packets dropped')


def verify(wan, lan, protected, confirmed_at, connections, logs):
    require(isinstance(confirmed_at, (int, float)), 'Missing confirmation timestamp')
    require(len(connections) == 4, 'Expected four recorded persistent connections')
    zero_drops(logs['wan'], len(wan))
    zero_drops(logs['lan'], len(lan))
    zero_drops(logs['protected'], len(protected))
    require(lan and min(p['at'] for p in lan) < confirmed_at < max(p['at'] for p in lan),
            'LAN capture does not span protected interval')
    old_flows = {}
    for connection in connections:
        local, remote = connection['local'], connection['remote']
        require(remote[0] in SERVERS and remote[1] in (53, 18080), 'Foreign persistent connection')
        require((connection['family'] == 2 and local[0] == '10.44.0.20') or
                (connection['family'] == 10 and ipaddress.ip_address(local[0]) in ipaddress.ip_network('fd44:1::/64')),
                'Persistent socket is not the isolated LAN client')
        key = (remote[0], remote[1], local[1])
        require(key not in old_flows, 'Duplicate persistent socket')
        local_syns = [p for p in lan if p['at'] < confirmed_at and p['protocol'] == 6 and
                      p['src'] == local[0] and p['dst'] == remote[0] and p['sport'] == local[1] and
                      p['dport'] == remote[1] and p['flags'] == 2 and p['ttl'] == 64]
        forwarded_syns = [p for p in wan if p['at'] < confirmed_at and p['protocol'] == 6 and
                         p['dst'] == remote[0] and p['sport'] == local[1] and p['dport'] == remote[1] and
                         p['flags'] == 2 and p['ttl'] == 63 and p['source_mac'] == ROUTER_MAC and
                         any(p['seq'] == initial['seq'] for initial in local_syns)]
        require(local_syns and forwarded_syns, 'Missing calibrated initial client connection')
        old_flows[key] = local[0]
    # The BPF expression can also match a *source* port. Never silently discard
    # an observed outgoing packet just because its destination port is different.
    outgoing = [p for p in wan if p['at'] >= confirmed_at and p['dst'] in SERVERS]
    proofs, seen = [], set()
    for packet in outgoing:
        require(packet['protocol'] == 6 and packet['flags'] == 4 and packet['ack'] == 0 and
                packet['window'] == 0 and packet['tcp_header'] == 20 and packet['payload_length'] == 0 and
                packet['ttl'] == 64 and packet['source_mac'] == ROUTER_MAC,
                'Protected traffic escaped: packet is not a bare router reset')
        key = (packet['dst'], packet['dport'], packet['sport'])
        require(key in old_flows and key not in seen, 'Reset is not one recorded old connection')
        seen.add(key)
        local = old_flows[key]
        require(packet['src'] == ('198.18.0.2' if ':' not in local else local), 'Unexpected reset source')
        preceding = [p for p in wan if p['protocol'] == 6 and 0 < packet['at'] - p['at'] <= 1 and
                     p['src'] == packet['dst'] and p['dst'] == packet['src'] and
                     p['sport'] == packet['dport'] and p['dport'] == packet['sport'] and
                     p['flags'] == 24 and p['ack'] == packet['seq'] and p['payload_length'] > 0]
        require(preceding, 'Reset has no matching inbound ACK')
        trigger = preceding[-1]
        require(any(p['at'] < confirmed_at and signature(p) == signature(trigger) for p in wan),
                'Trigger is not a recorded old server retransmission')
        require(max(p['at'] for p in lan) >= packet['at'], 'LAN capture ended before reset')
        require(not any(p['protocol'] == 6 and
                        p['src'] == local and p['dst'] == packet['dst'] and p['sport'] == packet['sport'] and
                        p['dport'] == packet['dport'] and p['seq'] == packet['seq'] and p['flags'] == packet['flags']
                        for p in lan), 'A matching reset was transmitted by the LAN client')
        require(not any(abs(p['at'] - trigger['at']) <= 1 and p['protocol'] == 6 and p['src'] == trigger['src'] and
                        p['dst'] == local and p['sport'] == trigger['sport'] and p['dport'] == trigger['dport'] and
                        p['seq'] == trigger['seq'] and p['ack'] == trigger['ack'] and
                        p['payload_sha256'] == trigger['payload_sha256'] for p in lan),
                'Triggering server data reached the protected LAN')
        proofs.append({'family': 4 if ':' not in local else 6, 'client_port': packet['sport'],
                       'server_port': packet['dport'], 'reset_at': packet['at'],
                       'reset_sequence': packet['seq'], 'inbound_ack': trigger['ack'],
                       'response_delay_ms': round((packet['at'] - trigger['at']) * 1000, 3)})
    # The independent outgoing capture must contain only the same proven frames.
    # No flags are removed from either filter and no unmatched RST is ignored.
    for packet in protected:
        require(any(signature(packet) == signature(p) and abs(packet['at'] - p['at']) < 0.01
                    for p in outgoing), 'Outgoing capture contains an unproven packet')
    return {'protected_client_packets': 0, 'router_generated_resets': len(proofs),
            'total_outgoing_wan_packets': len(outgoing), 'capture_drops': 0, 'proofs': proofs}


def verify_files(directory, metadata):
    def read(name):
        require(pathlib.Path(name).name == name, 'Evidence paths must be local filenames')
        return (directory / name).read_bytes()
    return verify(*(decode(read(metadata[key])) for key in ('wan', 'lan', 'protected')),
                  metadata['confirmed_at'], metadata['connections'],
                  {key: read(metadata['logs'][key]).decode() for key in ('wan', 'lan', 'protected')})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('metadata', type=pathlib.Path)
    args = parser.parse_args()
    print(json.dumps(verify_files(args.metadata.parent, json.loads(args.metadata.read_text())), indent=2))
