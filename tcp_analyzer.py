import struct
import socket
import sys

PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1


def _parse_ethernet(packet_data):
    """Returns EtherType. Raises ValueError for non-IPv4 frames."""
    eth_type = struct.unpack('!H', packet_data[12:14])[0]
    if eth_type != 0x0800:
        raise ValueError(f"Non-IPv4 EtherType: {eth_type:#06x}")
    return eth_type


def _parse_ipv4(packet_data, offset):
    """Returns (src_ip, dst_ip, ihl, total_ip_len). Raises ValueError for non-TCP packets."""
    version_ihl = packet_data[offset]
    ihl = (version_ihl & 0x0F) * 4
    total_ip_len = struct.unpack('!H', packet_data[offset+2:offset+4])[0]
    protocol = packet_data[offset+9]
    if protocol != 6:
        raise ValueError(f"Non-TCP protocol: {protocol}")
    src_ip = socket.inet_ntoa(packet_data[offset+12:offset+16])
    dst_ip = socket.inet_ntoa(packet_data[offset+16:offset+20])
    return src_ip, dst_ip, ihl, total_ip_len


def _parse_tcp(packet_data, offset):
    """Returns (src_port, dst_port, seq_num, ack_num, tcp_header_len, flags, window_size)."""
    src_port = struct.unpack('!H', packet_data[offset:offset+2])[0]
    dst_port = struct.unpack('!H', packet_data[offset+2:offset+4])[0]
    seq_num  = struct.unpack('!I', packet_data[offset+4:offset+8])[0]
    ack_num  = struct.unpack('!I', packet_data[offset+8:offset+12])[0]
    tcp_header_len = ((packet_data[offset+12] >> 4) & 0x0F) * 4
    raw_flags = packet_data[offset+13]
    flags = {
        'fin': (raw_flags & 0x01) != 0,
        'syn': (raw_flags & 0x02) != 0,
        'rst': (raw_flags & 0x04) != 0,
        'ack': (raw_flags & 0x10) != 0,
    }
    window_size = struct.unpack('!H', packet_data[offset+14:offset+16])[0]
    return src_port, dst_port, seq_num, ack_num, tcp_header_len, flags, window_size


def analyze_tcp_traffic(pcap_filepath):
    connections = {}

    with open(pcap_filepath, 'rb') as f:
        # Read and validate 24-byte PCAP Global Header
        global_header = f.read(24)
        if len(global_header) < 24:
            print("Invalid PCAP file.")
            return

        # Detect byte order from magic number
        magic = struct.unpack('<I', global_header[:4])[0]
        if magic == PCAP_MAGIC_LE:
            endian = '<'
        elif magic == PCAP_MAGIC_BE:
            endian = '>'
        else:
            print(f"Unrecognized PCAP magic: {magic:#010x}")
            return

        while True:
            # Read 16-byte PCAP Packet Header
            pcap_header = f.read(16)
            if len(pcap_header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', pcap_header)
            timestamp = ts_sec + (ts_usec / 1_000_000.0)

            packet_data = f.read(incl_len)

            # Layer 2 → 3 → 4 parsing
            try:
                _parse_ethernet(packet_data)
                src_ip, dst_ip, ihl, total_ip_len = _parse_ipv4(packet_data, ip_offset := 14)
                src_port, dst_port, seq_num, ack_num, tcp_header_len, flags, window_size = _parse_tcp(
                    packet_data, ip_offset + ihl
                )
            except (ValueError, struct.error):
                continue

            fin, syn, rst, ack = flags['fin'], flags['syn'], flags['rst'], flags['ack']
            tcp_payload_len = total_ip_len - ihl - tcp_header_len

            # 4-tuple connection demultiplexing
            endpoint1 = f"{src_ip}:{src_port}"
            endpoint2 = f"{dst_ip}:{dst_port}"
            connection_id = tuple(sorted([endpoint1, endpoint2]))

            if connection_id not in connections:
                connections[connection_id] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'state_syn': 0,
                    'state_fin': 0,
                    'is_reset': False,
                    'start_time': timestamp,
                    'end_time': timestamp,
                    'total_packets': 0,
                    'total_data_bytes': 0,
                    'pkts_src_to_dst': 0,
                    'pkts_dst_to_src': 0,
                    'bytes_src_to_dst': 0,
                    'bytes_dst_to_src': 0,
                    'window_sizes': [],
                    'rtt_values': [],
                    'unacked_packets_A_to_B': {},
                    'first_packet_flag': 'SYN' if syn else 'OTHER',
                    'data_after_fin': False,
                }

            conn = connections[connection_id]

            if conn['state_fin'] > 0 and tcp_payload_len > 0:
                conn['data_after_fin'] = True

            conn['total_packets'] += 1
            conn['end_time'] = timestamp
            conn['total_data_bytes'] += tcp_payload_len
            conn['window_sizes'].append(window_size)

            if syn: conn['state_syn'] += 1
            if fin: conn['state_fin'] += 1
            if rst: conn['is_reset'] = True

            if src_ip == conn['src_ip']:
                conn['pkts_src_to_dst'] += 1
                conn['bytes_src_to_dst'] += tcp_payload_len
            else:
                conn['pkts_dst_to_src'] += 1
                conn['bytes_dst_to_src'] += tcp_payload_len

            # RTT estimation: track unacked segments from initiator, match on ACK
            payload_len_for_ack = max(1, tcp_payload_len) if (syn or fin) else tcp_payload_len
            expected_ack = seq_num + payload_len_for_ack

            if src_ip == conn['src_ip']:
                if tcp_payload_len > 0 or syn or fin:
                    conn['unacked_packets_A_to_B'][expected_ack] = timestamp
            elif dst_ip == conn['src_ip']:
                if ack and ack_num in conn['unacked_packets_A_to_B']:
                    rtt = timestamp - conn['unacked_packets_A_to_B'].pop(ack_num)
                    conn['rtt_values'].append(rtt)

    return connections


def gen_formatted_output(connections):
    complete_conns = 0
    reset_conns = 0
    open_conns = 0
    established_before_capture = 0

    all_durations = []
    all_packet_counts = []
    all_window_sizes = []
    all_rtt_values = []

    print("\n")
    print(f"A) Total number of connections: {len(connections)}")
    print("____________________________________________________________________________________________ ")
    print("\n")
    print("B) Connections' details:")
    print("\n")

    conn_number = 1
    for conn_id, data in connections.items():
        if data['is_reset']:
            status = "R"
            reset_conns += 1
        else:
            status = f"S{data['state_syn']}F{data['state_fin']}"

        is_complete = data['state_syn'] >= 1 and data['state_fin'] >= 1
        if is_complete:
            complete_conns += 1
            duration = data['end_time'] - data['start_time']
            all_durations.append(duration)
            all_packet_counts.append(data['total_packets'])
            all_window_sizes.extend(data['window_sizes'])
            if data['rtt_values']:
                all_rtt_values.extend(data['rtt_values'])

        if data['first_packet_flag'] != 'SYN':
            established_before_capture += 1

        if data['state_fin'] == 0 or data['data_after_fin']:
            open_conns += 1

        print(f"Connection {conn_number}:")
        print(f"Source Address: {data['src_ip']}")
        print(f"Destination address: {data['dst_ip']}")
        print(f"Source Port: {data['src_port']}")
        print(f"Destination Port: {data['dst_port']}")
        print(f"Status: {status}")

        if is_complete:
            print(f"Duration: {duration:.6f}")
            print(f"Start time: {data['start_time']:.6f}")
            print(f"End Time: {data['end_time']:.6f}")
            print(f"Number of packets sent from Source to Destination: {data['pkts_src_to_dst']}")
            print(f"Number of packets sent from Destination to Source: {data['pkts_dst_to_src']}")
            print(f"Total number of packets: {data['total_packets']}")
            print(f"Number of data bytes sent from Source to Destination: {data['bytes_src_to_dst']}")
            print(f"Number of data bytes sent from Destination to Source: {data['bytes_dst_to_src']}")
            print(f"Total number of data bytes: {data['total_data_bytes']}")

        print("END")
        print("+++++++++++++++++++++++++++++++++")
        print(".")
        print(".")
        print(".")
        print("+++++++++++++++++++++++++++++++++")

        conn_number += 1

    print("____________________________________________________________________________________________ ")
    print("\n")
    print("C) General")
    print("\n")
    print(f"The total number of complete TCP connections: {complete_conns}")
    print(f"The number of reset TCP connections: {reset_conns}")
    print(f"The number of TCP connections that were still open when the trace capture ended: {open_conns}")
    print(f"The number of TCP connections established before the capture started: {established_before_capture}")

    print("____________________________________________________________________________________________ ")
    print("\n")
    print("D) Complete TCP connections:")
    print("\n")
    if complete_conns > 0:
        print(f"Minimum time duration: {min(all_durations):.6f} seconds")
        print(f"Mean time duration: {sum(all_durations)/len(all_durations):.6f} seconds")
        print(f"Maximum time duration: {max(all_durations):.6f} seconds")
        print("\n")

        if all_rtt_values:
            print(f"Minimum RTT value: {min(all_rtt_values):.6f}")
            print(f"Mean RTT value: {sum(all_rtt_values)/len(all_rtt_values):.6f}")
            print(f"Maximum RTT value: {max(all_rtt_values):.6f}")
        else:
            print("Minimum RTT value: 0.000000")
            print("Mean RTT value: 0.000000")
            print("Maximum RTT value: 0.000000")

        print("\n")
        print(f"Minimum number of packets including both send/received: {min(all_packet_counts)}")
        print(f"Mean number of packets including both send/received: {sum(all_packet_counts)/len(all_packet_counts):.6f}")
        print(f"Maximum number of packets including both send/received: {max(all_packet_counts)}")

        print("\n")
        if all_window_sizes:
            print(f"Minimum receive window size including both send/received: {min(all_window_sizes)}")
            print(f"Mean receive window size including both send/received: {sum(all_window_sizes)/len(all_window_sizes):.6f}")
            print(f"Maximum receive window size including both send/received: {max(all_window_sizes)}")

        print("____________________________________________________________________________________________ ")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 tcp_analyzer.py <pcap_file>")
        sys.exit(1)

    filepath = sys.argv[1]
    result_connections = analyze_tcp_traffic(filepath)
    if result_connections:
        gen_formatted_output(result_connections)
