import struct
import socket
import sys


# This function reads the pcap file, parses the TCP packets, and tracks connections using a 4-tuple (src_ip, src_port, dst_ip, dst_port).
# It also collects various statistics about each connection, such as the number of packets, bytes, window sizes, and RTT values.
def analyze_tcp_traffic(pcap_filepath):
    # This dictionary will track our 4-tuple connections
    connections = {}

    with open(pcap_filepath, 'rb') as f:
        # 1. Skip the 24-byte Global PCAP Header
        global_header = f.read(24) 
        if len(global_header) < 24:
            print("Invalid PCAP file.")
            return

        while True:
            # 2. Read the 16-byte PCAP Packet Header
            pcap_header = f.read(16)
            if len(pcap_header) < 16:
                break # End of file
            
            # Unpack PCAP Header (Little-Endian)
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pcap_header)
            timestamp = ts_sec + (ts_usec / 1000000.0)

            # Read the raw packet data based on incl_len
            packet_data = f.read(incl_len)

            # 3. Parse Ethernet Header (14 bytes)
            eth_type = struct.unpack('!H', packet_data[12:14])[0]
            
            # 0x0800 is IPv4. Skip anything else
            if eth_type != 0x0800:
                continue

            # 4. Parse IPv4 Header
            ip_header_start = 14
            version_ihl = packet_data[ip_header_start]
            ihl = (version_ihl & 0x0F) * 4 # Multiply by 4 to get bytes
            
            total_ip_len = struct.unpack('!H', packet_data[ip_header_start+2 : ip_header_start+4])[0]
            protocol = packet_data[ip_header_start + 9]
            
            # 6 is TCP. Skip UDP, ICMP, etc.
            if protocol != 6:
                continue

            # Extract IP addresses
            src_ip_raw = packet_data[ip_header_start+12 : ip_header_start+16]
            dst_ip_raw = packet_data[ip_header_start+16 : ip_header_start+20]
            src_ip = socket.inet_ntoa(src_ip_raw) 
            dst_ip = socket.inet_ntoa(dst_ip_raw)

            # 5. Parse TCP Header
            tcp_header_start = ip_header_start + ihl
            
            # Extract Ports 
            src_port = struct.unpack('!H', packet_data[tcp_header_start : tcp_header_start+2])[0]
            dst_port = struct.unpack('!H', packet_data[tcp_header_start+2 : tcp_header_start+4])[0]

            # Extract Sequence and Acknowledgment numbers
            seq_num = struct.unpack('!I', packet_data[tcp_header_start+4 : tcp_header_start+8])[0]
            ack_num = struct.unpack('!I', packet_data[tcp_header_start+8 : tcp_header_start+12])[0]

            # Data Offset
            data_offset_raw = packet_data[tcp_header_start + 12]
            tcp_header_len = ((data_offset_raw >> 4) & 0x0F) * 4

            # Flags
            flags = packet_data[tcp_header_start + 13]
            fin = (flags & 0x01) != 0
            syn = (flags & 0x02) != 0
            rst = (flags & 0x04) != 0
            ack = (flags & 0x10) != 0

            # Window Size
            window_size = struct.unpack('!H', packet_data[tcp_header_start+14 : tcp_header_start+16])[0]

            # Calculate actual TCP payload data length
            tcp_payload_len = total_ip_len - ihl - tcp_header_len

            # 6. Connection Tracking (The 4-Tuple)
            endpoint1 = f"{src_ip}:{src_port}"
            endpoint2 = f"{dst_ip}:{dst_port}"
            connection_id = tuple(sorted([endpoint1, endpoint2]))

            # INITIALIZE NEW CONNECTION
            if connection_id not in connections:
                connections[connection_id] = {
                    'src_ip': src_ip, # The initiator of the connection
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
                    'data_after_fin': False
                }
            
            # UPDATE CONNECTION DATA
            conn = connections[connection_id]
            
            # --- ADD THIS CHECK ---
            # If we've previously seen a FIN, and this packet has data
            if conn['state_fin'] > 0 and tcp_payload_len > 0:
                conn['data_after_fin'] = True
            # ----------------------

            conn['total_packets'] += 1
            conn['end_time'] = timestamp 
            conn['total_data_bytes'] += tcp_payload_len
            conn['window_sizes'].append(window_size) # Track window size
            
            if syn: conn['state_syn'] += 1
            if fin: conn['state_fin'] += 1
            if rst: conn['is_reset'] = True

            # DIRECTIONAL TRACKING (Packets and Bytes)
            if src_ip == conn['src_ip']:
                conn['pkts_src_to_dst'] += 1
                conn['bytes_src_to_dst'] += tcp_payload_len
            else:
                conn['pkts_dst_to_src'] += 1
                conn['bytes_dst_to_src'] += tcp_payload_len

            # RTT CALCULATION LOGIC!
            payload_len_for_ack = max(1, tcp_payload_len) if (syn or fin) else tcp_payload_len
            expected_ack = seq_num + payload_len_for_ack

            if src_ip == conn['src_ip']: # Packet sent by initiator
                if tcp_payload_len > 0 or syn or fin:
                    conn['unacked_packets_A_to_B'][expected_ack] = timestamp
            elif dst_ip == conn['src_ip']: # Packet coming back
                if ack and ack_num in conn['unacked_packets_A_to_B']:
                    time_sent = conn['unacked_packets_A_to_B'][ack_num]
                    rtt = timestamp - time_sent
                    conn['rtt_values'].append(rtt)
                    del conn['unacked_packets_A_to_B'][ack_num] # Remove after matching

    return connections


# This function takes the connections dictionary and generates the formatted output!!
def gen_formatte_output(connections):
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
        # 1. Determine Status
        if data['is_reset']:
            status = "R"
            reset_conns += 1
        else:
            status = f"S{data['state_syn']}F{data['state_fin']}"

        # 2. Determine if Complete
        is_complete = data['state_syn'] >= 1 and data['state_fin'] >= 1
        if is_complete:
            complete_conns += 1
            duration = data['end_time'] - data['start_time']
            all_durations.append(duration)
            all_packet_counts.append(data['total_packets'])
            all_window_sizes.extend(data['window_sizes'])
            if len(data['rtt_values']) > 0:
                all_rtt_values.extend(data['rtt_values'])

        # 3. Determine Edge Cases!
        if data['first_packet_flag'] != 'SYN':  
            established_before_capture += 1
        
        # Determine if open (No FIN, OR data sent after FIN)
        if data['state_fin'] == 0 or data['data_after_fin'] == True:
            open_conns += 1
        
        # 4. Print Connection Block 
        print(f"Connection {conn_number}:")
        print(f"Source Address: {data['src_ip']}")
        print(f"Destination address: {data['dst_ip']}")
        print(f"Source Port: {data['src_port']}")
        print(f"Destination Port: {data['dst_port']}")
        print(f"Status: {status}")

        #only print the following details if the connection is complete (SYN and FIN observed)
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

    # 5. Print Section C
    print("____________________________________________________________________________________________ ") 
    print("\n")
    print("C) General")
    print("\n")
    print(f"The total number of complete TCP connections: {complete_conns}")
    print(f"The number of reset TCP connections: {reset_conns}")
    print(f"The number of TCP connections that were still open when the trace capture ended: {open_conns}")
    print(f"The number of TCP connections established before the capture started: {established_before_capture}")

    # 6. Print Section D (Calculations)
    print("____________________________________________________________________________________________ ")
    print("\n")
    print("D) Complete TCP connections:")
    print("\n")
    if complete_conns > 0:
        print(f"Minimum time duration: {min(all_durations):.6f} seconds")
        print(f"Mean time duration: {sum(all_durations)/len(all_durations):.6f} seconds")
        print(f"Maximum time duration: {max(all_durations):.6f} seconds")
        print("\n")
  
        if len(all_rtt_values) > 0:
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
        if len(all_window_sizes) > 0:
            print(f"Minimum receive window size including both send/received: {min(all_window_sizes)}")
            print(f"Mean receive window size including both send/received: {sum(all_window_sizes)/len(all_window_sizes):.6f}")
            print(f"Maximum receive window size including both send/received: {max(all_window_sizes)}")

        print("____________________________________________________________________________________________ ")


# MAIN FUNCTION TO RUN THE ANALYZER AND FORMATTER!!
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 tcp_analyzer.py <pcap_file>")
        sys.exit(1)
        
    filepath = sys.argv[1]
    
    # 1. Run the parser
    result_connections = analyze_tcp_traffic(filepath)
    
    # 2. Run the formatter to print the results
    if result_connections:
        gen_formatte_output(result_connections)