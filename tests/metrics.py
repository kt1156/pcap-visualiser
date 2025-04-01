from collections import defaultdict
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

PCAP_FILE_BEFORE = 'before_mud.pcap'
PCAP_FILE_AFTER = 'after_mud.pcap'

# Function to extract bandwidth and latency data from a pcap files
def extract_traffic_stats(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    flow_data = defaultdict(lambda: {'timestamps': [], 'bytes': 0})

    print(f"Processing {pcap_file} for traffic stats...")
    
    for packet in cap:
        try:
            if 'IP' in packet:
                # Extract details
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                timestamp = float(packet.sniff_time.timestamp())
                size = int(packet.length)
                
                # Unique flow identification by source/destination IP
                flow_key = (src_ip, dst_ip)
                
                # Store the timestamp and packet size for this flow
                flow_data[flow_key]['timestamps'].append(timestamp)
                flow_data[flow_key]['bytes'] += size
        except AttributeError:
            continue

    # Convert flow data into a DataFrame with per/sec bandwidth and latency
    time_series = []
    for flow_key, data in flow_data.items():
        timestamps = data['timestamps']
        bytes_transferred = data['bytes']
        
        # Bandwidth: Sum bytes per second
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        # Calculate bandwidth for this flow (bytes per second)
        duration = end_time - start_time if end_time != start_time else 1
        bandwidth = bytes_transferred / duration
        
        # Latency: Difference between first and last timestamp
        latency = max(timestamps) - min(timestamps)
        
        time_series.append({'flow_key': flow_key, 'bandwidth': bandwidth, 'latency': latency, 'timestamps': (start_time, end_time)})
    
    df = pd.DataFrame(time_series)
    return df

# Function to plot bandwidth and latency as line graph
def plot_traffic_stats(df_before, df_after, output_file):
    plt.figure(figsize=(14, 7))

    # Plot Bandwidth (Before MUD)
    plt.subplot(1, 2, 1)
    plt.plot(df_before['timestamps'].apply(lambda x: x[0]), df_before['bandwidth'], label="Before MUD", color="blue")
    plt.plot(df_after['timestamps'].apply(lambda x: x[0]), df_after['bandwidth'], label="After MUD", color="green")
    plt.title("Bandwidth Over Time")
    plt.xlabel("Time (s)")
    plt.ylabel("Bandwidth (Bytes per second)")
    plt.legend()

    # Plot Latency (Before MUD)
    plt.subplot(1, 2, 2)
    plt.plot(df_before['timestamps'].apply(lambda x: x[0]), df_before['latency'], label="Before MUD", color="blue")
    plt.plot(df_after['timestamps'].apply(lambda x: x[0]), df_after['latency'], label="After MUD", color="green")
    plt.title("Latency Over Time")
    plt.xlabel("Time (s)")
    plt.ylabel("Latency (Seconds)")
    plt.legend()

    plt.tight_layout()
    plt.savefig(output_file)
    plt.show()

# Extract traffic stats for both before and after MUD
df_before_stats = extract_traffic_stats(PCAP_FILE_BEFORE)
df_after_stats = extract_traffic_stats(PCAP_FILE_AFTER)

# Plot and save the traffic stats line graph
plot_traffic_stats(df_before_stats, df_after_stats, "traffic_stats_comparison.png")
