import pyshark
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from collections import defaultdict
import io
import base64
import numpy as np

# CONFIGURATION
TOP_N = 10

# PCAP files
def process_pcap(pcap_file):
    cap = None
    try:
        cap = pyshark.FileCapture(pcap_file, keep_packets=False)
        app_layer_bytes = defaultdict(int)
        transport_layer_bytes = defaultdict(int)

        for packet in cap:
            try:
                app_proto = packet.highest_layer
                trans_proto = packet.transport_layer if packet.transport_layer else 'Encrypted/unidentified'
                size = int(packet.length)
                app_layer_bytes[app_proto] += size
                transport_layer_bytes[trans_proto] += size
            except AttributeError:
                continue

        df_app = pd.DataFrame({
            'Application_Protocol': list(app_layer_bytes.keys()),
            'Total_Bytes': list(app_layer_bytes.values())
        }).sort_values(by='Total_Bytes', ascending=False)

        df_trans = pd.DataFrame({
            'Transport_Protocol': list(transport_layer_bytes.keys()),
            'Total_Bytes': list(transport_layer_bytes.values())
        }).sort_values(by='Total_Bytes', ascending=False)

        return df_app, df_trans
    finally:
        if cap:
            cap.close()

# Top N protocols
def group_top_n(df, column_name, value_column, n=TOP_N):
    df_sorted = df.sort_values(by=value_column, ascending=False).reset_index(drop=True)
    if len(df_sorted) > n:
        top_df = df_sorted.head(n)
        other_sum = df_sorted[value_column].iloc[n:].sum()
        other_row = pd.DataFrame({column_name: ['Other'], value_column: [other_sum]})
        grouped_df = pd.concat([top_df, other_row], ignore_index=True)
    else:
        grouped_df = df_sorted
    grouped_df['Percentage'] = (grouped_df[value_column] / grouped_df[value_column].sum()) * 100
    return grouped_df

# Function to generate Application Protocol graph
def generate_application_graph(df_app):
    df_app_group = group_top_n(df_app, 'Application_Protocol', 'Total_Bytes')

    fig, ax = plt.subplots(figsize=(10, 6))

    palette = sns.color_palette("Blues_d", len(df_app_group))
    sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_group, palette=palette, ax=ax, hue="Application_Protocol", legend=False)
    ax.set_title("Application Protocols", pad=30) 
    ax.set_xlabel("")
    ax.set_xticklabels([])

    # Create legend handles
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette]

    # Place legend under the title and on top of the graph box
    ax.legend(handles, df_app_group['Application_Protocol'], title="Protocols",
              loc='upper center', bbox_to_anchor=(0.5, 1.1), ncol=3, frameon=True)

    img_data = io.BytesIO()
    fig.savefig(img_data, format='png')
    img_data.seek(0)
    img_base64 = base64.b64encode(img_data.read()).decode('utf-8')
    plt.close(fig)

    return img_base64


# Function to generate Transport Protocol graph
def generate_transport_graph(df_trans):
    df_trans_group = group_top_n(df_trans, 'Transport_Protocol', 'Total_Bytes')

    fig, ax = plt.subplots(figsize=(10, 6))

    palette = sns.color_palette("Greens_d", len(df_trans_group))
    sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_group, palette=palette, ax=ax, hue="Transport_Protocol", legend=False)
    ax.set_title("Transport Protocols", pad = 30)
    ax.set_xlabel("")
    ax.set_xticklabels([])

    # Create legend handles
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette]

    # Place legend under the title and on top of the graph box
    ax.legend(handles, df_trans_group['Transport_Protocol'], title="Protocols",
              loc='upper center', bbox_to_anchor=(0.5, 1.1), ncol=3, frameon=True)

    img_data = io.BytesIO()
    fig.savefig(img_data, format='png')
    img_data.seek(0)
    img_base64 = base64.b64encode(img_data.read()).decode('utf-8')
    plt.close(fig)

    return img_base64

# Function to generate Combined Application and Transport Protocol graph
def generate_combined_graph(df_app, df_trans):
    df_app_group = group_top_n(df_app, 'Application_Protocol', 'Total_Bytes')
    df_trans_group = group_top_n(df_trans, 'Transport_Protocol', 'Total_Bytes')

    df_app_group['Protocol'] = df_app_group['Application_Protocol']

    fig, ax = plt.subplots(figsize=(10, 6))

    palette = sns.color_palette("Purples_d", len(df_app_group))
    sns.barplot(x="Protocol", y="Percentage", data=df_app_group, palette=palette, ax=ax, hue="Protocol", legend=False)
    ax.set_title("Combined Application & Transport Protocols", pad=30)
    ax.set_xlabel("")
    ax.set_xticklabels([])

    # Create legend handles
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette]

    # Place legend under the title and on top of the graph box
    ax.legend(handles, df_app_group['Protocol'], title="Protocols",
              loc='upper center', bbox_to_anchor=(0.5, 1.1), ncol=3, frameon=True)

    img_data = io.BytesIO()
    fig.savefig(img_data, format='png')
    img_data.seek(0)
    img_base64 = base64.b64encode(img_data.read()).decode('utf-8')
    plt.close(fig)

    return img_base64

def calculate_latency_and_bandwidth(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    timestamps = []
    packet_sizes = []

    for packet in cap:
        try:
            timestamps.append(float(packet.sniff_time.timestamp()))
            packet_sizes.append(int(packet.length))
        except AttributeError:
            continue

    cap.close()

    if len(timestamps) < 2:
        return None, None

    # Calculate latency (differences in timestamps)
    latencies = np.diff(timestamps) * 1000  # convert to ms
    avg_latency = np.mean(latencies)

    # Calculate bandwidth (bytes per second)
    duration = timestamps[-1] - timestamps[0]
    bandwidth = sum(packet_sizes) / duration if duration > 0 else 0

    return avg_latency, bandwidth

def calculate_latency_and_bandwidth(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    timestamps = []
    packet_sizes = []

    for packet in cap:
        try:
            timestamps.append(float(packet.sniff_time.timestamp()))
            packet_sizes.append(int(packet.length))
        except AttributeError:
            continue

    cap.close()

    if len(timestamps) < 2:
        return None, None, None, None

    return timestamps, packet_sizes

def generate_latency_graph(timestamps):
    if len(timestamps) < 2:
        return None

    latencies = np.diff(timestamps) * 1000  # convert to milliseconds

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(timestamps[1:], latencies, marker="o", linestyle="-", color="blue", label="Latency (ms)")
    
    ax.set_title("Latency Over Time")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Latency (ms)")
    ax.legend()
    ax.grid(True)

    img_data = io.BytesIO()
    fig.savefig(img_data, format="png")
    img_data.seek(0)
    img_base64 = base64.b64encode(img_data.read()).decode("utf-8")
    plt.close(fig)

    return img_base64


def generate_bandwidth_graph(timestamps, packet_sizes):
    if len(timestamps) < 2:
        return None

    bandwidths = []
    for i in range(1, len(timestamps)):
        time_diff = timestamps[i] - timestamps[i - 1]
        if time_diff > 0:
            bandwidths.append(packet_sizes[i] / time_diff)  # Bytes per second
        else:
            bandwidths.append(0)

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(timestamps[1:], bandwidths, marker="o", linestyle="-", color="green", label="Bandwidth (Bytes/sec)")

    ax.set_title("Bandwidth Over Time")
    ax.set_xlabel("Timestamp")
    ax.set_ylabel("Bandwidth (Bytes/sec)")
    ax.legend()
    ax.grid(True)

    img_data = io.BytesIO()
    fig.savefig(img_data, format="png")
    img_data.seek(0)
    img_base64 = base64.b64encode(img_data.read()).decode("utf-8")
    plt.close(fig)

    return img_base64
