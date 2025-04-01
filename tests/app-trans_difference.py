import pyshark
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from collections import defaultdict

# CONFIGURATION 
PCAP_FILE_BEFORE = 'before_mud.pcap'
PCAP_FILE_AFTER = 'after_mud.pcap'
TOP_N = 10

# Figure settings
FIGSIZE_VERTICAL = (16, 7)
DPI = 300

# Function to process pcap files
def process_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    app_layer_bytes = defaultdict(int)
    transport_layer_bytes = defaultdict(int)

    print(f"Processing {pcap_file}...")
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
        'Protocol': list(app_layer_bytes.keys()),
        'Total_Bytes': list(app_layer_bytes.values())
    }).sort_values(by='Total_Bytes', ascending=False)

    df_trans = pd.DataFrame({
        'Protocol': list(transport_layer_bytes.keys()),
        'Total_Bytes': list(transport_layer_bytes.values())
    }).sort_values(by='Total_Bytes', ascending=False)

    return df_app, df_trans

# Function to group top N protocols
def group_top_n(df, n=TOP_N):
    df_sorted = df.sort_values(by="Total_Bytes", ascending=False).reset_index(drop=True)
    if len(df_sorted) > n:
        top_df = df_sorted.head(n)
        other_sum = df_sorted["Total_Bytes"].iloc[n:].sum()
        other_row = pd.DataFrame({'Protocol': ['Other'], 'Total_Bytes': [other_sum]})
        grouped_df = pd.concat([top_df, other_row], ignore_index=True)
    else:
        grouped_df = df_sorted
    grouped_df['Percentage'] = (grouped_df["Total_Bytes"] / grouped_df["Total_Bytes"].sum()) * 100
    return grouped_df

# Function to save and show graphs
def save_and_show(fig, filename):
    fig.tight_layout()
    fig.savefig(filename, dpi=DPI)
    plt.show()

# Process PCAP files
df_app_before, df_trans_before = process_pcap(PCAP_FILE_BEFORE)
df_app_after, df_trans_after = process_pcap(PCAP_FILE_AFTER)

df_app_before_group = group_top_n(df_app_before)
df_app_after_group = group_top_n(df_app_after)
df_trans_before_group = group_top_n(df_trans_before)
df_trans_after_group = group_top_n(df_trans_after)

# Create plots
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_VERTICAL)

# Before MUD (Application and Transport separate)
palette_before = sns.color_palette("Blues_d", len(df_app_before_group))
sns.barplot(x="Protocol", y="Percentage", data=df_app_before_group, palette=palette_before, ax=axes[0])
axes[0].set_title("Before MUD - Application & Transport Protocols")
axes[0].set_xlabel("")
axes[0].set_xticklabels(df_app_before_group["Protocol"], rotation=45, ha="right")

# After MUD (Application and Transport separate)
palette_after = sns.color_palette("Greens_d", len(df_app_after_group))
sns.barplot(x="Protocol", y="Percentage", data=df_app_after_group, palette=palette_after, ax=axes[1])
axes[1].set_title("After MUD - Application & Transport Protocols")
axes[1].set_xlabel("")
axes[1].set_xticklabels(df_app_after_group["Protocol"], rotation=45, ha="right")

# Number of protocols for dynamic positioning
num_protocols_before = len(df_app_before_group)
num_protocols_after = len(df_app_after_group)

# Dynamically adjust the legend position based on number of protocols
legend_y_offset = 1.1 + (max(num_protocols_before, num_protocols_after) // 5) * 0.05
title_pad = 45 + (max(num_protocols_before, num_protocols_after) // 5) * 10  

# Adjust layout for title and legend space
fig.subplots_adjust(top=0.95)  

# Move titles higher dynamically
axes[0].set_title("Before MUD - Application & Transport Protocols", pad=title_pad)
axes[1].set_title("After MUD - Application & Transport Protocols", pad=title_pad)

# Create dynamic legends
handles_before = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette_before]
handles_after = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette_after]

axes[0].legend(handles_before, df_app_before_group['Protocol'], title="Protocols", 
               loc='upper center', bbox_to_anchor=(0.5, legend_y_offset), ncol=3, frameon=True)

axes[1].legend(handles_after, df_app_after_group['Protocol'], title="Protocols", 
               loc='upper center', bbox_to_anchor=(0.5, legend_y_offset), ncol=3, frameon=True)

# Save and show the figure
save_and_show(fig, "app-trans_protocol_comparison.png")
