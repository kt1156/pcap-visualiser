import pyshark
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from collections import defaultdict

# CONFIGURATION 
PCAP_FILE_BEFORE = 'before_mud.pcap'
PCAP_FILE_AFTER = 'after_mud.pcap'
TOP_N = 10

# Consistent figure sizes 
FIGSIZE_VERTICAL = (16, 7)
DPI = 300

# PCAP files
def process_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    transport_layer_bytes = defaultdict(int)

    print(f"Processing {pcap_file}...")
    for packet in cap:
        try:
            trans_proto = packet.transport_layer if packet.transport_layer else 'Encrypted/unidentified'
            size = int(packet.length)
            transport_layer_bytes[trans_proto] += size
        except AttributeError:
            continue

    df_trans = pd.DataFrame({
        'Transport_Protocol': list(transport_layer_bytes.keys()),
        'Total_Bytes': list(transport_layer_bytes.values())
    }).sort_values(by='Total_Bytes', ascending=False)

    return df_trans

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

# Save graphs
def save_and_show(fig, filename):
    fig.tight_layout()
    fig.savefig(filename, dpi=DPI)
    plt.show()

# Process PCAP files
df_trans_before = process_pcap(PCAP_FILE_BEFORE)
df_trans_after = process_pcap(PCAP_FILE_AFTER)

df_trans_before_group = group_top_n(df_trans_before, 'Transport_Protocol', 'Total_Bytes')
df_trans_after_group = group_top_n(df_trans_after, 'Transport_Protocol', 'Total_Bytes')

# Vertical bar charts for Transport Layer with legend on top
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_VERTICAL)

# Before MUD
palette_before = sns.color_palette("Blues_d", len(df_trans_before_group))
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_before_group, palette=palette_before, ax=axes[0])
axes[0].set_title("Before MUD - Transport Protocols")
axes[0].set_xlabel("")
axes[0].set_xticklabels([])  # Remove x-axis tick labels

# After MUD
palette_after = sns.color_palette("Greens_d", len(df_trans_after_group))
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_after_group, palette=palette_after, ax=axes[1])
axes[1].set_title("After MUD - Transport Protocols")
axes[1].set_xlabel("")
axes[1].set_xticklabels([]) 

# Create legends
handles_before = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette_before]
handles_after = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette_after]

axes[0].legend(handles_before, df_trans_before_group['Transport_Protocol'], title="Protocols", bbox_to_anchor=(0.5, 0.97), loc='upper center', ncol=3)
axes[1].legend(handles_after, df_trans_after_group['Transport_Protocol'], title="Protocols", bbox_to_anchor=(0.5, 0.97), loc='upper center', ncol=3)

# Adjust layout to add extra space for the title and legend
fig.subplots_adjust(top=0.90)

# Number of protocols
num_protocols_before = len(df_trans_before_group)
num_protocols_after = len(df_trans_after_group)

# Dynamically adjust the legend position based on number of protocols
legend_y_offset = 1.1 + (num_protocols_before // 5) * 0.05 
title_pad = 45 + (num_protocols_before // 5) * 10  

# Adjust layout for title and legend space
fig.subplots_adjust(top=0.95)  

# Move titles higher dynamically
axes[0].set_title("Before MUD - Transport Protocols", pad=title_pad)
axes[1].set_title("After MUD - Transport Protocols", pad=title_pad)

# Place legends dynamically
axes[0].legend(handles_before, df_trans_before_group['Transport_Protocol'], title="Protocols", 
               loc='upper center', bbox_to_anchor=(0.5, legend_y_offset), ncol=3, frameon=True)

axes[1].legend(handles_after, df_trans_after_group['Transport_Protocol'], title="Protocols", 
               loc='upper center', bbox_to_anchor=(0.5, legend_y_offset), ncol=3, frameon=True)

save_and_show(fig, "vertical_transport_protocol_comparison.png")
