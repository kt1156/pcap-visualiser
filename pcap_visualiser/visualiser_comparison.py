import pyshark
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from collections import defaultdict

# Config
PCAP_FILE_BEFORE = 'pcap_files/before_mud.pcap' # Before MUD
PCAP_FILE_AFTER = 'pcap_files/after_mud.pcap'  # After MUD

TOP_N = 10

# Function to process PCAP file and return protocol data
def process_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
    
    app_layer_bytes = defaultdict(int)
    transport_layer_bytes = defaultdict(int)
    
    print(f"Processing {pcap_file} ...")
    for packet in cap:
        try:
            app_proto = packet.highest_layer
            trans_proto = packet.transport_layer if packet.transport_layer else 'Unknown'
            size = int(packet.length)
            app_layer_bytes[app_proto] += size
            transport_layer_bytes[trans_proto] += size
        except AttributeError:
            continue

    # Convert to DataFrames
    df_app = pd.DataFrame({
        'Application_Protocol': list(app_layer_bytes.keys()),
        'Total_Bytes': list(app_layer_bytes.values())
    }).sort_values(by='Total_Bytes', ascending=False)

    df_trans = pd.DataFrame({
        'Transport_Protocol': list(transport_layer_bytes.keys()),
        'Total_Bytes': list(transport_layer_bytes.values())
    }).sort_values(by='Total_Bytes', ascending=False)

    return df_app, df_trans

# Function to group top N protocols and other
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

# Process both PCAP files
df_app_before, df_trans_before = process_pcap(PCAP_FILE_BEFORE)
df_app_after, df_trans_after = process_pcap(PCAP_FILE_AFTER)

# Group top N protocols for both before and after MUD
df_app_grouped_before = group_top_n(df_app_before, 'Application_Protocol', 'Total_Bytes', n=TOP_N)
df_trans_grouped_before = group_top_n(df_trans_before, 'Transport_Protocol', 'Total_Bytes', n=TOP_N)

df_app_grouped_after = group_top_n(df_app_after, 'Application_Protocol', 'Total_Bytes', n=TOP_N)
df_trans_grouped_after = group_top_n(df_trans_after, 'Transport_Protocol', 'Total_Bytes', n=TOP_N)

# Set plot style
sns.set_theme(style="whitegrid", palette="muted")

# Create side-by-side bar charts for application layer protocols
fig, axes = plt.subplots(1, 2, figsize=(18, 6))

# Application-layer bar chart Before MUD
sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_grouped_before, palette="viridis", ax=axes[0])
axes[0].set_title(f"Before MUD: Top {TOP_N} Application-Layer Protocols", fontsize=16)
axes[0].set_xlabel("Application Protocol", fontsize=12)
axes[0].set_ylabel("Percentage of Total Traffic (%)", fontsize=12)
axes[0].tick_params(axis='x', rotation=45)

# Add percentage labels on top for Before MUD
for p in axes[0].patches:
    height = p.get_height()
    axes[0].annotate(f'{height:.1f}%', (p.get_x() + p.get_width() / 2., height),
                     ha='center', va='bottom', fontsize=10, color='black')

# Application-layer bar chart After MUD
sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_grouped_after, palette="viridis", ax=axes[1])
axes[1].set_title(f"After MUD: Top {TOP_N} Application-Layer Protocols", fontsize=16)
axes[1].set_xlabel("Application Protocol", fontsize=12)
axes[1].set_ylabel("Percentage of Total Traffic (%)", fontsize=12)
axes[1].tick_params(axis='x', rotation=45)

# Add percentage labels on top for After MUD
for p in axes[1].patches:
    height = p.get_height()
    axes[1].annotate(f'{height:.1f}%', (p.get_x() + p.get_width() / 2., height),
                     ha='center', va='bottom', fontsize=10, color='black')

plt.tight_layout()
plt.savefig("before_and_after_app_layer_comparison.png", dpi=300)
plt.show()

# Create side-by-side bar charts for transport layer protocols
fig, axes = plt.subplots(1, 2, figsize=(18, 6))

# Transport-layer bar chart Before MUD
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_grouped_before, palette="magma", ax=axes[0])
axes[0].set_title(f"Before MUD: Top {TOP_N} Transport-Layer Protocols", fontsize=16)
axes[0].set_xlabel("Transport Protocol", fontsize=12)
axes[0].set_ylabel("Percentage of Total Traffic (%)", fontsize=12)

# Add percentage labels on top for Before MUD
for p in axes[0].patches:
    height = p.get_height()
    axes[0].annotate(f'{height:.1f}%', (p.get_x() + p.get_width() / 2., height),
                     ha='center', va='bottom', fontsize=10, color='black')

# Transport-layer bar chart After MUD
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_grouped_after, palette="magma", ax=axes[1])
axes[1].set_title(f"After MUD: Top {TOP_N} Transport-Layer Protocols", fontsize=16)
axes[1].set_xlabel("Transport Protocol", fontsize=12)
axes[1].set_ylabel("Percentage of Total Traffic (%)", fontsize=12)

# Add percentage labels on top for After MUD
for p in axes[1].patches:
    height = p.get_height()
    axes[1].annotate(f'{height:.1f}%', (p.get_x() + p.get_width() / 2., height),
                     ha='center', va='bottom', fontsize=10, color='black')

plt.tight_layout()
plt.savefig("before_and_after_transport_layer_comparison.png", dpi=300)
plt.show()

print("All graphs saved.")