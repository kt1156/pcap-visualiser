import pyshark
import pandas as pd
from collections import defaultdict
import plotly.graph_objects as go

# Config
PCAP_FILE_BEFORE = 'before_mud.pcap'
PCAP_FILE_AFTER = 'after_mud.pcap'
TOP_N = 10

# Function to process PCAP and return protocol stats
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
        'Application_Protocol': list(app_layer_bytes.keys()),
        'Total_Bytes': list(app_layer_bytes.values())
    }).sort_values(by='Total_Bytes', ascending=False)

    df_trans = pd.DataFrame({
        'Transport_Protocol': list(transport_layer_bytes.keys()),
        'Total_Bytes': list(transport_layer_bytes.values())
    }).sort_values(by='Total_Bytes', ascending=False)

    return df_app, df_trans

# Grouping function for top N protocols
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

# Process PCAPs
df_app_before, df_trans_before = process_pcap(PCAP_FILE_BEFORE)
df_app_after, df_trans_after = process_pcap(PCAP_FILE_AFTER)

# Group dataframes for application & transport layer
df_app_before_group = group_top_n(df_app_before, 'Application_Protocol', 'Total_Bytes')
df_app_after_group = group_top_n(df_app_after, 'Application_Protocol', 'Total_Bytes')
df_trans_before_group = group_top_n(df_trans_before, 'Transport_Protocol', 'Total_Bytes')
df_trans_after_group = group_top_n(df_trans_after, 'Transport_Protocol', 'Total_Bytes')

# Example: Matching protocols before and after MUD
protocols_before = df_app_before_group['Application_Protocol'].tolist()
protocols_after = df_app_after_group['Application_Protocol'].tolist()

# Combine lists and remove duplicates for node list
all_protocols = list(set(protocols_before + protocols_after))

# Create source-target-value lists
source_indices = []
target_indices = []
values = []

# Match protocols — if something disappears, target could be "Blocked"
for i, row in df_app_before_group.iterrows():
    proto = row['Application_Protocol']
    traffic = row['Total_Bytes']
    if proto in protocols_after:
        source_indices.append(all_protocols.index(proto))
        target_indices.append(all_protocols.index(proto))
        values.append(traffic)
    else:
        # Disappeared traffic → Blocked
        source_indices.append(all_protocols.index(proto))
        target_indices.append(len(all_protocols))  # add "Blocked" node at the end
        values.append(traffic)

all_protocols.append("Blocked")  # Add a Blocked node

# Sankey plot
fig = go.Figure(data=[go.Sankey(
    node=dict(
        pad=15,
        thickness=20,
        line=dict(color="black", width=0.5),
        label=all_protocols
    ),
    link=dict(
        source=source_indices,
        target=target_indices,
        value=values
    ))])

fig.update_layout(title_text="Application-Layer Traffic Flow Before and After MUD", font_size=12)
fig.show()