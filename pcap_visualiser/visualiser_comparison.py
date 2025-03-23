import pyshark
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from collections import defaultdict

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

# ------------------------------------------

# Horizontal bar (Application Layer)
fig, axes = plt.subplots(1, 2, figsize=(18, 8))
sns.barplot(y="Application_Protocol", x="Percentage", data=df_app_before_group, palette="Blues_d", ax=axes[0])
axes[0].set_title("Before MUD - App Protocols (Horizontal)")
axes[0].set_ylabel("Application Protocol")

# Add percentage labels to the bars in the first plot (Before MUD)
# for p in axes[0].patches:
   #  width = p.get_width()  # Get the width of the bar
   #  axes[0].text(width + 1, p.get_y() + p.get_height() / 2, f'{width:.1f}%', ha='left', va='center')

sns.barplot(y="Application_Protocol", x="Percentage", data=df_app_after_group, palette="Greens_d", ax=axes[1])
axes[1].set_title("After MUD - App Protocols (Horizontal)")
axes[1].set_ylabel("Application Protocol")

# Add percentage labels to the bars in the second plot (After MUD)
# for p in axes[1].patches:
   #  width = p.get_width()  # Get the width of the bar
   #  axes[1].text(width + 1, p.get_y() + p.get_height() / 2, f'{width:.1f}%', ha='left', va='center')

plt.tight_layout()
plt.savefig("horizontal_app_protocol_comparison.png", dpi=300)
plt.show()

# Horizontal bar (Transport Layer)
fig, axes = plt.subplots(1, 2, figsize=(16, 7))
sns.barplot(y="Transport_Protocol", x="Percentage", data=df_trans_before_group, palette="Oranges_d", ax=axes[0])
axes[0].set_title("Before MUD - Transport Protocols (Horizontal)")
axes[0].set_ylabel("Transport Protocol")

# Add percentage labels to the bars in the first plot (Before MUD)
# for p in axes[0].patches:
    # width = p.get_width()  # Get the width of the bar
    # axes[0].text(width + 1, p.get_y() + p.get_height() / 2, f'{width:.1f}%', ha='left', va='center')

sns.barplot(y="Transport_Protocol", x="Percentage", data=df_trans_after_group, palette="Purples_d", ax=axes[1])
axes[1].set_title("After MUD - Transport Protocols (Horizontal)")
axes[1].set_ylabel("Transport Protocol")

# Add percentage labels to the bars in the second plot (After MUD)
# for p in axes[1].patches:
    # width = p.get_width()  # Get the width of the bar
   #  axes[1].text(width + 1, p.get_y() + p.get_height() / 2, f'{width:.1f}%', ha='left', va='center')

plt.tight_layout()
plt.savefig("horizontal_transport_protocol_comparison.png", dpi=300)
plt.show()

# ------------------------------------------

# Vertical bar (Application Layer)

fig, axes = plt.subplots(1, 2, figsize=(18, 8))

sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_before_group, palette="Blues_d", ax=axes[0])
axes[0].set_title("Before MUD - App Protocols (Vertical)")
axes[0].set_xlabel("Application Protocol")
axes[0].set_ylabel("Percentage")

# After MUD bar plot 
sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_after_group, palette="Greens_d", ax=axes[1])
axes[1].set_title("After MUD - App Protocols (Vertical)")
axes[1].set_xlabel("Application Protocol")
axes[1].set_ylabel("Percentage")

plt.tight_layout()
plt.savefig("vertical_app_protocol_comparison.png", dpi=300)
plt.show()

# Vertical bar (Transport Layer)

fig, axes = plt.subplots(1, 2, figsize=(16, 7))

# Before MUD bar plot
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_before_group, palette="Oranges_d", ax=axes[0])
axes[0].set_title("Before MUD - Transport Protocols (Vertical)")
axes[0].set_xlabel("Transport Protocol")
axes[0].set_ylabel("Percentage")

# After MUD bar plot 
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_after_group, palette="Purples_d", ax=axes[1])
axes[1].set_title("After MUD - Transport Protocols (Vertical)")
axes[1].set_xlabel("Transport Protocol")
axes[1].set_ylabel("Percentage")

plt.tight_layout()
plt.savefig("vertical_transport_protocol_comparison.png", dpi=300)
plt.show()

# ------------------------------------------

# Stacked bar

df_app_before_group['Type'] = 'Before'
df_app_after_group['Type'] = 'After'
df_trans_before_group['Type'] = 'Before'
df_trans_after_group['Type'] = 'After'

# Pivot data for stacked bar
df_app_combined = pd.concat([df_app_before_group, df_app_after_group])
app_stacked = df_app_combined.pivot(index='Application_Protocol', columns='Type', values='Percentage').fillna(0)

# Create stacked bar chart
plt.figure(figsize=(10, 6))
bottom_values = None
for column, color in zip(app_stacked.columns, ['blue', 'green']):
    plt.bar(app_stacked.index, app_stacked[column], bottom=bottom_values, label=column, color=color)
    if bottom_values is None:
        bottom_values = app_stacked[column]
    else:
        bottom_values += app_stacked[column]

plt.title("Stacked Application Protocols (Before & After MUD)")
plt.xlabel("Application Protocol")
plt.ylabel("Percentage")
plt.legend()
plt.tight_layout()
plt.savefig("stacked_app_protocol_comparison.png", dpi=300)
plt.show()

# Pivot data for stacked bar
df_trans_combined = pd.concat([df_trans_before_group, df_trans_after_group])
trans_stacked = df_trans_combined.pivot(index='Transport_Protocol', columns='Type', values='Percentage').fillna(0)

# Create stacked bar chart
plt.figure(figsize=(10, 6))
bottom_values = None
for column, color in zip(trans_stacked.columns, ['orange', 'purple']):
    plt.bar(trans_stacked.index, trans_stacked[column], bottom=bottom_values, label=column, color=color)
    if bottom_values is None:
        bottom_values = trans_stacked[column]
    else:
        bottom_values += trans_stacked[column]

plt.title("Stacked Transport Protocols (Before & After MUD)")
plt.xlabel("Transport Protocol")
plt.ylabel("Percentage")
plt.legend()
plt.tight_layout()
plt.savefig("stacked_transport_protocol_comparison.png", dpi=300)
plt.show()

# ------------------------------------------

# Diverging bar (Application Layer difference)
app_compare = pd.merge(
    df_app_before_group[['Application_Protocol', 'Percentage']],
    df_app_after_group[['Application_Protocol', 'Percentage']],
    on='Application_Protocol', how='outer', suffixes=('_Before', '_After')
).fillna(0)
app_compare['Difference'] = app_compare['Percentage_After'] - app_compare['Percentage_Before']
app_compare = app_compare.sort_values(by='Difference', ascending=False)

plt.figure(figsize=(10, 8))
sns.barplot(y='Application_Protocol', x='Difference', data=app_compare, palette="coolwarm")
plt.axvline(0, color='black', linewidth=1)
plt.title("Diverging Bar Chart: App Protocol Change (After - Before)")
plt.xlabel("Percentage Difference")
plt.ylabel("Application Protocol")
plt.tight_layout()
plt.savefig("diverging_app_protocols.png", dpi=300)
plt.show()

# Diverging bar (Transport Layer difference)
trans_compare = pd.merge(
    df_trans_before_group[['Transport_Protocol', 'Percentage']],
    df_trans_after_group[['Transport_Protocol', 'Percentage']],
    on='Transport_Protocol', how='outer', suffixes=('_Before', '_After')
).fillna(0)
trans_compare['Difference'] = trans_compare['Percentage_After'] - trans_compare['Percentage_Before']
trans_compare = trans_compare.sort_values(by='Difference', ascending=False)

plt.figure(figsize=(9, 7))
sns.barplot(y='Transport_Protocol', x='Difference', data=trans_compare, palette="vlag")
plt.axvline(0, color='black', linewidth=1)
plt.title("Diverging Bar Chart: Transport Protocol Change (After - Before)")
plt.xlabel("Percentage Difference")
plt.ylabel("Transport Protocol")
plt.tight_layout()
plt.savefig("diverging_transport_protocols.png", dpi=300)
plt.show()

# ------------------------------------------

# Pie Charts for application layer
fig, axes = plt.subplots(1, 2, figsize=(18, 8))

# Application-layer pie chart Before MUD
axes[0].pie(
    df_app_before_group['Total_Bytes'], 
    labels=df_app_before_group['Application_Protocol'], 
    autopct='%1.1f%%', 
    startangle=140, 
    colors=sns.color_palette("colorblind", len(df_app_before_group))
)
axes[0].set_title(f"Before MUD: Application-Layer Traffic Distribution", fontsize=16)

# Application-layer pie chart After MUD
axes[1].pie(
    df_app_after_group['Total_Bytes'], 
    labels=df_app_after_group['Application_Protocol'], 
    autopct='%1.1f%%', 
    startangle=140, 
    colors=sns.color_palette("colorblind", len(df_app_after_group))
)
axes[1].set_title(f"After MUD: Application-Layer Traffic Distribution", fontsize=16)

plt.tight_layout()
plt.savefig("before_and_after_app_layer_pie_comparison.png", dpi=300)
plt.show()

# Pie charts for transport layer
fig, axes = plt.subplots(1, 2, figsize=(18, 8))

# Transport-layer pie chart Before MUD
axes[0].pie(
    df_trans_before_group['Total_Bytes'], 
    labels=df_trans_before_group['Transport_Protocol'], 
    autopct='%1.1f%%', 
    startangle=140, 
    colors=sns.color_palette("colorblind", len(df_trans_before_group))
)
axes[0].set_title(f"Before MUD: Transport-Layer Traffic Distribution", fontsize=16)

# Transport-layer pie chart After MUD
axes[1].pie(
    df_trans_after_group['Total_Bytes'], 
    labels=df_trans_before_group['Transport_Protocol'], 
    autopct='%1.1f%%', 
    startangle=140, 
    colors=sns.color_palette("colorblind", len(df_trans_after_group))
)
axes[1].set_title(f"After MUD: Transport-Layer Traffic Distribution", fontsize=16)

plt.tight_layout()
plt.savefig("before_and_after_transport_layer_pie_comparison.png", dpi=300)
plt.show()

print("All graphs saved.")
