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
FIGSIZE_HORIZONTAL = (18, 8)
FIGSIZE_VERTICAL = (16, 7)
FIGSIZE_STACKED = (12, 8)
FIGSIZE_PIE = (18, 8)
DPI = 300

# PCAP files
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
df_app_before, df_trans_before = process_pcap(PCAP_FILE_BEFORE)
df_app_after, df_trans_after = process_pcap(PCAP_FILE_AFTER)

df_app_before_group = group_top_n(df_app_before, 'Application_Protocol', 'Total_Bytes')
df_app_after_group = group_top_n(df_app_after, 'Application_Protocol', 'Total_Bytes')
df_trans_before_group = group_top_n(df_trans_before, 'Transport_Protocol', 'Total_Bytes')
df_trans_after_group = group_top_n(df_trans_after, 'Transport_Protocol', 'Total_Bytes')

# Plots

# Horizontal bar charts for Application Layer
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_HORIZONTAL)
sns.barplot(y="Application_Protocol", x="Percentage", data=df_app_before_group, palette="Blues_d", ax=axes[0])
axes[0].set_title("Before MUD - Application Protocols")
axes[0].set_ylabel("")
sns.barplot(y="Application_Protocol", x="Percentage", data=df_app_after_group, palette="Greens_d", ax=axes[1])
axes[1].set_title("After MUD - Application Protocols")
axes[1].set_ylabel("")
save_and_show(fig, "horizontal_app_protocol_comparison.png")

# Horizontal bar charts for Transport Layer
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_HORIZONTAL)
sns.barplot(y="Transport_Protocol", x="Percentage", data=df_trans_before_group, palette="Oranges_d", ax=axes[0])
axes[0].set_title("Before MUD - Transport Protocols")
axes[0].set_ylabel("")
sns.barplot(y="Transport_Protocol", x="Percentage", data=df_trans_after_group, palette="Purples_d", ax=axes[1])
axes[1].set_title("After MUD - Transport Protocols")
axes[1].set_ylabel("")
save_and_show(fig, "horizontal_transport_protocol_comparison.png")

# Vertical bar charts for Application Layer
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_VERTICAL)
sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_before_group, palette="Blues_d", ax=axes[0])
axes[0].set_title("Before MUD - Application Protocols")
axes[0].set_xlabel("")
sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_after_group, palette="Greens_d", ax=axes[1])
axes[1].set_title("After MUD - Application Protocols")
axes[1].set_xlabel("")
save_and_show(fig, "vertical_app_protocol_comparison.png")

# Vertical bar charts for Transport Layer
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_VERTICAL)
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_before_group, palette="Oranges_d", ax=axes[0])
axes[0].set_title("Before MUD - Transport Protocols")
axes[0].set_xlabel("")
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_after_group, palette="Purples_d", ax=axes[1])
axes[1].set_title("After MUD - Transport Protocols")
axes[1].set_xlabel("")
save_and_show(fig, "vertical_transport_protocol_comparison.png")

# Vertical bar charts for Application Layer with legend on top
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_VERTICAL)

# Before MUD
palette_before = sns.color_palette("Blues_d", len(df_app_before_group))
sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_before_group, palette=palette_before, ax=axes[0])
axes[0].set_title("Before MUD - Application Protocols")
axes[0].set_xlabel("")
axes[0].set_xticklabels([])  # remove x-axis tick labels

# After MUD
palette_after = sns.color_palette("Greens_d", len(df_app_after_group))
sns.barplot(x="Application_Protocol", y="Percentage", data=df_app_after_group, palette=palette_after, ax=axes[1])
axes[1].set_title("After MUD - Application Protocols")
axes[1].set_xlabel("")
axes[1].set_xticklabels([]) 

# Create legends
handles_before = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette_before]
handles_after = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette_after]

axes[0].legend(handles_before, df_app_before_group['Application_Protocol'], title="Protocols", bbox_to_anchor=(0.5, 0.95), loc='upper center', ncol=3)
axes[1].legend(handles_after, df_app_after_group['Application_Protocol'], title="Protocols", bbox_to_anchor=(0.5, 0.95), loc='upper center', ncol=3)
save_and_show(fig, "vertical_app_protocol_comparison)_with_legends.png")

# Vertical bar charts for Transport Layer with legend on top
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_VERTICAL)

# Before MUD
palette_before = sns.color_palette("Blues_d", len(df_trans_before_group))
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_before_group, palette=palette_before, ax=axes[0])
axes[0].set_title("Before MUD - Transport Protocols")
axes[0].set_xlabel("")
axes[0].set_xticklabels([])  # remove x-axis tick labels

# After MUD
palette_after = sns.color_palette("Greens_d", len(df_trans_after_group))
sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans_after_group, palette=palette_after, ax=axes[1])
axes[1].set_title("After MUD - Transport Protocols")
axes[1].set_xlabel("")
axes[1].set_xticklabels([]) 

# Create legends
handles_before = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette_before]
handles_after = [plt.Rectangle((0, 0), 1, 1, color=c) for c in palette_after]

axes[0].legend(handles_before, df_trans_before_group['Transport_Protocol'], title="Protocols", bbox_to_anchor=(0.65, 0.95), loc='upper center', ncol=3)
axes[1].legend(handles_after, df_trans_after_group['Transport_Protocol'], title="Protocols", bbox_to_anchor=(0.65, 0.95), loc='upper center', ncol=3)
save_and_show(fig, "vertical_trans_protocol_comparison)_with_legends.png")

# Diverging bar chart for Application Layer differences
app_compare = pd.merge(
    df_app_before_group[['Application_Protocol', 'Percentage']],
    df_app_after_group[['Application_Protocol', 'Percentage']],
    on='Application_Protocol', how='outer', suffixes=('_Before', '_After')
).fillna(0)
app_compare['Difference'] = app_compare['Percentage_After'] - app_compare['Percentage_Before']
app_compare = app_compare.sort_values(by='Difference', ascending=False)

fig, ax = plt.subplots(figsize=FIGSIZE_VERTICAL)
sns.barplot(y='Application_Protocol', x='Difference', data=app_compare, palette="coolwarm")
ax.axvline(0, color='black')
ax.set_title("Change in Application Protocol Usage (After - Before)")
ax.set_ylabel("")
save_and_show(fig, "diverging_app_protocols.png")

# Diverging bar chart for Transport Layer differences
trans_compare = pd.merge(
    df_trans_before_group[['Transport_Protocol', 'Percentage']],
    df_trans_after_group[['Transport_Protocol', 'Percentage']],
    on='Transport_Protocol', how='outer', suffixes=('_Before', '_After')
).fillna(0)
trans_compare['Difference'] = trans_compare['Percentage_After'] - trans_compare['Percentage_Before']
trans_compare = trans_compare.sort_values(by='Difference', ascending=False)

fig, ax = plt.subplots(figsize=FIGSIZE_VERTICAL)
sns.barplot(y='Transport_Protocol', x='Difference', data=trans_compare, palette="vlag")
ax.axvline(0, color='black')
ax.set_title("Change in Transport Protocol Usage (After - Before)")
ax.set_ylabel("")
save_and_show(fig, "diverging_transport_protocols.png")

# Pie chart for Application Layer
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_PIE)
axes[0].pie(df_app_before_group['Total_Bytes'], labels=df_app_before_group['Application_Protocol'], autopct='%1.1f%%')
axes[0].set_title("Before MUD - Application Layer Distribution")
axes[1].pie(df_app_after_group['Total_Bytes'], labels=df_app_after_group['Application_Protocol'], autopct='%1.1f%%')
axes[1].set_title("After MUD - Application Layer Distribution")
save_and_show(fig, "app_layer_pie_comparison.png")

# Pie chart for Transport Layer
fig, axes = plt.subplots(1, 2, figsize=FIGSIZE_PIE)
axes[0].pie(df_trans_before_group['Total_Bytes'], labels=df_trans_before_group['Transport_Protocol'], autopct='%1.1f%%')
axes[0].set_title("Before MUD - Transport Layer Distribution")
axes[1].pie(df_trans_after_group['Total_Bytes'], labels=df_trans_after_group['Transport_Protocol'], autopct='%1.1f%%')
axes[1].set_title("After MUD - Transport Layer Distribution")
save_and_show(fig, "transport_layer_pie_comparison.png")

print("All plots finished and saved")
