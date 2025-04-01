import pyshark
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from collections import defaultdict

# Config
PCAP_FILE = 'pcap_files/cmp_in_http_with_pkixcmp-poll_content_type.pcap.gz'

# Read PCAP file
print(f"Reading {PCAP_FILE} ...")
cap = pyshark.FileCapture(PCAP_FILE, keep_packets=False)

# Aggregation 
app_layer_bytes = defaultdict(int)
transport_layer_bytes = defaultdict(int)

print("Processing packets...")
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

# Percentages

df_app['Percentage'] = (df_app['Total_Bytes'] / df_app['Total_Bytes'].sum()) * 100
df_trans['Percentage'] = (df_trans['Total_Bytes'] / df_trans['Total_Bytes'].sum()) * 100


print("\nApplication-layer protocols:")
print(df_app)
print("\nTransport-layer protocols:")
print(df_trans)

# Set plot style
sns.set_theme(style="whitegrid", palette="muted")

# Application-layer bar chart
plt.figure(figsize=(10, 6))
ax_app = sns.barplot(x="Application_Protocol", y="Percentage", data=df_app, palette="viridis")
plt.title("Application-Layer Protocol Traffic (% of Total)", fontsize=16)
plt.xlabel("Application Protocol", fontsize=12)
plt.ylabel("Percentage of Total Traffic (%)", fontsize=12)
plt.xticks(rotation=45)

# Percetages on top
for p in ax_app.patches:
    height = p.get_height()
    ax_app.annotate(f'{height:.1f}%', (p.get_x() + p.get_width() / 2., height),
                    ha='center', va='bottom', fontsize=10, color='black')

plt.tight_layout()
plt.savefig("app_layer_traffic_percentage_bar.png", dpi=300)
plt.show()

# Transport-layer bar chart
plt.figure(figsize=(8, 5))
ax_trans = sns.barplot(x="Transport_Protocol", y="Percentage", data=df_trans, palette="magma")
plt.title("Transport-Layer Protocol Traffic (% of Total)", fontsize=16)
plt.xlabel("Transport Protocol", fontsize=12)
plt.ylabel("Percentage of Total Traffic (%)", fontsize=12)

# Percetages on top

for p in ax_trans.patches:
    height = p.get_height()
    ax_trans.annotate(f'{height:.1f}%', (p.get_x() + p.get_width() / 2., height),
                      ha='center', va='bottom', fontsize=10, color='black')

plt.tight_layout()
plt.savefig("transport_layer_traffic_percentage_bar.png", dpi=300)
plt.show()

# Pie chart for application protocols
plt.figure(figsize=(8, 8))
plt.pie(df_app['Total_Bytes'], labels=df_app['Application_Protocol'], autopct='%1.1f%%', startangle=140, colors=sns.color_palette("viridis", len(df_app)))
plt.title("Application-Layer Traffic Distribution", fontsize=16)
plt.tight_layout()
plt.savefig("app_layer_traffic_pie.png", dpi=300)
plt.show()

print("All graphs saved")
