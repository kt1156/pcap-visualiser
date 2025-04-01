from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
from process_pcap import process_pcap, generate_transport_graph, generate_application_graph, generate_combined_graph
import matplotlib

matplotlib.use('Agg') # disable gui, fixes asynchronous 

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pcap'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/processPcap', methods=['POST'])
def process_pcap_api():
    print("Received a request to /api/processPcap")

    if 'pcap1' not in request.files or 'pcap2' not in request.files:
        print("Error: No files provided")
        return jsonify({"error": "No files provided"}), 400

    pcap1 = request.files['pcap1']
    pcap2 = request.files['pcap2']

    print(f"pcap1: {pcap1.filename}, pcap2: {pcap2.filename}")

    if pcap1 and allowed_file(pcap1.filename) and pcap2 and allowed_file(pcap2.filename):
        pcap1_filename = secure_filename(pcap1.filename)
        pcap2_filename = secure_filename(pcap2.filename)
        pcap1_path = os.path.join(app.config['UPLOAD_FOLDER'], pcap1_filename)
        pcap2_path = os.path.join(app.config['UPLOAD_FOLDER'], pcap2_filename)

        try:
            pcap1.save(pcap1_path)
            pcap2.save(pcap2_path)
            print("Files saved successfully")
        except Exception as e:
            print(f"Error saving files: {e}")
            return jsonify({"error": "Error saving files"}), 500

        try:
            df_app1, df_trans1 = process_pcap(pcap1_path)
            df_app2, df_trans2 = process_pcap(pcap2_path)
            print("Pcap files processed successfully")
        except Exception as e:
            print(f"Error processing pcap files: {e}")
            return jsonify({"error": "Error processing pcap files"}), 500

        try:
            transport_graph1 = generate_transport_graph(df_trans1)
            app_graph1 = generate_application_graph(df_app1)
            mixed_graph1 = generate_combined_graph(df_app1, df_trans1)

            transport_graph2 = generate_transport_graph(df_trans2)
            app_graph2 = generate_application_graph(df_app2)
            mixed_graph2 = generate_combined_graph(df_app2, df_trans2)
            print("Graphs generated successfully")

        except Exception as e:
            print(f"Error generating graphs: {e}")
            return jsonify({"error": "Error generating graphs"}), 500

        results = {
            "transportGraph1": transport_graph1,
            "appGraph1": app_graph1,
            "mixedGraph1": mixed_graph1,
            "transportGraph2": transport_graph2,
            "appGraph2": app_graph2,
            "mixedGraph2": mixed_graph2
        }

        print(f"appGraph1 (first 50 chars): {results['appGraph1'][:50]}")
        return jsonify(results)

    else:
        print("Error: Invalid file format")
        return jsonify({"error": "Invalid file format"}), 400

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)