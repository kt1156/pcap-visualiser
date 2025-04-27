# pcap-visualiser

This is a Python project built using [Flask](https://flask.palletsprojects.com/), designed to process and visaulise PCAP files for analysis alongside the [osMUD-UI2](https://github.com/kt1156/osMUD-UI2) interface.

## Included Libraries

- [Flask](https://flask.palletsprojects.com/)
- [Flask-CORS](https://flask-cors.readthedocs.io/)
- [PyShark](https://github.com/KimiNewt/pyshark)
- [Matplotlib](https://matplotlib.org/)
- [Seaborn](https://seaborn.pydata.org/)
- [Werkzeug](https://werkzeug.palletsprojects.com/)

## Getting Started

First, install the required libraries:

```bash
pip install flask flask-cors pyshark matplotlib seaborn werkzeug 
```

Then, start the API server by running:
```bash
python server.py
```
Make sure the uploads/ folder exists — it will be used to store incoming PCAP files.

On macOS, you might need to manually adjust permissions with chmod 777 uploads/ if you encounter file write permission issues.

The server will start on http://localhost:5001.

You can then interact with the /api/processPcap endpoint by sending two .pcap files (as pcap1 and pcap2) via a POST request.

## Features
- Upload and process two .pcap files.
- Automatically generate:
    - Application protocol graphs
    - Transport protocol graphs
    - Combined graphs
    - Latency graph
    - Bandwidth graph

Graphs are returned as Base64-encoded images in the API response.

##  File Structure
server.py: Main Flask server handling uploads and processing requests.

process_pcap.py: Functions for analysing PCAP files and generating graphs.

script.py: A helper script to generate mock PCAP files for before/after MUD is applied.

uploads/: Folder where uploaded PCAPs are stored temporarily.

## Mock Data Generation
You can generate mock before_mud.pcap and after_mud.pcap files using:
```bash
python script.py
```
This script uses Scapy to simulate common network traffic, ideal for testing.

## Notes

Make sure tshark (Wireshark command line tool) is installed if you encounter issues with PyShark.
You can install tshark using:

```bash
brew install wireshark
```