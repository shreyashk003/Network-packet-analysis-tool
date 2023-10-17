import sys
from scapy.all import *
import os
from flask import Flask, render_template, request, jsonify
import threading
import time
from flask import send_file, make_response
from flask import Flask, render_template, request, jsonify


app = Flask(__name__)
packets = []
refresh_flag = False


def packet_sniffer(packet):
    global packets
    if IP in packet:
        if packet.haslayer(TCP):
            src_ip = packet[IPC].src
            src_port = packet[TCP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            packets.append(f"TCP Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
        elif packet.haslayer(UDP):
            src_ip = packet[IP].src
            src_port = packet[UDP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[UDP].dport
            packets.append(f"UDP Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")
    else:
        packets.append("Non-IP packet detected.")


def start_sniffing():
    global packets
    try:
        sniff(iface=interface, prn=packet_sniffer, timeout=5)
    except KeyboardInterrupt:
        pass


@app.route("/")
def index():
    return render_template("index.html", packets=packets)


@app.route("/start_sniffing", methods=["POST"])
def start_sniffing_route():
    global interface, refresh_flag, packets
    interface = request.form["interface"]
    refresh_flag = False
    packets = []
    sniffer_thread = threading.Thread(target=start_sniffing)
    sniffer_thread.start()
    return "Sniffing started."


@app.route("/refresh")
def refresh():
    global refresh_flag
    refresh_flag = True
    return jsonify({"refresh_flag": refresh_flag})


@app.route("/get_packets")
def get_packets():
    global packets
    return jsonify({"packets": packets})


@app.route("/download")
def download():
    global packets
    packet_list = "\n".join(packets)
    response = make_response(packet_list)
    response.headers.set(
        "Content-Disposition", "attachment", filename="packet_list.txt"
    )
    response.headers.set("Content-Type", "text/plain")
    return response


if __name__ == "__main__":
    app.run(port=5001)
