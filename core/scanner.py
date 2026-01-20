# =========================================
# Temporal Network Enumerator
# Author: Thabet Hamdi
# =========================================

import time
import json
from collections import defaultdict
from datetime import datetime

import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
from rich import print

# ----------------------------------------
# CONFIG
# ----------------------------------------
OBSERVATION_TIME = 10           # you can modify the session duration seconds
ACTIVE_ARP_SWEEP = True          # minimal active probing
ARP_RANGE = "192.168.1.0/24"     # adjust the network for your lab
PCAP_FILTER = "tcp or udp or icmp or arp"  # BPF filter for sniffing

# ----------------------------------------
# DATA STRUCTURES
# ----------------------------------------
class NetworkState:
    def __init__(self):
        self.hosts = defaultdict(lambda: {"mac": None, "protocols": set(), "services": set()})

    def touch_host(self, ip):
        if not self.hosts[ip]["mac"]:
            self.hosts[ip]["mac"] = None
            self.hosts[ip]["protocols"] = set()
            self.hosts[ip]["services"] = set()

    def update_arp(self, ip, mac):
        if not self.hosts[ip]["mac"]:
            self.touch_host(ip)
        self.hosts[ip]["mac"] = mac
        self.hosts[ip]["protocols"].add("ARP")

    def update_packet(self, pkt):
        if scapy.ARP in pkt:
            ip = pkt[scapy.ARP].psrc
            mac = pkt[scapy.ARP].hwsrc
            self.update_arp(ip, mac)
        elif scapy.ICMP in pkt:
            ip = pkt[scapy.IP].src
            self.hosts[ip]["protocols"].add("ICMP")
        elif scapy.TCP in pkt:
            ip_src = pkt[scapy.IP].src
            port_dst = pkt[scapy.TCP].dport
            self.hosts[ip_src]["protocols"].add("TCP")
            self.hosts[ip_src]["services"].add(str(port_dst))
        elif scapy.UDP in pkt:
            ip_src = pkt[scapy.IP].src
            port_dst = pkt[scapy.UDP].dport
            self.hosts[ip_src]["protocols"].add("UDP")
            self.hosts[ip_src]["services"].add(str(port_dst))

# ----------------------------------------
# UTILITY FUNCTIONS
# ----------------------------------------
def active_arp_sweep(cidr, state):
    print("[yellow][*] Performing minimal ARP discovery[/yellow]")
    arp = scapy.ARP(pdst=cidr)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    answered, _ = scapy.srp(packet, timeout=2, verbose=False)

    for _, recv in answered:
        ip = recv.psrc
        mac = recv.hwsrc
        state.update_arp(ip, mac)

def diff_states(old, new):
    old_ips = set(old.keys())
    new_ips = set(new.keys())

    appeared = new_ips - old_ips
    disappeared = old_ips - new_ips
    common = old_ips & new_ips

    changes = {}
    for ip in common:
        if old[ip]["services"] != new[ip]["services"]:
            changes[ip] = {"old_services": old[ip]["services"], "new_services": new[ip]["services"]}

    return appeared, disappeared, changes

def draw_graph(state):
    G = nx.Graph()

    for ip, data in state.items():
        G.add_node(ip)
        for svc in data["services"]:
            svc_node = f"{ip}:{svc}"
            G.add_node(svc_node)
            G.add_edge(ip, svc_node)

    plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, k=0.6)
    nx.draw(G, pos, with_labels=True, node_size=900, font_size=8)
    plt.title("Temporal Network Enumeration Graph")
    plt.show()

# ----------------------------------------
# MAIN FUNCTION
# ----------------------------------------
def main():
    print("[bold cyan]Temporal Network Enumerator Started[/bold cyan]")
    print(f"[*] Observation time: {OBSERVATION_TIME} seconds")

    state = NetworkState()
    start_time = time.time()

    if ACTIVE_ARP_SWEEP:
        active_arp_sweep(ARP_RANGE, state)

    print("[*] Passive observation running...")
    try:
        scapy.sniff(filter=PCAP_FILTER, prn=state.update_packet, timeout=OBSERVATION_TIME, store=False)
    except Exception as e:
        print("[red]Error during observation: ", str(e))

    print("[green][+] Observation complete[/green]")

    session_state = dict(state.hosts)

    # Convert non-serializable set objects into lists for JSON
    serializable_state = {}
    for ip, data in session_state.items():
        serializable_state[ip] = {
            "mac": data.get("mac"),
            "protocols": list(data.get("protocols", [])),
            "services": list(data.get("services", [])),
        }

    with open("session.json", "w") as f:
        json.dump(serializable_state, f, indent=4)

    print("[*] Session saved to session.json")

    print("\n[bold]Discovered Hosts[/bold]")
    for ip, data in serializable_state.items():
        print(f" {ip} → MAC={data['mac']} Protocols={data['protocols']} Services={data['services']}")

    draw_graph(serializable_state)

if __name__ == "__main__":
    main()
