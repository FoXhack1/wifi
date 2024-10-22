import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)

def scan_wifi():
    # Définition de l'interface réseau à utiliser
    interface = "wlan1"  # Remplacez par votre interface réseau Wi-Fi

    # Scan des réseaux Wi-Fi
    logging.info("Début du scan des réseaux Wi-Fi...")
    packets = scapy.sniff(iface=interface, count=100, timeout=10)

    # Récupération des informations des réseaux Wi-Fi
    networks = []
    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            # Récupération de l'adresse MAC du réseau
            mac_address = packet[Dot11].addr3

            # Récupération du nom du réseau
            ssid = None
            for elt in packet[Dot11Elt]:
                if elt.ID == 0:
                    ssid = elt.info.decode("utf-8")
                    break

            # Ajout du réseau à la liste
            networks.append((mac_address, ssid))

    # Sauvegarde des informations dans un fichier .txt
    with open("networks.txt", "w") as f:
        for network in networks:
            f.write(f"{network[0]} - {network[1]}\n")

    logging.info("Scan des réseaux Wi-Fi terminé.")

if __name__ == "__main__":
    scan_wifi()
