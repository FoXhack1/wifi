from scapy.all import *

# Définition de la fonction pour scanner les réseaux
def scan_networks():
    # Création d'une liste pour stocker les adresses MAC
    mac_addresses = []

    # Scan des réseaux
    for packet in sniff(iface="wlan1", count=100):
        # Vérification si le paquet est un paquet ARP
        if packet.haslayer(ARP):
            # Récupération de l'adresse MAC
            mac_address = packet.hwsrc
            # Ajout de l'adresse MAC à la liste
            mac_addresses.append(mac_address)

    # Retour de la liste des adresses MAC
    return mac_addresses

# Appel de la fonction pour scanner les réseaux
mac_addresses = scan_networks()

# Affichage des adresses MAC
for mac_address in mac_addresses:
    print(mac_address)
