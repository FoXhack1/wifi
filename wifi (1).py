from scapy.all import *
import json

networks = []

def write_networks():
    # Open the file in write mode
    with open("wifi_networks.json", "w") as f:
        # Write the JSON data to the file
        json.dump(networks, f, indent=4)  # Use json.dump instead of json.dumps

def WifiEnumeration(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")

        # Check if crypto is a list or set, convert to list if necessary
        if isinstance(crypto, set):
            crypto = list(crypto)

        if "WPA/PSK" in crypto or "WPA2/PSK" in crypto:
            data = {"ssid": ssid, "bssid": bssid, "channel": channel, "crypto": crypto}
            networks.append(data)

if __name__ == "__main__":
    sniff(prn=WifiEnumeration, iface="wlan1", timeout=5)
    write_networks()
