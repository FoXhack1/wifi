from scapy.all import *
import json

networks = []

def write_networks():
    with open("wifi_networks.json","r") as f:
        f.write(json.dumps(networks))
def WifiEnumeration(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()

        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")

        if "WPA/PSK" in crypto or "WPA2/PSK" in crypto:
            data = {"ssid":ssid, "bssid":bssid, "channel":channel, "crypto": crypto}
            networks.append(data)




if __name__ == "__main__":
    sniff(prn=WifiEnumeration, iface="wlan1", timeout=5)
    write_networks()
