import wifi

def scan_wifi():
    # Scan for WiFi networks
    networks = wifi.scan_interface('wlan1')

    # Print the names of the WiFi networks found
    print("WiFi networks found:")
    for network in networks:
        print(network.ssid)

if __name__ == "__main__":
    scan_wifi()
