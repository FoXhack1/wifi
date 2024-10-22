import tkinter as tk
from tkinter import ttk
import pywifi
import pywifi.const as const
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import speedtest

class WiFiAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Wi-Fi Analyzer")

        # Create a notebook with three tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # Create a frame for the network list
        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="Networks")

        # Create a treeview to display the network list
        self.networks_tree = ttk.Treeview(self.network_frame, columns=("ESSID", "BSSID", "Security", "Signal", "Channel", "Frequency", "Encryption"))
        self.networks_tree.pack(fill="both", expand=True, padx=10, pady=10)

        # Create a frame for the graph
        self.graph_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.graph_frame, text="Graph")

        # Create a figure and axis for the graph
        self.figure, self.axis = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)

        # Create a frame for the adapter selection
        self.adapter_frame = ttk.Frame(self.network_frame)
        self.adapter_frame.pack(fill="x", padx=10, pady=10)

        # Create a label and listbox for adapter selection
        self.adapter_label = ttk.Label(self.adapter_frame, text="Select Wi-Fi Adapter:")
        self.adapter_label.pack(side="left")
        self.adapter_listbox = tk.Listbox(self.adapter_frame, width=20)
        self.adapter_listbox.pack(side="left")
        self.adapter_listbox.bind("<<ListboxSelect>>", self.adapter_selected)

        # Create a refresh button to refresh the adapter list
        self.refresh_button = ttk.Button(self.adapter_frame, text="Refresh", command=self.refresh_adapters)
        self.refresh_button.pack(side="left")

        # Create a button to scan for networks
        self.scan_button = ttk.Button(self.network_frame, text="Scan", command=self.scan_wifi_and_update_graph)
        self.scan_button.pack(fill="x", padx=10, pady=10)

        # Populate the adapter listbox
        self.wifi = pywifi.PyWiFi()
        self.adapters = self.wifi.interfaces()
        for adapter in self.adapters:
            self.adapter_listbox.insert("end", adapter.name())

        # Create a checkbox for continuous scanning
        self.continuous_scan_var = tk.IntVar()
        self.continuous_scan_checkbox = ttk.Checkbutton(self.network_frame, text="Continuous Scan", variable=self.continuous_scan_var, command=self.start_continuous_scan)
        self.continuous_scan_checkbox.pack(fill="x", padx=10, pady=10)

        # Create a frame for the speed test
        self.speed_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.speed_frame, text="Speed")

        # Create a button to test internet speed
        self.speed_button = ttk.Button(self.speed_frame, text="Test Internet Speed", command=self.test_internet_speed)
        self.speed_button.pack(fill="x", padx=10, pady=10)

        # Create a label to display the speed test results
        self.speed_label = ttk.Label(self.speed_frame, text="")
        self.speed_label.pack(fill="x", padx=10, pady=10)

    def start_continuous_scan(self):
        if self.continuous_scan_var.get():
            self.refresh_graph()
        else:
            if hasattr(self, 'after_id'):
                self.root.after_cancel(self.after_id)

    def refresh_graph(self):
        self.update_graph(self.scan_wifi())
        self.canvas.draw()
        self.after_id = self.root.after(1000, self.refresh_graph)  # call refresh_graph every 1000ms (1 second)

    def scan_wifi_and_update_graph(self):
        self.update_graph(self.scan_wifi())
        self.canvas.draw()

    def run(self):
        self.root.mainloop()

    def adapter_selected(self, event):
        self.selected_adapter = self.adapters[self.adapter_listbox.curselection()[0]]

    def refresh_adapters(self):
        # Clear the adapter listbox
        self.adapter_listbox.delete(0, "end")

        # Get the updated list of adapters
        self.wifi = pywifi.PyWiFi()
        self.adapters = self.wifi.interfaces()

        # Populate the adapter listbox
        for adapter in self.adapters:
            self.adapter_listbox.insert("end", adapter.name())



    def test_internet_speed(self):
        try:
            st = speedtest.Speedtest()
            
            st.get_servers(['speedtest-servers.cdn77.com'])
            st.get_best_server()
            print("Test de la vitesse Internet...")

            # Effectuer le test de vitesse de téléchargement
            download_speed = st.download() / 1000000  # Convertir en Mbps

            # Effectuer le test de vitesse de téléversement
            upload_speed = st.upload() / 1000000  # Convertir en Mbps

            # Imprimer les résultats
            print("Vitesse de téléchargement : {:.2f} Mbps".format(download_speed))
            print("Vitesse de téléversement : {:.2f} Mbps".format(upload_speed))

            # Update the speed label
            self.speed_label.config(text="Vitesse de téléchargement : {:.2f} Mbps\nVitesse de téléversement : {:.2f} Mbps".format(download_speed, upload_speed))

        except Exception as e:
            print("Une erreur s'est produite pendant le test de vitesse :", str(e))
            self.speed_label.config(text="Erreur : " + str(e))

    def scan_wifi(self):
        # Scan for Wi-Fi networks using the selected adapter
        self.selected_adapter.scan()
        results = self.selected_adapter.scan_results()
        if results:
            return results
        else:
            return []

    def update_graph(self, results):
        if results:
            # Clear the axis
            self.axis.clear()

            # Create a list of signal strengths in dBm
            signal_strengths = [result.signal for result in results]

            # Create a list of network names
            network_names = [result.ssid for result in results]

            # Define color thresholds for signal strength
            poor_threshold = -70
            fair_threshold = -50
            good_threshold = -30

            # Create a list of colors for each bar
            colors = []
            for signal in signal_strengths:
                if signal < poor_threshold:
                    colors.append('red')  # poor signal
                elif signal < fair_threshold:
                    colors.append('yellow')  # fair signal
                elif signal < good_threshold:
                    colors.append('green')  # good signal
                else:
                    colors.append('blue')  # excellent signal

            # Plot the signal strengths with colors
            self.axis.bar(range(len(network_names)), signal_strengths, color=colors)
            self.axis.set_xlabel("Network Name")
            self.axis.set_ylabel("Signal Strength (dBm)")
            self.axis.set_title("Wi-Fi Signal Strengths")

            # Set xticks and xticklabels
            self.axis.set_xticks(range(len(network_names)))
            self.axis.set_xticklabels(network_names, rotation=45, ha='right')

            # Use tight layout to ensure plot fits within figure area
            self.figure.tight_layout()

            # Update the canvas
            self.canvas.draw()

            # Update the networks treeview
            self.networks_tree.delete(*self.networks_tree.get_children())
            for result in results:
                essid = result.ssid
                bssid = result.bssid
                security = self.get_security(result.akm)
                signal = self.get_signal_strength(result.signal)
                channel = self.get_channel(result.freq)
                frequency = self.get_frequency(result.freq)
                encryption = self.get_encryption(result.cipher)
                self.networks_tree.insert("", "end", values=(essid, bssid, security, signal, channel, frequency, encryption))
        else:
            self.axis.clear()
            self.axis.set_title("No networks found")
            self.canvas.draw()
            self.networks_tree.delete(*self.networks_tree.get_children())

    def get_signal_strength(self, signal):
        if signal > -50:
            return "Excellent"
        elif signal > -60:
            return "Good"
        elif signal > -70:
            return "Fair"
        else:
            return "Poor"

    def get_channel(self, freq):
        # Convert frequency to channel
        if freq == 2412:
            return "1"
        elif freq == 2417:
            return "2"
        elif freq == 2422:
            return "3"
        elif freq == 2427:
            return "4"
        elif freq == 2432:
            return "5"
        elif freq == 2437:
            return "6"
        elif freq == 2442:
            return "7"
        elif freq == 2447:
            return "8"
        elif freq == 2452:
            return "9"
        elif freq == 2457:
            return "10"
        elif freq == 2462:
            return "11"
        else:
            return "Unknown"

    def get_encryption(self, cipher):
        if cipher == const.CIPHER_TYPE_NONE:
            return "Open"
        elif cipher == const.CIPHER_TYPE_WEP:
            return "WEP"
        elif cipher == const.CIPHER_TYPE_TKIP:
            return "WPA"
        elif cipher == const.CIPHER_TYPE_CCMP:
            return "WPA2"
        elif cipher == const.CIPHER_TYPE_GCMP:
            return "WPA3"
        else:
            return "Unknown"

    def get_security(self, akm):
        if akm == const.AKM_TYPE_NONE:
            return "Open"
        elif akm == const.AKM_TYPE_WPA:
            return "WPA"
        elif akm == const.AKM_TYPE_WPAPSK:
            return "WPA-PSK"
        elif akm == const.AKM_TYPE_WPA2:
            return "WPA2"
        elif akm == const.AKM_TYPE_WPA2PSK:
            return "WPA2-PSK"
        else:
            return "Unknown"

    def get_frequency(self, freq):
        if freq == 2412:
            return "2.4 GHz"
        elif freq == 5180:
            return "5 GHz"
        else:
            return "Unknown"

if __name__ == "__main__":
    root = tk.Tk()
    app = WiFiAnalyzer(root)
    app.run()
