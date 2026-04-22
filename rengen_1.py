from scapy.all import *
import numpy as np

# Routeringizning MAC manzili (BSSID)
TARGET_MAC = "00:11:22:33:44:55" # O'zingiznikiga o'zgartiring

signal_history = []

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11):
        if pkt.addr3 == TARGET_MAC:
            # Signal kuchini olish (RSSI)
            rssi = pkt.dBm_AntSignal
            signal_history.append(rssi)
            
            if len(signal_history) > 10:
                signal_history.pop(0)
                
            # Signalning o'zgaruvchanligini (Variance) hisoblash
            variance = np.var(signal_history)
            
            if variance > 2.5: # Bu chegara tajriba orqali aniqlanadi
                print(f"HARAKAT ANIQLANDI! (Signal o'zgarishi: {variance:.2f})")
            else:
                print(f"Tinchlik... (Signal barqaror: {variance:.2f})")

print("Devor ortini kuzatish boshlandi...")
sniff(iface="wlan0mon", prn=packet_handler, store=0)