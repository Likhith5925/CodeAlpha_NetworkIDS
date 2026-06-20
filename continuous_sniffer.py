import time
import sqlite3
import joblib
import pandas as pd
from datetime import datetime
from sniffer import capture_traffic # Your existing, untouched sniffer.py

# Load your serialized ML artifacts
models = {
    "bin": joblib.load("models/best_binary_model.pkl"),
    "multi": joblib.load("models/best_multiclass_model.pkl"),
    "scaler": joblib.load("models/scaler.pkl"),
    "le": joblib.load("models/le_multi.pkl"),
    "features": joblib.load("models/features.pkl")
}

def init_db():
    conn = sqlite3.connect('ids_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (time TEXT, type TEXT, status TEXT, suggestion TEXT)''')
    conn.commit()
    conn.close()

def get_suggestion(attack_type):
    suggestions = {
        "DDoS": "Action: Enable Rate Limiting, filter UDP/ICMP traffic.",
        "PortScan": "Action: Close non-essential ports, implement 'Port Knocking'.",
        "Botnet": "Action: Isolate infected endpoints, block C&C IPs.",
        "Infiltration": "Action: Revoke compromised credentials, audit logs.",
        "Web Attack": "Action: Update WAF, patch SQLi/XSS vulnerabilities."
    }
    return suggestions.get(attack_type, "Action: Perform standard security audit.")

def log_incident(a_type, status):
    sugg = get_suggestion(a_type)
    conn = sqlite3.connect('ids_data.db')
    c = conn.cursor()
    c.execute('INSERT INTO logs VALUES (?,?,?,?)', 
              (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), a_type, status, sugg))
    conn.commit()
    conn.close()

def run_daemon(interface="eth0", chunk_duration=30, sensitivity=0.5):
    print(f"[*] Starting AI-NIDS background daemon on interface: {interface}")
    init_db()
    
    while True:
        try:
            # Capture traffic in chunks
            df = capture_traffic(interface, chunk_duration, models['features'])
            
            if not df.empty:
                X_sc = models['scaler'].transform(df[models['features']])
                bin_probs = models['bin'].predict_proba(X_sc)[:, 1]
                multi_preds = models['multi'].predict(X_sc)
                
                for i in range(len(bin_probs)):
                    is_attack = bin_probs[i] >= (1.0 - sensitivity)
                    if is_attack:
                        label = models['le'].inverse_transform([multi_preds[i]])[0]
                        log_incident(label, "Alert")
                        print(f"[!] Threat Logged: {label} at {datetime.now()}")
                        
        except Exception as e:
            print(f"[-] Error in sniffing loop: {e}")
            time.sleep(5) # Prevent crash loops

if __name__ == "__main__":
    # Change "eth0" to "lo" if you are testing locally on Kali
    run_daemon(interface="eth0", chunk_duration=30)
