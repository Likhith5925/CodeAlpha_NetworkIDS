from scapy.all import IP, TCP, UDP
import pandas as pd
import numpy as np

def extract_flow_features(packets, feature_names):
    flows = {}
    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            sport = pkt.sport if hasattr(pkt, 'sport') else 0
            dport = pkt.dport if hasattr(pkt, 'dport') else 0
            key = f"{pkt[IP].src}-{pkt[IP].dst}-{pkt[IP].proto}-{sport}-{dport}"
            
            if key not in flows:
                flows[key] = {'start': pkt.time, 'end': pkt.time, 'f_pkts': 0, 'b_pkts': 0, 
                              'f_bytes': 0, 'b_bytes': 0, 'iats': [], 'lens': [], 'syn': 0, 'dport': dport}
            f = flows[key]
            iat = float(pkt.time - f['end'])
            if iat > 0: 
                f['iats'].append(iat)
            f['end'] = pkt.time
            f['lens'].append(len(pkt))
            f['f_pkts'] += 1
            f['f_bytes'] += len(pkt)
            if TCP in pkt and pkt[TCP].flags.S: 
                f['syn'] += 1
                
    rows = []
    for f in flows.values():
        dur = float(f['end'] - f['start'])
        safe_dur = dur if dur > 0 else 0.000001
        rows.append({
            'Flow_Duration': dur * 1e6,
            'Total_Fwd_Packets': f['f_pkts'],
            'Total_Backward_Packets': f['b_pkts'],
            'Total_Length_of_Fwd_Packets': f['f_bytes'],
            'Total_Length_of_Bwd_Packets': f['b_bytes'],
            'Flow_IAT_Mean': np.mean(f['iats']) if f['iats'] else 0,
            'Flow_IAT_Std': np.std(f['iats']) if f['iats'] else 0,
            'Flow_Packets_s': (f['f_pkts'] + f['b_pkts']) / safe_dur,
            'Flow_Bytes_s': (f['f_bytes'] + f['b_bytes']) / safe_dur,
            'Packet_Length_Mean': np.mean(f['lens']) if f['lens'] else 0,
            'Packet_Length_Std': np.std(f['lens']) if f['lens'] else 0,
            'SYN_Flag_Count': f['syn'],
            'Destination_Port': f['dport']
        })
    df = pd.DataFrame(rows)
    for col in feature_names:
        if col not in df.columns: 
            df[col] = 0
    return df[feature_names]
