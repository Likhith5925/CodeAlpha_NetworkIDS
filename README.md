🛡️ AI-Powered Network Intrusion Detection System (NIDS)

An enterprise-grade, machine learning-based Intrusion Detection System designed for continuous, real-time network traffic anomaly detection. Built for Kali Linux/Debian environments, this system utilizes a dual-stage ML architecture to identify zero-day vulnerabilities, DDoS attacks, Port Scanning, and Infiltration attempts.

🌟 Key Features

Continuous Background Monitoring: Operates silently as a systemd background daemon, capturing and analyzing traffic from boot to shutdown without requiring an active terminal window.

Dual-Stage ML Architecture: * Stage 1 (The Sentinel): A high-recall Binary Classifier (Random Forest) that instantly distinguishes between Benign and Malicious traffic.

Stage 2 (The Categorizer): A high-precision Multiclass Classifier (XGBoost/RF) that categorizes the specific attack vector.

Line-Rate Feature Extraction: Utilizes Scapy to intercept live packets and extract 78 statistical network flow features on the fly.

Actionable Intelligence (XAI): Automatically maps detected statistical anomalies to real-world mitigation strategies (e.g., firewall configurations).

Interactive Threat Dashboard: A secure, dark-themed Streamlit web console that provides real-time traffic visualizations, attack timelines, and threat distribution analytics.

🏗️ System Architecture

The project is decoupled into a Client-Server model for enterprise scalability:

The Daemon (continuous_sniffer.py): Runs infinitely in the background, sniffs packets, processes them through the .pkl ML models, and writes incidents to a local SQLite database.

The Dashboard (IDS.py): A lightweight, read-only Streamlit web interface that queries the database to display analytics and live alerts.

📂 Project Structure

AI-NIDS/
├── models/                     # Pre-trained ML artifacts (Joblib)
│   ├── best_binary_model.pkl   
│   ├── best_multiclass_model.pkl 
│   ├── scaler.pkl              
│   ├── le_multi.pkl            
│   └── features.pkl            
├── continuous_sniffer.py       # Background daemon script
├── sniffer.py                  # Scapy live-capture utility module
├── IDS.py                      # Streamlit interactive dashboard
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation


🚀 Installation & Setup Guide

1. Prerequisites

This system is optimized for Kali Linux or Debian-based distributions. Ensure you have Python 3 installed.

# Clone the repository
git clone [https://github.com/YOUR_USERNAME/AI-NIDS.git](https://github.com/YOUR_USERNAME/AI-NIDS.git)
cd AI-NIDS

# Install the required Python libraries
pip install -r requirements.txt


2. Configure the Background Daemon (Systemd)

To ensure the NIDS runs automatically from the moment the machine boots:

Create a service file:

sudo nano /etc/systemd/system/ai-ids.service


Paste the following configuration (Ensure you update the WorkingDirectory to your actual path):

[Unit]
Description=AI Intrusion Detection Background Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/your/AI-NIDS
ExecStart=/usr/bin/python3 continuous_sniffer.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target


Enable and start the service:

sudo systemctl daemon-reload
sudo systemctl enable ai-ids.service
sudo systemctl start ai-ids.service


3. Launching the Control Panel

With the daemon actively monitoring the network in the background, you can launch the secure UI to view live threats:

streamlit run IDS.py


Navigate to http://localhost:8501 in your browser.

Register a new administrator account and log in.

View real-time attack metrics, visualizations, and actionable mitigation steps.

📊 Dataset & Model Training

The models powering this system were trained on the comprehensive CICIDS 2017 Dataset. Synthetic Minority Over-sampling Technique (SMOTE) was utilized during training to ensure high sensitivity to rare attack classes like Infiltration and Heartbleed, maintaining an overall baseline accuracy of 98.4%.

👨‍💻 Credits

Developed by Nara Likhith & Shiva Kumar
