import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from datetime import datetime

# Database Initialization for Users and Logs
def init_db():
    conn = sqlite3.connect('ids_data.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (user TEXT PRIMARY KEY, pass TEXT)')
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (time TEXT, type TEXT, status TEXT, suggestion TEXT)''')
    conn.commit()
    conn.close()

st.set_page_config(page_title="AI-IDS Secure Console", layout="wide")
init_db()

# --- Access Control Logic ---
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False

if not st.session_state['logged_in']:
    st.markdown("<h1 style='text-align: center;'> 🛡️ AI-IDS Access Control</h1>", unsafe_allow_html=True)
    tab1, tab2 = st.tabs([" 🔑 Login", " 📝 Register"])
    
    with tab1:
        u_l = st.text_input("Username", key="l_u")
        p_l = st.text_input("Password", type="password", key="l_p")
        if st.button("Login", use_container_width=True):
            hpw = hashlib.sha256(p_l.encode()).hexdigest()
            conn = sqlite3.connect('ids_data.db')
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE user=? AND pass=?', (u_l, hpw))
            if c.fetchone():
                st.session_state['logged_in'] = True
                st.rerun()
            else: 
                st.error("Invalid credentials.")
            conn.close()
            
    with tab2:
        u_r = st.text_input("New Username", key="r_u")
        p_r = st.text_input("New Password", type="password", key="r_p")
        if st.button("Create Account", use_container_width=True):
            hpw = hashlib.sha256(p_r.encode()).hexdigest()
            conn = sqlite3.connect('ids_data.db')
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users VALUES (?,?)', (u_r, hpw))
                conn.commit()
                st.success("Account created! Please switch to the Login tab.")
            except sqlite3.IntegrityError: 
                st.error("Username already exists.")
            finally: 
                conn.close()

# --- Main Dashboard Logic ---
else:
    st.sidebar.title("IDS Control Panel")
    nav = st.sidebar.radio("Navigation", ["Dashboard", "Live Network Logs", "Logout"])
    
    if nav == "Logout":
        st.session_state['logged_in'] = False
        st.rerun()
        
    elif nav == "Dashboard":
        st.title(" 🛡️ Project Overview: AI-Powered IDS")
        st.write("""
        This console monitors the AI-NIDS background daemon. The machine learning models 
        (Random Forest/XGBoost) are currently analyzing traffic on the network interface 
        and logging threats directly to the local database.
        """)
        st.info(" 💡 The sniffer is running securely in the background via systemd.")

    elif nav == "Live Network Logs":
        st.title(" 🔍 Live Threat Audit & Analytics")
        st.write("Displaying real-time incidents and traffic patterns captured by the background daemon.")
        
        # Refresh button to fetch new DB entries
        if st.button("🔄 Refresh Logs"):
            st.rerun()
            
        conn = sqlite3.connect('ids_data.db')
        log_df = pd.read_sql('SELECT * FROM logs ORDER BY time DESC', conn)
        conn.close()
        
        if not log_df.empty:
            st.error(f"⚠️ {len(log_df)} Total Incidents Logged")
            
            # --- Visualizations Section ---
            # Convert time string to datetime objects for accurate plotting
            log_df['time'] = pd.to_datetime(log_df['time'])
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("📊 Threat Type Breakdown")
                type_counts = log_df['type'].value_counts()
                st.bar_chart(type_counts)
            
            with col2:
                st.subheader("📈 Attack Timeline")
                # Create a timeline dataframe, counting incidents per minute
                timeline_df = log_df.copy()
                timeline_df['count'] = 1
                timeline_df = timeline_df.set_index('time').resample('1min').sum(numeric_only=True).fillna(0)
                st.line_chart(timeline_df['count'])
            
            st.markdown("---")
            st.subheader("📝 Detailed Incident Log")
            
            # Convert datetime back to a clean string format for the table view
            display_df = log_df.copy()
            display_df['time'] = display_df['time'].dt.strftime('%Y-%m-%d %H:%M:%S')
            st.dataframe(display_df, use_container_width=True)
            
        else:
            st.success("✅ No threats detected currently. Network is operating normally.")
