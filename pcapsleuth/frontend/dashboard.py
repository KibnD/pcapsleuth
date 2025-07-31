import streamlit as st
import tempfile
import os
import sys
import pandas as pd
import plotly.graph_objects as go
import streamlit.components.v1 as components
from datetime import datetime
# Append root project directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from pcapsleuth.core import PcapAnalysisEngine
from pcapsleuth.reporting import generate_report
from pcapsleuth.models import Config

# ----------------------
# Page Configuration
# ----------------------
st.set_page_config(
    page_title="🕵️ PcapSleuth Dashboard",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------------------
# Custom Full Dark Theme CSS
# ----------------------
st.markdown(
    """
    <style>
    html, body, [data-testid="stApp"] {
        background-color: #000000;
        color: #00ff66;
        font-family: 'Courier New', Courier, monospace;
    }

    section[data-testid="stSidebar"], .css-1d391kg, .st-emotion-cache-1cypcdb {
        background-color: #000 !important;
        color: #00ff66 !important;
    }

    .stButton > button, .stDownloadButton > button {
        background-color: #00ff66 !important;
        color: #000 !important;
        font-weight: bold;
        border-radius: 10px;
        border: none;
        padding: 0.5rem 1rem;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        background-color: #00cc55 !important;
        color: #000 !important;
    }

    .stTabs [data-baseweb="tab"] {
        background-color: #001f1f !important;
        color: #00ff66 !important;
        padding: 10px;
        border-radius: 5px 5px 0 0;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00ff66 !important;
        color: #000000 !important;
        font-weight: bold;
    }

    iframe[data-testid="stDataFrame"] {
        background-color: #000 !important;
        border: 1px solid #00ff66 !important;
        border-radius: 10px !important;
    }

    iframe[data-testid="stDataFrame"] body {
        color: #00ff66 !important;
        background-color: #000 !important;
        font-family: 'Courier New', Courier, monospace !important;
    }

    .stMarkdown, .css-ffhzg2 {
        color: #00ff66 !important;
    }

    .css-1r6slb0 input, .stSelectbox > div > div {
        background-color: #000 !important;
        color: #00ff66 !important;
    }

    .stFileUploader {
        background-color: #000 !important;
        border: 2px dashed #00ff66 !important;
        border-radius: 10px;
        padding: 1rem;
    }

    .stFileUploader label, .stFileUploader span, .stFileUploader div {
        color: #00ff66 !important;
    }
    div[data-testid="stFileUploader"] > div {
        background-color: #000 !important;
        border-radius: 10px !important;
        padding: 1rem !important;
        color: #00ff66 !important;
    }


    .st-emotion-cache-ocqkz7 {
        background-color: #000 !important;
        color: #00ff66 !important;
    }

    [data-testid="metric-container"] {
        background-color: #000 !important;
        color: #00ff66 !important;
        border: 1px solid #00ff66 !important;
        border-radius: 10px;
        padding: 10px;
    }
    .st-emotion-cache-1h9usn5 {
        background-color: #000 !important;
        color: #00ff66 !important;
        border: 1px solid #00ff66 !important;
        border-radius: 10px;
        padding: 10px;
    }



    .st-emotion-cache-1wmy9hl {
        background-color: #000 !important;
    }

    .stAlert, .stAlert > div {
        background-color: #001a00 !important;
        color: #00ff66 !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ----------------------
# Sidebar
# ----------------------
st.sidebar.title("🕵️‍♂️ PcapSleuth")
st.sidebar.markdown("Analyze .pcap files for network forensics and threats.")
st.sidebar.markdown("---")
report_format = st.sidebar.selectbox("Report format", ["text", "markdown", "json", "html"])

# ----------------------
# File Upload
# ----------------------
st.title("🕵️‍♂️ PcapSleuth network forensics and threats.")
st.markdown("### Choose a PCAP file")

uploaded_file = st.file_uploader("", type="pcap", label_visibility="collapsed")

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_file_path = tmp_file.name

    st.success("File uploaded successfully. Starting analysis...")

    # Run analysis
    config = Config()
    engine = PcapAnalysisEngine(config)
    results = engine.analyze_pcap(tmp_file_path)
    threat_detected = (
        results.dns_tunneling.total_suspicious_queries > 0 or
        len(results.icmp_floods.potential_floods) > 0 or
        results.port_scanning.total_scan_attempts > 0
    )

    if threat_detected:
        st.toast("🚨 Threats detected in this capture! Check the 🚨 Threats tab.", icon="⚠️")

    st.markdown("---")
    st.header("📊 Analysis Summary")
    # Threat detection overview
    has_threats = (
        results.dns_tunneling.total_suspicious_queries > 0 or
        len(results.icmp_floods.potential_floods) > 0 or
        results.port_scanning.total_scan_attempts > 0
    )

    if has_threats:
        st.error("🚨 **Threats detected in this capture! Review details in each tab.**")
    else:
        st.success("✅ No threats detected.")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Packets", f"{results.packet_count:,}")
        st.caption("🧾 Total number of packets in the capture file.")

    with col2:
        st.metric("Top Talkers", len(results.top_talkers))
        st.caption("📡 Unique IP conversations seen the most.")

    with col3:
        st.metric("DNS Queries", len(results.dns_queries))
        st.caption("🌍 Count of DNS lookups (domain resolutions).")

    threat_count = sum([
        results.dns_tunneling.total_suspicious_queries > 0,
        len(results.icmp_floods.potential_floods) > 0,
        results.port_scanning.total_scan_attempts > 0
    ])
    # Risk Level Logic
    if threat_count == 0:
        risk_level = " No Risk"
        risk_color = "green"
    elif threat_count == 1:
        risk_level = " Low Risk"
        risk_color = "blue"
    elif threat_count == 2:
        risk_level = " Medium Risk"
        risk_color = "orange"
    elif threat_count == 3:
        risk_level = " High Risk"
        risk_color = "red"
    else:
        risk_level = "🚨 Critical Risk"
        risk_color = "darkred"

    delta_color = "inverse" if threat_count > 0 else "normal"  # red if non-zero
    with col4:
        st.metric("Threats Detected", threat_count, delta=None, delta_color=delta_color)
        st.caption("🚨 Count of major threats like floods, scans, tunneling.")
    
    # threats badge
    st.markdown("### 🛡️ Risk Assessment")
    st.markdown(
        f"<div style='padding:10px; background-color:{risk_color}; color:white; border-radius:10px; text-align:center;'>"
        f"<strong>{risk_level}</strong></div>",
        unsafe_allow_html=True
    )

    # Tabs for each analyzer
    tab0, tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🚨 Threats", "📈 Basic Stats", "🌐 DNS", "📶 ICMP", "🔍 Port Scans", "📡 HTTP", "🔐 TLS"
    ])

    with tab0:
        st.subheader("🚨 Threats Overview")

        if not has_threats:
            st.success("✅ No threats were detected in this analysis.")
        else:
            if results.dns_tunneling.total_suspicious_queries > 0:
                st.warning(f"🔎 Suspicious DNS Queries: {results.dns_tunneling.total_suspicious_queries}")
                with st.expander("🔍 View Suspicious DNS Query Details"):
                    st.json(results.dns_tunneling.high_entropy_queries)

            if results.icmp_floods.potential_floods:
                st.warning("🌊 ICMP Flooding Detected")
                with st.expander("📥 View ICMP Flood Details"):
                    st.json(results.icmp_floods.potential_floods)

            if results.port_scanning.total_scan_attempts > 0:
                st.warning(f"🔍 Port Scans Detected: {results.port_scanning.total_scan_attempts} attempts")
                if results.port_scanning.rapid_scans:
                    with st.expander("**⚡ Rapid Scans**"):
                        st.dataframe(pd.DataFrame(results.port_scanning.rapid_scans))
                if results.port_scanning.tcp_syn_scans:
                    with st.expander("**🔁 TCP SYN Scans**"):
                        st.json(results.port_scanning.tcp_syn_scans[:3])
                if results.port_scanning.udp_scans:
                    with st.expander("**📤 UDP Scans**"):
                        st.json(results.port_scanning.udp_scans[:3])

    with tab1:
        st.subheader("📈 Basic Protocol Distribution")
        df_proto = pd.DataFrame(results.protocol_distribution.items(), columns=["Protocol", "Packets"])
        with st.expander("click to view details"):
            st.dataframe(df_proto)

        st.subheader("📨 Top Talkers")
        df_talkers = pd.DataFrame(results.top_talkers, columns=["Conversation", "Packets"])
        with st.expander("click to view details"):
            st.dataframe(df_talkers)

    with tab2:
        st.subheader("🌐 Top DNS Queries")
        df_dns = pd.DataFrame(results.dns_queries, columns=["Domain", "Count"])
        with st.expander("click to view details"):
            st.dataframe(df_dns)

        st.subheader("⚠️ DNS Tunneling Detection")
        if results.dns_tunneling.total_suspicious_queries:
            st.warning(f"Suspicious Queries Detected: {results.dns_tunneling.total_suspicious_queries}")
            with st.expander("click to view details"):    
                st.json(results.dns_tunneling.high_entropy_queries)
        else:
            st.success("No suspicious DNS tunneling detected.")

    with tab3:
        st.subheader("📶 ICMP Activity")
        st.metric("Total ICMP Packets", results.icmp_floods.total_icmp_packets)
        st.subheader("🌊 Potential Floods")
        if results.icmp_floods.potential_floods:
            with st.expander("click to view details"):
                st.json(results.icmp_floods.potential_floods)
        else:
            st.success("No ICMP floods detected.")

    with tab4:
        st.subheader("🔍 Port Scanning Activity")
        st.metric("Total Scan Attempts", results.port_scanning.total_scan_attempts)

        # Rapid scans
        if results.port_scanning.rapid_scans:
            st.markdown("#### ⚡ Rapid Scans Detected")
            df_rapid = pd.DataFrame(results.port_scanning.rapid_scans)
            with st.expander("click to view details"):
                st.dataframe(df_rapid)

        # TCP SYN Scans
        if results.port_scanning.tcp_syn_scans:
            st.markdown("#### 🔁 TCP SYN Scans")
            with st.expander("click to view details"):
                st.json(results.port_scanning.tcp_syn_scans[:5])

        # UDP Scans
        if results.port_scanning.udp_scans:
            st.markdown("#### 📤 UDP Scans")
            with st.expander("click to view details"):
                st.json(results.port_scanning.udp_scans[:5])

        # Stealth Scans
        if results.port_scanning.stealth_scans:
            st.markdown("#### 🕵️ Stealth Scans")
            with st.expander("click to view details"):
                st.json(results.port_scanning.stealth_scans[:5])

        # Discovered Open Ports
        if results.port_scanning.open_ports:
            st.markdown("#### 🟢 Discovered Open Ports")
            open_ports_data = []
            for host, port_info in results.port_scanning.open_ports.items():
                for proto, ports in port_info.items():
                    open_ports_data.append({
                        "Host": host,
                        "Protocol": proto,
                        "Ports": ', '.join(str(p) for p in ports)
                    })
            df_open_ports = pd.DataFrame(open_ports_data)
            with st.expander("click to view details"):
                st.dataframe(df_open_ports)
        else:
            st.success("✅ No open ports detected.")

    with tab5:
        st.subheader("📡 HTTP Analysis")
        st.metric("Total HTTP Requests", results.http_analysis.total_http_requests)
        df_methods = pd.DataFrame(results.http_analysis.http_methods.items(), columns=["Method", "Count"])
        with st.expander("click to view details"):
            st.dataframe(df_methods)

        df_hosts = pd.DataFrame(results.http_analysis.hostnames.items(), columns=["Host", "Requests"])
        st.write("### Top Hostnames")
        with st.expander("click to view details"):
            st.dataframe(df_hosts)

        if results.http_analysis.errors:
            st.warning("HTTP Errors")
            with st.expander("click to view details"):
                st.json(results.http_analysis.errors[:5])

    with tab6:
        st.subheader("🔐 TLS Sessions")
        st.metric("Total TLS Sessions", results.tls_analysis.total_tls_sessions)

        df_versions = pd.DataFrame(results.tls_analysis.tls_versions.items(), columns=["TLS Version", "Count"])
        st.write("### TLS Versions")
        with st.expander("click to view details"):
            st.dataframe(df_versions)

        df_hosts = pd.DataFrame(results.tls_analysis.certificate_hosts.items(), columns=["SNI Host", "Count"])
        st.write("### Certificate Hosts")
        with st.expander("click to view details"):
            st.dataframe(df_hosts)

        if results.tls_analysis.errors:
            st.warning("TLS Errors")
            with st.expander("click to view details"):
                st.json(results.tls_analysis.errors[:5])

    # Generate report
    st.markdown("---")
    st.subheader("📤 Download Report")
    report_content = generate_report(results, report_format)
    file_name = f"pcapsleuth_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{report_format if report_format != 'text' else 'txt'}"
    st.download_button(
        label=f"Download {report_format.capitalize()} Report",
        data=report_content,
        file_name=file_name,
        mime="text/plain" if report_format in ["text", "markdown"] else "application/json"
    )
else:
    st.info("Please upload a PCAP file to start analysis.")
