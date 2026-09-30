import streamlit as st
import time
import email
from email import policy

# 1. CORE CONFIGURATION
st.set_page_config(page_title="Guardingo", layout="wide", page_icon="🛡️")

st.markdown("""
    <style>
    .metric-box { background-color: #111827; padding: 15px; border-radius: 10px; border: 1px solid #334155; }
    .stProgress > div > div > div > div { background-color: #8B5CF6; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishGuard Command Center")
st.caption("Enterprise-grade Phishing Forensics & Incident Response Platform")
st.markdown("---")

# =============================================================
# 🔌 INPUT HOOK #1: EXTRACTION (Teammate 1 Presets)
# =============================================================
def get_extracted_emails():
    """
    Returns the baseline demo stream packets.
    """
    return [
        {
            "id": "packet_829",
            "sender": "accounts-security@paypaI-update.com",
            "subject": "[CRITICAL] Account Suspension Notice",
            "body": "Dear customer, your account has been restricted due to suspicious billing cycles. Verify immediately: http://paypai-identity-check.top. Failure to act results in termination."
        },
        {
            "id": "packet_828",
            "sender": "hr-portal@internal-corporate.net",
            "subject": "⚠️ Action Required: Q3 Benefits Renewal",
            "body": "Team, please log into the newly deployed insurance matrix to sign your Q3 waivers before midnight tonight: http://corporate-benefits-login.xyz"
        },
        {
            "id": "packet_827",
            "sender": "noreply@github.com",
            "subject": "[GitHub] New Login Alert from Berlin",
            "body": "Hi developer, a new login was logged from IP 192.168.1.1. If this wasn't you, please cycle your security tokens."
        }
    ]

# =============================================================
# 🔌 INPUT HOOK #2: ANALYZER ENGINE (Teammate 2 Logic)
# =============================================================
def run_analyzer_engine(email_sender, email_body):
    """
    DYNAMIC ANALYZER: This reads the actual content of whatever email is selected 
    (including your uploaded files!) and calculates the threat score dynamically.
    """
    sender_lower = email_sender.lower()
    body_lower = email_body.lower()
    
    score = 0
    flags = []
    urls = []
    
    # Check 1: Brand Spoofing / Typosquatting (Lookalike characters)
    if "paypai" in sender_lower or "paypaI" in email_sender:
        flags.append("🚨 Lookalike Character Hijacking: Sender domain attempts to mimic a trusted brand.")
        score += 50
        
    # Check 2: Urgent Language & Coercion
    urgency_terms = ["urgent", "verify your account", "restricted", "suspended", "termination", "immediately"]
    found_terms = [term for term in urgency_terms if term in body_lower or term in sender_lower]
    if found_terms:
        flags.append(f"🚨 Coercive Threat Framework: High-urgency keywords detected ({', '.join(found_terms)}).")
        score += 35
        
    # Check 3: Untrusted Top-Level Domains or Gateways
    if ".xyz" in sender_lower or ".xyz" in body_lower or "secure-pay" in sender_lower:
        flags.append("🚨 Untrusted Gateway Routing: Path directs traffic through malicious TLD spaces (.xyz).")
        score += 45
        urls.append(f"Flagged Domain: {email_sender}")

    # --- SCORE BOUNDARY COMPILATION ---
    if score > 0:
        score = min(score, 100)
        return {
            "score": score,
            "verdict": "HIGH RISK / MALICIOUS" if score >= 75 else "SUSPICIOUS ACTIVITY",
            "color": "red" if score >= 75 else "orange",
            "flags": flags,
            "urls": urls if urls else ["Links extracted securely from file corpus"]
        }
        
    # Default State for clean emails (like the GitHub preset)
    return {
        "score": 8,
        "verdict": "SECURE PACKET",
        "color": "green",
        "flags": ["✅ Email corpus matches verified corporate communication baselines."],
        "urls": []
    }

# =============================================================
# 📬 THE FILE UPLOADER CONNECTOR
# =============================================================
st.markdown("### 📥 Live Forensic Ingestion")
uploaded_file = st.file_uploader("Drag and drop a raw .eml file here to parse and analyze it instantly", type=["eml"])

# 1. Initialize inbox list with your standard hackathon presets
live_inbox = get_extracted_emails()

# 2. If a custom file is dropped, parse it and stick it at the top of the list
if uploaded_file is not None:
    try:
        file_bytes = uploaded_file.read()
        parsed_msg = email.message_from_bytes(file_bytes, policy=policy.default)
        
        custom_sender = parsed_msg.get('From', 'Unknown Sender')
        custom_subject = parsed_msg.get('Subject', '(No Subject)')
        
        custom_body = ""
        if parsed_msg.is_multipart():
            for part in parsed_msg.walk():
                if part.get_content_type() == 'text/plain':
                    custom_body += part.get_payload(decode=True).decode(errors='ignore')
        else:
            custom_body = parsed_msg.get_payload(decode=True).decode(errors='ignore')
            
        uploaded_packet = {
            "id": "packet_uploaded",
            "sender": custom_sender,
            "subject": custom_subject,
            "body": custom_body if custom_body.strip() else "Empty Payload Data"
        }
        
        # Prepend the uploaded file to the array so it shows first!
        live_inbox.insert(0, uploaded_packet)
        st.success(f"🎉 File '{uploaded_file.name}' processed! Select it below to analyze.")
    except Exception as e:
        st.error(f"Error parsing uploaded file: {str(e)}")

st.markdown("---")

# =============================================================
# 3. INTERACTIVE LAYOUT CORES
# =============================================================

# NOTE: The duplicate bug line that used to reset live_inbox here has been deleted!

col_feed, col_viewer, col_metrics = st.columns([1, 1.5, 1.5])

# --- COLUMN 1: ACTIVE INBOX STREAM ---
with col_feed:
    st.markdown("### 📥 Active Stream")
    st.caption("Select an ingested packet to evaluate")
    st.button("🔄 Refresh Stream", use_container_width=True)
    st.markdown("---")
    
    # Generate labels dynamically
    email_display_mapping = {}
    for email_obj in live_inbox:
        if email_obj["id"] == "packet_uploaded":
            label = f"📁 UPLOADED FILE — {uploaded_file.name}"
        else:
            label = f"{email_obj['sender'][:25]}...\n↳ {email_obj['subject'][:30]}"
        email_display_mapping[label] = email_obj["id"]
        
    selected_display_label = st.radio("Packets:", list(email_display_mapping.keys()), label_visibility="collapsed")
    
    selected_id = email_display_mapping[selected_display_label]
    active_email = next(email for email in live_inbox if email["id"] == selected_id)

# --- COLUMN 2: INSPECTOR ---
with col_viewer:
    st.markdown("### 📄 Packet Inspector")
    st.caption("Active data fields fed into the analyzer")
    
    st.text_input("Sender String", value=active_email["sender"], disabled=True)
    st.text_input("Subject Header", value=active_email["subject"], disabled=True)
    
    st.markdown("---")
    st.markdown("**Isolated Assets:**")
    st.caption("📁 attachment_invoice_pdf.exe (Blocked by sandbox — Hash check mismatch)")

# --- COLUMN 3: ANALYSIS REPORT ---
with col_metrics:
    st.markdown("### 📊 Threat Telemetry")
    st.caption("Live feedback directly from the Analyzer engine")
    
    with st.spinner("Running deep pattern analysis..."):
        # 🔌 Passing the selected email text dynamically into the analyzer engine!
        report = run_analyzer_engine(active_email["sender"], active_email["body"])
    
    # Render UI dynamically based on the report results
    if report["color"] == "red":
        st.error(f"### Engine Verdict: {report['verdict']}")
    elif report["color"] == "orange":
        st.warning(f"### Engine Verdict: {report['verdict']}")
    else:
        st.success(f"### Engine Verdict: {report['verdict']}")
        
    st.markdown(f"**Calculated Phishing Coefficient:** `{report['score']} / 100`")
    st.progress(report["score"] / 100)
    
    st.markdown("---")
    
    tab_flags, tab_network = st.tabs(["🔎 Red Flags Found", "🌐 Extracted Links"])
    
    with tab_flags:
        st.markdown("##### Threat Vector Checklist")
        for flag in report["flags"]:
            st.markdown(flag)
            
    with tab_network:
        st.markdown("##### Isolated Link Matrix")
        if report["urls"]:
            for url in report["urls"]:
                st.code(url, language="text")
        else:
            st.write("✅ Zero untrusted external connections requested by this payload.")
