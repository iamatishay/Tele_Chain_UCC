import streamlit as st
import requests
from datetime import datetime

API_URL = "http://127.0.0.1:8000"

st.title("📲 Simulate SMS & Verify Ledger")

# Inputs
phone = st.text_input("Customer Phone", value="9876543210")
principal_id = st.text_input("Principal ID", value="PR-1")
header = st.text_input("Header", value="HDR-1")
message = st.text_area("Message Content", value="Hello! This is a test SMS.")
operator = st.selectbox("Operator", ["OperatorA", "OperatorB"])

# Button to simulate SMS
if st.button("Send SMS"):
    payload = {
        "operator": operator,
        "phone": phone,
        "principal_id": principal_id,
        "header": header,
        "message": message
    }
    try:
        res = requests.post(f"{API_URL}/sms/send", json=payload)
        if res.status_code == 200:
            data = res.json()
            st.success(f"✅ SMS simulated successfully! TXID: {data['txid']}")
        else:
            st.error(f"❌ Error {res.status_code}: {res.text}")
    except Exception as e:
        st.error(f"⚠️ Failed to send SMS: {e}")

# Button to check ledger
if st.button("Check Ledger"):
    try:
        res = requests.get(f"{API_URL}/ledger")
        if res.status_code == 200:
            ledger = res.json()
            # Filter SMS-related entries
            sms_entries = [tx for tx in ledger if tx.get("type") in ["sms_sent", "sms_rejected"]]
            st.subheader("📜 SMS Ledger Entries")
            if sms_entries:
                for tx in sms_entries[-5:]:  # last 5 entries
                    status = "✅ Sent" if tx["type"]=="sms_sent" else "❌ Rejected"
                    granted_at = tx.get("consent_granted_at", "N/A")
                    st.write(f"**Phone Hash:** {tx['phone_hash'][:8]}... | **Principal:** {tx['principal_id']} | **Header:** {tx['header']} | **Operator:** {tx['operator']} | **Status:** {status} | **Consent Granted At:** {granted_at}")
            else:
                st.info("No SMS entries found in ledger.")
        else:
            st.error(f"❌ Failed to fetch ledger: {res.text}")
    except Exception as e:
        st.error(f"⚠️ Ledger request failed: {e}")
