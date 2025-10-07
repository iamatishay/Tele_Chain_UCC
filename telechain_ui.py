import streamlit as st
import requests
from datetime import datetime

API_URL = "http://127.0.0.1:8000"

st.set_page_config(page_title="📡 Telechain Prototype", layout="centered")
st.title("📡 Telechain Prototype – Blockchain-based Consent Management")
st.markdown("A decentralized workflow for consent, scrubbing, and campaign execution using blockchain logic.")

# -------------------- Session State Initialization --------------------
if "token" not in st.session_state:
    st.session_state.token = None
if "phone" not in st.session_state:
    st.session_state.phone = None
if "last_otp" not in st.session_state:
    st.session_state.last_otp = None

# -------------------- Helper Functions --------------------
def check_api_health():
    try:
        res = requests.get(f"{API_URL}/ledger", timeout=3)
        return res.status_code == 200
    except:
        return False

def api_headers():
    if st.session_state.token:
        return {"Authorization": f"Bearer {st.session_state.token}"}
    return {}

# -------------------- Sidebar Navigation --------------------
menu = st.sidebar.radio("Navigate", ["Setup", "Send Consent Request", "Grant Consent", "Customer Dashboard", "View Ledger"])

# -------------------- Setup --------------------
if menu == "Setup":
    st.header("⚙️ Setup – Register Entities")
    st.write("Register telemarketers, principals, and headers to enable testing.")

    tab1, tab2, tab3 = st.tabs(["Register Telemarketer", "Register Principal", "Register Header"])

    with tab1:
        st.subheader("📞 Register Telemarketer")
        tm_name = st.text_input("Telemarketer Name", value="Random TM", key="tm_name")
        trai_id = st.text_input("TRAI ID", value="TRAI-RND-123", key="trai_id")
        deposit = st.number_input("Deposit (e.g., 1000)", value=1000, min_value=0, key="deposit")
        if st.button("Register Telemarketer", key="btn_tm"):
            payload = {"name": tm_name, "trai_id": trai_id, "deposit": deposit}
            try:
                res = requests.post(f"{API_URL}/telemarketer/register", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    st.success(f"✅ Telemarketer registered! ID: {data['telemarketer_id']}, TXID: {data['txid']}")
                else:
                    st.error(f"❌ Error {res.status_code}: {res.text}")
            except Exception as e:
                st.error(f"⚠️ Request failed: {e}")

    with tab2:
        st.subheader("🏢 Register Principal")
        principal_name = st.text_input("Principal Name", value="Random Corp", key="principal_name")
        if st.button("Register Principal", key="btn_pr"):
            payload = {"name": principal_name}
            try:
                res = requests.post(f"{API_URL}/principal/register", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    st.success(f"✅ Principal registered! ID: {data['principal_id']}, TXID: {data['txid']}")
                else:
                    st.error(f"❌ Error {res.status_code}: {res.text}")
            except Exception as e:
                st.error(f"⚠️ Request failed: {e}")

    with tab3:
        st.subheader("📝 Register Header")
        principal_id = st.text_input("Principal ID (e.g., PR-1)", value="PR-1", key="header_principal")
        header = st.text_input("Header (e.g., RND-HDR)", value="RND-HDR", key="header_input")
        if st.button("Register Header", key="btn_header"):
            payload = {"principal_id": principal_id, "header": header}
            try:
                res = requests.post(f"{API_URL}/principal/register_header", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    st.success(f"✅ Header '{header}' registered under {principal_id}! TXID: {data['txid']}")
                else:
                    st.error(f"❌ Error {res.status_code}: {res.text}")
            except Exception as e:
                st.error(f"⚠️ Request failed: {e}")

# -------------------- Send Consent Request --------------------
elif menu == "Send Consent Request":
    st.header("📩 Send Consent Request")
    st.write("Trigger consent acquisition for a customer via SMS.")

    principal_id = st.text_input("Principal ID", value="PR-1", key="consent_req_principal")
    header = st.text_input("Header ID", value="HDR-1", key="consent_req_header")
    phone = st.text_input("Customer Phone", value="9876543210", key="consent_req_phone")
    channel = st.selectbox("Channel", ["SMS", "VOICE"], key="consent_req_channel")

    if st.button("Send Consent Request", key="btn_send_consent"):
        payload = {"principal_id": principal_id, "header": header, "phone": phone}
        try:
            res = requests.post(f"{API_URL}/consent/request", json=payload)
            if res.status_code == 200:
                data = res.json()
                st.session_state.last_otp = data['otp']
                st.success(f"✅ OTP sent successfully! (Demo OTP: {data['otp']})")
            else:
                st.error(f"❌ Error {res.status_code}: {res.text}")
        except Exception as e:
            st.error(f"⚠️ Request failed: {e}")

# -------------------- Grant Consent --------------------
elif menu == "Grant Consent":
    st.header("🔐 Grant Consent")
    st.write("Validate OTP to register consent.")

    with st.form("grant_consent_form"):
        principal_id = st.text_input("Principal ID", value="PR-1", key="grant_principal")
        header = st.text_input("Header ID", value="HDR-1", key="grant_header")
        phone = st.text_input("Customer Phone", value="9876543210", key="grant_phone")
        otp = st.text_input("Enter OTP", value=st.session_state.get("last_otp", "123456"), key="grant_otp")
        submitted = st.form_submit_button("Verify & Grant")

        if submitted:
            payload = {"principal_id": principal_id, "header": header, "phone": phone, "otp": otp}
            try:
                res = requests.post(f"{API_URL}/consent/grant", json=payload)
                if res.status_code == 200:
                    st.success("✅ Consent granted successfully!")
                else:
                    st.error(f"❌ Error {res.status_code}: {res.text}")
            except Exception as e:
                st.error(f"⚠️ Request failed: {e}")

# -------------------- Customer Dashboard --------------------
elif menu == "Customer Dashboard":
    st.header("👤 Customer Dashboard")
    st.write("Login to view and manage your consent preferences.")

    # Debug API connection
    if st.checkbox("Debug: Check API Connection"):
        if check_api_health():
            st.success("✅ API is reachable!")
        else:
            st.error("❌ API not reachable! Check server on port 8000.")

    # Logged in
    if st.session_state.token and st.session_state.phone:
        if st.button("Logout"):
            st.session_state.token = None
            st.session_state.phone = None
            st.rerun()

        st.success(f"✅ Welcome, {st.session_state.phone}!")
        st.subheader("📋 Your Consent Preferences")

        try:
            res = requests.get(f"{API_URL}/consent/preferences/{st.session_state.phone}", headers=api_headers())
            if res.status_code == 200:
                prefs = res.json()
                if prefs:
                    for p in prefs:
                        granted_at = p.get('granted_at', 'N/A')
                        if granted_at != 'N/A':
                            try:
                                parsed_time = datetime.fromisoformat(granted_at.replace('Z', '+00:00'))
                                granted_at = parsed_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                            except ValueError:
                                pass
                        st.write(f"**Company:** {p['principal_id']} | **Header:** {p['header']} | **Status:** {p['status']} | **Granted:** {granted_at}")
                        col1, col2 = st.columns(2)
                        with col1:
                            if p['status'] == 'pending':
                                if st.button(f"Approve {p['principal_id']}", key=f"approve_{p['principal_id']}_{p['header']}"):
                                    update_payload = {"phone": st.session_state.phone, "principal_id": p['principal_id'], "header": p['header'], "status": "approved"}
                                    update_res = requests.post(f"{API_URL}/consent/update", json=update_payload, headers=api_headers())
                                    if update_res.status_code == 200:
                                        st.success(f"✅ Approved consent for {p['principal_id']} ({p['header']})")
                                        st.rerun()
                                    else:
                                        st.error(f"❌ Update failed: {update_res.text}")
                        with col2:
                            if st.button(f"Revoke {p['principal_id']}", key=f"revoke_{p['principal_id']}_{p['header']}"):
                                update_payload = {"phone": st.session_state.phone, "principal_id": p['principal_id'], "header": p['header'], "status": "revoked"}
                                update_res = requests.post(f"{API_URL}/consent/update", json=update_payload, headers=api_headers())
                                if update_res.status_code == 200:
                                    st.warning(f"🚫 Revoked consent for {p['principal_id']} ({p['header']})")
                                    st.rerun()
                                else:
                                    st.error(f"❌ Update failed: {update_res.text}")
                else:
                    st.info("No consent preferences found.")
            elif res.status_code == 401:
                st.error("❌ Session expired. Please login again.")
                st.session_state.token = None
                st.session_state.phone = None
                st.rerun()
            else:
                st.error(f"❌ Error {res.status_code}: {res.text}")
        except Exception as e:
            st.error(f"⚠️ Failed to fetch preferences: {e}")
            st.session_state.token = None
            st.session_state.phone = None
            st.rerun()

    # Login/Register
    else:
        tab1, tab2 = st.tabs(["Login", "Register"])

        with tab1:
            st.info("💡 Default demo: phone=9876543210, password=1234")
            phone = st.text_input("Phone Number", value="", key="login_phone")
            password = st.text_input("Password", type="password", value="", key="login_password")
            if st.button("Login", key="btn_login"):
                payload = {"phone": phone, "password": password}
                try:
                    res = requests.post(f"{API_URL}/users/login", json=payload)
                    if res.status_code == 200:
                        data = res.json()
                        st.session_state.token = data.get("access_token")
                        st.session_state.phone = phone
                        st.success(f"✅ Logged in as {phone}")
                        st.rerun()
                    else:
                        st.error(f"❌ Login failed: {res.text}")
                except Exception as e:
                    st.error(f"⚠️ Login request failed: {e}")

        with tab2:
            reg_phone = st.text_input("Phone Number", key="reg_phone")
            reg_password = st.text_input("Password", type="password", key="reg_password")
            if st.button("Register", key="btn_register"):
                payload = {"phone": reg_phone, "password": reg_password}
                try:
                    res = requests.post(f"{API_URL}/users/register", json=payload)
                    if res.status_code == 200:
                        data = res.json()
                        st.session_state.token = data.get("access_token")
                        st.session_state.phone = reg_phone
                        st.success(f"✅ Registered and logged in as {reg_phone}!")
                        st.rerun()
                    else:
                        st.error(f"❌ Registration failed: {res.text}")
                except Exception as e:
                    st.error(f"⚠️ Registration request failed: {e}")

# -------------------- View Ledger --------------------
elif menu == "View Ledger":
    st.header("📜 Ledger Records")
    st.write("All transactions, including registrations and consents, are logged here.")
    try:
        res = requests.get(f"{API_URL}/ledger")
        if res.status_code == 200:
            data = res.json()
            st.json(data)
        else:
            st.error(f"❌ Error {res.status_code}: {res.text}")
    except Exception as e:
        st.error(f"⚠️ Request failed: {e}")
