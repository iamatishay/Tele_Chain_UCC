import streamlit as st
import requests
from datetime import datetime

API_URL = "http://127.0.0.1:8000"

st.set_page_config(page_title="📡 Telechain Prototype", layout="wide")
st.title("📡 Telechain Prototype – Blockchain Consent Management")


# -------------------- Session State --------------------
if "token" not in st.session_state:
    st.session_state.token = None
if "phone" not in st.session_state:
    st.session_state.phone = None
if "last_otp" not in st.session_state:
    st.session_state.last_otp = None

# -------------------- Helpers --------------------
def api_headers():
    return {"Authorization": f"Bearer {st.session_state.token}"} if st.session_state.token else {}

def show_status(success: bool, msg: str):
    if success:
        st.success(msg)
    else:
        st.error(msg)

# -------------------- Sidebar Navigation --------------------
menu = st.sidebar.radio("Navigate", [
    "Concept Intro",
    "Setup",
    "Send Consent Request",
    "Grant Consent",
    "Customer Dashboard",
    "View Ledger",
    "TRAI Compliance"
])
# -------------------- Concept Intro --------------------
if menu == "Concept Intro":
    st.info("A UCC (Unsolicited Commercial Communication) regulation/compliance program can protect users from spam, but a traditional anti-spam filter/program cannot protect users from UCC violations. Because UCC Program is based on Legal Compliance but an Anti-Spam Program is based on content or behavioural analysis. A UCC compliance system is proactive and regulatory, so it stops spam at the source. UCC programs can protect from spam (because they ensure consent, compliance, and pre-scrubbing). Anti-spam programs cannot protect from UCC violations (because they lack legal validation or consent awareness)")

# -------------------- Setup --------------------
elif menu == "Setup":
    st.header("⚙️ Setup – Register Entities")
    st.write("Register telemarketers, principals, and headers for testing.")

    tab1, tab2, tab3 = st.tabs(["Telemarketer", "Principal", "Header"])

    with tab1:
        st.subheader("📞 Register Telemarketer")
        tm_name = st.text_input("Telemarketer Name", value="Random TM", key="tm_name")
        trai_id = st.text_input("TRAI ID", value="TRAI-RND-123", key="trai_id")
        deposit = st.number_input("Deposit", value=1000, min_value=0, key="deposit")
        if st.button("Register Telemarketer"):
            payload = {"name": tm_name, "trai_id": trai_id, "deposit": deposit}
            try:
                res = requests.post(f"{API_URL}/telemarketer/register", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    show_status(True, f"Telemarketer registered! ID: {data['telemarketer_id']}, TXID: {data['txid']}")
                else:
                    show_status(False, res.text)
            except Exception as e:
                show_status(False, str(e))

    with tab2:
        st.subheader("🏢 Register Principal")
        principal_name = st.text_input("Principal Name", value="Random Corp", key="principal_name")
        if st.button("Register Principal"):
            payload = {"name": principal_name}
            try:
                res = requests.post(f"{API_URL}/principal/register", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    show_status(True, f"Principal registered! ID: {data['principal_id']}, TXID: {data['txid']}")
                else:
                    show_status(False, res.text)
            except Exception as e:
                show_status(False, str(e))

    with tab3:
        st.subheader("📝 Register Header")
        principal_id = st.text_input("Principal ID", value="PR-1", key="header_principal")
        header = st.text_input("Header", value="RND-HDR", key="header_input")
        if st.button("Register Header"):
            payload = {"principal_id": principal_id, "header": header}
            try:
                res = requests.post(f"{API_URL}/principal/register_header", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    show_status(True, f"Header '{header}' registered under {principal_id}! TXID: {data['txid']}")
                else:
                    show_status(False, res.text)
            except Exception as e:
                show_status(False, str(e))

# -------------------- Send Consent Request --------------------
elif menu == "Send Consent Request":
    st.header("📩 Send Consent Request")

    tab1, tab2 = st.tabs(["Single Request", "Bulk Request"])

    # ---- Single Request ----
    with tab1:
        principal_id = st.text_input("Principal ID", value="PR-1", key="single_principal")
        header = st.text_input("Header", value="RND-HDR", key="single_header")
        phone = st.text_input("Customer Phone", value="9876543210", key="single_phone")
        channel = st.selectbox("Channel", ["SMS", "VOICE"], key="single_channel")

        if st.button("Send Single Consent Request"):
            payload = {"principal_id": principal_id, "header": header, "phone": phone}
            try:
                res = requests.post(f"{API_URL}/consent/request", json=payload)
                if res.status_code == 200:
                    data = res.json()
                    st.session_state.last_otp = data.get("otp", "")
                    show_status(True, f"OTP sent! (Demo OTP: {data.get('otp', 'N/A')})")
                else:
                    show_status(False, res.text)
            except Exception as e:
                show_status(False, str(e))

    # ---- Bulk Request ----
    # ---- Bulk Request ----
    with tab2:
        st.subheader("📤 Bulk Consent Requests")
        st.markdown(
            "Upload a `.txt` file containing one phone number per line. "
            "Only 10-digit numbers will be accepted."
        )

        principal_id = st.text_input("Principal ID", value="PR-1", key="bulk_principal")

        # 👇 New field for Principal Name
        principal_name = st.text_input("Principal Name", value="Random Corp", key="bulk_principal_name")

        header = st.text_input("Header", value="RND-HDR", key="bulk_header")
        uploaded_file = st.file_uploader("Upload Phone Numbers (.txt only)", type=["txt"])

        if uploaded_file:
            try:
                numbers = uploaded_file.read().decode("utf-8").splitlines()
                numbers = [n.strip() for n in numbers if n.strip()]  # remove blanks
                valid_numbers = [n for n in numbers if n.isdigit() and len(n) == 10]
                invalid_numbers = [n for n in numbers if n not in valid_numbers]

                st.info(f"✅ Valid Numbers: {len(valid_numbers)} | ❌ Invalid Numbers: {len(invalid_numbers)}")

                if invalid_numbers:
                    with st.expander("View Invalid Numbers"):
                        st.write(invalid_numbers)

                # 👇 Updated message uses principal_name instead of principal_id
                consent_message = (
                    f"Dear Customer, we request your consent to receive updates and offers from "
                    f"{principal_name}. Reply YES to consent. - {principal_name}"
                )
                st.markdown(f"**Consent Message Template:**\n\n> {consent_message}")

                if valid_numbers and st.button("Send Bulk Consent Requests"):
                    sent, failed = 0, 0
                    for num in valid_numbers:
                        payload = {"principal_id": principal_id, "header": header, "phone": num}
                        try:
                            res = requests.post(f"{API_URL}/consent/request", json=payload)
                            if res.status_code == 200:
                                sent += 1
                            else:
                                failed += 1
                        except Exception:
                            failed += 1

                    show_status(True, f"Bulk consent requests completed! ✅ Sent: {sent} | ❌ Failed: {failed}")
            except Exception as e:
                show_status(False, f"File processing failed: {e}")



# -------------------- Grant Consent --------------------
elif menu == "Grant Consent":
    st.header("🔐 Grant Consent")
    st.write("Validate OTP to register consent.")

    with st.form("grant_form"):
        principal_id = st.text_input("Principal ID", value="PR-1")
        header = st.text_input("Header", value="RND-HDR")
        phone = st.text_input("Customer Phone", value="9876543210")
        otp = st.text_input("OTP", value=st.session_state.get("last_otp", "123456"))
        submitted = st.form_submit_button("Verify & Grant")

        if submitted:
            payload = {
                "principal_id": principal_id,
                "header": header,
                "phone": phone,
                "otp": otp,
            }
            try:
                res = requests.post(f"{API_URL}/consent/grant", json=payload)
                if res.status_code == 200:
                    show_status(True, "Consent granted successfully!")
                else:
                    show_status(False, res.text)
            except Exception as e:
                show_status(False, str(e))


# -------------------- Customer Dashboard --------------------
# -------------------- Customer Dashboard --------------------
elif menu == "Customer Dashboard":
    st.header("👤 Customer Dashboard")
    st.write("Login to view and manage your consent preferences.")

    if st.session_state.token and st.session_state.phone:
        if st.button("Logout"):
            st.session_state.token = None
            st.session_state.phone = None
            st.rerun()

        st.success(f"Logged in as {st.session_state.phone}")

        # --- Step 1: Fetch ledger and build principal mapping ---
        try:
            ledger_res = requests.get(f"{API_URL}/ledger")
            ledger_data = ledger_res.json() if ledger_res.status_code == 200 else []
        except Exception:
            ledger_data = []

        principal_map = {}
        for tx in ledger_data:
            if tx.get("type") == "principal_register":
                principal_map[tx["principal_id"]] = tx.get("name", tx["principal_id"])

        # --- Step 2: Fetch user consent preferences ---
        try:
            res = requests.get(
                f"{API_URL}/consent/preferences/{st.session_state.phone}",
                headers=api_headers(),
            )
            if res.status_code == 200:
                prefs = res.json()

                if prefs:
                    # 👇 Group consents by Principal name
                    grouped = {}
                    for p in prefs:
                        principal_name = principal_map.get(p.get("principal_id"), p.get("principal_id", "Unknown Principal"))
                        grouped.setdefault(principal_name, []).append(p)

                    for principal_name, items in grouped.items():
                        st.markdown(f"### 🏢 {principal_name}")

                        for p in items:
                            granted_at = p.get("granted_at", "N/A")
                            if granted_at != "N/A":
                                try:
                                    granted_at = datetime.fromisoformat(
                                        granted_at.replace("Z", "+00:00")
                                    ).strftime("%Y-%m-%d %H:%M:%S IST")
                                except:
                                    pass

                            st.markdown(
                                f"- **Header:** {p['header']} | "
                                f"**Status:** {p['status']} | "
                                f"**Granted:** {granted_at}"
                            )

                            col1, col2 = st.columns(2)
                            with col1:
                                if st.button(
                                    f"Approve {p['header']} ({principal_name})",
                                    key=f"approve_{p['principal_id']}_{p['header']}",
                                ):
                                    update_payload = {
                                        "phone": st.session_state.phone,
                                        "principal_id": p["principal_id"],
                                        "header": p["header"],
                                        "status": "approved",
                                    }
                                    res = requests.post(
                                        f"{API_URL}/consent/update",
                                        json=update_payload,
                                        headers=api_headers(),
                                    )
                                    if res.status_code == 200:
                                        show_status(True, f"Approved consent for {principal_name}")
                                        st.rerun()
                                    else:
                                        show_status(False, res.text)

                            with col2:
                                if st.button(
                                    f"Revoke {p['header']} ({principal_name})",
                                    key=f"revoke_{p['principal_id']}_{p['header']}",
                                ):
                                    update_payload = {
                                        "phone": st.session_state.phone,
                                        "principal_id": p["principal_id"],
                                        "header": p["header"],
                                        "status": "revoked",
                                    }
                                    res = requests.post(
                                        f"{API_URL}/consent/update",
                                        json=update_payload,
                                        headers=api_headers(),
                                    )
                                    if res.status_code == 200:
                                        show_status(False, f"Revoked consent for {principal_name}")
                                        st.rerun()
                                    else:
                                        show_status(False, res.text)

                        st.markdown("---")

                else:
                    st.info("No consent preferences found.")
            else:
                st.error("Failed to fetch preferences.")
        except Exception as e:
            st.error(str(e))
            st.session_state.token = None
            st.session_state.phone = None
            st.rerun()

    else:
        tab1, tab2 = st.tabs(["Login", "Register"])

        with tab1:
            phone = st.text_input("Phone Number", key="login_phone")
            password = st.text_input("Password", type="password", key="login_password")
            if st.button("Login"):
                payload = {"phone": phone, "password": password}
                try:
                    res = requests.post(f"{API_URL}/users/login", json=payload)
                    if res.status_code == 200:
                        data = res.json()
                        st.session_state.token = data.get("access_token")
                        st.session_state.phone = phone
                        show_status(True, f"Logged in as {phone}")
                        st.rerun()
                    else:
                        show_status(False, res.text)
                except Exception as e:
                    show_status(False, str(e))

        with tab2:
            reg_phone = st.text_input("Phone Number", key="reg_phone")
            reg_password = st.text_input("Password", type="password", key="reg_password")
            if st.button("Register"):
                payload = {"phone": reg_phone, "password": reg_password}
                try:
                    res = requests.post(f"{API_URL}/users/register", json=payload)
                    if res.status_code == 200:
                        data = res.json()
                        st.session_state.token = data.get("access_token")
                        st.session_state.phone = reg_phone
                        show_status(True, f"Registered and logged in as {reg_phone}")
                        st.rerun()
                    else:
                        show_status(False, res.text)
                except Exception as e:
                    show_status(False, str(e))


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


# -------------------- TRAI Compliance --------------------
elif menu == "TRAI Compliance":
    st.header("📊 TRAI Compliance Dashboard")
    st.write("View consent statistics, SMS sends, blocks, and penalties for audit purposes.")

    from_date = st.date_input("From Date")
    to_date = st.date_input("To Date")

    if st.button("Generate Compliance Report"):
        try:
            params = {
                "from_date": from_date.isoformat() + "Z",
                "to_date": to_date.isoformat() + "Z",
            }

            res = requests.get(f"{API_URL}/audit/report", params=params, headers=api_headers())
            ledger_res = requests.get(f"{API_URL}/ledger", headers=api_headers())

            if res.status_code == 200 and ledger_res.status_code == 200:
                report = res.json()
                ledger_data = ledger_res.json()

                # -------------------- Principals & Headers --------------------
                principals = [tx for tx in ledger_data if tx["type"] == "principal_register"]
                headers = [tx for tx in ledger_data if tx["type"] == "header_register"]

                st.subheader("Entities Registered")
                st.write(f"Total Principals Registered: {len(principals)}")  # Should be 7
                st.write(f"Total Headers Registered: {len(headers)}")

                # -------------------- Consent Summary --------------------
                st.subheader("Consent Summary")
                consent_stats = report.get("consent_stats", {})
                total_consents = sum(consent_stats.values())
                st.write(f"Total Consent Requests: {total_consents}")
                st.write(f"Approved Consents: {consent_stats.get('approved', 0)}")
                st.write(f"Pending Consents: {consent_stats.get('requested', 0)}")
                st.write(f"Revoked Consents: {consent_stats.get('revoked', 0)}")

                # -------------------- SMS Rejections --------------------
                st.subheader("SMS Rejections")
                sms_rejections = report.get("sms_rejections", {})
                st.write(f"Rejected SMS (No Consent): {sms_rejections.get('consent_not_granted', 0)}")
                st.write(
                    f"Other Rejections: {sum(v for k, v in sms_rejections.items() if k != 'consent_not_granted')}"
                )

                # -------------------- Transaction Summary --------------------
                st.subheader("Transaction Summary")
                summary = report.get("summary", {})
                st.write(f"Total Transactions: {summary.get('total_transactions', len(ledger_data))}")
                st.write(f"Transactions by Type: {summary.get('by_type', {})}")

                # -------------------- Full Ledger --------------------
                st.subheader("Full Ledger Entries")
                st.dataframe(ledger_data)
            else:
                st.error(f"❌ Error fetching report or ledger: {res.status_code}/{ledger_res.status_code}")

        except Exception as e:
            st.error(f"⚠️ Failed to generate report: {e}")
