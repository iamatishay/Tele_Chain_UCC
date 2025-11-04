# 🛰️ Tele_Chain – Blockchain-Based UCC Compliance & Consent Management System

Tele_Chain is a **blockchain-inspired regulatory compliance framework** designed to manage and enforce **UCC (Unsolicited Commercial Communication)** regulations in telecom and digital communication ecosystems.

It ensures that every commercial message is **consent-driven, traceable, and compliant** with TRAI (Telecom Regulatory Authority of India) norms.

Unlike traditional anti-spam filters that rely only on content or behavior analysis, **Tele_Chain** is **proactive and regulatory** — stopping spam at the source through consent validation, pre-scrubbing, and ledger-based audit trails.

---

## 🚀 Core Features

| Feature                                  | Description                                                                          |
| ---------------------------------------- | ------------------------------------------------------------------------------------ |
| 🧱 **Immutable Ledger**                  | Records every consent, registration, or message event with timestamped traceability. |
| 🔐 **Consent Lifecycle Management**      | Tracks full consent flow — Request → Grant → Revoke — ensuring user rights.          |
| 🏢 **Principal & Telemarketer Registry** | Authenticates entities and links them with verified headers and message templates.   |
| 🪪 **Global Header Uniqueness**          | Prevents header duplication or misuse across different principals.                   |
| 📊 **Automated Audit Reports**           | Generates IST-based TRAI audit reports with compliance summaries.                    |
| 🧽 **Pre-Scrubbing Enforcement**         | Ensures only consented and compliant messages are sent.                              |

---

## ⚙️ Technical Highlights

* Modular, **smart-contract-inspired architecture** using FastAPI
* Persistent state via **verifiable JSON database (DB)** and **immutable ledger**
* Standardized **IST (UTC+5:30)** timestamps
* **JWT-secured authentication** for all REST endpoints
* **RSA encryption** for operator-level message simulation
* Fully auditable and transparent transaction flow

---

## 🧩 System Architecture

```text
User / Principal / Telemarketer
        │
        ▼
 [ REST API Layer ]
        │
        ▼
 [ Smart Contract Modules ]
   ├── Registration
   ├── Consent
   ├── Scrubbing
   ├── Campaign
   ├── SMS Send
   └── TRAI Audit
        │
        ▼
 [ Ledger + Persistent DB ]
 Immutable • Auditable • IST-based
```

---

## 🧠 Difference from Traditional Anti-Spam

| Aspect                 | Traditional Anti-Spam       | Tele_Chain UCC Compliance          |
| ---------------------- | --------------------------- | ---------------------------------- |
| **Approach**           | Content or behavior filters | Legal & consent-based enforcement  |
| **Timing**             | Reactive                    | Proactive (stops spam before send) |
| **Legal Awareness**    | None                        | Full TRAI / UCC compliance         |
| **Traceability**       | Limited                     | Immutable ledger                   |
| **Consent Management** | Not supported               | Fully integrated                   |
| **Auditability**       | Minimal                     | Complete compliance reports        |

---

## 🧰 Tech Stack

* **Framework:** FastAPI
* **Auth:** JWT (via `python-jose`)
* **Hashing:** bcrypt (`passlib`)
* **Encryption:** RSA (`cryptography`)
* **Persistence:** JSON-based DB + Ledger
* **Logging:** Python `logging`

---

## 🧾 Example Ledger Entry

```json
{
  "type": "consent_grant",
  "phone_hash": "d34b5b9f9e...",
  "principal_id": "PR-1",
  "header": "RND-HDR",
  "timestamp": "2025-11-04T08:21:23+05:30",
  "txid": "c91e2a1a7d..."
}
```

---

## 🧪 Example Run

### ▶️ Start the Server

```bash
uvicorn telechain_prototype_persistent:app --reload --port 8000
```

### 🔁 Example API Workflow

1. **Register Entities**

   * `/telemarketer/register`
   * `/principal/register`
   * `/principal/register_header`

2. **Consent Flow**

   * `/consent/request`
   * `/consent/grant`
   * `/consent/update`

3. **Scrubbing & Campaign**

   * `/scrub/phones`
   * `/campaign/create`
   * `/sms/send`

4. **Audit**

   * `/audit/report?from_date=2025-01-01&to_date=2025-12-31`

---

## 🧾 Auto-Seeding (Demo Mode)

On first startup, the system auto-generates:

* A sample Principal (`Random Corp`)
* A Telemarketer (`Random TM`)
* Header (`RND-HDR`)
* Demo User (`9876543210` / password `1234`)
* A pre-approved consent record

---

## 🧭 Compliance Focus

Tele_Chain directly aligns with **TRAI’s UCC 2018** framework:

* Consent traceability via hashed IDs
* Immutable ledger for auditability
* Real-time consent revocation
* Operator encryption simulation
* Regulatory data retention integrity

---

## 📅 Roadmap

* [ ] Integration with telecom DLT frameworks
* [ ] Blockchain-based consent proofing (e.g., Hyperledger Fabric)
* [ ] AI-driven spam anomaly detection
* [ ] Role-based dashboards for stakeholders
* [ ] Multi-operator simulation

---

## 🧠 Vision

> “To create a transparent, tamper-proof, and consent-centric communication ecosystem that protects users from spam, empowers enterprises with compliant messaging, and supports regulators with real-time auditability.”

---

## 📜 License

This project is a **regulatory technology prototype** developed for demonstrating **UCC compliance automation**.
It may be adapted for telecom or enterprise-grade integration under suitable licensing.

---

## 📸 Prototype Screens

| Ledger Trace                                                                                                           | Consent Flow                                                                                                           | Entity Registry                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| <img width="680" height="414" src="https://github.com/user-attachments/assets/b030d823-55d5-4dac-b6f7-e754fb21510b" /> | <img width="944" height="415" src="https://github.com/user-attachments/assets/e17a5a28-7d49-43e6-bb14-369c34acc57b" /> | <img width="805" height="371" src="https://github.com/user-attachments/assets/4217a36d-f748-41a8-beb1-9e26a1f4882f" /> |

| Audit Dashboard                                                                                                        | Scrubbing                                                                                                              | Principal Registry                                                                                                     |
| ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| <img width="947" height="413" src="https://github.com/user-attachments/assets/9d7729cd-788f-4d1c-8ecc-b34ec1471c4b" /> | <img width="950" height="341" src="https://github.com/user-attachments/assets/eff57930-7672-4f8e-bd60-8363ca25c3b2" /> | <img width="874" height="416" src="https://github.com/user-attachments/assets/5c367359-2fdf-4512-8544-8ce9276b5fc5" /> |

| Consent Analytics                                                                                                      | Audit Log |
| ---------------------------------------------------------------------------------------------------------------------- | --------- |
| <img width="939" height="412" src="https://github.com/user-attachments/assets/d8e1e0d2-49d2-4008-acb1-0262d660fff0" /> |           |

---

