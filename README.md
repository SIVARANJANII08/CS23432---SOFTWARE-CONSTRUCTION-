# EvidenceTrail: Digital Evidence Chain-of-Custody Management System

**CS23432 – Software Construction | Rajalakshmi Engineering College, Chennai**
Department of Computer Science and Engineering (Cyber Security)

---

## Authors

| Name | Role |
|---|---|
| **Sivaranjanii M** | Developer |
| **Sree Dharshini M** | Developer |

---

## 1. About the Project

EvidenceTrail is a web application that helps investigators register digital evidence, prove it has not been altered, and keep a complete record of who handled it and when. In digital investigations, evidence is only useful if its integrity can be proven. EvidenceTrail does this by calculating a **SHA-256 hash** of every file at the time of registration and comparing it again at any later time.

Every important action (login, viewing, verification, custody transfer) is written to a **tamper-evident audit log**, where each entry is linked to the previous one by a hash. Any change to old log entries can be detected.

The application is deployed on **Microsoft Azure**: the web app runs on Azure App Service, metadata is stored in Azure SQL Database, and evidence files are stored in Azure Blob Storage.

## 2. Problem Statement

Manual evidence tracking (paper registers, spreadsheets, shared folders) makes it hard to:
- prove a file has not been modified after collection,
- show a clear chain of custody from one person to another,
- stop unauthorised people from viewing or changing records,
- detect tampering with the records themselves.

EvidenceTrail solves these problems with automated hashing, role-based access and a hash-chained audit trail.

## 3. Key Features

- **Evidence registration**: upload a file with case number and title. The system generates a unique evidence number (for example `EV-2026-00001`) and stores the original SHA-256 hash.
- **Secure file storage**: evidence files are saved in a private Azure Blob Storage container with no anonymous access.
- **Integrity verification**: recompute the file's SHA-256 and compare it with the original hash. The result is shown as **PASS** (intact) or **FAIL** (tampered).
- **Chain of custody**: transfer custody to another user with a reason. Every transfer is recorded in a timeline.
- **Verification history**: each integrity check is saved with the time, the user, the result and the computed hash.
- **Tamper-evident audit log**: every action is logged with the user, time, IP address and an entry hash linked to the previous entry. An **audit chain integrity check** detects any change to the log.
- **Role-based access control**: separate permissions for Admin, Investigator and Auditor.
- **User management**: the admin can add users and disable accounts.
- **Dashboard**: counts of evidence items, verified-intact items, tampered items, items not yet verified, and items in the current user's custody.
- **Search**: find evidence by case, title, evidence number or hash.

## 4. User Roles

| Role | Permissions |
|---|---|
| **Admin** | Manage users, view all evidence, view the audit log, check audit chain integrity |
| **Investigator** | Register evidence, verify integrity, download files, transfer custody |
| **Auditor** | Review evidence records and audit information (read-focused access) |

## 5. Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS (Jinja2 templates) |
| Database | Azure SQL Database (Basic tier) |
| File storage | Azure Blob Storage (`evidence` container) |
| Hosting | Azure App Service (Central India) |
| Integrity | SHA-256 hashing (Python `hashlib`) |
| Project management | Azure DevOps (Boards, Sprints, Test Plans, Pipelines) |
| Version control | Git and GitHub |

## 6. System Architecture

```
 User (Browser)
       |
       v
 Azure App Service (Flask application)
       |                    |
       v                    v
 Azure SQL Database    Azure Blob Storage
 (metadata, users,     (evidence files,
  custody, audit log)   private container)
```

## 7. Database Design

| Table | Purpose |
|---|---|
| `users` | Username, full name, role, password hash, active status |
| `evidence` | Evidence number, case, title, file name, size, original SHA-256, current custodian, status |
| `custody_events` | Registration and transfer history of each evidence item |
| `verification_records` | Each integrity check with result and computed hash |
| `audit_logs` | Action log with IP address and chained entry hash |

## 8. How Integrity Verification Works

1. When evidence is registered, the file is hashed with SHA-256 and the hash is stored.
2. The file is uploaded to Azure Blob Storage.
3. When "Verify integrity" is clicked, the file is read from Blob Storage and hashed again.
4. If both hashes match, the result is **PASS** and the evidence is marked **Intact**.
5. If they differ, the result is **FAIL** and the evidence is marked **Tampered**.
6. The check is saved in the verification history and the audit log.

## 9. Security Measures

- Passwords are stored as hashes, not as plain text.
- Role-based access control on every protected page.
- Secrets (database connection, storage connection string, secret key) are kept in Azure App Service environment variables and are **not** stored in this repository.
- Blob container is private (no anonymous access).
- SQL server uses a firewall and a minimum TLS version of 1.2.
- Secure cookies are enabled.
- Audit log entries are hash-chained so tampering can be detected.

## 10. Project Structure

```
evidencetrail/
├── app.py                  # Flask application and routes
├── requirements.txt        # Python dependencies
├── azure-pipelines.yml     # Azure DevOps pipeline
├── templates/              # HTML pages
├── static/                 # CSS and static files
└── README.md
```

> Adjust this section to match the final folder layout of the repository.

## 11. Running Locally

```bash
# 1. Clone the repository
git clone https://github.com/SIVARANJANII08/CS23432---SOFTWARE-CONSTRUCTION-.git
cd CS23432---SOFTWARE-CONSTRUCTION-

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables (use your own values)
set SECRET_KEY=your-secret-key
set DATABASE_URL=your-database-connection
set AZURE_STORAGE_CONNECTION_STRING=your-storage-connection
set AZURE_BLOB_CONTAINER=evidence

# 5. Run the app
python app.py
```

## 12. Environment Variables

| Variable | Description |
|---|---|
| `SECRET_KEY` | Flask session secret |
| `DATABASE_URL` | Azure SQL Database connection |
| `AZURE_STORAGE_CONNECTION_STRING` | Azure Blob Storage connection |
| `AZURE_BLOB_CONTAINER` | Blob container name (`evidence`) |
| `COOKIE_SECURE` | Enables secure cookies |

Never commit real values of these variables to GitHub.

## 13. DevOps and Software Engineering Practices

This project was planned and managed with Azure DevOps:
- Epics, Features and User Stories in Azure Boards
- Sprint planning and story point estimation
- Class, sequence, architecture and ER diagrams in the project Wiki
- Test plans with happy-path and error-path test cases
- Load testing with Azure Load Testing
- CI pipeline with `azure-pipelines.yml`

## 14. Acknowledgement

Developed as part of the **CS23432 – Software Construction** course at Rajalakshmi Engineering College, Chennai, under the guidance of **Mrs. Fowzia Sihana**, Assistant Professor, Department of Computer Science and Engineering (Cyber Security).

---

**Developed by Sivaranjanii M and Sree Dharshini M**
