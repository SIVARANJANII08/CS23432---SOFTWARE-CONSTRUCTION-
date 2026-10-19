# EvidenceTrail test plan (capture a screenshot for every row marked [SS])

Setup users first (log in as admin > Users): `inv1` (investigator), `inv2` (investigator), `aud1` (auditor).

| # | Test | Steps | Expected result |
|---|------|-------|-----------------|
| T1 | Login success [SS] | Sign in as admin | Dashboard opens |
| T2 | Login failure | Wrong password | Generic error, no hint which part was wrong |
| T3 | Account lockout [SS] | 5 wrong passwords for inv2, then correct one | "Account temporarily locked" |
| T4 | Register evidence [SS] | As inv1: Register evidence, upload a .txt | Evidence no. EV-2026-00001 + SHA-256 shown |
| T5 | Hash correctness [SS] | PowerShell: `Get-FileHash file.txt -Algorithm SHA256` | Same hash as the app shows |
| T6 | Integrity PASS [SS] | Click Verify integrity now | Green PASSED message, status Intact |
| T7 | Tamper detection [SS] | Local: edit the file inside local_evidence/ (add one character). Azure: re-upload a different file over the blob in Azure Portal. Click Verify | Red FAILED, status Tampered, hash differs |
| T8 | Custody transfer [SS] | As inv1: transfer to inv2 with a reason | Timeline shows new node; custodian changes |
| T9 | Transfer blocked | Log in again as inv1 (no longer custodian), try transfer | Transfer form is hidden; forced POST gives 403 |
| T10 | RBAC auditor [SS] | Sign in as aud1, open /evidence/new and /admin/users | 403 Access denied; Audit log opens |
| T11 | Disallowed file type | Upload evil.exe | "File type not allowed" |
| T12 | Audit log [SS] | As admin open Audit log | All actions above are listed, incl. ACCESS_DENIED |
| T13 | Audit chain OK [SS] | Click "Check audit chain integrity" | Green: all entries verified |
| T14 | Audit chain tamper [SS] | Stop app. Open instance/evidencetrail.db in DB Browser for SQLite, change one audit_logs.details value. Restart, check chain | Red: chain broken at entry #N |
| T15 | Automated tests | `python -m pytest tests -v` | All tests pass |
