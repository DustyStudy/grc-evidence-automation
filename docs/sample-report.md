# SOC 2 (Trust Services Criteria): control evidence status

Run `20260920T060000Z-1ed7bd13` (2026-09-20T06:00:00+00:00), accounts: 123456789012

**Read this as a triage view, not an audit conclusion.** Automated evidence shows configuration state at collection time; control effectiveness is the auditor's judgement. `error` means the check could not run (for example, missing permissions) and is *not* a pass.

| Status | Controls |
|---|---:|
| fail | 2 |
| no_automated_evidence | 34 |
| pass | 2 |

| Control | Title | Status | Evidence from | Top findings |
|---|---|---|---|---|
| CC1.1 | Commitment to integrity and ethical values | no_automated_evidence | - | - |
| CC1.2 | Board independence and oversight of controls | no_automated_evidence | - | - |
| CC1.3 | Structures, reporting lines and authorities | no_automated_evidence | - | - |
| CC1.4 | Commitment to attract, develop and retain competent people | no_automated_evidence | - | - |
| CC1.5 | Accountability for internal control responsibilities | no_automated_evidence | - | - |
| CC2.1 | Uses relevant, quality information for internal control | no_automated_evidence | - | - |
| CC2.2 | Internal communication of control objectives | no_automated_evidence | - | - |
| CC2.3 | Communication with external parties | no_automated_evidence | - | - |
| CC3.1 | Specifies suitable objectives | no_automated_evidence | - | - |
| CC3.2 | Identifies and analyzes risks | no_automated_evidence | - | - |
| CC3.3 | Considers potential for fraud | no_automated_evidence | - | - |
| CC3.4 | Identifies and assesses changes affecting controls | no_automated_evidence | - | - |
| CC4.1 | Ongoing and separate evaluations of controls | no_automated_evidence | - | - |
| CC4.2 | Evaluates and communicates deficiencies | no_automated_evidence | - | - |
| CC5.1 | Selects and develops control activities | no_automated_evidence | - | - |
| CC5.2 | General controls over technology | no_automated_evidence | - | - |
| CC5.3 | Deploys controls through policies and procedures | no_automated_evidence | - | - |
| CC6.1 | Logical access security software, infrastructure and architectures | fail | aws.iam_mfa, aws.iam_password_policy | root: Root account does not have MFA enabled |
| CC6.2 | User registration, authorization and credential issuance | no_automated_evidence | - | - |
| CC6.3 | Role-based access, least privilege and access removal | no_automated_evidence | - | - |
| CC6.4 | Physical access restrictions | no_automated_evidence | - | - |
| CC6.5 | Disposal of logical and physical assets | no_automated_evidence | - | - |
| CC6.6 | Protection against threats from outside system boundaries | fail | aws.iam_mfa, aws.network_exposure | root: Root account does not have MFA enabled<br>sg-e70e730ea5b4180c0 (legacy-bastion): Port 22/tcp open to the internet |
| CC6.7 | Restricts transmission, movement and removal of information | no_automated_evidence | - | - |
| CC6.8 | Prevents and detects unauthorized or malicious software | no_automated_evidence | - | - |
| CC7.1 | Detects new vulnerabilities and configuration changes | no_automated_evidence | - | - |
| CC7.2 | Monitors system components for anomalies | pass | aws.cloudtrail, aws.threat_detection | - |
| CC7.3 | Evaluates security events | pass | aws.cloudtrail, aws.threat_detection | - |
| CC7.4 | Responds to security incidents | no_automated_evidence | - | - |
| CC7.5 | Recovers from security incidents | no_automated_evidence | - | - |
| CC8.1 | Authorizes, tests, approves and implements changes | no_automated_evidence | - | - |
| CC9.1 | Risk mitigation for business disruptions | no_automated_evidence | - | - |
| CC9.2 | Vendor and business-partner risk management | no_automated_evidence | - | - |
| A1.1 | Capacity management | no_automated_evidence | - | - |
| A1.2 | Environmental protections, backups and recovery infrastructure | no_automated_evidence | - | - |
| A1.3 | Tests recovery plan procedures | no_automated_evidence | - | - |
| C1.1 | Identifies and maintains confidential information | no_automated_evidence | - | - |
| C1.2 | Disposes of confidential information | no_automated_evidence | - | - |
