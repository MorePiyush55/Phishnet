# PhishNet — Mode 1 vs Mode 2 Comparison

## One-Line Summary

**Mode 1 and Mode 2 share the same database and schema but are logically isolated through different triggers, pipelines, and data-retention policies.**

- **Mode 1** → *"Scan everything unless I stop you."* (Bulk Forward)
- **Mode 2** → *"Scan only when I explicitly ask."* (On-Demand)

---

## Database Architecture (Critical Understanding)

### ✅ What Is Actually True

**Single database instance with two logical collections (Mode 1 & Mode 2) sharing the same schema.**

This is not a weakness. This is normal, cost-effective architecture.

### Storage Reality

| Component | Reality |
|-----------|---------|
| **Database Engine** | Single MongoDB instance |
| **Collections** | Two separate collections (`email_analysis`, `ondemand_analysis`) |
| **Schema** | Identical schema (by design) |
| **Separation** | Logical (policy-driven), not physical |

### What Is Separated

| Layer | Separated? | How |
|-------|-----------|-----|
| **Trigger** | ✅ | IMAP worker vs user click |
| **Pipeline** | ✅ | Bulk pipeline vs on-demand pipeline |
| **Storage lifecycle** | ✅ | Persistent vs ephemeral |
| **Consent model** | ✅ | Delegation vs explicit consent |
| **Collections** | ✅ | Mode-tagged collections |
| **Schema** | ❌ | Same schema (by design) |
| **Database engine** | ❌ | Same MongoDB instance |

---

## Mode 1: Bulk Forward Mode (IMAP-based)

👉 *"AI checks emails because they arrive — not because the user asked."*

### What Actually Happens

1. **User forwards emails** (or sets up auto-forward)
   - To PhishNet mailbox: `phishnet.ai@gmail.com`
   - Can forward individual emails or ALL emails

2. **IMAP Polling Worker (Background Process)**
   - Runs every 60 seconds automatically
   - Fetches new emails from IMAP inbox
   - ❗ No user click, no UI action required

3. **AI Analysis Pipeline Triggers Automatically**
   - Sender analysis (SPF/DKIM/DMARC)
   - Content analysis (phishing keywords, urgency)
   - Link analysis (VirusTotal, URL reputation)
   - Attachment analysis (malware scanning)
   - AI summary (Gemini)

4. **Verdict Generated**
   - PHISHING / SUSPICIOUS / SAFE
   - Risk score (0-100)
   - Threat indicators

5. **Results Stored**
   - Email metadata
   - Analysis output
   - Stored in `email_analysis` collection

6. **AI Sends Reply Email**
   - Automatic email reply to original sender
   - "This email is phishing" or "Safe to ignore"
   - Happens without user intervention

### Key Truth

> **Yes, the AI analyzes emails ONLY because they were forwarded — but once forwarding is enabled, AI decides everything.**

The **user is no longer in control per email**.

**Forwarding = Delegation of Control**

---

## Mode 2: On-Demand Check Mode (Gmail API)

👉 *"AI checks an email ONLY because the user explicitly asked."*

### What Actually Happens

1. **User Sees Suspicious Email**
   - In Gmail UI
   - In PhishNet dashboard

2. **User Clicks "Check This Email"**
   - ❗ This click is **mandatory**
   - No click = No analysis

3. **Gmail API Fetches ONLY That Email**
   - Uses `gmail.readonly` scope
   - Fetches by `message_id`
   - No inbox scanning
   - No background access

4. **AI Analysis Pipeline Runs**
   - Same analyzers as Mode 1
   - But isolated to ONE email
   - Single-shot analysis

5. **Verdict Shown to User**
   - Dashboard UI shows result
   - PHISHING / SUSPICIOUS / SAFE
   - Risk score and threat indicators

6. **Data Handling**
   - By default → **Deleted immediately**
   - Stored only if user explicitly consents
   - Stored in `ondemand_analysis` collection (separate from Mode 1)

### Key Truth

> **If the user does nothing, AI does nothing. Period.**

No background workers.
No inbox access.
No auto-analysis.

**On-Demand = Per-Email Consent**

---

## The CORE Difference

### Control Model

| Question | Mode 1 | Mode 2 |
|----------|--------|--------|
| **Who triggers analysis?** | System (IMAP worker) | User (button click) |
| **Does AI act automatically?** | ✅ Yes | ❌ No |
| **Does AI see all emails?** | ✅ Yes (forwarded inbox) | ❌ Only selected email |
| **Is email forwarding required?** | ✅ Yes | ❌ No |
| **Is storage default?** | ✅ Yes | ❌ No (opt-in only) |
| **Privacy level** | Medium | High |
| **User control** | Delegation | Per-email consent |

---

## Common Misconceptions (WRONG)

### ❌ "Mode 1 and Mode 2 use different databases"

**NO.**

- **Reality**: Single MongoDB instance
- **Separation**: Two logical collections with identical schemas
- **Isolation**: Policy-driven (triggers, pipelines, retention)

### ❌ "User forwarded the email, so it's same as on-demand"

**NO.**

- **Forwarding** = Permanent permission ("scan everything I forward")
- **On-Demand** = Temporary permission ("scan this one email right now")

### ❌ "Mode 2 uses a Chrome extension"

**NO.**

- Mode 2 uses **PhishNet dashboard UI**
- User logs in with Gmail OAuth
- Selects email from dashboard
- Clicks "Check This Email"

---

## Use Cases

### When to Use Mode 1 (Bulk Forward)

✅ Enterprise security teams monitoring employee inboxes
✅ Users who want automatic protection for all emails
✅ High-volume email analysis (100+ emails/day)
✅ Automated threat intelligence gathering

**Example**: Company forwards all employee emails to PhishNet for automatic scanning.

### When to Use Mode 2 (On-Demand)

✅ Privacy-conscious users who want control
✅ Occasional suspicious email checks
✅ Users who don't want to forward emails
✅ Testing specific emails without storage

**Example**: User receives a suspicious PayPal email and wants to check if it's phishing before clicking any links.

---

## Technical Architecture

### Correct Architecture Diagram

```
                    ┌─────────────────────────────┐
                    │   MongoDB (Single Instance) │
                    │                             │
                    │  ┌────────────────────────┐ │
                    │  │ email_analysis         │ │ ← Mode 1
                    │  │ (persistent storage)   │ │
                    │  └────────────────────────┘ │
                    │                             │
                    │  ┌────────────────────────┐ │
                    │  │ ondemand_analysis      │ │ ← Mode 2
                    │  │ (ephemeral by default) │ │
                    │  └────────────────────────┘ │
                    └─────────────────────────────┘
                              ▲         ▲
                              │         │
                    ┌─────────┘         └─────────┐
                    │                             │
          ┌─────────────────┐         ┌─────────────────┐
          │  Mode 1 Pipeline│         │  Mode 2 Pipeline│
          │  (IMAP Worker)  │         │  (On-Demand API)│
          └─────────────────┘         └─────────────────┘
                    ▲                           ▲
                    │                           │
          ┌─────────────────┐         ┌─────────────────┐
          │ Forwarded Emails│         │  User Click     │
          │ (Automatic)     │         │  (Manual)       │
          └─────────────────┘         └─────────────────┘
```

**Key Points**:
- ✅ **Logical separation** (different collections)
- ✅ **Policy-driven lifecycle** (persistent vs ephemeral)
- ✅ **Shared schema** (same data model)
- ✅ **Single database** (cost-effective)

### Mode 1 Flow

```
User → Forwards Email → phishnet.ai@gmail.com
                              ↓
                  IMAP Polling Worker (60s interval)
                              ↓
                  Email Analysis Pipeline
                              ↓
                  MongoDB.email_analysis (persistent)
                              ↓
                  Send Reply Email to User
```

### Mode 2 Flow

```
User → Dashboard UI → Click "Check Email"
                              ↓
                  Gmail API (fetch message_id)
                              ↓
                  Email Analysis Pipeline
                              ↓
                  MongoDB.ondemand_analysis (ephemeral)
                              ↓
                  Show Result in Dashboard
                              ↓
                  Delete (unless user consents)
```

---

## API Endpoints

### Mode 1 Endpoints

- `GET /api/v1/mode1/status` - Check if Mode 1 is running
- `GET /api/v1/mode1/pipeline/stats` - Pipeline metrics
- `POST /api/v1/mode1/start` - Start Mode 1 orchestrator
- `POST /api/v1/mode1/stop` - Stop Mode 1 orchestrator

### Mode 2 Endpoints

- `POST /api/v2/gmail/check/request` - Request email analysis
- `GET /api/v2/gmail/check/history` - User's analysis history
- `GET /api/v2/gmail/auth/google` - OAuth flow
- `DELETE /api/v2/gmail/check/history/{id}` - Delete analysis result

---

## Interview/Documentation Explanation

**Interviewer**: "What's the difference between Mode 1 and Mode 2?"

**You**: 

> "PhishNet has two execution modes that share the same database but are logically isolated:
> 
> **Mode 1 is bulk forward mode** where users forward emails to our IMAP inbox. An IMAP polling worker automatically fetches and analyzes all forwarded emails every 60 seconds. The user delegates control — once they forward, AI handles everything automatically. Results are stored persistently in the `email_analysis` collection.
> 
> **Mode 2 is on-demand mode** where users explicitly click 'Check This Email' in our dashboard. We use Gmail API to fetch only that specific email, analyze it, show the result, and delete it immediately unless the user consents to storage. Results go to the `ondemand_analysis` collection. The user has full control — AI does nothing unless explicitly asked.
> 
> Both modes use the same MongoDB instance and identical schemas, but they're separated through different triggers (automatic vs manual), different pipelines, and different data-retention policies. Mode 1 is persistent by default, Mode 2 is ephemeral by default. This gives us logical isolation without the cost of maintaining separate databases."

**Interviewer**: "So they share the same database?"

**You**:

> "Yes, same MongoDB instance, but logically separated. Think of it as two execution paths over the same data model, governed by different triggers and consent rules. The separation happens at the control and lifecycle level, not the schema level. This is actually stronger from a privacy perspective because we can enforce different retention policies programmatically rather than relying on infrastructure separation."

---

## Summary Table

| Feature | Mode 1 (Bulk Forward) | Mode 2 (On-Demand) |
|---------|----------------------|-------------------|
| **Trigger** | Automatic (IMAP worker) | Manual (user click) |
| **Email Access** | IMAP inbox | Gmail API |
| **Scope** | All forwarded emails | Single selected email |
| **Storage** | Persistent (always) | Ephemeral (opt-in) |
| **Privacy** | Medium | High |
| **Control** | Delegation | Per-email consent |
| **Use Case** | Enterprise/automation | Privacy-conscious users |
| **Collection** | `email_analysis` | `ondemand_analysis` |
| **Database** | **Shared MongoDB** | **Shared MongoDB** |
| **Schema** | **Identical** | **Identical** |
| **Separation** | **Logical (policy-driven)** | **Logical (policy-driven)** |
| **Reply** | Automatic email | Dashboard UI |

---

## Mental Model

Remember this:

- **Mode 1** = "I trust you to scan everything I forward" (Delegation)
- **Mode 2** = "I'll tell you exactly what to scan, when" (Consent)

**Forwarding ≠ On-Demand**

**Forwarding is delegation. On-Demand is consent.**

**Same database, different execution paths, different policies.**

