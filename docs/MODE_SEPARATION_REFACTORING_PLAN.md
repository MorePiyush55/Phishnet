# PhishNet Mode Separation Refactoring Plan

**Document Version:** 1.0  
**Created:** January 28, 2026  
**Status:** ✅ Phase 1 Complete  
**Purpose:** Clean separation of Bulk Forward Mode (IMAP) and On-Demand Check Mode (Gmail API)

---

## Executive Summary

The PhishNet codebase currently suffers from **tight coupling** between two operating modes:
1. **Mode 1: Bulk Forward (IMAP-based)** - Users forward emails to a central inbox for automatic analysis
2. **Mode 2: On-Demand Check (Gmail API)** - Users click a button to check specific emails with minimal data storage

This coupling causes:
- Changes in one mode breaking the other
- Shared state and services causing unexpected side effects
- Difficult testing and maintenance
- Unclear ownership of components

---

## 1. Current Architecture Analysis

### 1.1 Identified Coupling Points

| Component | Mode 1 (IMAP) | Mode 2 (Gmail API) | Coupling Issue |
|-----------|---------------|-------------------|----------------|
| `quick_imap.py` | Primary | Used by `ondemand_orchestrator.py` | Shared IMAP service |
| `enhanced_phishing_analyzer.py` | Primary | Primary | Shared (OK - this is core logic) |
| `ondemand_orchestrator.py` | Uses IMAP | Originally for Gmail | Mixed responsibilities |
| `mode1_orchestrator.py` | Primary | N/A | Clean |
| `gmail_ondemand.py` | N/A | Primary | Clean |
| `email_poller.py` | Uses | Uses (via orchestrator) | Confusing delegation |
| `ForwardedEmailAnalysis` model | Primary | N/A | Clean |
| `OnDemandAnalysis` model | N/A | Primary | Clean |

### 1.2 Service Dependencies Graph (Current)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CURRENT ARCHITECTURE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐        ┌──────────────────┐                           │
│  │  imap_emails.py  │        │   on_demand.py   │   API Layer               │
│  │     (v1 API)     │        │     (v2 API)     │                           │
│  └────────┬─────────┘        └────────┬─────────┘                           │
│           │                           │                                      │
│           │  ┌────────────────────────┘                                      │
│           │  │                                                               │
│           ▼  ▼                                                               │
│  ┌──────────────────────────────────────────────────┐                       │
│  │              ondemand_orchestrator.py            │   MIXED               │
│  │    (Confusing: uses IMAP but named "ondemand")   │   RESPONSIBILITY      │
│  └──────────────────────────────────────────────────┘                       │
│           │                           │                                      │
│  ┌────────▼─────────┐       ┌────────▼─────────┐                            │
│  │   quick_imap.py  │       │gmail_ondemand.py │                            │
│  │   (Shared!)      │       │   (Gmail API)    │                            │
│  └────────┬─────────┘       └────────┬─────────┘                            │
│           │                           │                                      │
│           └───────────┬───────────────┘                                      │
│                       ▼                                                      │
│           ┌───────────────────────────┐                                      │
│           │enhanced_phishing_analyzer │  SHARED CORE                        │
│           │    (Analysis Engine)      │  (This is OK)                       │
│           └───────────────────────────┘                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Files to Analyze for Refactoring

#### Mode 1 (IMAP/Bulk Forward) - Current Files:
- `app/services/quick_imap.py` - IMAP connection and email fetching
- `app/services/mode1_orchestrator.py` - Enterprise pipeline orchestrator
- `app/services/ondemand_orchestrator.py` - Confusingly named, used for IMAP workflows
- `app/services/email_poller.py` - Background polling service
- `app/workers/email_polling_worker.py` - Background worker
- `app/api/v1/imap_emails.py` - IMAP API endpoints
- `app/api/v1/mode1.py` - Mode 1 enterprise endpoints
- `app/api/v1/ondemand.py` - Named poorly, actually for IMAP workflows

#### Mode 2 (Gmail API/On-Demand) - Current Files:
- `app/services/gmail_ondemand.py` - Gmail API integration
- `app/services/gmail.py` - Gmail service utilities
- `app/services/gmail_oauth.py` - OAuth flow
- `app/api/v2/on_demand.py` - On-demand API endpoints
- `app/api/gmail_oauth.py` - OAuth endpoints

#### Shared Components (Should Remain Shared):
- `app/services/enhanced_phishing_analyzer.py` - Core analysis engine
- `app/services/gemini.py` - AI interpretation
- `app/services/email_sender.py` - Send response emails
- `app/models/mongodb_models.py` - Data models
- `app/config/settings.py` - Configuration

---

## 2. Proposed New Architecture

### 2.1 New Folder Structure

```
backend/app/
├── modes/                           # Mode-specific implementations
│   ├── __init__.py
│   ├── base.py                      # Abstract base classes for modes
│   ├── dependencies.py              # Dependency injection factories
│   │
│   ├── imap/                        # Mode 1: IMAP Bulk Forward
│   │   ├── __init__.py
│   │   ├── service.py               # IMAPEmailService
│   │   ├── orchestrator.py          # IMAPOrchestrator
│   │   ├── poller.py                # IMAPPollingService
│   │   └── worker.py                # IMAPPollingWorker
│   │
│   └── gmail/                       # Mode 2: Gmail API On-Demand
│       ├── __init__.py
│       ├── service.py               # GmailAPIService
│       ├── orchestrator.py          # GmailOrchestrator
│       └── oauth.py                 # GmailOAuthHandler
│
├── api/
│   ├── v1/
│   │   └── imap/                    # IMAP endpoints grouped
│   │       ├── __init__.py
│   │       ├── emails.py
│   │       ├── analysis.py
│   │       └── connection.py
│   │
│   └── v2/
│       └── gmail/                   # Gmail endpoints grouped
│           ├── __init__.py
│           ├── check.py
│           └── oauth.py
│
├── core/                            # SHARED: Mode-agnostic utilities
│   ├── analysis/                    # Phishing analyzer
│   ├── messaging/                   # Email sending
│   └── ai/                          # AI integration
│
├── compat/                          # Backward compatibility aliases
│   └── __init__.py
│
└── services/                        # Shared utilities only
    ├── deduplication.py
    ├── policy_engine.py
    └── worker_resilience.py
```

### 2.2 Target Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TARGET ARCHITECTURE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                          API LAYER                                   │    │
│  │  ┌─────────────────────┐        ┌─────────────────────┐             │    │
│  │  │   /api/v1/imap/*    │        │  /api/v2/gmail/*    │             │    │
│  │  │  (Mode 1 Endpoints) │        │ (Mode 2 Endpoints)  │             │    │
│  │  └──────────┬──────────┘        └──────────┬──────────┘             │    │
│  └─────────────│───────────────────────────────│───────────────────────┘    │
│                │                               │                             │
│  ┌─────────────▼───────────────┐  ┌───────────▼───────────────┐             │
│  │     modes/imap/             │  │     modes/gmail/          │             │
│  │  ┌───────────────────────┐  │  │  ┌───────────────────────┐│             │
│  │  │   IMAPOrchestrator    │  │  │  │   GmailOrchestrator   ││   MODE      │
│  │  └───────────┬───────────┘  │  │  └───────────┬───────────┘│   LAYER     │
│  │              │              │  │              │            │             │
│  │  ┌───────────▼───────────┐  │  │  ┌───────────▼───────────┐│             │
│  │  │   IMAPEmailService    │  │  │  │   GmailAPIService    ││             │
│  │  └───────────────────────┘  │  │  └───────────────────────┘│             │
│  │                             │  │                           │             │
│  │  ┌───────────────────────┐  │  │  ┌───────────────────────┐│             │
│  │  │   IMAPPollingWorker   │  │  │  │   GmailOAuthHandler   ││             │
│  │  └───────────────────────┘  │  │  └───────────────────────┘│             │
│  └─────────────────────────────┘  └───────────────────────────┘             │
│                │                               │                             │
│                └────────────┬──────────────────┘                             │
│                             ▼                                                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                          CORE LAYER (Shared)                          │   │
│  │                                                                       │   │
│  │  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐      │   │
│  │  │ PhishingAnalyzer │ │  ThreatIntel     │ │    GeminiAI      │      │   │
│  │  │ (Detection)      │ │  (VirusTotal,    │ │  (Interpretation)│      │   │
│  │  │                  │ │   AbuseIPDB)     │ │                  │      │   │
│  │  └──────────────────┘ └──────────────────┘ └──────────────────┘      │   │
│  │                                                                       │   │
│  │  ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐      │   │
│  │  │ Deduplication    │ │  PolicyEngine    │ │   EmailSender    │      │   │
│  │  │ Service          │ │  (Org rules)     │ │  (Notifications) │      │   │
│  │  └──────────────────┘ └──────────────────┘ └──────────────────┘      │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                             │                                                │
│                             ▼                                                │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                       DATA LAYER (Shared)                             │   │
│  │  ┌──────────────────────────────┐  ┌──────────────────────────────┐  │   │
│  │  │   ForwardedEmailAnalysis     │  │     OnDemandAnalysis         │  │   │
│  │  │   (Mode 1 specific model)    │  │   (Mode 2 specific model)    │  │   │
│  │  └──────────────────────────────┘  └──────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Refactoring Steps

### Phase 1: Create Mode Base Architecture ✅ COMPLETE

**Deliverables:**
- `modes/base.py` - Abstract base classes (`ModeType`, `EmailFetcher`, `ModeOrchestrator`, `AnalysisRequest`, `AnalysisResult`)
- `modes/dependencies.py` - Dependency injection factories
- `modes/imap/__init__.py` - IMAP package initialization
- `modes/gmail/__init__.py` - Gmail package initialization
- Directory structure for `modes/`, `core/`, `compat/`

### Phase 2: Extract and Isolate IMAP Mode ✅ COMPLETE

**Deliverables:**
- `modes/imap/service.py` - `IMAPEmailService` implementing `EmailFetcher`
- `modes/imap/orchestrator.py` - `IMAPOrchestrator` implementing `ModeOrchestrator`

**IMAPEmailService responsibilities:**
- IMAP connection management
- Fetch email by UID
- List pending emails in inbox
- Mark emails as processed
- Test connection

**IMAPOrchestrator pipeline:**
1. Deduplication check
2. Fetch email from IMAP
3. Parse email content
4. Run phishing analysis
5. Apply organizational policies
6. Store results in MongoDB
7. Send notifications

### Phase 3: Extract and Isolate Gmail Mode ✅ COMPLETE

**Deliverables:**
- `modes/gmail/service.py` - `GmailAPIService` implementing `EmailFetcher`
- `modes/gmail/orchestrator.py` - `GmailOrchestrator` implementing `ModeOrchestrator`
- `modes/gmail/oauth.py` - `GmailOAuthHandler` for OAuth 2.0

**GmailAPIService responsibilities:**
- Fetch email by Message ID via Gmail API
- Minimal scope (gmail.readonly)
- No background scanning

**GmailOrchestrator pipeline:**
1. Validate/refresh OAuth token
2. Fetch email via Gmail API
3. Run phishing analysis
4. Return results (store only if user consents)

### Phase 4: Extract Shared Core Components

**To be moved to `core/`:**
- `enhanced_phishing_analyzer.py` → `core/analysis/phishing_analyzer.py`
- `gemini.py` → `core/ai/gemini.py`
- `email_sender.py` → `core/messaging/sender.py`

### Phase 5: Update API Routes ✅ COMPLETE

**New route structure:**
- `/api/v1/imap/emails/*` - IMAP email listing/fetching
- `/api/v1/imap/analysis/*` - IMAP analysis operations
- `/api/v1/imap/connection/*` - IMAP connection management
- `/api/v2/gmail/check/*` - On-demand email checking
- `/api/v2/gmail/oauth/*` - OAuth flow management

---

## 4. Files Migration Matrix

### 4.1 Files to Move/Rename

| Current Location | New Location | Action |
|------------------|--------------|--------|
| `services/quick_imap.py` | `modes/imap/service.py` | Move & Refactor |
| `services/mode1_orchestrator.py` | `modes/imap/orchestrator.py` | Move & Refactor |
| `services/ondemand_orchestrator.py` | Split → `modes/imap/` & `modes/gmail/` | Split |
| `services/email_poller.py` | `modes/imap/poller.py` | Move |
| `workers/email_polling_worker.py` | `modes/imap/worker.py` | Move |
| `services/gmail_ondemand.py` | `modes/gmail/service.py` | Move & Refactor |
| `services/gmail_oauth.py` | `modes/gmail/oauth.py` | Move |
| `services/enhanced_phishing_analyzer.py` | `core/analysis/phishing_analyzer.py` | Move |
| `services/gemini.py` | `core/ai/gemini.py` | Move |
| `services/email_sender.py` | `core/messaging/sender.py` | Move |
| `api/v1/imap_emails.py` | `api/v1/imap/emails.py` | Move |
| `api/v1/mode1.py` | `api/v1/imap/enterprise.py` | Move & Rename |
| `api/v1/ondemand.py` | `api/v1/imap/background.py` | Move & Rename |
| `api/v2/on_demand.py` | `api/v2/gmail/check.py` | Move & Rename |
| `api/gmail_oauth.py` | `api/v2/gmail/oauth.py` | Move |

### 4.2 Files to Delete (After Migration)

| File | Reason |
|------|--------|
| `services/orchestrator.py` | Replaced by mode-specific orchestrators |
| `services/orchestrator_deprecated.py` | Deprecated |
| `services/gmail.py` | Consolidated into `modes/gmail/service.py` |
| `api/gmail_simple.py` | Deprecated |
| `api/simple_auth.py` | Deprecated |

### 4.3 Files to Keep in `services/` (Shared Utilities)

| File | Purpose |
|------|---------|
| `deduplication.py` | Shared deduplication service |
| `policy_engine.py` | Shared policy engine |
| `worker_resilience.py` | Shared resilience patterns |
| `tenant_mailbox.py` | Multi-tenant support |
| `mode1_audit.py` | Audit logging |
| `virustotal.py` | Threat intelligence |
| `abuseipdb.py` | Threat intelligence |

---

## 5. Dependencies to Decouple

### 5.1 Current Tight Couplings

| Dependency | Current State | Decoupling Strategy |
|------------|---------------|---------------------|
| `ondemand_orchestrator.py` → `quick_imap.py` | Direct import | Create interface, inject dependency |
| `email_poller.py` → `ondemand_orchestrator.py` | Direct instantiation | Use factory pattern |
| `mode1_orchestrator.py` → `enhanced_phishing_analyzer.py` | Direct import | Move analyzer to `core/` |
| `imap_emails.py` → `quick_imap.py` | Global instance | Inject via dependency |
| `gmail_ondemand.py` → `enhanced_phishing_analyzer.py` | Missing link | Add proper import after move |

### 5.2 Dependency Injection Pattern

The `modes/dependencies.py` module provides:
- `get_imap_orchestrator()` - Singleton IMAP orchestrator
- `get_gmail_orchestrator()` - Singleton Gmail orchestrator
- `get_orchestrator(mode: ModeType)` - Factory by mode type
- `get_phishing_analyzer()` - Shared analyzer
- FastAPI dependency functions for route injection

---

## 6. Risks & Migration Considerations

### 6.1 High-Risk Changes

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking existing API endpoints | Frontend breaks | Keep old routes as aliases during transition |
| Import path changes | Runtime errors | Use `__init__.py` re-exports for backward compatibility |
| Shared state issues | Race conditions | Ensure orchestrators are properly isolated |
| MongoDB model changes | Data loss | No schema changes needed - models stay in place |

### 6.2 Testing Strategy

1. **Before Refactoring:**
   - Create integration tests for both modes
   - Document current API contract

2. **During Refactoring:**
   - Maintain test coverage >80%
   - Run tests after each file move

3. **After Refactoring:**
   - Full regression testing
   - Performance benchmarks
   - Load testing both modes simultaneously

### 6.3 Backward Compatibility

The `compat/__init__.py` module provides temporary backward-compatible imports with deprecation warnings:
- `QuickIMAPService` → `IMAPEmailService`
- `EnhancedPhishingAnalyzer` → (unchanged, will be in `core/`)
- `GmailOnDemandService` → `GmailAPIService`

---

## 7. Implementation Timeline

| Week | Phase | Deliverables | Status |
|------|-------|--------------|--------|
| 1 | Create Base Architecture | `modes/base.py`, directory structure, abstract classes | ✅ Complete |
| 2 | IMAP Mode Isolation | `modes/imap/*`, migrate all IMAP-related code | ✅ Complete |
| 3 | Gmail Mode Isolation | `modes/gmail/*`, migrate all Gmail-related code | ✅ Complete |
| 4 | Core Extraction | `core/analysis/*`, `core/messaging/*`, `core/ai/*` | 🔄 Pending |
| 5 | API Restructuring | New route structure, update `main.py` | ✅ Complete |
| 6 | Testing & Cleanup | Integration tests, remove deprecated files | 🔄 Pending |
| 7 | Documentation | Update all docs, API reference | 🔄 Pending |

---

## 8. Success Criteria

After the refactoring is complete:

1. **Independence:** Changes to `modes/imap/` do not affect `modes/gmail/` and vice versa
2. **Testability:** Each mode can be tested in isolation
3. **Clarity:** File location clearly indicates which mode it belongs to
4. **Performance:** No degradation in response times
5. **Maintainability:** New developers can understand mode separation in <30 minutes

---

## 9. Key Mode Differences

| Aspect | Mode 1 (IMAP Bulk) | Mode 2 (Gmail On-Demand) |
|--------|-------------------|--------------------------|
| **Email Retrieval** | IMAP protocol | Gmail REST API |
| **Triggering** | Background polling | User-initiated click |
| **Data Storage** | Always store analysis | Consent-based storage |
| **Authentication** | Server IMAP credentials | User OAuth 2.0 tokens |
| **Target Users** | Enterprise security teams | Individual Gmail users |
| **Privacy Model** | Central inbox access | Minimal scope per email |

---

## 10. Conclusion

This refactoring plan provides a clear path to separate the two operating modes while:
- Maintaining shared core functionality
- Enabling independent development
- Preserving backward compatibility during transition
- Establishing clear ownership and boundaries

The key insight is that both modes share the **analysis engine** but differ in email retrieval, triggering, data storage, and authentication. By extracting these differences into mode-specific modules while keeping the analysis core shared, we achieve the separation needed for independent evolution.

---

## 11. Current Implementation Status

### ✅ Completed Files

**Mode Infrastructure:**
- `app/modes/__init__.py` - Package exports
- `app/modes/base.py` - Abstract interfaces
- `app/modes/dependencies.py` - Dependency injection

**Mode 1 - IMAP:**
- `app/modes/imap/__init__.py`
- `app/modes/imap/service.py` - IMAPEmailService
- `app/modes/imap/orchestrator.py` - IMAPOrchestrator

**Mode 2 - Gmail:**
- `app/modes/gmail/__init__.py`
- `app/modes/gmail/service.py` - GmailAPIService
- `app/modes/gmail/orchestrator.py` - GmailOrchestrator
- `app/modes/gmail/oauth.py` - GmailOAuthHandler

**API Routes:**
- `app/api/v1/imap/__init__.py`
- `app/api/v1/imap/emails.py`
- `app/api/v1/imap/analysis.py`
- `app/api/v1/imap/connection.py`
- `app/api/v2/gmail/__init__.py`
- `app/api/v2/gmail/check.py`
- `app/api/v2/gmail/oauth.py`

**Compatibility:**
- `app/compat/__init__.py` - Backward compatibility aliases

### 🔄 Pending

- Move shared components to `core/`
- Full test suite validation
- Remove deprecated files
- Update frontend integration documentation
