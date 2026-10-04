# REIVE — Regulatory Intelligence & Verification Engine

**REIVE** is an enterprise AI-powered regulatory intelligence and verification platform engineered to streamline US FDA Premarket Notification (510(k)) research, classification determination, candidate predicate identification, and post-market safety surveillance for medical device manufacturers, regulatory affairs (RA) professionals, quality teams, and medtech innovators.

---

## 1. Executive Summary & Core Workflow

Navigating FDA premarket requirements typically requires hours of manual cross-referencing between 21 CFR classification databases, historical 510(k) clearances, CDRH summary PDFs, and post-market safety databases. 

ReIVE automates this research through a deterministic, evidence-grounded 6-stage pipeline:

```
[ 01 DEVICE SPECIFICATION ]
       │  (Natural language input, intended clinical use, technological modality)
       ▼
[ 02 CLASSIFICATION DETERMINATION ]
       │  (Deterministic matching against FDA Product Classification database)
       ▼
[ 03 CANDIDATE PREDICATE RETRIEVAL ]
       │  (Live openFDA query for cleared 510(k) devices sharing Product Code)
       ▼
[ 04 SAFETY & POST-MARKET SURVEILLANCE ]
       │  (Screening FDA Recalls RES & MAUDE Adverse Event reporting distributions)
       ▼
[ 05 EVIDENCE & SOURCES AUDIT ]
       │  (Direct hyperlinks to FDA CDRH 510(k) Summary PDFs & AccessData records)
       ▼
[ 06 DOSSIER & REPORT COMPILATION ]
          (Publication-ready PDF dossiers, Markdown export, and RLS-secured persistence)
```

---

## 2. Key Product Capabilities

- **Deterministic Classification Matching:** Maps plain-language device concepts to official 3-letter FDA Product Codes, 21 CFR regulations, and device classes (Class I, II, III).
- **Candidate Predicate Identification:** Queries authoritative openFDA records for active 510(k) clearances sharing identical product codes and classification scopes.
- **Direct Source PDF Links:** Automatically constructs verified URLs to official FDA CDRH 510(k) Summary/Statement PDFs (`https://www.accessdata.fda.gov/cdrh_docs/pdf...`).
- **Post-Market Surveillance Screening:** Aggregates Class I/II/III recall signals and MAUDE adverse event distributions (Malfunctions, Injuries, Deaths) under neutral evidence styling.
- **Strict Anti-Hallucination Guardrails:** AI performs query understanding, comparison, and synthesis only; regulatory facts, K-numbers, and product codes are strictly retrieved from official databases.
- **Multi-Tenant Security Architecture:** Streamlit session isolation combined with Supabase Auth and PostgreSQL Row Level Security (RLS).
- **Publication-Ready Dossier Export:** Instant generation of formal A4 PDF reports and structured Markdown summaries.

---

## 3. System Architecture & Authoritative Data Sources

```
                     ┌────────────────────────────────────────┐
                     │   User Device Description & Use Case   │
                     └───────────────────┬────────────────────┘
                                         │
                                         ▼
                     ┌────────────────────────────────────────┐
                     │     Concept Extraction & Normalization │
                     │  (Delimited Untrusted Data Isolation)  │
                     └───────────────────┬────────────────────┘
                                         │
                                         ▼
                     ┌────────────────────────────────────────┐
                     │    Semantic Classification Matcher     │
                     │  (Curated FDA Product Classification)  │
                     └───────────────────┬────────────────────┘
                                         │ Top Matched Product Code
                                         ▼
                     ┌────────────────────────────────────────┐
                     │    openFDA REST API Orchestrator       │
                     └───────┬───────────────┬────────────────┘
                             │               │
            ┌────────────────┴──────┐ ┌──────┴───────────────┐
            ▼                       ▼ ▼                      ▼
    /device/510k.json      /device/recall.json      /device/event.json
  Candidate Predicates     FDA Recalls (RES)        MAUDE Adverse Events
            │                       │                        │
            └───────────────────────┼────────────────────────┘
                                    │ Structured Context Payload
                                    ▼
                     ┌────────────────────────────────────────┐
                     │   Grounded Synthesis & Report Engine   │
                     └───────────────────┬────────────────────┘
                                         │
                         ┌───────────────┴───────────────┐
                         ▼                               ▼
               Interactive Dashboard            Supabase PostgreSQL
              (PDF / Markdown Export)         (Row Level Security / RLS)
```

### Verified Authoritative Data Sources
| Data Domain | Base URL / Resource Path | Auth / Key Requirements |
| :--- | :--- | :--- |
| **Product Classification** | `https://api.fda.gov/device/classification.json` | None (Optional API key for higher rate limits) |
| **510(k) Premarket Clearances** | `https://api.fda.gov/device/510k.json` | None (Optional API key) |
| **Medical Device Recalls** | `https://api.fda.gov/device/recall.json` | None (Optional API key) |
| **Adverse Events (MAUDE)** | `https://api.fda.gov/device/event.json` | None (Optional API key) |
| **Primary CDRH PDFs** | `https://www.accessdata.fda.gov/cdrh_docs/pdf{YY}/{K_NUMBER}.pdf` | Public Web (Direct GET) |

---

## 4. Supabase Database Setup & Row Level Security (RLS)

To configure persistent analysis history with multi-tenant data isolation:

### Step 1: Execute SQL in Supabase SQL Editor
Navigate to your **Supabase Dashboard → SQL Editor** and run:

```sql
-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Create analyses table
create table public.analyses (
    id uuid default uuid_generate_v4() primary key,
    user_id uuid references auth.users(id) on delete cascade not null,
    device_description text not null,
    intended_use text,
    technology text,
    structured_device_profile jsonb not null default '{}'::jsonb,
    classification_results jsonb not null default '[]'::jsonb,
    selected_product_code text,
    predicate_results jsonb not null default '[]'::jsonb,
    safety_results jsonb not null default '{}'::jsonb,
    report_data text,
    created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Enable Row Level Security (RLS)
alter table public.analyses enable row level security;

-- Row Level Security Policies
create policy "Users can view own analyses"
    on public.analyses for select
    using (auth.uid() = user_id);

create policy "Users can insert own analyses"
    on public.analyses for insert
    with check (auth.uid() = user_id);

create policy "Users can update own analyses"
    on public.analyses for update
    using (auth.uid() = user_id);

create policy "Users can delete own analyses"
    on public.analyses for delete
    using (auth.uid() = user_id);
```

### Step 2: Verify Multi-Tenant Data Isolation
1. Create Test Account A in ReIVE and perform a device analysis. Save it to account.
2. Sign out and create Test Account B.
3. Verify that Account B's **Analysis History** and **Dashboard** show 0 records and cannot access Account A's records.

---

## 5. Configuration & Secrets Setup

ReIVE uses the **Supabase Public Anon Key** and **Gemini API Key**. Supabase administrative service keys are strictly forbidden and never used in frontend application code.


### Local Configuration (`.streamlit/secrets.toml`)
Create a local `.streamlit/secrets.toml` file in your repository root (**never commit this file to Git**):

```toml
# Supabase Authentication & PostgreSQL
SUPABASE_URL = "https://your-project-id.supabase.co"
SUPABASE_ANON_KEY = "your-supabase-anon-key"

# AI / LLM Configuration (Google Gemini)
GEMINI_API_KEY = "your-gemini-api-key"

# openFDA API Key (Optional — increases limit to 120k requests/day)
OPENFDA_API_KEY = "your-openfda-key"
```

---

## 6. Local Installation, Testing & Execution

### 1. Clone & Set Up Environment
```bash
git clone <your-repository-url>
cd reive

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install verified dependencies
pip install -r requirements.txt
```

### 2. Run Automated Test Suite
```bash
python -m pytest tests/test_reive.py -v
```

### 3. Launch Local Streamlit Application
```bash
python -m streamlit run app.py
```

---

## 7. Streamlit Community Cloud Deployment Guide

1. Push your repository to **GitHub** (ensure `.gitignore` excludes `.streamlit/secrets.toml` and `.env`).
2. Log in to [share.streamlit.io](https://share.streamlit.io).
3. Click **"New app"** and select your GitHub repository and branch (`main`).
4. Set **Main file path** to `app.py`.
5. Click **"Advanced settings..."** and navigate to the **Secrets** tab.
6. Paste your secrets:
   ```toml
   SUPABASE_URL = "https://your-project-id.supabase.co"
   SUPABASE_ANON_KEY = "your-supabase-anon-key"
   GEMINI_API_KEY = "your-gemini-api-key"
   OPENFDA_API_KEY = "your-openfda-key"
   ```
7. Click **Save** and **Deploy!**

---

## 8. Known Limitations & Regulatory Disclaimers

### Technical & Data Limitations
1. **Candidate Predicate Framing:** The official openFDA 510(k) API does not export relational predicate dependency graphs. Cleared devices retrieved by product code are strictly **Candidate Predicates** requiring human verification against primary 510(k) Summary PDFs.
2. **MAUDE Adverse Event Interpretation:** MAUDE event reporting volumes reflect passive surveillance data, not clinical incidence rates or confirmed device defects.

### Statutory Regulatory Disclaimer
> **IMPORTANT NOTICE:** ReIVE is an automated regulatory decision-support and research tool. It is **NOT** an FDA decision engine, does not guarantee 510(k) substantial equivalence determination or clearance, and does not provide legal advice. All candidate predicates and classification product codes must be verified against primary FDA CDRH documentation and evaluated by a qualified Regulatory Affairs professional.

---

## 9. Future Roadmap & Research Direction

- **Automated CDRH PDF Table Extraction:** Ingesting historical 510(k) Summary PDF scans to extract technological comparison tables directly.
- **De Novo & PMA Comparative Pathways:** Direct classification mapping for novel devices lacking clear 510(k) predicates.
- **Continuous Post-Market Monitoring:** Automated email alerts when new MAUDE adverse events or Class I/II recalls are posted for saved devices.
- **EU MDR / CE Mark Harmonization:** Cross-referencing US FDA Product Codes with European EUDAMED classifications.
