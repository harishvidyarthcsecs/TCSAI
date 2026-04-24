# CLAUDE CODE PROMPT — OTSight Command Board

## CONTEXT
We are building "OTSight Command Board" — a hackathon project for Tamil Nadu's first Industrial Cyber SOC concept targeting the Sriperumbudur manufacturing corridor (Samsung, BMW, Bosch factories).

**Problem:** OT cyber risk is invisible to leadership, ownerless, and frontline staff fear being blamed for reporting. There is no local OT security ecosystem.

**Root Cause:** Outdated governance and blame-oriented culture leave OT cyber risk ownerless and invisible.

**Solution:** A web dashboard that lets frontline OT staff (Bosch engineers, BMW workers, auto parts supervisors) report anomalies in plain language, auto-translates them into production risk metrics (₹ impact, downtime, safety), assigns ownership, detects patterns, and surfaces risk to leadership as operational KPIs.

---

## DESIGN REQUIREMENTS

### Visual Identity
- **Theme:** Dark industrial command center meets modern SaaS dashboard
- **Primary color:** #1a73e8 (electric blue — action, safety)
- **Accent:** #0d8044 (green — safety, resolved)
- **Warning:** #f39c12 (amber — risk, exposure)
- **Danger:** #c5221f (red — critical, active threats)
- **Background:** Dark navy theme (#1a1a2e base) with card surfaces
- **Font:** Inter (Google Fonts) — clean, professional, data-dense
- **Style:** Clean command center aesthetic — like a cybersecurity SOC or mission control. Data-forward, minimal decoration, maximum clarity.

### Layout
- **Header:** Dark bar with logo, navigation tabs, role switcher (OT Staff / Engineer / Manager / Admin)
- **Dashboard:** KPI cards row → Charts row (3 charts) → Full-width incident table
- **Report view:** Two-column (form left, recent reports sidebar right) — mobile-first
- **Responsive:** Must work beautifully on mobile (report view) and desktop (dashboard view)

---

## FEATURES (Build ALL of these)

### 1. Anomaly Reporting Interface
- **Multi-language input:** Supports Tamil, Hinglish, English — no translation needed, staff type naturally
- **Quick-select tags:** 10 buttons (PLC Freeze, USB Seen, HMI Slow, Network Issue, Strange Popup, Unauthorized Person, Power Fluctuation, Safety Interlock, Sensor Error, Vendor Laptop) — tap to select
- **5-step form:** (1) Where & When (shift, zone, system dropdowns), (2) What happened (quick tags + free text), (3) Description (multi-language textarea with placeholder examples in Tamil/Hinglish), (4) Impact (duration dropdown + perceived impact dropdown → auto-calculates ₹), (5) Reporter (anonymous or named option)
- **Blame-free banner:** Green banner above form: "This is a blame-free safety log. Reporting protects the plant and you."
- **Impact preview:** Live calculation shows estimated ₹ exposure, downtime, detected category, safety flag as user fills the form
- **Submission:** < 60 seconds to complete. Shows success toast on submit.
- **Auto-assign:** On submit, system looks up the current shift + selected system → assigns to named owner automatically

### 2. Risk Translation Engine (Backend Logic)
- **Keyword classification:** Maps Tamil/Hinglish keywords (plc hang, aagiduchu, USB near cabinet) to categories
- **Categories:** Unauthorized Device (USB), OT Availability, Suspicious Activity, Network Degradation, Configuration Change, Physical Security, Power/Electrical, Safety Event, Near-Miss/Observation
- **Severity scoring:** 0-10 scale based on: system criticality × duration × impact type × safety keywords
- **₹ impact formula:** `downtime_hours × hourly_run_rate × impact_multiplier`
  - Each system (PLC-01, SCADA-Server, HMI-01, etc.) has a stored hourly_run_rate
  - Multipliers: none=1.0, minor=1.2, temp-stop=1.5, safety=2.5, major=4.0
- **Safety flag:** Auto-set if keywords like safety, emergency, smoke, fire, interlock detected
- **Output:** English summary, category, severity (Critical/High/Medium/Low), ₹ exposure, safety flag, owner

### 3. Ownership Assignment System
- **System registry:** Table of OT assets with names, zones, hourly run rates
- **Shift-wise owners:** Each system has a named owner per shift (Morning/Afternoon/Night)
- **Auto-assignment:** On report submit, lookup `shift_owners[shift][system]` → set owner
- **Ownerless flag:** If no owner found, assign to supervisor and flag as "Ownerless — Escalated"
- **Display:** Every incident card/row shows owner clearly with name + role

### 4. Impact Visualization Dashboard (Leadership View)
- **6 KPI cards:** Open Issues, Total ₹ Exposure, Safety-Relevant Issues, Total Downtime Hours, Reports This Week, Pattern Clusters Detected
- **3 charts:** (1) Line chart — incident trend + ₹ exposure over 30 days (dual Y-axis), (2) Bar chart — ₹ exposure by zone, (3) Doughnut chart — incidents by category
- **Filterable incident table:** Columns — ID, Date/Time, Zone, System, Category, Description (truncated), ₹ Impact, Severity (badge), Safety, Owner, Status, Action. Filters: by zone, by status, by severity
- **Severity badges:** Critical=red, High=amber, Medium=blue, Low=green
- **Status badges:** Open=red, In Progress=amber, Mitigated=blue, Resolved=green
- **Zone filter dropdown:** Filters all views (KPIs, charts, table)
- **Action buttons:** View (opens detail modal), Resolve (one-click resolve)
- **OEM Export button:** Top-right — opens weekly compliance report modal

### 5. Blame-Free Reporting Guidelines
- **Full page at /guidelines:** Separate navigation tab
- **Content:** Our commitment, what to report (examples good/bad), how reports are used (flow diagram), your protection (anonymous option, good faith protection, recognition culture), categories we track
- **Embedded in report form:** Green banner + inline microcopy hints
- **Non-punitive culture banner:** On scoreboard page — "High reporting rate = Strong safety culture"

### 6. Pattern Clustering & Near-Miss Scoreboard
- **Pattern Detection (Patterns tab):**
  - Groups incidents by zone + category within configurable window (7/21/30 days)
  - Threshold: 2+ incidents → creates a pattern cluster
  - Shows: Pattern cards (category, zone, count, combined ₹ exposure, time window, risk velocity)
  - Risk velocity: Increasing (red) if last incident within 3 days, Stable (amber) otherwise
  - Pattern table: Full detail with all cluster metrics
  - Heatmap: Zones × Categories grid with color intensity (0=light, 4+=dark red)
  - Legend for heatmap colors

- **Near-Miss Scoreboard (Scoreboard tab):**
  - Top 3 badges: Top Reporting Zone, Most Active Shift, Total Reports (30 days)
  - Bar chart: Reports by zone
  - Doughnut chart: Reports by shift
  - Scoreboard table: Zone × Shift matrix with counts + trend arrows + status badges
  - Status badges: 🏆 Top (≥4 reports), ✅ Active (2-3), ⚠️ Silent (0), 🔵 Low (1)
  - Culture banner: Non-punitive commitment statement

### 7. OEM Compliance Bridge
- **Weekly OT Risk Summary modal (Export button):**
  - Period selector (auto: last 7 days)
  - 4 stat cards: Incidents (7d), Open Issues, ₹ Exposure, Issues with Owner %
  - Summary table: Critical count, safety issues, resolved, risk mitigated (₹)
  - Open Issues by Category: table with count, ₹ exposure, % of total
  - Open Issues by Zone: table with open count, critical count, ₹ exposure
  - Ownership & Accountability: table by owner name, open issues, resolved (30d), total ₹
  - Print/Save PDF button
  - Professional format that a Bosch HQ or Samsung compliance team can read in 60 seconds

### 8. Incident Detail Modal
- Opens on "View" button click from table
- Shows: All incident fields in a clean grid layout
- Raw description in a highlighted box
- Quick tags displayed as badges
- Status update dropdown (Open → In Progress → Mitigated → Resolved)
- Resolved timestamp captured

---

## DATA & STORAGE
- **Use localStorage** for data persistence — no backend needed
- **Seed with 15 realistic incidents** spanning all zones, categories, severities, and dates over past 30 days — realistic Tamil Nadu plant floor descriptions
- **Systems:** PLC-01 through PLC-04, HMI-01 through HMI-03, SCADA-Server, DCS-01, Network Switch, Fire System — each with realistic hourly run rates (₹30K-1.2L/hour)
- **Shift owners:** 5 named people (Ramkumar R, Priya S, Karthik M, Sundari P, Arun V) with realistic shift allocations

---

## TECHNICAL SPECS
- **Files:** Single-page HTML + CSS + JavaScript only. No frameworks, no build step.
- **Structure:**
  - `index.html` — complete UI with all views
  - `css/style.css` — all styles
  - `js/app.js` — all logic
- **External resources:** Only Chart.js (CDN), Google Fonts (Inter)
- **Browser target:** Modern browsers (Chrome, Firefox, Safari)
- **GitHub Pages:** Must deploy directly — no server config needed

---

## INNOVATION HOOKS (What makes this stand out)

1. **Tamil + Hinglish native input** — No other OT reporting tool accepts Tamil shop-floor language
2. **₹ exposure calculator** — Translates cyber risk into the only language plant managers understand: money
3. **Auto-assignment** — Removes the "not my problem" excuse at the moment of reporting
4. **Pattern detection** — Turns invisible near-misses into visible systemic risk
5. **Non-punitive scoreboard** — Flips the feedback loop: high reporters = heroes, not audit targets
6. **OEM-ready export** — Tier-2 suppliers can prove cyber hygiene to Samsung/Bosch without a security team
7. **Role-based views** — OT staff gets a 60-second mobile form; managers get a command center

---

## SUCCESS CRITERIA
When a Samsung DGM opens this in a browser:
- They immediately see ₹ exposure across their plant
- They can filter by zone and see which line has the most risk
- They can click any incident and see who owns it
- They can export a one-page report to send to Bangalore HQ
- A Bosch engineer can submit a report in under 60 seconds from their phone

When a BMW line operator opens this:
- They see the green blame-free banner
- They tap 2-3 quick buttons + write 2 lines
- They submit and feel heard

---

## DEPLOY TO GITHUB PAGES
1. Create a new GitHub repo named `otsight-command-board`
2. Push all files to the repo
3. Go to Settings → Pages → Source: Deploy from `main` branch
4. Share the live URL

---

Build this completely. Every feature. Every view. Every interaction. Make it polished, professional, and ready to demo to a panel.
