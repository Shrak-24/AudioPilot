# AuditPilot — RBI CSITE Compliance Automation

> Agentic compliance pipeline for Indian banks. Turns a raw SOC alert into a filed RBI incident report in under 6 minutes.

![AuditPilot Dashboard](https://img.shields.io/badge/Status-Live%20Demo-brightgreen) ![RBI CSITE](https://img.shields.io/badge/Framework-RBI%20CSITE-blue) ![No Backend](https://img.shields.io/badge/Backend-None-lightgrey)

---

## The Problem

When a cyber incident hits a bank, the **6-hour RBI CSITE reporting deadline** quietly passes — not because of negligence, but because SOC teams and compliance teams work in silos. Alerts get raised, emails get sent, spreadsheets get updated, and somewhere in that manual chain the clock runs out.

## The Solution

AuditPilot replaces that manual chain with **three intelligent agents working in sequence**:

```
SOC Alert → [Classification Agent] → [Report Generation Agent] → [Compliance Workbench] → RBI Filed
```

| Agent | What it does | Time |
|---|---|---|
| **Classification Agent** | Reads SOC alert, determines RBI reportability, computes deadline | ~4 sec |
| **Report Generation Agent** | Drafts complete 9-section RBI CSITE report, zero human input | ~6 sec |
| **Compliance Workbench** | Converts report to MAP, assigns teams, starts countdown, gates closure on evidence | Live |

---

## Features

- 🚨 **Live countdown timers** — T+2hr initial notification, T+6hr full report, T+6hr CERT-In, T+21day post-incident
- 🤖 **Classification Agent** — evaluates severity, financial exposure, customer impact, system criticality against RBI threshold matrix
- 📄 **Auto-generated RBI report** — all 9 prescribed sections including timeline, impact assessment, RCA, regulatory submission table, officer certification
- 📋 **Kanban MAP** — 10 auto-generated action items, drag-and-drop, team assignments across 6 teams
- 🔐 **Evidence-gated closure** — tasks can only close after evidence is uploaded and verified
- 📜 **Immutable audit trail** — every agent and human action timestamped, filterable, exportable as CSV
- 🖨️ **PDF export** — print-optimised report layout via browser print

---

## Demo

**Fastest path:**
1. Open `index.html` in any browser
2. Click **"Load Demo Scenario"** — pre-fills a LockBit 3.0 ransomware attack on CBS/SWIFT
3. Click **"Feed to Classification Agent"** — watch it classify in real-time
4. Follow the pipeline through Report → Workbench → evidence upload → closure

Full pipeline demo takes **~3 minutes**.

---

## Tech Stack

| Layer | Choice |
|---|---|
| Structure | HTML5 (semantic) |
| Styling | Vanilla CSS (custom design system, glassmorphism, animations) |
| Logic | Vanilla JavaScript (IIFE module pattern, no frameworks) |
| Fonts | Inter + JetBrains Mono (Google Fonts) |
| Backend | None — runs fully offline |
| Data | In-memory state + localStorage |

---

## Regulatory Basis

- **RBI Master Direction – Information Technology Framework 2024**
- **RBI Circular DIT.CO.OSD.No.S2584/07.01.016/2018-19**
- **CERT-In Directions 2022, Section 4(i)(a)** — parallel 6-hour reporting obligation
- **RBI DAKSH Portal** — prescribed submission channel
- Incident classification per RBI CSITE taxonomy (Tier-1 mandatory: Ransomware, DDoS, Data Breach, SWIFT Fraud, Web Defacement)

---

## Project Structure

```
canara/
├── index.html    # Shell + all 5 views (SOC → Classification → Report → Workbench → Audit)
├── styles.css    # Full design system — 700+ lines, dark theme, glassmorphism
├── app.js        # State machine, agent simulations, timers, kanban, audit log — 1000 lines
└── README.md
```

---

## Built For

Banks, NBFCs, and payment system operators operating under RBI's CSITE framework who need to close the gap between incident detection and regulatory reporting — before the 6-hour clock runs out.

---

*Built with vanilla HTML/CSS/JS. No dependencies. No build step. Open and run.*
