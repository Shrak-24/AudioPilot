/* ================================================================
   AUDITPILOT — RBI CSITE COMPLIANCE ENGINE
   Application State Machine & Agent Orchestration
   ================================================================ */

const App = (() => {

  /* ─── STATE ─────────────────────────────────────────────── */
  const S = {
    unlocked:       ['soc'],
    currentView:    'soc',
    severity:       null,
    detectionTime:  null,
    incidentId:     null,
    form:           null,
    classification: null,
    tasks:          [],
    activeTask:     null,
    auditLog:       [],
    teams:          [],
    timerInterval:  null,
  };

  /* ─── NAVIGATION ─────────────────────────────────────────── */
  function nav(view) {
    if (!S.unlocked.includes(view)) {
      toast('Complete the current stage first', 'warning'); return;
    }
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(`${view}-view`).classList.add('active');
    document.querySelectorAll('.stage-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(`stage-${view}`).classList.add('active');
    S.currentView = view;
    if (view === 'audit') renderAuditTable();
  }

  function unlock(stage) {
    if (S.unlocked.includes(stage)) return;
    S.unlocked.push(stage);
    document.getElementById(`stage-${stage}`).classList.remove('locked');
  }

  function complete(stage) {
    const btn = document.getElementById(`stage-${stage}`);
    btn.classList.remove('active');
    btn.classList.add('complete');
    document.getElementById(`chk-${stage}`).style.display = 'flex';
  }

  /* ─── DEMO DATA ──────────────────────────────────────────── */
  function fillDemo() {
    const detect = new Date(Date.now() - 8.5 * 60 * 1000); // 8.5 min ago
    document.getElementById('f-alert-id').value      = 'SOC-2026-0847';
    document.getElementById('f-detect-time').value   = toLocalISOString(detect);
    document.getElementById('f-source').value        = 'edr';
    document.getElementById('f-type').value          = 'ransomware';
    document.getElementById('f-financial').value     = '25000000';
    document.getElementById('f-customers').value     = '15000';
    document.getElementById('f-desc').value          =
      'CrowdStrike Falcon EDR detected LockBit 3.0 ransomware execution on CBS primary node (CNRB-CBSPRD-01). ' +
      'Process chain: svchost.exe → msiexec.exe → lockbit3.exe. Lateral movement identified originating from ' +
      'domain controller CNRB-DC-01 via CVE-2023-23397 exploit. Encryption attempt observed on file server ' +
      'cluster FS-01, FS-02, FS-03 (est. 3.2TB data at risk). C2 communication detected to 185.220.101.47:443 ' +
      '(TOR exit node). SWIFT messaging gateway SWG-PROD showing anomalous authentication attempts from ' +
      'compromised service account CNRB\\svc-batch01. Ransomware note found: "All your CBS files are encrypted."';
    ['s-cbs','s-swift','s-ib'].forEach(id => { document.getElementById(id).checked = true; });
    setSev('p1', document.querySelector('.sev-btn[data-sev="p1"]'));
    toast('Demo loaded: LockBit 3.0 on Canara Bank CBS', 'success');
    log('SOC Intake','system','AuditPilot','Demo scenario pre-loaded: LockBit 3.0 Ransomware targeting CBS/SWIFT','Complete');
  }

  function setSev(sev, btn) {
    document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    S.severity = sev;
  }

  /* ─── SOC SUBMIT ─────────────────────────────────────────── */
  function submit() {
    const type = document.getElementById('f-type').value;
    const desc = document.getElementById('f-desc').value.trim();
    if (!type)        { toast('Please select an incident type', 'error'); return; }
    if (!desc)        { toast('Please provide an incident description', 'error'); return; }
    if (!S.severity)  { toast('Please select a severity level', 'error'); return; }

    const dtVal = document.getElementById('f-detect-time').value;
    S.detectionTime = dtVal ? new Date(dtVal) : new Date(Date.now() - 8.5 * 60 * 1000);
    S.incidentId    = 'IR-CNRB-2026-0847';

    const systems = [];
    document.querySelectorAll('.systems-grid input:checked').forEach(el => systems.push(el.value));

    S.form = {
      alertId:    document.getElementById('f-alert-id').value || 'SOC-2026-0847',
      detTime:    S.detectionTime,
      source:     document.getElementById('f-source').value || 'edr',
      type, systems, severity: S.severity,
      desc,
      financial:  parseFloat(document.getElementById('f-financial').value) || 0,
      customers:  parseInt(document.getElementById('f-customers').value)   || 0,
      officer:    document.getElementById('f-officer').value || 'Rajesh Kumar Sharma',
      desig:      document.getElementById('f-desig').value  || 'CISO',
      dept:       document.getElementById('f-dept').value   || 'Information Security',
      email:      document.getElementById('f-email').value  || 'ciso@canarabank.co.in',
      phone:      document.getElementById('f-phone').value  || '+91-80-2223-0000',
    };

    startTimers();

    // Navbar badge
    document.getElementById('incident-badge').style.display = 'flex';
    document.getElementById('incident-id-display').textContent = S.incidentId;
    document.getElementById('deadline-chip').textContent = 'ACTIVE INCIDENT';
    document.getElementById('deadline-chip').classList.add('live');

    complete('soc');
    unlock('classification');

    log('SOC Intake','human','SOC Analyst',
      `Alert ${S.form.alertId} ingested — ${typeName(type)} | Severity: ${S.severity.toUpperCase()} | Systems: ${systems.join(', ') || 'unspecified'}`,
      'Complete');
    log('SOC Intake','system','AuditPilot',
      `Incident ${S.incidentId} created. RBI CSITE deadline clock started. T+0 = ${fmt(S.detectionTime)}`, 'Complete');

    nav('classification');
    setTimeout(runClassification, 350);
  }

  /* ─── CLASSIFICATION AGENT ───────────────────────────────── */
  function runClassification() {
    const avatar  = document.getElementById('a1-avatar');
    const status  = document.getElementById('a1-status');
    const steps   = document.getElementById('proc-steps');
    const resLoad = document.getElementById('result-loading');
    const resCont = document.getElementById('result-content');
    const confBlk = document.getElementById('conf-block');
    const actions = document.getElementById('a1-actions');

    avatar.classList.add('thinking');
    status.textContent = 'Analyzing alert...';

    const STEPS = [
      { t:'Parsing SOC Alert Metadata',         s:'Extracting incident type, severity, affected systems' },
      { t:'Querying RBI CSITE Taxonomy',         s:'Matching incident against reportability rule matrix' },
      { t:'Evaluating Threshold Criteria',       s:'Financial exposure · customer count · system criticality' },
      { t:'Checking CERT-In Directions 2022',   s:'Parallel reporting obligation analysis' },
      { t:'Generating Regulatory Decision',      s:'Computing confidence score and submission deadlines' },
    ];

    steps.innerHTML = STEPS.map((s,i) => `
      <div class="proc-step pending" id="ps-${i}">
        <div class="proc-step-icon">⟳</div>
        <div class="proc-step-text">
          <span class="proc-step-title">${s.t}</span>
          <span class="proc-step-sub">${s.s}</span>
        </div>
      </div>`).join('');

    STEPS.forEach((step, i) => {
      setTimeout(() => {
        for (let j = 0; j < i; j++) markStep(j, 'done');
        markStep(i, 'active');
        status.textContent = step.t + '...';
      }, i * 850);
    });

    setTimeout(() => {
      STEPS.forEach((_,i) => markStep(i, 'done'));
      avatar.classList.remove('thinking');
      status.textContent = 'Classification Complete ✓';

      S.classification = classify(S.form);

      confBlk.style.display = 'block';
      document.getElementById('conf-pct').textContent = S.classification.confidence.toFixed(0) + '%';
      setTimeout(() => { document.getElementById('conf-fill').style.width = S.classification.confidence + '%'; }, 80);

      resLoad.style.display = 'none';
      resCont.style.display = 'flex';
      resCont.innerHTML = buildClassResult(S.classification);
      actions.style.display = 'flex';

      complete('classification');
      unlock('report');

      log('Classification','agent','Classification Agent v2.1',
        `Incident classified as ${S.classification.reportable ? 'REPORTABLE' : 'NOT REPORTABLE'} to RBI CSITE. ` +
        `Confidence: ${S.classification.confidence.toFixed(0)}%. Deadline: T+${S.classification.initDeadline}hr initial, T+6hr full.`,
        'Complete');
    }, STEPS.length * 850 + 400);
  }

  function markStep(i, state) {
    const el = document.getElementById(`ps-${i}`);
    if (!el) return;
    el.className = `proc-step ${state}`;
    const icon = el.querySelector('.proc-step-icon');
    if (state === 'done') icon.textContent = '✓';
    else if (state === 'active') icon.textContent = '⟳';
    else icon.textContent = '⟳';
  }

  function classify(d) {
    const reasons = []; let reportable = false;
    if (d.severity === 'p1') {
      reportable = true;
      reasons.push('P1 Critical severity mandates immediate RBI notification per Master Direction – IT Framework 2024, Clause 7.3');
    }
    const t1Types = ['ransomware','ddos','data-breach','swift-fraud','web-defacement'];
    if (t1Types.includes(d.type)) {
      reportable = true;
      reasons.push(`${typeName(d.type)} is a Tier-1 incident category under RBI CSITE — unconditionally reportable`);
    }
    if (d.financial > 100000) {
      reportable = true;
      reasons.push(`Financial exposure ₹${inr(d.financial)} exceeds statutory ₹1,00,000 threshold`);
    }
    if (d.customers > 100) {
      reportable = true;
      reasons.push(`${d.customers.toLocaleString('en-IN')} customers impacted — exceeds 100-customer mandatory reporting trigger`);
    }
    if (d.systems.includes('swift')) {
      reportable = true;
      reasons.push('SWIFT messaging gateway compromised — critical financial market infrastructure, auto-reportable');
    }
    if (d.systems.includes('cbs')) {
      reportable = true;
      reasons.push('Core Banking System (CBS) affected — primary customer-facing infrastructure triggers mandatory notification');
    }
    if (!reportable) reasons.push('Incident does not meet RBI CSITE minimum reporting criteria. Document internally per CCMP.');

    return {
      reportable, reasons,
      confidence: reportable ? 91 + Math.random() * 7 : 88 + Math.random() * 8,
      initDeadline: d.severity === 'p1' ? 2 : 6,
      category: incidentCat(d.type),
      certIn: reportable,
      ref: 'RBI Master Direction – IT Framework 2024 | CERT-In Directions 2022 | DIT.CO.OSD.No.S2584/07.01.016/2018-19',
    };
  }

  function buildClassResult(r) {
    const isRep = r.reportable;
    const rTags = (isRep ? ['RBI CSITE','CERT-In','DAKSH Portal'] : ['Internal CCMP Only'])
      .map(t => `<span class="reg-tag">${t}</span>`).join('');
    const reasons = r.reasons.map(x => `
      <div class="verdict-reason${isRep ? '' : ' green'}">
        <span style="flex-shrink:0">${isRep ? '⚠' : '✓'}</span><span>${x}</span>
      </div>`).join('');
    return `
      <div class="verdict-card ${isRep ? 'reportable' : 'not-reportable'}">
        <div class="verdict-badge ${isRep ? 'red' : 'green'}">
          <span class="verdict-icon">${isRep ? '🚨' : '✅'}</span>
          <span>${isRep ? 'REPORTABLE TO RBI' : 'NOT REPORTABLE'}</span>
        </div>
        <div class="verdict-sub">${isRep
          ? `This incident MUST be reported to RBI CSITE via DAKSH portal within ${r.initDeadline} hours (initial notification) and 6 hours for the full structured report.`
          : 'This incident does not meet RBI CSITE reportability thresholds. Document internally per your Cyber Crisis Management Plan.'
        }</div>
        <div class="verdict-reasons">${reasons}</div>
      </div>
      <div class="class-details-grid">
        <div class="class-detail-card"><div class="cd-label">Incident Category</div><div class="cd-value">${r.category}</div></div>
        <div class="class-detail-card"><div class="cd-label">Severity Rating</div><div class="cd-value red">P1 — CRITICAL</div></div>
        <div class="class-detail-card"><div class="cd-label">Initial Notification</div><div class="cd-value amber">T + ${r.initDeadline} hours</div></div>
        <div class="class-detail-card"><div class="cd-label">Full Report Deadline</div><div class="cd-value red">T + 6 hours</div></div>
        <div class="class-detail-card" style="grid-column:1/-1">
          <div class="cd-label">Mandatory Submissions</div>
          <div class="regulatory-tags">${rTags}</div>
        </div>
        <div class="class-detail-card" style="grid-column:1/-1">
          <div class="cd-label">Regulatory Reference</div>
          <div class="cd-value blue" style="font-size:11px;font-weight:500">${r.ref}</div>
        </div>
      </div>`;
  }

  /* ─── REPORT GENERATION AGENT ────────────────────────────── */
  function startReport() {
    unlock('report');
    nav('report');
    setTimeout(runReport, 400);
  }

  function runReport() {
    const t0   = Date.now();
    const sList = document.getElementById('report-steps');
    const doc  = document.getElementById('report-doc');
    const a2   = document.getElementById('a2-status');
    const stats= document.getElementById('report-stats');
    const acts = document.getElementById('report-act-panel');

    const STEPS = [
      'Extracting incident metadata',
      'Auto-filling organisation details',
      'Computing impact assessment',
      'Building chronological timeline',
      'Drafting interim mitigation actions',
      'Generating preliminary RCA',
      'Structuring regulatory submissions',
      'Formatting per RBI Annexure',
      'Validating all required fields',
      'Finalising report document',
    ];

    sList.innerHTML = STEPS.map((s,i) => `
      <div class="report-step pending" id="rs-${i}">
        <div class="rs-dot">⟳</div>
        <span class="rs-text">${s}</span>
      </div>`).join('');

    doc.innerHTML = `<div class="result-loading" style="min-height:400px"><div class="loading-spinner"></div><span>Generating report...</span></div>`;

    STEPS.forEach((_, i) => {
      setTimeout(() => {
        for (let j = 0; j < i; j++) {
          const e = document.getElementById(`rs-${j}`);
          if (e) { e.className = 'report-step done'; e.querySelector('.rs-dot').textContent = '✓'; }
        }
        const cur = document.getElementById(`rs-${i}`);
        if (cur) cur.className = 'report-step active';
        a2.textContent = STEPS[i] + '...';
      }, i * 480);
    });

    setTimeout(() => {
      STEPS.forEach((_,i) => {
        const e = document.getElementById(`rs-${i}`);
        if (e) { e.className = 'report-step done'; e.querySelector('.rs-dot').textContent = '✓'; }
      });
      a2.textContent = 'Report Generated ✓';
      const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
      document.getElementById('rs-time').textContent = elapsed + 's';
      stats.style.display = 'grid';
      acts.style.display  = 'flex';
      doc.innerHTML = buildReportHTML();

      complete('report');
      unlock('workbench');
      unlock('audit');

      log('Report Generation','agent','Report Agent v2.1',
        `RBI CSITE Incident Report ${S.incidentId} generated in ${elapsed}s. 9 sections · 47 fields auto-filled. Status: PENDING SUBMISSION.`,
        'Complete');
    }, STEPS.length * 480 + 500);
  }

  function buildReportHTML() {
    const d = S.form;
    const dt = d.detTime;
    const now = new Date();
    const esc = new Date(dt.getTime() + 15 * 60000);
    const con = new Date(dt.getTime() + 35 * 60000);
    const rep = new Date(dt.getTime() + 47 * 60000);

    const sysMap = { 'cbs':'Core Banking System (CBS)', 'swift':'SWIFT Messaging Gateway',
      'internet-banking':'Internet Banking Portal', 'mobile-banking':'Mobile Banking App',
      'atm':'ATM Network', 'upi':'UPI Payment System', 'rtgs-neft':'RTGS / NEFT Gateway',
      'treasury':'Treasury Management System', 'trade-finance':'Trade Finance System',
      'datacenter':'Data Centre Infrastructure' };
    const sysTags = d.systems.map(s => `<span class="report-sys-tag">${sysMap[s]||s}</span>`).join('');

    return `
<div class="report-doc-header">
  <div class="report-doc-logo">Reserve Bank of India — CSITE Framework | Strictly Confidential</div>
  <div class="report-doc-title">CYBER SECURITY INCIDENT REPORT</div>
  <div class="report-doc-subtitle">Prescribed Annexure Format — Not for Public Disclosure | Filed under RBI Master Direction – IT Framework 2024</div>
</div>

<div class="report-section">
  <div class="report-section-title">Section 1 — Report Identification</div>
  <div class="report-field-grid">
    <div class="report-field"><div class="report-field-label">Incident Reference No.</div><div class="report-field-value bold">${S.incidentId}</div></div>
    <div class="report-field"><div class="report-field-label">SOC Alert ID</div><div class="report-field-value">${d.alertId}</div></div>
    <div class="report-field"><div class="report-field-label">Report Status</div><div class="report-field-value bold red">NEW INCIDENT</div></div>
    <div class="report-field"><div class="report-field-label">Report Date &amp; Time</div><div class="report-field-value">${fmt(now)}</div></div>
    <div class="report-field"><div class="report-field-label">DAKSH Reference</div><div class="report-field-value blue">DAKSH-CNRB-2026-0847 (Pending)</div></div>
    <div class="report-field"><div class="report-field-label">Update Reference</div><div class="report-field-value">N/A — Initial Report</div></div>
  </div>
</div>

<div class="report-section">
  <div class="report-section-title">Section 2 — Organisation Details</div>
  <div class="report-field-grid">
    <div class="report-field"><div class="report-field-label">Name of Bank / Entity</div><div class="report-field-value bold">Canara Bank Limited</div></div>
    <div class="report-field"><div class="report-field-label">RBI Registration No.</div><div class="report-field-value">RBI/SCH/2024/CB-0047</div></div>
    <div class="report-field"><div class="report-field-label">Reporting Officer</div><div class="report-field-value bold">${d.officer}</div></div>
    <div class="report-field"><div class="report-field-label">Designation</div><div class="report-field-value">${d.desig}</div></div>
    <div class="report-field"><div class="report-field-label">Department</div><div class="report-field-value">${d.dept}</div></div>
    <div class="report-field"><div class="report-field-label">Official Email</div><div class="report-field-value blue">${d.email}</div></div>
    <div class="report-field"><div class="report-field-label">Contact Number</div><div class="report-field-value">${d.phone}</div></div>
    <div class="report-field"><div class="report-field-label">Head Office Address</div><div class="report-field-value">112, J.C. Road, Bengaluru — 560 002, Karnataka</div></div>
  </div>
</div>

<div class="report-section">
  <div class="report-section-title">Section 3 — Incident Information</div>
  <div class="report-field-grid">
    <div class="report-field"><div class="report-field-label">Detection Date &amp; Time</div><div class="report-field-value bold red">${fmt(dt)}</div></div>
    <div class="report-field"><div class="report-field-label">Detection Source / Tool</div><div class="report-field-value">${srcName(d.source)}</div></div>
    <div class="report-field"><div class="report-field-label">Incident Category</div><div class="report-field-value bold">${incidentCat(d.type)}</div></div>
    <div class="report-field"><div class="report-field-label">Incident Type</div><div class="report-field-value bold red">${typeName(d.type)}</div></div>
    <div class="report-field"><div class="report-field-label">Severity Classification</div><div class="report-field-value bold red">P1 — CRITICAL</div></div>
    <div class="report-field"><div class="report-field-label">Current Incident Status</div><div class="report-field-value">Under Active Investigation</div></div>
    <div class="report-field" style="grid-column:1/-1"><div class="report-field-label">Affected Systems</div><div class="report-systems-list" style="margin-top:6px">${sysTags}</div></div>
    <div class="report-field" style="grid-column:1/-1"><div class="report-field-label">Incident Description (as reported by SOC)</div>
      <div class="report-field-value" style="margin-top:6px;background:#f7fafc;padding:10px 12px;border-radius:4px;border-left:3px solid #fc8181;font-family:monospace;font-size:12px;line-height:1.65;color:#2d3748">${d.desc}</div>
    </div>
  </div>
</div>

<div class="report-section">
  <div class="report-section-title">Section 4 — Impact Assessment</div>
  <div class="report-field-grid">
    <div class="report-field"><div class="report-field-label">Estimated Financial Exposure</div><div class="report-field-value bold red">₹ ${inr(d.financial)}</div></div>
    <div class="report-field"><div class="report-field-label">Customers Potentially Impacted</div><div class="report-field-value bold">${d.customers.toLocaleString('en-IN')} (Retail + Corporate)</div></div>
    <div class="report-field"><div class="report-field-label">Service Availability Impact</div><div class="report-field-value red">Internet Banking: DEGRADED | CBS: PARTIALLY OFFLINE</div></div>
    <div class="report-field"><div class="report-field-label">Market / Regulatory Impact</div><div class="report-field-value">Potential customer data exposure; SWIFT transaction integrity at risk</div></div>
    <div class="report-field"><div class="report-field-label">Business Continuity Status</div><div class="report-field-value red">BCP ACTIVATED — Secondary CBS (Chennai DC) brought online</div></div>
    <div class="report-field"><div class="report-field-label">Reputational Risk Assessment</div><div class="report-field-value">HIGH — Proactive media containment initiated</div></div>
  </div>
</div>

<div class="report-section">
  <div class="report-section-title">Section 5 — Chronological Timeline</div>
  <div class="report-timeline">
    <div class="report-timeline-item"><div class="rtti-time">T+0 min</div><div class="rtti-event"><strong>Detection:</strong> CrowdStrike Falcon EDR triggered CRITICAL alert on CBS primary node (CNRB-CBSPRD-01). LockBit 3.0 execution pattern confirmed. Alert auto-escalated to L3 SOC Analyst.</div></div>
    <div class="report-timeline-item"><div class="rtti-time">T+8 min</div><div class="rtti-event"><strong>Triage:</strong> L3 SOC Analyst confirmed ransomware activity. Incident ticket opened. C2 IP 185.220.101.47 blocked at perimeter NGFW. Lateral movement traced to DC CNRB-DC-01.</div></div>
    <div class="report-timeline-item"><div class="rtti-time">T+15 min</div><div class="rtti-event"><strong>Escalation:</strong> CISO (${d.officer}), MD &amp; CEO, Head of Risk and Head of Compliance notified via secure channel. Emergency IR team mobilised.</div></div>
    <div class="report-timeline-item"><div class="rtti-time">T+22 min</div><div class="rtti-event"><strong>Network Isolation:</strong> Affected CBS nodes isolated from production network segment. Lateral movement contained at VLAN boundary. BCP for CBS and payment systems initiated.</div></div>
    <div class="report-timeline-item"><div class="rtti-time">T+35 min</div><div class="rtti-event"><strong>Containment:</strong> Forensic imaging of affected servers FS-01/FS-02/FS-03 initiated. Compromised domain accounts suspended. SWIFT gateway placed in read-only mode. SWIFT ISAC notified.</div></div>
    <div class="report-timeline-item"><div class="rtti-time">T+47 min</div><div class="rtti-event"><strong>Regulatory Action:</strong> AuditPilot Classification Agent determined RBI reportability. Report generation and MAP creation initiated. Deadline clock: T+6hr full report.</div></div>
  </div>
</div>

<div class="report-section">
  <div class="report-section-title">Section 6 — Interim Mitigation Actions Taken</div>
  <div class="report-actions-list">
    <div class="report-action-item"><span class="rai-num">1.</span>CBS primary node isolated from production network. Secondary CBS at Chennai Data Centre activated under BCP. All critical banking operations (RTGS, NEFT, UPI) rerouted to backup systems.</div>
    <div class="report-action-item"><span class="rai-num">2.</span>All domain administrator and service accounts suspended; passwords reset across CNRB.corp domain. Forced MFA re-enrollment for all privileged users.</div>
    <div class="report-action-item"><span class="rai-num">3.</span>C2 IP range 185.220.101.0/24 (TOR exit nodes) blocked at all perimeter firewalls and NGFWs. DNS sinkholing activated for identified malicious domains.</div>
    <div class="report-action-item"><span class="rai-num">4.</span>SWIFT messaging gateway placed in read-only / supervised mode. SWIFT ISAC and SWIFT Customer Security Programme (CSP) notified per SWIFT policy.</div>
    <div class="report-action-item"><span class="rai-num">5.</span>Forensic imaging of affected file servers (FS-01, FS-02, FS-03) initiated. Strict chain-of-custody maintained. Memory dumps captured before any remediation.</div>
    <div class="report-action-item"><span class="rai-num">6.</span>Business Continuity Plan activated for all Critical Banking Operations. Board Risk Committee convened for emergency briefing. Customer helpdesk on standby alert.</div>
  </div>
</div>

<div class="report-section">
  <div class="report-section-title">Section 7 — Preliminary Root Cause Analysis</div>
  <div class="report-field-grid">
    <div class="report-field"><div class="report-field-label">Suspected Attack Vector</div><div class="report-field-value">Spear-phishing email with malicious macro (Finance Dept user: CNRB\\finance.user04)</div></div>
    <div class="report-field"><div class="report-field-label">Initial Compromise Point</div><div class="report-field-value">Domain Controller CNRB-DC-01 — Privilege Escalation via CVE-2023-23397</div></div>
    <div class="report-field"><div class="report-field-label">Malware Variant Identified</div><div class="report-field-value bold red">LockBit 3.0 (SHA256: a1b2c3d4e5f6... — CERT-In IOC database match)</div></div>
    <div class="report-field"><div class="report-field-label">Estimated Dwell Time</div><div class="report-field-value">~4 hours (forensic analysis ongoing — subject to revision)</div></div>
    <div class="report-field" style="grid-column:1/-1">
      <div class="report-field-label">Contributing Factors (Preliminary)</div>
      <div class="report-field-value" style="margin-top:6px;background:#fff5f5;padding:10px;border-radius:4px;border-left:3px solid #fc8181">
        (i) Unpatched MS Outlook vulnerability CVE-2023-23397 on Domain Controller; (ii) Over-privileged service account CNRB\\svc-batch01 with domain admin rights;
        (iii) Macro execution not disabled on Finance Dept endpoints; (iv) SIEM alert for DC lateral movement suppressed due to erroneous false-positive tuning rule.
      </div>
    </div>
  </div>
</div>

<div class="report-section">
  <div class="report-section-title">Section 8 — Regulatory Notification Status</div>
  <table class="report-regulatory-table">
    <thead><tr><th>Authority</th><th>Submission Channel</th><th>Deadline</th><th>Status</th><th>Regulatory Basis</th></tr></thead>
    <tbody>
      <tr><td><strong>RBI CSITE</strong></td><td>DAKSH Portal (csite@rbi.org.in)</td><td style="color:#c53030;font-weight:700">T + 6 hours</td><td style="color:#c53030;font-weight:700">⏳ PENDING</td><td>Master Direction – IT Framework 2024, Clause 7</td></tr>
      <tr><td><strong>CERT-In</strong></td><td>incidents@cert-in.org.in / CERT-In Portal</td><td style="color:#c53030;font-weight:700">T + 6 hours</td><td style="color:#c53030;font-weight:700">⏳ PENDING</td><td>CERT-In Directions 2022, Section 4(i)(a)</td></tr>
      <tr><td><strong>SWIFT ISAC</strong></td><td>SWIFT Customer Security Programme</td><td>Immediate</td><td style="color:#276749;font-weight:700">✅ NOTIFIED</td><td>SWIFT CSP Mandatory Requirement v2023</td></tr>
      <tr><td><strong>Board / Risk Committee</strong></td><td>Secure Email + War Room Briefing</td><td>T + 2 hours</td><td style="color:#b7791f;font-weight:700">🔄 IN PROGRESS</td><td>Internal CCMP Section 3.2 | RBI Board Accountability Framework</td></tr>
      <tr><td><strong>Post-Incident Report (RBI)</strong></td><td>DAKSH Portal</td><td>T + 21 days</td><td style="color:#718096;font-weight:700">📅 SCHEDULED</td><td>RBI Circular DIT.CO.OSD.No.xxx / Master Direction Clause 7.5</td></tr>
    </tbody>
  </table>
</div>

<div class="report-section">
  <div class="report-section-title">Section 9 — Officer Certification</div>
  <div class="report-sig-block">
    <div class="report-sig-field">
      <div class="report-sig-label">Reporting Officer Signature</div>
      <div class="report-sig-value">${d.officer}</div>
      <div style="font-size:11px;color:#718096;margin-top:4px">${d.desig}, ${d.dept}, Canara Bank Ltd</div>
    </div>
    <div class="report-sig-field">
      <div class="report-sig-label">Date &amp; Time of Certification</div>
      <div class="report-sig-value">${fmt(now)}</div>
      <div style="font-size:11px;color:#718096;margin-top:4px">I certify this report is true and accurate to the best of my knowledge.</div>
    </div>
  </div>
  <div style="margin-top:16px;padding:10px 12px;background:#fff5f5;border:1px solid #feb2b2;border-radius:4px;font-size:11px;color:#742a2a;line-height:1.6">
    ⚠ <strong>CONFIDENTIALITY NOTICE:</strong> This document contains sensitive regulatory information. Unauthorised disclosure is prohibited under Section 45NB of the RBI Act, 1934.
    Report ID: ${S.incidentId} | DAKSH Reference: DAKSH-CNRB-2026-0847 | Generated by AuditPilot v2.1 at ${fmt(now)}
  </div>
</div>`;
  }

  /* ─── MAP GENERATION ─────────────────────────────────────── */
  function convertToMAP() {
    nav('workbench');
    if (S.tasks.length === 0) {
      S.teams = [
        { id:'soc',        name:'SOC Team',        color:'#ef4444', init:'ST', lead:'Arjun Mehta' },
        { id:'ir',         name:'IR Team',          color:'#f59e0b', init:'IR', lead:'Priya Krishnan' },
        { id:'compliance', name:'Compliance',       color:'#3b82f6', init:'CO', lead:'Sunita Rao' },
        { id:'ops',        name:'Ops Team',         color:'#8b5cf6', init:'OT', lead:'Vikram Singh' },
        { id:'ciso',       name:'CISO Office',      color:'#10b981', init:'CI', lead:'Rajesh K. Sharma' },
        { id:'customer',   name:'Customer Service', color:'#06b6d4', init:'CS', lead:'Meena Pillai' },
      ];
      const det = S.detectionTime.getTime();
      S.tasks = [
        mk('MAP-001','Network Isolation of Affected Systems',
          'Immediately isolate CBS primary node and file servers FS-01/FS-02/FS-03 from production network. Block all outbound traffic to C2 IP range 185.220.101.0/24. Verify BCP CBS is fully operational on secondary data centre.',
          'soc','Arjun Mehta','AM','critical', det + 30*60000),
        mk('MAP-002','Forensic Evidence Preservation',
          'Capture memory dumps from all affected servers BEFORE any remediation. Create bit-for-bit disk images. Maintain chain-of-custody documentation. Do NOT restart or reimage any system until imaging is complete.',
          'ir','Priya Krishnan','PK','critical', det + 60*60000),
        mk('MAP-003','CISO, Board & Compliance Notification',
          'Notify CISO, MD & CEO, Head of Risk, Board Risk Committee, and Head of Compliance. Convene Emergency War Room. Prepare executive briefing note. Document all notification timestamps for regulatory proof.',
          'compliance','Sunita Rao','SR','critical', det + 2*3600000),
        mk('MAP-004','Compromised Account Remediation',
          'Suspend all compromised domain accounts. Reset passwords for all domain admins. Revoke all active SSO/OAuth tokens. Force MFA re-enrollment. Audit privileged access logs for the past 30 days.',
          'ops','Vikram Singh','VS','critical', det + 2*3600000),
        mk('MAP-005','Submit RBI Initial Notification (DAKSH)',
          'File initial cyber incident notification on RBI DAKSH portal. Include: Incident ID, type, affected systems, preliminary impact. Attach generated report as supporting document. Screenshot submission confirmation as evidence.',
          'ciso','Rajesh K. Sharma','RS','critical', det + 2*3600000),
        mk('MAP-006','Submit CERT-In Incident Report',
          'File cyber incident report with CERT-In via incidents@cert-in.org.in and CERT-In portal. Include all mandatory fields per CERT-In Directions 2022, Section 4. Copy to csite@rbi.org.in. Retain portal acknowledgement.',
          'ciso','Rajesh K. Sharma','RS','critical', det + 6*3600000),
        mk('MAP-007','Submit Full RBI CSITE Report via DAKSH',
          'Submit complete RBI CSITE Cyber Security Incident Report via DAKSH portal. All 9 sections must be populated. The auto-generated report (IR-CNRB-2026-0847) is pre-formatted. Upload and screenshot portal confirmation.',
          'ciso','Rajesh K. Sharma','RS','critical', det + 6*3600000),
        mk('MAP-008','Customer Advisory & Helpdesk Activation',
          'Notify affected customers via SMS, email, and app push notifications. Activate 24x7 dedicated helpdesk with specific CBS/SWIFT issue scripting. Update bank website service status. Coordinate PR team on media advisory if needed.',
          'customer','Meena Pillai','MP','high', det + 4*3600000),
        mk('MAP-009','Forensic Vendor Engagement',
          'Engage approved forensic vendor (Deloitte Cyber / PwC IR). Share forensic images and IOC list (IP: 185.220.101.47, Hash: LockBit 3.0). Initiate deep-dive malware analysis. Obtain timeline for full forensic report required for RBI post-incident submission.',
          'ir','Priya Krishnan','PK','high', det + 8*3600000),
        mk('MAP-010','Post-Incident Analysis Report to RBI',
          'Prepare comprehensive post-incident analysis report: full forensic RCA, detailed timeline, lessons learned, and corrective action plan with ownership. Submit to RBI CSITE via DAKSH within 21 days. This is a mandatory follow-up requirement.',
          'compliance','Sunita Rao','SR','medium', det + 21*24*3600000),
      ];
      renderKanban();
      renderTeams();
      updateProgress();
      log('Workbench','agent','AuditPilot Engine','MAP generated: 10 action items across 6 teams. 5 critical tasks assigned to CISO Office and SOC. Deadline tracking active.','Complete');
      S.tasks.forEach((t,i) => {
        setTimeout(() => {
          log('Workbench','system','MAP Engine',`${t.id} "${t.title}" → ${t.assignee} (${teamName(t.teamId)})`,'Pending');
          feed('system','MAP Engine',`${t.id} assigned to ${t.assignee}`);
        }, i * 150 + 500);
      });
    }
  }

  function mk(id, title, desc, teamId, assignee, init, priority, dueMs) {
    return { id, title, desc, teamId, assignee, init, priority, dueMs, status:'open', evidence:[], notes:[], verified:false };
  }

  /* ─── KANBAN ─────────────────────────────────────────────── */
  function renderKanban() {
    const cols = { open:[], inprogress:[], closed:[] };
    S.tasks.forEach(t => cols[t.status].push(t));
    ['open','inprogress','closed'].forEach(s => {
      document.getElementById(`col-${s}`).innerHTML = '';
      document.getElementById(`cnt-${s}`).textContent = cols[s].length;
      cols[s].forEach(t => document.getElementById(`col-${s}`).appendChild(makeCard(t)));
    });
  }

  function makeCard(t) {
    const el = document.createElement('div');
    el.className = 'task-card';
    el.draggable = true;
    el.dataset.taskId = t.id;
    el.dataset.priority = t.priority;

    const rem = t.dueMs - Date.now();
    const dueStr = fmtDue(rem);
    const dueCls = rem < 3600000 && t.status !== 'closed' ? 'urgent' : rem < 7200000 && t.status !== 'closed' ? 'warning' : '';

    const evLine = t.evidence.length
      ? `📎 ${t.evidence.length} file(s) ${t.verified ? '<span class="evidence-verified">✓ Verified</span>' : ''}`
      : `<span style="color:var(--text-4)">📎 No evidence — upload to close</span>`;

    el.innerHTML = `
      <div class="task-card-top">
        <span class="task-title">${t.title}</span>
        <span class="task-priority-badge ${t.priority}">${t.priority.toUpperCase()}</span>
      </div>
      <div class="task-meta">
        <div class="task-assignee">
          <div class="assignee-avatar">${t.init}</div>
          <span>${t.assignee}</span>
        </div>
        <div class="task-due ${dueCls}">${dueStr}</div>
      </div>
      <div class="task-evidence-bar">${evLine}</div>`;

    el.addEventListener('dragstart', e => { e.dataTransfer.setData('taskId', t.id); el.classList.add('dragging'); });
    el.addEventListener('dragend',   () => el.classList.remove('dragging'));
    el.addEventListener('click',     () => openDrawer(t.id));
    return el;
  }

  function drop(e, status) {
    e.preventDefault();
    document.querySelectorAll('.kanban-col-body').forEach(c => c.classList.remove('drag-over'));
    const id = e.dataTransfer.getData('taskId');
    const t  = S.tasks.find(x => x.id === id);
    if (!t) return;
    if (status === 'closed') {
      if (!t.verified) { toast('Evidence must be verified before closing this task', 'error'); return; }
    }
    const old = t.status; t.status = status;
    renderKanban(); renderTeams(); updateProgress();
    log('Workbench','human','Analyst',`Task ${t.id} moved: ${old} → ${status}`, status === 'closed' ? 'Complete' : 'Pending');
    feed('human','Analyst',`${t.id} → ${status === 'closed' ? '✅ Closed' : status}`);
    if (status === 'closed') { toast(`${t.id} closed with verified evidence ✓`, 'success'); checkRegulatory(); }
  }

  function updateProgress() {
    const total  = S.tasks.length;
    const closed = S.tasks.filter(t => t.status === 'closed').length;
    const pct    = total > 0 ? (closed / total) * 100 : 0;
    document.getElementById('wb-prog-fill').style.width = pct + '%';
    document.getElementById('wb-prog-text').textContent = `${closed} / ${total} tasks`;
    document.getElementById('ast-pending').textContent  = total - closed;
  }

  function checkRegulatory() {
    const rbi   = S.tasks.find(t => t.id === 'MAP-007');
    const certi = S.tasks.find(t => t.id === 'MAP-006');
    if (rbi?.status   === 'closed') { document.getElementById('wb-rbi-badge').className='wb-status-badge submitted'; document.getElementById('wb-rbi-badge').innerHTML='<span class="badge-dot green"></span>RBI SUBMITTED ✓'; }
    if (certi?.status === 'closed') { document.getElementById('wb-certin-badge').className='wb-status-badge submitted'; document.getElementById('wb-certin-badge').innerHTML='<span class="badge-dot green"></span>CERT-In SUBMITTED ✓'; }
  }

  /* ─── TEAMS ──────────────────────────────────────────────── */
  function renderTeams() {
    const list = document.getElementById('team-list');
    if (!S.teams.length) return;
    list.innerHTML = S.teams.map(tm => {
      const tasks = S.tasks.filter(t => t.teamId === tm.id);
      const open  = tasks.filter(t => t.status !== 'closed').length;
      const hasCrit = tasks.some(t => t.priority === 'critical' && t.status === 'open');
      const icon = open === 0 ? '✅' : hasCrit ? '🔴' : '🟡';
      return `
        <div class="team-row">
          <div class="team-avatar" style="background:${tm.color}">${tm.init}</div>
          <div class="team-info">
            <span class="team-name">${tm.name}</span>
            <span class="team-tasks">${open} open · ${tm.lead}</span>
          </div>
          <span class="team-status">${icon}</span>
        </div>`;
    }).join('');
  }

  /* ─── LIVE FEED ──────────────────────────────────────────── */
  function feed(type, actor, text) {
    const list = document.getElementById('feed-list');
    if (!list) return;
    const now = new Date();
    const entry = document.createElement('div');
    entry.className = `feed-entry ${type}`;
    entry.innerHTML = `
      <div class="feed-time">${now.toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}</div>
      <div class="feed-text">${text}</div>
      <div class="feed-actor">${actor}</div>`;
    list.insertBefore(entry, list.firstChild);
    while (list.children.length > 25) list.removeChild(list.lastChild);
  }

  /* ─── EVIDENCE DRAWER ────────────────────────────────────── */
  function openDrawer(taskId) {
    S.activeTask = taskId;
    const t  = S.tasks.find(x => x.id === taskId);
    if (!t) return;
    const tm = S.teams.find(x => x.id === t.teamId) || {};

    document.getElementById('d-title').textContent = t.title;
    document.getElementById('d-meta').innerHTML = `
      <span class="task-priority-badge ${t.priority}">${t.priority.toUpperCase()}</span>
      <span style="font-size:11px;color:var(--text-3)">${t.id}</span>`;
    document.getElementById('d-desc').textContent = t.desc;
    document.getElementById('d-assignee').innerHTML = `
      <div class="assignee-avatar" style="width:28px;height:28px;font-size:11px;background:${tm.color||'#3b82f6'}">${t.init}</div>
      <div>
        <div style="font-size:13px;font-weight:600;color:var(--text-0)">${t.assignee}</div>
        <div style="font-size:11px;color:var(--text-3)">${teamName(t.teamId)}</div>
      </div>`;

    renderEvidenceList(t);
    renderNotesList(t);

    const toggle = document.getElementById('d-verified');
    toggle.checked = t.verified;
    document.getElementById('d-close-btn').disabled = !t.verified;

    document.getElementById('ev-drawer').classList.add('open');
    document.getElementById('overlay').classList.add('active');
  }

  function closeDrawer() {
    document.getElementById('ev-drawer').classList.remove('open');
    document.getElementById('overlay').classList.remove('active');
    S.activeTask = null;
  }

  function renderEvidenceList(t) {
    const list = document.getElementById('d-evidence');
    list.innerHTML = t.evidence.map(e => `
      <div class="evidence-item">
        <span class="evidence-file-icon">${e.icon}</span>
        <span class="evidence-file-name">${e.name}</span>
        <span class="evidence-file-size">${e.size}</span>
        <span class="evidence-file-status">✓</span>
      </div>`).join('');
  }

  function renderNotesList(t) {
    const list = document.getElementById('d-notes');
    list.innerHTML = t.notes.map(n => `
      <div class="note-item">${n.text}<div class="note-time">${n.ts}</div></div>`).join('');
  }

  function uploadEvidence() {
    const t = S.tasks.find(x => x.id === S.activeTask);
    if (!t) return;
    const pool = [
      { name:`forensic_memory_${t.id}.mem`,               icon:'🖥️', size:'1.2 GB' },
      { name:`soc_alert_${t.id}_screenshot.png`,          icon:'🖼️', size:'342 KB' },
      { name:`network_capture_${now8()}.pcap`,            icon:'📋', size:'8.7 MB' },
      { name:`ir_investigation_report_v1.pdf`,            icon:'📄', size:'2.1 MB' },
      { name:`ciso_notification_email.eml`,               icon:'📧', size:'28 KB' },
      { name:`daksh_submission_confirmation.png`,         icon:'🖼️', size:'189 KB' },
      { name:`certin_portal_ack_${now8()}.pdf`,           icon:'📄', size:'95 KB' },
      { name:`blocked_accounts_list.xlsx`,                icon:'📊', size:'44 KB' },
    ];
    const file = pool[t.evidence.length % pool.length];
    t.evidence.push(file);
    renderEvidenceList(t);
    renderKanban();
    log('Workbench','human','Analyst',`Evidence uploaded to ${t.id}: "${file.name}" (${file.size})`,'Complete');
    feed('human','Analyst',`Evidence attached: ${file.name} → ${t.id}`);
    toast(`Uploaded: ${file.name}`, 'success');
  }

  function addNote() {
    const t = S.tasks.find(x => x.id === S.activeTask);
    if (!t) return;
    const inp = document.getElementById('d-note');
    const text = inp.value.trim();
    if (!text) { toast('Enter a note first', 'warning'); return; }
    const ts = new Date().toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit'});
    t.notes.push({ text, ts });
    inp.value = '';
    renderNotesList(t);
    feed('human','Analyst',`Note added to ${t.id}`);
    toast('Note saved', 'success');
  }

  function toggleVerified() {
    const t  = S.tasks.find(x => x.id === S.activeTask);
    if (!t) return;
    const chk = document.getElementById('d-verified');
    if (chk.checked && t.evidence.length === 0) {
      toast('Upload at least one evidence file before verifying', 'warning');
      chk.checked = false; return;
    }
    t.verified = chk.checked;
    document.getElementById('d-close-btn').disabled = !t.verified;
    renderKanban();
    if (t.verified) {
      toast('Evidence verified ✓ Task can now be closed', 'success');
      log('Workbench','human','Analyst',`Evidence for ${t.id} marked as VERIFIED. Task now eligible for closure.`,'Complete');
    }
  }

  function moveDrawerTask(status) {
    const t = S.tasks.find(x => x.id === S.activeTask);
    if (!t) return;
    const old = t.status; t.status = status;
    renderKanban(); renderTeams(); updateProgress();
    closeDrawer();
    log('Workbench','human','Analyst',`Task ${t.id} moved: ${old} → ${status}`,'Pending');
    feed('human','Analyst',`${t.id} → In Progress`);
    toast('Task moved to In Progress', 'info');
  }

  function closeDrawerTask() {
    const t = S.tasks.find(x => x.id === S.activeTask);
    if (!t || !t.verified) { toast('Evidence must be verified first', 'error'); return; }
    t.status = 'closed';
    renderKanban(); renderTeams(); updateProgress(); checkRegulatory();
    closeDrawer();
    log('Workbench','human','Analyst',`Task ${t.id} CLOSED — evidence verified. Auditable closure recorded.`,'Complete');
    feed('human','Analyst',`✅ ${t.id} Closed — evidence verified`);
    toast(`${t.id} closed with verified evidence ✓`, 'success');
  }

  /* ─── TIMERS ─────────────────────────────────────────────── */
  function startTimers() {
    if (S.timerInterval) clearInterval(S.timerInterval);
    S.timerInterval = setInterval(tickTimers, 1000);
    tickTimers();
  }

  function tickTimers() {
    if (!S.detectionTime) return;
    const now    = Date.now();
    const det    = S.detectionTime.getTime();
    const total  = 6 * 3600000;
    const t6     = det + total;
    const t2     = det + 2 * 3600000;
    const elapsed= now - det;
    const pct    = Math.min(100, (elapsed / total) * 100);

    setTimer('timer-initial', t2 - now, 2*3600000);
    setTimer('timer-full',    t6 - now, total);
    setTimer('timer-certin',  t6 - now, total);

    const fill = document.getElementById('elapsed-fill');
    fill.style.width = pct + '%';
    fill.className = `progress-bar-fill ${pct > 80 ? 'red' : pct > 50 ? 'amber' : ''}`;

    // Workbench timers
    setTimerEl('wb-t1', t6 - now, total);
    setTimerEl('wb-t2', t6 - now, total);

    // Post-incident (21 days)
    const t21 = det + 21 * 24 * 3600000;
    const wb3 = document.getElementById('wb-t3');
    if (wb3) {
      const rem21 = t21 - now;
      const d = Math.floor(rem21 / 86400000);
      const h = Math.floor((rem21 % 86400000) / 3600000);
      const m = Math.floor((rem21 % 3600000) / 60000);
      wb3.textContent = `${d}d ${pad(h)}:${pad(m)}`;
    }
  }

  function setTimer(id, ms, total) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = fmtCountdown(ms);
    el.classList.remove('green','amber','red','breached');
    if (ms <= 0) el.classList.add('breached');
    else if (ms / total > 0.5) el.classList.add('green');
    else if (ms / total > 0.2) el.classList.add('amber');
    else el.classList.add('red');
  }

  function setTimerEl(id, ms, total) { setTimer(id, ms, total); }

  function fmtCountdown(ms) {
    if (ms <= 0) return 'BREACHED';
    const h = Math.floor(ms / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    const s = Math.floor((ms % 60000) / 1000);
    return `${pad(h)}:${pad(m)}:${pad(s)}`;
  }

  function fmtDue(ms) {
    if (ms <= 0) return 'OVERDUE';
    const d = Math.floor(ms / 86400000);
    const h = Math.floor((ms % 86400000) / 3600000);
    const m = Math.floor((ms % 3600000) / 60000);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  /* ─── AUDIT LOG ──────────────────────────────────────────── */
  function log(stage, type, actor, action, status) {
    const now = new Date();
    S.auditLog.push({
      id: S.auditLog.length + 1,
      ts: now.toLocaleString('en-IN',{dateStyle:'short',timeStyle:'medium'}),
      stage, type, actor, action, status,
    });
    document.getElementById('ast-total').textContent  = S.auditLog.length;
    document.getElementById('ast-agents').textContent = S.auditLog.filter(e=>e.type==='agent').length;
    document.getElementById('ast-human').textContent  = S.auditLog.filter(e=>e.type==='human').length;
  }

  function filterLog() { renderAuditTable(); }

  function renderAuditTable() {
    const tbody = document.getElementById('audit-tbody');
    const search = (document.getElementById('audit-search')?.value || '').toLowerCase();
    const tFilter= document.getElementById('audit-type')?.value  || '';
    const sFilter= document.getElementById('audit-stage')?.value || '';

    let rows = [...S.auditLog].reverse();
    if (search)  rows = rows.filter(e => e.action.toLowerCase().includes(search) || e.actor.toLowerCase().includes(search));
    if (tFilter) rows = rows.filter(e => e.type  === tFilter);
    if (sFilter) rows = rows.filter(e => e.stage === sFilter);

    if (rows.length === 0) {
      tbody.innerHTML = `<tr class="audit-empty-row"><td colspan="7">No events found.</td></tr>`; return;
    }
    tbody.innerHTML = rows.map(e => `
      <tr>
        <td style="color:var(--text-4);font-family:monospace;font-size:11px">#${e.id}</td>
        <td style="font-family:monospace;font-size:11px;color:var(--text-3)">${e.ts}</td>
        <td style="font-size:12px">${e.stage}</td>
        <td style="font-size:12px;color:var(--text-2)">${e.actor}</td>
        <td><span class="audit-type-badge ${e.type}">${e.type==='agent'?'🤖 Agent':e.type==='human'?'👤 Human':'⚙ System'}</span></td>
        <td style="max-width:340px;line-height:1.5;font-size:12px">${e.action}</td>
        <td><span class="audit-status-badge ${e.status==='Complete'?'success':'pending'}">${e.status}</span></td>
      </tr>`).join('');
  }

  function exportCSV() {
    const rows = [
      ['#','Timestamp','Stage','Actor','Type','Action','Status'].join(','),
      ...S.auditLog.map(e => [e.id,`"${e.ts}"`,e.stage,`"${e.actor}"`,e.type,`"${e.action.replace(/"/g,"'")}"`,e.status].join(','))
    ];
    const blob = new Blob([rows.join('\n')], {type:'text/csv'});
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `AuditPilot_${S.incidentId||'log'}_${now8()}.csv`;
    a.click(); URL.revokeObjectURL(a.href);
    toast('Audit log exported as CSV', 'success');
  }

  /* ─── TOAST ──────────────────────────────────────────────── */
  function toast(msg, type='info') {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `<span>${{success:'✓',error:'✕',warning:'⚠',info:'ℹ'}[type]||'ℹ'}</span><span>${msg}</span>`;
    container.appendChild(el);
    setTimeout(() => { el.style.opacity='0'; el.style.transform='translateX(16px)'; el.style.transition='all 0.3s'; setTimeout(()=>el.remove(),320); }, 4000);
  }

  /* ─── HELPERS ────────────────────────────────────────────── */
  function typeName(t) {
    return {'ransomware':'Ransomware / Malware','ddos':'DDoS Attack','data-breach':'Data Breach',
      'web-defacement':'Web Defacement','unauthorized-access':'Unauthorized Access',
      'phishing':'Phishing / BEC','system-outage':'Critical System Outage',
      'fraud-transaction':'Fraudulent Transaction','swift-fraud':'SWIFT Fraud'}[t] || t;
  }
  function incidentCat(t) {
    return {'ransomware':'Malware / Ransomware Attack','ddos':'Denial-of-Service Attack',
      'data-breach':'Data Theft / Breach','web-defacement':'Website Defacement',
      'unauthorized-access':'Unauthorized System Access','phishing':'Social Engineering / Phishing',
      'system-outage':'Critical Infrastructure Outage','fraud-transaction':'Financial Fraud',
      'swift-fraud':'SWIFT / Payment System Fraud'}[t] || 'Cyber Security Incident';
  }
  function srcName(s) {
    return {'edr':'EDR (CrowdStrike Falcon)','siem':'SIEM (Splunk/QRadar)','dlp':'DLP System',
      'firewall':'Next-Gen Firewall','swift':'SWIFT Monitor','atm':'ATM Monitoring System',
      'waf':'Web Application Firewall','manual':'Manual Detection'}[s] || s;
  }
  function teamName(id) {
    return (S.teams.find(t=>t.id===id)||{}).name || id;
  }
  function inr(n) { return new Intl.NumberFormat('en-IN').format(n); }
  function pad(n) { return String(n).padStart(2,'0'); }
  function now8() { return new Date().toISOString().slice(0,10).replace(/-/g,''); }
  function fmt(d) {
    return d.toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'}) + ', ' +
           d.toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  }
  function toLocalISOString(d) {
    const off = d.getTimezoneOffset();
    return new Date(d.getTime() - off * 60000).toISOString().slice(0,16);
  }

  /* ─── INIT ───────────────────────────────────────────────── */
  function init() {
    // Live clock
    const clk = () => { document.getElementById('current-time').textContent = new Date().toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit',second:'2-digit'}); };
    clk(); setInterval(clk, 1000);

    // Auto-fill Alert ID and detection time
    document.getElementById('f-alert-id').value = `SOC-2026-${Math.floor(800 + Math.random() * 199)}`;
    document.getElementById('f-detect-time').value = toLocalISOString(new Date());

    // Seed audit log
    log('System','system','AuditPilot','Engine initialized. RBI CSITE Compliance Pipeline v2.1 armed and ready.','Complete');
    log('System','system','AuditPilot','Canara Bank CISO credentials loaded. All 5 pipeline stages standing by.','Complete');
  }

  document.addEventListener('DOMContentLoaded', init);

  /* ─── PUBLIC API ─────────────────────────────────────────── */
  return { nav, fillDemo, setSev, submit, drop, uploadEvidence, addNote, toggleVerified,
           moveDrawerTask, closeDrawerTask, closeDrawer, convertToMAP, startReport,
           filterLog, exportCSV, window_print: ()=>window.print() };

})();
