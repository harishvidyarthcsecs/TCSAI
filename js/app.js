/* ========================================
   OTSight Command Board — App Logic
   ======================================== */

const STORAGE_KEY = 'otsight_incidents';

const SYSTEMS_OWNERS = {
    'PLC-01': { name: 'PLC-01 — Assembly Main', hourlyRate: 85000 },
    'PLC-02': { name: 'PLC-02 — Welding Station', hourlyRate: 65000 },
    'PLC-03': { name: 'PLC-03 — Paint Booth', hourlyRate: 95000 },
    'PLC-04': { name: 'PLC-04 — Conveyor', hourlyRate: 55000 },
    'HMI-01': { name: 'HMI-01 — Line A Operator', hourlyRate: 30000 },
    'HMI-02': { name: 'HMI-02 — Line B Operator', hourlyRate: 30000 },
    'HMI-03': { name: 'HMI-03 — Line C Operator', hourlyRate: 30000 },
    'SCADA-SERVER': { name: 'SCADA Server — Plant-wide', hourlyRate: 120000 },
    'DCS-01': { name: 'DCS-01 — Boiler / Utilities', hourlyRate: 75000 },
    'NETWORK-SWITCH': { name: 'Network Switch', hourlyRate: 40000 },
    'FIRE-SYSTEM': { name: 'Fire System Controller', hourlyRate: 20000 },
    'Unknown': { name: 'Unknown System', hourlyRate: 40000 },
    '': { name: 'Not Specified', hourlyRate: 30000 }
};

const SHIFT_OWNERS = {
    'Morning (6AM-2PM)': { 'PLC-01': 'Ramkumar R', 'PLC-02': 'Priya S', 'PLC-03': 'Priya S', 'PLC-04': 'Ramkumar R', 'HMI-01': 'Sundari P', 'HMI-02': 'Sundari P', 'HMI-03': 'Arun V', 'SCADA-SERVER': 'Priya S', 'DCS-01': 'Karthik M', 'NETWORK-SWITCH': 'Arun V', 'FIRE-SYSTEM': 'Karthik M', 'Unknown': 'Karthik M', '': 'Karthik M' },
    'Afternoon (2PM-10PM)': { 'PLC-01': 'Karthik M', 'PLC-02': 'Arun V', 'PLC-03': 'Priya S', 'PLC-04': 'Karthik M', 'HMI-01': 'Sundari P', 'HMI-02': 'Arun V', 'HMI-03': 'Arun V', 'SCADA-SERVER': 'Priya S', 'DCS-01': 'Karthik M', 'NETWORK-SWITCH': 'Arun V', 'FIRE-SYSTEM': 'Karthik M', 'Unknown': 'Karthik M', '': 'Karthik M' },
    'Night (10PM-6AM)': { 'PLC-01': 'Arun V', 'PLC-02': 'Arun V', 'PLC-03': 'Karthik M', 'PLC-04': 'Arun V', 'HMI-01': 'Sundari P', 'HMI-02': 'Sundari P', 'HMI-03': 'Sundari P', 'SCADA-SERVER': 'Karthik M', 'DCS-01': 'Karthik M', 'NETWORK-SWITCH': 'Arun V', 'FIRE-SYSTEM': 'Sundari P', 'Unknown': 'Karthik M', '': 'Karthik M' }
};

const CATEGORY_KEYWORDS = {
    'Unauthorized Device (USB)': ['usb', 'pendrive', 'flash drive', 'memory stick', 'external drive', 'cd', 'dvd'],
    'OT Availability': ['freeze', 'hang', 'stuck', 'stop', 'crash', 'down', 'offline', 'no response', 'not responding', 'hung', 'aagiduchu'],
    'Suspicious Activity': ['virus', 'malware', 'popup', 'error message', 'strange', 'suspicious', 'unauthorized', 'hacked'],
    'Network Degradation': ['network', 'connectivity', 'connection lost', 'lan', 'ethernet', 'port', 'switch', 'fiber'],
    'Configuration Change': ['change', 'modified', 'settings changed', 'parameter', 'logic changed', 'unauthorized change'],
    'Physical Security': ['unauthorized person', 'visitor', 'intruder', 'open cabinet', 'door open', 'restricted area'],
    'Power / Electrical': ['power', 'voltage', 'fluctuation', 'surge', 'trip', 'electric', 'power cut'],
    'Safety Event': ['safety', 'interlock', 'emergency stop', 'e-stop', 'alarm', 'smoke', 'overheat', 'fire']
};

const SAFETY_KEYWORDS = ['safety', 'emergency', 'smoke', 'fire', 'overheat', 'interlock', 'alarm', 'e-stop', 'emergency stop', 'danger', 'injury'];

// Feature 1: MITRE ATT&CK for ICS mapping
const ATTACK_MAP = {
    'Unauthorized Device (USB)': { id: 'T0847', name: 'Replication Through Removable Media', tactic: 'Initial Access', stage: 0, color: '#e74c3c' },
    'Physical Security':         { id: 'T0864', name: 'Transient Cyber Asset',                tactic: 'Initial Access', stage: 0, color: '#e74c3c' },
    'Suspicious Activity':       { id: 'T0863', name: 'User Execution',                       tactic: 'Execution',      stage: 2, color: '#8e44ad' },
    'Configuration Change':      { id: 'T0831', name: 'Manipulation of Control',              tactic: 'Impair Ctrl',    stage: 3, color: '#d35400' },
    'Network Degradation':       { id: 'T0815', name: 'Denial of Service',                    tactic: 'Impact',         stage: 4, color: '#922b21' },
    'OT Availability':           { id: 'T0816', name: 'Device Restart/Shutdown',              tactic: 'Impact',         stage: 4, color: '#922b21' },
    'Power / Electrical':        { id: 'T0813', name: 'Denial of Control',                    tactic: 'Impact',         stage: 4, color: '#922b21' },
    'Safety Event':              { id: 'T0880', name: 'Loss of Safety',                       tactic: 'Impact',         stage: 4, color: '#7b241c' },
    'Near-Miss / Observation':   { id: 'T0861', name: 'Point & Tag Identification',           tactic: 'Discovery',      stage: 1, color: '#2980b9' },
};

// Feature 4: IR Playbooks
const IR_PLAYBOOKS = {
    'Unauthorized Device (USB)': {
        icon: '💾', title: 'USB / Removable Media — ICS-IR-001',
        technique: 'T0847 · Replication Through Removable Media',
        steps: [
            'DO NOT reconnect the device or run any files from it',
            'Photograph device + location; note exact time and shift in log',
            'Physically isolate device in a bag — do not discard (it is evidence)',
            'Pull the ethernet cable from the affected PLC/HMI (hardware, not software)',
            'DO NOT restart the system — memory forensic artifacts will be destroyed',
            'Extract system event logs before any power cycle',
            'Notify OT security lead and plant manager within 15 minutes',
            'System returns to service only after offline ICS malware scan is cleared'
        ]
    },
    'Suspicious Activity': {
        icon: '⚠️', title: 'Suspicious Execution — ICS-IR-002',
        technique: 'T0863 · User Execution',
        steps: [
            'DO NOT click any popup or link — close only via Task Manager if safe to do so',
            'Photograph the screen with your phone immediately',
            'Note exact time, logged-in user, and what was done before popup appeared',
            'Pull network cable from affected HMI/workstation immediately',
            'DO NOT restart — live memory contains critical forensic evidence',
            'Ask engineer to run: tasklist > procs.txt (captures running process list)',
            'Notify OT security team — Potential Execution Indicator (ATT&CK T0863)',
            'System returns to service only after forensic clearance'
        ]
    },
    'Configuration Change': {
        icon: '🔧', title: 'Unauthorized Config Change — ICS-IR-003',
        technique: 'T0831 · Manipulation of Control',
        steps: [
            'Export the current PLC program immediately — save with timestamp',
            'Compare against last known-good backup (verify MD5 checksum, not just date)',
            'Review who had physical or remote access to this system in the past 24 hours',
            'Check engineering workstation for unauthorized USB or remote session logs',
            'DO NOT overwrite current state — preserve as forensic evidence',
            'If change differs from approved: treat as Active ICS Intrusion',
            'Notify plant manager + ICS-CERT India within 1 hour (mandatory for OT breach)',
            'Restore from verified backup only after root cause is confirmed'
        ]
    },
    'Physical Security': {
        icon: '🚫', title: 'Unauthorized Physical Access — ICS-IR-004',
        technique: 'T0864 · Transient Cyber Asset',
        steps: [
            'Note person description, time, duration, zone, and badge status',
            'Check if any OT cabinet, USB port, or terminal was touched or opened',
            'Inspect all USB ports and network patch panels for foreign devices',
            'Review CCTV footage and physical access system logs for that time window',
            'Change any credentials that person may have observed on screen',
            'Conduct USB port sweep of all systems in the accessed zone',
            'If any foreign device is found: immediately escalate to ICS-IR-001'
        ]
    },
    'OT Availability': {
        icon: '🧊', title: 'OT System Availability — ICS-IR-005',
        technique: 'T0816 · Device Restart/Shutdown',
        steps: [
            'Note exact time, what was last running, and any changes before the freeze',
            'Check system event logs and PLC diagnostic buffer BEFORE any restart',
            'Capture screenshot or photo of any error codes displayed',
            'Check CPU/memory load — abnormal load may indicate malware activity',
            'Look for new scheduled tasks or processes not present in previous shift',
            'Restart only after log collection — document restart in shift log with timestamp',
            'If freeze recurs 2+ times in one shift: isolate and escalate immediately'
        ]
    },
    'Network Degradation': {
        icon: '📡', title: 'OT Network Anomaly — ICS-IR-006',
        technique: 'T0815 · Denial of Service',
        steps: [
            'Note which systems lost connectivity and the exact sequence of events',
            'Check switch port LEDs — note unexpected blinking patterns',
            'DO NOT connect new diagnostic devices to the OT network (risk of further compromise)',
            'Check for unknown MAC addresses on switch ARP table if accessible',
            'Identify whether anomaly is zone-isolated or plant-wide',
            'If unknown device suspected: physically disconnect only that switch port',
            'Rogue device on OT network = ATT&CK T0848 — escalate immediately'
        ]
    },
    'Safety Event': {
        icon: '🛡️', title: 'Safety System Event — ICS-IR-007',
        technique: 'T0880 · Loss of Safety',
        steps: [
            'FIRST: Ensure all personnel are clear of affected area — people before systems',
            'DO NOT reset interlock or E-stop without authorization from safety officer',
            'Preserve exact system state — note all alarm codes and timestamps',
            'Determine: did interlock trigger due to process condition or cyber manipulation?',
            'If cyber cause suspected: run ICS-IR-003 (Config Change) in parallel',
            'Photograph all alarm displays and control panel states before reset',
            'Return to service only after safety officer AND OT engineer sign off in writing'
        ]
    },
    'Power / Electrical': {
        icon: '⚡', title: 'Power Anomaly Response — ICS-IR-008',
        technique: 'T0813 · Denial of Control',
        steps: [
            'Note time, affected systems, and whether auto-recovery occurred',
            'Verify PLC state after recovery — compare to pre-event configuration backup',
            'Check UPS status and battery health on all OT systems in the zone',
            'Look for parameter changes that may have occurred during the power event',
            'Check if power event coincided with USB insertion, network anomaly, or physical access',
            'Simultaneous power + network + PLC anomaly may indicate coordinated attack',
            'Log the incident even if all systems appear to have auto-recovered'
        ]
    }
};

const EVIDENCE_CHECKLISTS = {
    'Unauthorized Device (USB)': [
        'Photograph the device and its exact location with your phone now',
        'DO NOT restart the PLC or HMI — event logs will be erased',
        'Pull the ethernet cable from the system (hardware disconnect, not software)',
        'Place the device in a bag and hand to supervisor — do not discard',
        'Write down who was near the system in the last hour and when'
    ],
    'Suspicious Activity': [
        'Photograph the screen showing the popup or error right now',
        'Pull the network cable from the workstation or HMI immediately',
        'DO NOT restart — live memory has forensic evidence',
        'Write down exactly what you were doing when the popup appeared',
        'Do not click OK, Yes, or any button on the popup'
    ],
    'Configuration Change': [
        'Export and save the current PLC program with today\'s timestamp',
        'Do not apply or approve the change on any other system',
        'Note who had access to this system in the last 24 hours',
        'Preserve current state — do not overwrite or restore yet',
        'Contact OT engineer immediately — this may be an active intrusion'
    ],
    'Physical Security': [
        'Note person description: clothing, badge, time, exact zone, duration',
        'Check all USB ports in the area for foreign devices right now',
        'Do not let the person leave without notifying supervisor',
        'Review if any OT cabinet or terminal was opened or touched',
        'Contact plant security within 5 minutes'
    ],
    'OT Availability': [
        'Check and save system event logs BEFORE restarting anything',
        'Take a photo or screenshot of any error messages displayed',
        'Note the exact time the issue started and what was running',
        'Check if other systems in the zone are also affected',
        'Do not restart until an engineer reviews the logs'
    ],
    'Network Degradation': [
        'Note which systems lost connection and in what order',
        'Check switch port LEDs — photo any unusual blinking patterns',
        'Do not plug in any new cables or devices to diagnose',
        'Note if the issue is in one zone or plant-wide',
        'Call OT engineer — a rogue device on the network is a cyber incident'
    ],
    'Safety Event': [
        'Clear all personnel from the affected area immediately',
        'Do NOT reset the safety interlock without supervisor authorization',
        'Photograph all alarm codes and display states now',
        'Note whether the trigger appeared process-related or unexpected',
        'Contact safety officer AND OT engineer simultaneously'
    ],
    'Power / Electrical': [
        'Note exact time, which systems were affected, and auto-recovery status',
        'Check UPS status indicators on all OT equipment in the zone',
        'Verify PLC state after recovery matches expected operating parameters',
        'Note if any other anomaly occurred at the same time (USB, network, access)',
        'Log even if everything appears normal — power events can mask other activity'
    ],
    'Near-Miss / Observation': [
        'Write down exactly what you observed and at what time',
        'Note who else was present and can confirm the observation',
        'Photograph anything unusual if safe to do so',
        'Do not modify or touch the area — preserve the scene',
        'Report to shift supervisor before end of shift'
    ]
};

// =============================================
// DATA MANAGEMENT
// =============================================

function getIncidents() {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) return JSON.parse(stored);
    const seed = generateSeedData();
    saveIncidents(seed);
    return seed;
}

function saveIncidents(incidents) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(incidents));
}

function generateId() {
    return 'INC-' + Math.random().toString(36).substr(2, 6).toUpperCase();
}

function generateSeedData() {
    const now = new Date();
    const incidents = [];
    const shifts = ['Morning (6AM-2PM)', 'Afternoon (2PM-10PM)', 'Night (10PM-6AM)'];

    const seedData = [
        // Index 0: Zone-A PLC freeze
        { desc: 'PLC screen frozen for 5 minutes. Had to restart manually. Line stopped during morning shift.', zone: 'Zone-A', system: 'PLC-01', sev: 'High', cat: 'OT Availability', downtime: 5, impact: 'temp-stop' },
        // Index 1: Zone-B USB — Kill Chain Step 1 (Initial Access T0847) — 2 days ago
        { desc: 'USB drive found near PLC cabinet in Zone B. Not labeled. Removed and handed to supervisor immediately.', zone: 'Zone-B', system: 'PLC-02', sev: 'High', cat: 'Unauthorized Device (USB)', downtime: 0, impact: 'none' },
        // Index 2: Zone-B HMI popup — Kill Chain Step 2 (Execution T0863) — 1 day ago (changed from Zone-E/HMI-03 to Zone-B/HMI-02)
        { desc: 'HMI showing strange error popup — "Runtime Error" on Line B. Closed and restarted. Happened twice in 2 hours.', zone: 'Zone-B', system: 'HMI-02', sev: 'High', cat: 'Suspicious Activity', downtime: 3, impact: 'minor' },
        // Index 3
        { desc: 'Network switch port 3 blinking red intermittently. Tried resetting. Came back after 5 mins.', zone: 'Zone-C', system: 'NETWORK-SWITCH', sev: 'Medium', cat: 'Network Degradation', downtime: 5, impact: 'minor' },
        // Index 4
        { desc: 'Vendor engineer connected laptop to SCADA network without informing. Asked for admin password. Denied access.', zone: 'Zone-A', system: 'SCADA-SERVER', sev: 'Critical', cat: 'Unauthorized Device (USB)', downtime: 0, impact: 'none' },
        // Index 5
        { desc: 'Power fluctuation caused PLC to go into fault mode. Auto-recovered after 2 minutes. Boiler tripped momentarily.', zone: 'Zone-F', system: 'DCS-01', sev: 'High', cat: 'Power / Electrical', downtime: 2, impact: 'temp-stop' },
        // Index 6
        { desc: 'Temperature sensor giving erratic readings since morning on Line A. Replaced sensor. Calibration needed.', zone: 'Zone-A', system: 'PLC-01', sev: 'Medium', cat: 'Configuration Change', downtime: 8, impact: 'minor' },
        // Index 7
        { desc: 'Unknown device detected on OT network switch — not in our inventory. MAC address logged and sent to IT.', zone: 'Zone-B', system: 'NETWORK-SWITCH', sev: 'High', cat: 'Unauthorized Device (USB)', downtime: 0, impact: 'none' },
        // Index 8: Zone-B Safety interlock — Kill Chain Step 3 (Impact T0880) — today (0 days ago)
        { desc: 'Safety interlock tripped on robotic arm — area had to be cleared. Emergency stop pressed. Investigation ongoing.', zone: 'Zone-B', system: 'PLC-02', sev: 'Critical', cat: 'Safety Event', downtime: 15, impact: 'safety' },
        // Index 9
        { desc: 'USB drive found near fire system PLC cabinet. Removed and kept in security office. No label found.', zone: 'Zone-F', system: 'FIRE-SYSTEM', sev: 'High', cat: 'Unauthorized Device (USB)', downtime: 0, impact: 'none' },
        // Index 10
        { desc: 'SCADA server showing high CPU usage since afternoon. Response very slow. Restarted SCADA services.', zone: 'Zone-C', system: 'SCADA-SERVER', sev: 'High', cat: 'OT Availability', downtime: 4, impact: 'temp-stop' },
        // Index 11
        { desc: 'Operator accidentally clicked unknown link on HMI. Closed immediately. Full scan requested.', zone: 'Zone-D', system: 'HMI-02', sev: 'Medium', cat: 'Suspicious Activity', downtime: 0, impact: 'none' },
        // Index 12
        { desc: 'USB found near conveyor PLC cabinet, Zone E. Same area as last week. Staff reminded about policy.', zone: 'Zone-E', system: 'PLC-04', sev: 'Medium', cat: 'Unauthorized Device (USB)', downtime: 0, impact: 'none' },
        // Index 13
        { desc: 'Network connectivity loss for 10 mins in Zone D. All HMIs showed "connection lost". Auto-recovered.', zone: 'Zone-D', system: 'NETWORK-SWITCH', sev: 'Medium', cat: 'Network Degradation', downtime: 10, impact: 'temp-stop' },
        // Index 14: PLC-03 change at 3AM — timing anomaly
        { desc: 'PLC-03 programme changed at 3AM — not by maintenance team. Shift engineer notified. Log reviewed.', zone: 'Zone-C', system: 'PLC-03', sev: 'Critical', cat: 'Configuration Change', downtime: 0, impact: 'none' },
    ];

    // daysAgo for kill chain: index 1 = 2 days ago, index 2 = 1 day ago, index 8 = 0 days ago
    const daysAgoMap = [5, 2, 1, 1, 12, 2, 6, 10, 0, 4, 7, 3, 2, 9, 14];

    seedData.forEach((s, i) => {
        const daysAgo = daysAgoMap[i];
        let hoursAgo = Math.floor(Math.random() * 8);
        const reportTime = new Date(now.getTime() - daysAgo * 86400000 - hoursAgo * 3600000);

        // Index 14: force 3AM timestamp for timing anomaly
        if (i === 14) {
            reportTime.setHours(3, 0, 0, 0);
        }

        const duration = s.downtime / 60;
        const sys = SYSTEMS_OWNERS[s.system] || SYSTEMS_OWNERS[''];
        const impactInr = Math.round(duration * sys.hourlyRate);
        const shift = (i === 14) ? 'Night (10PM-6AM)' : shifts[i % 3];
        const owner = SHIFT_OWNERS[shift]?.[s.system] || 'Karthik M';
        const status = (daysAgo > 7) ? 'Resolved' : (daysAgo > 3 ? ['In Progress', 'Mitigated'][i % 2] : 'Open');

        incidents.push({
            id: 'INC-' + ('000' + (i + 1)).slice(-4),
            reportedAt: reportTime.toISOString(),
            shift,
            zone: s.zone,
            system: s.system,
            systemName: sys.name,
            hourlyRate: sys.hourlyRate,
            rawDescription: s.desc,
            normalizedDescription: s.desc,
            category: s.cat,
            severity: s.sev,
            safetyFlag: s.cat === 'Safety Event' || s.impact === 'safety',
            status,
            estimatedDowntime: duration,
            estimatedImpact: impactInr,
            owner,
            ownerless: false,
            clusterId: null,
            selectedTags: []
        });
    });

    return incidents;
}

// =============================================
// RISK TRANSLATION ENGINE
// =============================================

function classifyDescription(text) {
    const lower = text.toLowerCase();
    let category = 'Near-Miss / Observation';
    let severity = 'Low';
    let safetyFlag = false;
    let score = 0;

    for (const [cat, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
        for (const kw of keywords) {
            if (lower.includes(kw)) {
                category = cat;
                score += 2;
                break;
            }
        }
    }

    for (const kw of SAFETY_KEYWORDS) {
        if (lower.includes(kw)) { safetyFlag = true; category = 'Safety Event'; score += 5; break; }
    }

    if (lower.includes('usb') || lower.includes('pendrive')) score += 3;
    if (lower.includes('freeze') || lower.includes('hang') || lower.includes('stop') || lower.includes('hung')) score += 2;
    if (lower.includes('twice') || lower.includes('multiple') || lower.includes('again')) score += 2;
    if (lower.includes('3am') || lower.includes('night') || lower.includes('after hours')) score += 1;

    if (score >= 7) severity = 'Critical';
    else if (score >= 5) severity = 'High';
    else if (score >= 3) severity = 'Medium';
    else severity = 'Low';

    return { category, severity, safetyFlag };
}

// Renamed from calculateImpact to avoid collision with form handler
function calcFinancialImpact(durationHours, systemId, impactType) {
    const sys = SYSTEMS_OWNERS[systemId] || SYSTEMS_OWNERS[''];
    const hourlyRate = sys.hourlyRate;

    let multiplier = 1;
    if (impactType === 'temp-stop') multiplier = 1.2;
    if (impactType === 'safety') multiplier = 2.0;
    if (impactType === 'major') multiplier = 3.0;

    const impact = Math.round(durationHours * hourlyRate * multiplier);
    const downtimeDisplay = durationHours < 1
        ? Math.round(durationHours * 60) + ' min'
        : durationHours + ' hrs';

    return { impact, downtimeDisplay, hourlyRate };
}

// =============================================
// FEATURE 6: ANOMALOUS TIMING DETECTOR
// =============================================

function detectTimingAnomaly(incident) {
    const d = new Date(incident.reportedAt);
    const h = d.getHours();
    const day = d.getDay(); // 0=Sun, 6=Sat

    if (day === 0 || day === 6) return { type: 'weekend', label: '📅 Weekend' };
    if (h >= 22 || h < 5) return { type: 'night', label: '🌙 Night Activity' };
    return null;
}

function isAfterHours(incident) {
    return detectTimingAnomaly(incident) !== null;
}

// =============================================
// FEATURE 2: KILL CHAIN CORRELATOR
// =============================================

function detectKillChain(incidents, windowHours) {
    if (windowHours === undefined) windowHours = 72;
    const now = Date.now();
    const windowMs = windowHours * 3600000;
    const recent = incidents.filter(i => (now - new Date(i.reportedAt).getTime()) <= windowMs);

    // Group by zone
    const byZone = {};
    recent.forEach(i => {
        const atk = ATTACK_MAP[i.category];
        if (!atk) return;
        if (!byZone[i.zone]) byZone[i.zone] = [];
        byZone[i.zone].push({ incident: i, atk });
    });

    const campaigns = [];

    Object.entries(byZone).forEach(([zone, items]) => {
        // Find unique stages present
        const stageSet = new Set(items.map(x => x.atk.stage));
        const stages = Array.from(stageSet).sort((a, b) => a - b);

        if (stages.length < 2) return;

        // Check spans at least 2 different stages
        const minTime = Math.min(...items.map(x => new Date(x.incident.reportedAt).getTime()));
        const maxTime = Math.max(...items.map(x => new Date(x.incident.reportedAt).getTime()));
        const spanHours = (maxTime - minTime) / 3600000;

        const confidence = stages.length >= 3 ? 'HIGH' : 'MEDIUM';

        // Map stage numbers to tactic names
        const stageNames = { 0: 'Initial Access', 1: 'Discovery', 2: 'Execution', 3: 'Impair Ctrl', 4: 'Impact' };
        const stagesCovered = stages.map(s => stageNames[s] || ('Stage ' + s));

        campaigns.push({
            zone,
            incidents: items.map(x => x.incident),
            confidence,
            spanHours: Math.round(spanHours),
            stagesCovered,
            stages,
            items
        });
    });

    return campaigns;
}

// =============================================
// FEATURE 3: OT CYBER THREAT SCORE
// =============================================

function calcThreatScore(incidents) {
    let score = 0;
    const now = new Date();
    const todayStr = now.toISOString().split('T')[0];

    const open = incidents.filter(i => i.status !== 'Resolved');

    open.forEach(i => {
        if (i.severity === 'Critical') score += 20;
        else if (i.severity === 'High') score += 10;
        else if (i.severity === 'Medium') score += 5;

        if (i.safetyFlag) score += 12;
        if (i.category === 'Unauthorized Device (USB)') score += 15;
        if (isAfterHours(i)) score += 8;
    });

    // +30 if kill chain detected
    const campaigns = detectKillChain(incidents, 72);
    if (campaigns.length > 0) score += 30;

    // -10 if any report was made today (rewards reporting culture)
    const reportedToday = incidents.some(i => i.reportedAt.split('T')[0] === todayStr);
    if (reportedToday) score -= 10;

    return Math.min(100, Math.max(0, score));
}

function updateThreatScore(incidents) {
    const score = calcThreatScore(incidents);
    const el = document.getElementById('tsScore');
    if (!el) return;

    el.textContent = score;
    el.className = 'ts-score';
    if (score > 60) el.classList.add('ts-red');
    else if (score >= 30) el.classList.add('ts-amber');
    else el.classList.add('ts-green');
}

// =============================================
// KILL CHAIN ALERT BANNER
// =============================================

function renderKillChainAlert(incidents) {
    const el = document.getElementById('killChainAlert');
    if (!el) return;

    const campaigns = detectKillChain(incidents, 72);

    if (campaigns.length === 0) {
        el.style.display = 'none';
        return;
    }

    el.style.display = 'block';
    const c = campaigns[0]; // show first/most prominent campaign

    // Sort items by time for chain display
    const sortedItems = [...c.items].sort((a, b) =>
        new Date(a.incident.reportedAt) - new Date(b.incident.reportedAt)
    );

    const chainHTML = sortedItems.map((item, idx) => {
        const d = new Date(item.incident.reportedAt);
        const timeStr = d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' }) + ' ' +
            d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true });
        const arrow = idx < sortedItems.length - 1 ? '<div class="kca-arrow">&#9658;</div>' : '';
        return `<div class="kca-step">
            <div class="kca-tactic">${item.atk.tactic}</div>
            <div class="kca-event">${item.incident.rawDescription.substring(0, 40)}...</div>
            <div class="kca-technique">${item.atk.id}</div>
            <div class="kca-time">${timeStr}</div>
        </div>${arrow}`;
    }).join('');

    const stagesStr = c.stagesCovered.join(' ──▶ ');
    const confColor = c.confidence === 'HIGH' ? '#fca5a5' : '#fcd34d';

    el.innerHTML = `
        <div class="kca-header">
            <div>
                <div class="kca-title">🔴 ATTACK CAMPAIGN DETECTED — ${c.zone} · Confidence: <span style="color:${confColor}">${c.confidence}</span> · ${c.spanHours}h window</div>
                <div class="kca-meta">${stagesStr}</div>
            </div>
            <div class="kca-actions">
                <button class="btn-ghost" onclick="dismissKillChain()">Dismiss</button>
                <button class="btn-danger-sm" onclick="showView('patterns')">View in Patterns</button>
            </div>
        </div>
        <div class="kca-chain">${chainHTML}</div>
    `;
}

function dismissKillChain() {
    const el = document.getElementById('killChainAlert');
    if (el) el.style.display = 'none';
}

// =============================================
// VIEW MANAGEMENT
// =============================================

function showView(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));

    const view = document.getElementById('view-' + viewId);
    if (view) view.classList.add('active');

    const btn = document.querySelector('.nav-btn[data-view="' + viewId + '"]');
    if (btn) btn.classList.add('active');

    if (viewId === 'dashboard') renderDashboard();
    if (viewId === 'report') renderRecentReportsSidebar();
    if (viewId === 'patterns') renderPatterns();
    if (viewId === 'scoreboard') renderScoreboard();
    if (viewId === 'topology') renderTopology();
}

// =============================================
// DASHBOARD RENDERING
// =============================================

let trendChartInstance = null;
let zoneChartInstance = null;
let categoryChartInstance = null;

function renderDashboard() {
    const incidents = getIncidents();
    const filterZone = document.getElementById('dashboardFilterZone')?.value || 'all';
    const filterStatus = document.getElementById('tableFilterStatus')?.value || 'Open';

    let filtered = incidents;
    if (filterZone !== 'all') filtered = filtered.filter(i => i.zone === filterZone);

    const open = filtered.filter(i => i.status !== 'Resolved');
    const safety = open.filter(i => i.safetyFlag);
    const totalExposure = open.reduce((sum, i) => sum + i.estimatedImpact, 0);
    const totalDowntime = open.reduce((sum, i) => sum + i.estimatedDowntime, 0);

    document.getElementById('kpi-open-count').textContent = open.length;
    document.getElementById('kpi-exposure-value').textContent = formatINR(totalExposure);
    document.getElementById('kpi-safety-count').textContent = safety.length;
    document.getElementById('kpi-downtime-value').textContent = totalDowntime < 1
        ? Math.round(totalDowntime * 60) + 'm'
        : totalDowntime.toFixed(1) + 'h';

    const oneWeekAgo = new Date(Date.now() - 7 * 86400000);
    const thisWeek = incidents.filter(i => new Date(i.reportedAt) > oneWeekAgo).length;
    document.getElementById('kpi-reporting-value').textContent = thisWeek;

    const clusters = detectPatterns(incidents, 21);
    document.getElementById('kpi-patterns-value').textContent = clusters.length;

    renderTrendChart(incidents);
    renderZoneChart(open);
    renderCategoryChart(open);
    renderIncidentTable(incidents, filterStatus, filterZone);

    // New features
    updateThreatScore(incidents);
    renderKillChainAlert(incidents);
}

function renderTrendChart(incidents) {
    const ctx = document.getElementById('trendChart');
    if (!ctx) return;

    const last30 = [];
    for (let i = 29; i >= 0; i--) {
        const date = new Date(Date.now() - i * 86400000);
        const dateStr = date.toISOString().split('T')[0];
        const count = incidents.filter(inc => inc.reportedAt.split('T')[0] === dateStr).length;
        const exposure = incidents.filter(inc => inc.reportedAt.split('T')[0] === dateStr)
            .reduce((s, inc) => s + inc.estimatedImpact, 0);
        last30.push({ date: date.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' }), count, exposure });
    }

    if (trendChartInstance) trendChartInstance.destroy();
    trendChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: last30.map(d => d.date),
            datasets: [
                {
                    label: 'Incidents',
                    data: last30.map(d => d.count),
                    borderColor: '#1a73e8',
                    backgroundColor: 'rgba(26,115,232,0.1)',
                    fill: true,
                    tension: 0.4,
                    yAxisID: 'y'
                },
                {
                    label: '₹ Exposure (÷10K)',
                    data: last30.map(d => d.exposure / 10000),
                    borderColor: '#f39c12',
                    backgroundColor: 'rgba(243,156,18,0.05)',
                    fill: false,
                    tension: 0.4,
                    borderDash: [5, 5],
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { position: 'top', labels: { font: { size: 11 }, boxWidth: 12 } } },
            scales: {
                y: { position: 'left', title: { display: true, text: 'Incidents', font: { size: 10 } } },
                y1: { position: 'right', title: { display: true, text: '₹ Exposure (÷10K)', font: { size: 10 } }, grid: { drawOnChartArea: false } }
            }
        }
    });
}

function renderZoneChart(openIncidents) {
    const ctx = document.getElementById('zoneChart');
    if (!ctx) return;

    const zones = ['Zone-A', 'Zone-B', 'Zone-C', 'Zone-D', 'Zone-E', 'Zone-F'];
    const zoneData = zones.map(z => openIncidents.filter(i => i.zone === z).reduce((s, i) => s + i.estimatedImpact, 0));
    const zoneColors = ['#1a73e8', '#0d8044', '#f39c12', '#9b59b6', '#e74c3c', '#3498db'];

    if (zoneChartInstance) zoneChartInstance.destroy();
    zoneChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: zones.map(z => z.replace('Zone-', 'Zone ')),
            datasets: [{ label: '₹ Exposure', data: zoneData.map(v => v / 1000), backgroundColor: zoneColors }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { y: { title: { display: true, text: '₹ Exposure (×1000)', font: { size: 10 } } } }
        }
    });
}

function renderCategoryChart(openIncidents) {
    const ctx = document.getElementById('categoryChart');
    if (!ctx) return;

    const cats = {};
    openIncidents.forEach(i => { cats[i.category] = (cats[i.category] || 0) + 1; });
    const labels = Object.keys(cats);
    const data = Object.values(cats);
    const colors = ['#e74c3c', '#f39c12', '#3498db', '#9b59b6', '#e67e22', '#1abc9c', '#34495e', '#2c3e50'];

    if (categoryChartInstance) categoryChartInstance.destroy();
    categoryChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: { labels, datasets: [{ data, backgroundColor: colors.slice(0, labels.length) }] },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'right', labels: { font: { size: 10 }, boxWidth: 12 } } }
        }
    });
}

function renderIncidentTable(incidents, filterStatus, filterZone) {
    const tbody = document.getElementById('incidentTableBody');
    if (!tbody) return;

    // If called from filter dropdowns (no args), pull values from DOM
    if (filterStatus === undefined) {
        filterStatus = document.getElementById('tableFilterStatus')?.value || 'Open';
    }
    if (filterZone === undefined) {
        filterZone = document.getElementById('dashboardFilterZone')?.value || 'all';
    }
    if (!incidents) incidents = getIncidents();

    let filtered = incidents;
    if (filterZone !== 'all') filtered = filtered.filter(i => i.zone === filterZone);
    if (filterStatus !== 'all') filtered = filtered.filter(i => i.status === filterStatus);

    // Also apply severity filter from table header
    const sevFilter = document.getElementById('tableFilterSeverity')?.value || 'all';
    if (sevFilter !== 'all') filtered = filtered.filter(i => i.severity === sevFilter);

    filtered.sort((a, b) => {
        const sev = { Critical: 0, High: 1, Medium: 2, Low: 3 };
        return (sev[a.severity] || 4) - (sev[b.severity] || 4) || new Date(b.reportedAt) - new Date(a.reportedAt);
    });

    tbody.innerHTML = filtered.map(i => {
        const date = new Date(i.reportedAt);
        const statusLabel = i.status;
        const sevClass = 'severity-' + i.severity;
        const statusClass = i.status === 'Open' ? 'status-Open' : i.status === 'In Progress' ? 'status-In' : i.status === 'Mitigated' ? 'status-Mitigated' : 'status-Resolved';

        // Feature 1: ATT&CK badge in category cell
        const atk = ATTACK_MAP[i.category];
        const atkBadge = atk ? `<div><span class="attack-badge" style="color:${atk.color};border-color:${atk.color}">${atk.id} · ${atk.tactic}</span></div>` : '';

        // Feature 6: Timing badge in date cell
        const timing = detectTimingAnomaly(i);
        const timingBadge = timing ? `<div class="timing-badge">${timing.label}</div>` : '';

        return `<tr>
            <td><span class="table-id">${i.id}</span></td>
            <td>${date.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })} ${date.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true })}${timingBadge}</td>
            <td>${i.zone}</td>
            <td>${i.systemName}</td>
            <td>${i.category}${atkBadge}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${i.rawDescription}">${i.rawDescription}</td>
            <td class="impact-money">${formatINR(i.estimatedImpact)}</td>
            <td><span class="severity-badge ${sevClass}">${i.severity}</span></td>
            <td>${i.safetyFlag ? '<span class="safety-flag">⚠</span>' : '<span class="safety-ok">✓</span>'}</td>
            <td>${i.owner}</td>
            <td><span class="status-badge ${statusClass}">${statusLabel}</span></td>
            <td>
                <button onclick="openIncidentDetail('${i.id}')" style="padding:4px 10px;font-size:11px;border:none;cursor:pointer;background:#1a73e8;color:white;border-radius:4px;font-family:inherit">View</button>
                ${i.status !== 'Resolved' ? `<button onclick="resolveIncident('${i.id}')" style="padding:4px 10px;font-size:11px;border:none;cursor:pointer;background:#0d8044;color:white;border-radius:4px;margin-left:4px;font-family:inherit">Resolve</button>` : ''}
            </td>
        </tr>`;
    }).join('');
}

// =============================================
// REPORT SUBMISSION
// =============================================

let selectedTags = [];

function toggleTag(btn, tag) {
    btn.classList.toggle('selected');
    if (btn.classList.contains('selected')) {
        selectedTags.push(tag);
    } else {
        selectedTags = selectedTags.filter(t => t !== tag);
    }
    onImpactChange();
}

function updateSystemOptions() {
    // System options are static in this version
}

// Renamed from calculateImpact to onImpactChange to avoid name collision
function onImpactChange() {
    const duration = parseFloat(document.getElementById('reportDuration').value) || 0;
    const system = document.getElementById('reportSystem').value || '';
    const impactType = document.getElementById('reportImpact').value || 'none';
    const desc = document.getElementById('reportDescription').value || '';

    if (!duration) {
        document.getElementById('impactPreview').style.display = 'none';
        return;
    }

    const { category, severity, safetyFlag } = classifyDescription(desc + ' ' + selectedTags.join(' '));
    const { impact, downtimeDisplay } = calcFinancialImpact(duration, system, impactType);

    document.getElementById('impactPreview').style.display = 'grid';
    document.getElementById('impactDowntime').textContent = downtimeDisplay;
    document.getElementById('impactMoney').textContent = formatINR(impact);
    document.getElementById('impactSafety').textContent = safetyFlag ? '⚠ YES — Immediate Action' : 'No direct safety concern';
    document.getElementById('impactSafety').style.color = safetyFlag ? '#c5221f' : '#0d652d';
    document.getElementById('impactCategory').textContent = category;
}

function submitReport(e) {
    e.preventDefault();

    const shift = document.getElementById('reportShift').value;
    const zone = document.getElementById('reportZone').value;
    const system = document.getElementById('reportSystem').value || 'Unknown';
    const desc = document.getElementById('reportDescription').value;
    const duration = parseFloat(document.getElementById('reportDuration').value) || 0;
    const impactType = document.getElementById('reportImpact').value || 'none';
    const reporter = document.getElementById('reportReporter').value;

    const fullDesc = selectedTags.length > 0
        ? '[' + selectedTags.join(', ') + '] ' + desc
        : desc;

    const { category, severity, safetyFlag } = classifyDescription(fullDesc);
    const { impact } = calcFinancialImpact(duration, system, impactType);
    const sys = SYSTEMS_OWNERS[system] || SYSTEMS_OWNERS[''];
    const owner = SHIFT_OWNERS[shift]?.[system] || 'Karthik M';

    const incident = {
        id: generateId(),
        reportedAt: new Date().toISOString(),
        shift,
        zone,
        system,
        systemName: sys.name,
        hourlyRate: sys.hourlyRate,
        rawDescription: fullDesc,
        normalizedDescription: desc,
        category,
        severity,
        safetyFlag,
        status: 'Open',
        estimatedDowntime: duration / 60,
        estimatedImpact: impact,
        owner,
        ownerless: false,
        clusterId: null,
        selectedTags: [...selectedTags]
    };

    const incidents = getIncidents();
    incidents.unshift(incident);
    saveIncidents(incidents);

    // Reset form
    document.getElementById('reportForm').reset();
    selectedTags = [];
    document.querySelectorAll('.tag-btn').forEach(b => b.classList.remove('selected'));
    document.getElementById('impactPreview').style.display = 'none';

    showToast('Report submitted successfully. Thank you for keeping the plant safe!', 'success');
    renderRecentReportsSidebar();

    // Feature 7: Show evidence capture modal
    showEvidenceModal(category);
}

function renderRecentReportsSidebar() {
    const sidebar = document.getElementById('recentReportsSidebar');
    if (!sidebar) return;

    const incidents = getIncidents().slice(0, 8);
    sidebar.innerHTML = incidents.map(i => {
        const date = new Date(i.reportedAt);
        const sevColor = i.severity === 'Critical' ? '#c5221f' : i.severity === 'High' ? '#b06000' : i.severity === 'Medium' ? '#1a73e8' : '#0d652d';
        return `<div class="sidebar-report" style="border-left-color:${sevColor}">
            <div class="sidebar-report-meta">${i.id} · ${i.zone} · ${date.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })}</div>
            <div class="sidebar-report-desc">${i.rawDescription.substring(0, 80)}${i.rawDescription.length > 80 ? '...' : ''}</div>
        </div>`;
    }).join('') || '<p style="font-size:13px;color:var(--text-muted)">No reports yet. Be the first to report.</p>';
}

// =============================================
// FEATURE 7: EVIDENCE CAPTURE MODAL
// =============================================

function showEvidenceModal(category) {
    const checklist = EVIDENCE_CHECKLISTS[category] || EVIDENCE_CHECKLISTS['Near-Miss / Observation'];
    const titleEl = document.getElementById('evidenceModalTitle');
    if (titleEl) titleEl.textContent = '✅ Report Submitted — Act Now';

    const container = document.getElementById('evidenceChecklist');
    if (!container) return;

    container.innerHTML = checklist.map((step, idx) => {
        return `<div class="evidence-item">
            <input type="checkbox" id="ev-${idx}">
            <label for="ev-${idx}">${step}</label>
        </div>`;
    }).join('');

    document.getElementById('evidenceModal').style.display = 'flex';
}

function closeEvidenceModal() {
    document.getElementById('evidenceModal').style.display = 'none';
    showView('dashboard');
}

// =============================================
// PATTERN DETECTION
// =============================================

function detectPatterns(incidents, windowDays) {
    const cutoff = new Date(Date.now() - windowDays * 86400000);
    const recent = incidents.filter(i => new Date(i.reportedAt) > cutoff);
    const clusters = {};

    recent.forEach(i => {
        const key = i.zone + '__' + i.category;
        if (!clusters[key]) {
            clusters[key] = { zone: i.zone, category: i.category, incidents: [], totalExposure: 0, first: i.reportedAt, last: i.reportedAt };
        }
        clusters[key].incidents.push(i);
        clusters[key].totalExposure += i.estimatedImpact;
        if (i.reportedAt > clusters[key].last) clusters[key].last = i.reportedAt;
        if (i.reportedAt < clusters[key].first) clusters[key].first = i.reportedAt;
    });

    return Object.values(clusters).filter(c => c.incidents.length >= 2);
}

function renderPatterns() {
    const incidents = getIncidents();
    const windowDays = parseInt(document.getElementById('patternWindow')?.value || 21);
    const clusters = detectPatterns(incidents, windowDays);

    document.getElementById('kpi-patterns-value').textContent = clusters.length;

    // Kill chain section in Patterns view
    renderPatternKillChainSection(incidents);

    // Anomalous Timing section
    renderPatternTimingSection(incidents);

    const grid = document.getElementById('patternsGrid');
    if (!grid) return;

    grid.innerHTML = clusters.map(c => {
        const riskLevel = c.incidents.length >= 3 ? 'pattern-critical' : '';
        const riskVel = new Date(c.last) > new Date(Date.now() - 3 * 86400000) ? '🔴 Increasing' : '🟡 Stable';

        return `<div class="pattern-card ${riskLevel}">
            <div class="pattern-header">
                <div>
                    <div class="pattern-title">${c.category}</div>
                    <div class="pattern-zone">${c.zone}</div>
                </div>
                <div class="pattern-count">${c.incidents.length} reports</div>
            </div>
            <div class="pattern-desc">
                ${c.incidents.length} similar reports in ${windowDays} days in ${c.zone}. Combined potential exposure: <strong>${formatINR(c.totalExposure)}</strong>. First: ${new Date(c.first).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })}, Last: ${new Date(c.last).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })}.
            </div>
            <div class="pattern-stats">
                <div class="pattern-stat">
                    <span class="pattern-stat-label">Combined ₹ Exposure</span>
                    <span class="pattern-stat-value exposure">${formatINR(c.totalExposure)}</span>
                </div>
                <div class="pattern-stat">
                    <span class="pattern-stat-label">Risk Velocity</span>
                    <span class="pattern-stat-value">${riskVel}</span>
                </div>
                <div class="pattern-stat">
                    <span class="pattern-stat-label">Window</span>
                    <span class="pattern-stat-value">${windowDays} days</span>
                </div>
            </div>
        </div>`;
    }).join('') || '<p style="color:var(--text-muted);grid-column:1/-1">No patterns detected yet. Patterns appear when 2+ similar incidents occur in the same zone within the time window.</p>';

    const tbody = document.getElementById('patternTableBody');
    if (tbody) {
        tbody.innerHTML = clusters.map(c => {
            const riskVel = new Date(c.last) > new Date(Date.now() - 3 * 86400000) ? '🔴 Increasing' : '🟡 Stable';
            return `<tr>
                <td>${c.category}</td>
                <td>${c.zone}</td>
                <td>${c.category}</td>
                <td><strong>${c.incidents.length}</strong></td>
                <td>${new Date(c.first).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })}</td>
                <td>${new Date(c.last).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })}</td>
                <td class="impact-money">${formatINR(c.totalExposure)}</td>
                <td>${riskVel}</td>
                <td>${c.incidents[0]?.owner || '—'}</td>
            </tr>`;
        }).join('') || '<tr><td colspan="9" style="text-align:center;color:var(--text-muted)">No patterns detected</td></tr>';
    }

    renderHeatmap(incidents);
}

function renderPatternKillChainSection(incidents) {
    const el = document.getElementById('patternKillChainSection');
    if (!el) return;

    const campaigns = detectKillChain(incidents, 72);
    if (campaigns.length === 0) {
        el.innerHTML = '';
        return;
    }

    el.innerHTML = campaigns.map(c => {
        const sortedItems = [...c.items].sort((a, b) =>
            new Date(a.incident.reportedAt) - new Date(b.incident.reportedAt)
        );
        const chainHTML = sortedItems.map((item, idx) => {
            const d = new Date(item.incident.reportedAt);
            const timeStr = d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' }) + ' ' +
                d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true });
            const arrow = idx < sortedItems.length - 1 ? '<div class="kca-arrow">&#9658;</div>' : '';
            return `<div class="kca-step">
                <div class="kca-tactic">${item.atk.tactic}</div>
                <div class="kca-event">${item.incident.rawDescription.substring(0, 40)}...</div>
                <div class="kca-technique">${item.atk.id}</div>
                <div class="kca-time">${timeStr}</div>
            </div>${arrow}`;
        }).join('');

        const confColor = c.confidence === 'HIGH' ? '#fca5a5' : '#fcd34d';
        return `<div class="kill-chain-alert" style="margin-bottom:24px">
            <div class="kca-header">
                <div>
                    <div class="kca-title">🔴 KILL CHAIN — ${c.zone} · Confidence: <span style="color:${confColor}">${c.confidence}</span> · ${c.spanHours}h window</div>
                    <div class="kca-meta">${c.stagesCovered.join(' ──▶ ')}</div>
                </div>
            </div>
            <div class="kca-chain">${chainHTML}</div>
        </div>`;
    }).join('');
}

function renderPatternTimingSection(incidents) {
    const el = document.getElementById('patternTimingSection');
    if (!el) return;

    const cutoff = new Date(Date.now() - 30 * 86400000);
    const anomalous = incidents
        .filter(i => new Date(i.reportedAt) > cutoff && detectTimingAnomaly(i) !== null)
        .sort((a, b) => {
            const sev = { Critical: 0, High: 1, Medium: 2, Low: 3 };
            return (sev[a.severity] || 4) - (sev[b.severity] || 4);
        });

    if (anomalous.length === 0) {
        el.innerHTML = '';
        return;
    }

    const rows = anomalous.map(i => {
        const d = new Date(i.reportedAt);
        const timing = detectTimingAnomaly(i);
        const sevClass = 'severity-' + i.severity;
        return `<tr>
            <td><span class="table-id">${i.id}</span></td>
            <td>${d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short' })} ${d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', hour12: true })}</td>
            <td>${i.zone}</td>
            <td>${i.category}</td>
            <td><span class="severity-badge ${sevClass}">${i.severity}</span></td>
            <td><span class="timing-badge">${timing.label}</span></td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${i.rawDescription.substring(0, 60)}...</td>
        </tr>`;
    }).join('');

    el.innerHTML = `<div class="table-card" style="margin-bottom:24px">
        <div class="table-header">
            <h3 class="table-title">🌙 Anomalous Timing — After-Hours &amp; Weekend Activity (Last 30 Days)</h3>
        </div>
        <div class="table-scroll">
            <table class="incident-table">
                <thead><tr>
                    <th>ID</th><th>Date/Time</th><th>Zone</th><th>Category</th><th>Severity</th><th>Timing Flag</th><th>Description</th>
                </tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    </div>`;
}

function renderHeatmap(incidents) {
    const container = document.getElementById('heatmapContainer');
    if (!container) return;

    const zones = ['Zone-A', 'Zone-B', 'Zone-C', 'Zone-D', 'Zone-E', 'Zone-F'];
    const categories = ['Unauthorized Device (USB)', 'OT Availability', 'Suspicious Activity', 'Network Degradation', 'Safety Event', 'Near-Miss / Observation'];

    const matrix = {};
    zones.forEach(z => { matrix[z] = {}; categories.forEach(c => { matrix[z][c] = 0; }); });

    const cutoff = new Date(Date.now() - 30 * 86400000);
    incidents.filter(i => new Date(i.reportedAt) > cutoff).forEach(i => {
        if (matrix[i.zone] && matrix[i.zone][i.category] !== undefined) {
            matrix[i.zone][i.category]++;
        }
    });

    container.innerHTML = `
        <div class="heatmap-header">
            ${categories.map(c => `<span>${c.split(' ')[0]}</span>`).join('')}
        </div>
        <div class="heatmap">
            ${zones.map(z => `
                <div class="heatmap-row">
                    <div class="heatmap-label">${z}</div>
                    <div class="heatmap-cells">
                        ${categories.map(c => {
                            const count = matrix[z][c];
                            const cls = count === 0 ? 'heatmap-cell-0' : count === 1 ? 'heatmap-cell-1' : count === 2 ? 'heatmap-cell-2' : count === 3 ? 'heatmap-cell-3' : 'heatmap-cell-4';
                            return `<div class="heatmap-cell ${cls}" title="${z}: ${c} = ${count} incidents">${count}</div>`;
                        }).join('')}
                    </div>
                </div>
            `).join('')}
        </div>
        <div style="display:flex;gap:12px;margin-top:12px;align-items:center;font-size:11px;color:var(--text-muted)">
            <span>Intensity:</span>
            <div style="display:flex;gap:4px;align-items:center"><div class="heatmap-cell heatmap-cell-0" style="height:20px;min-width:24px">0</div> None</div>
            <div style="display:flex;gap:4px;align-items:center"><div class="heatmap-cell heatmap-cell-1" style="height:20px;min-width:24px">1</div> Low</div>
            <div style="display:flex;gap:4px;align-items:center"><div class="heatmap-cell heatmap-cell-2" style="height:20px;min-width:24px">2</div> Medium</div>
            <div style="display:flex;gap:4px;align-items:center"><div class="heatmap-cell heatmap-cell-3" style="height:20px;min-width:24px">3</div> High</div>
            <div style="display:flex;gap:4px;align-items:center"><div class="heatmap-cell heatmap-cell-4" style="height:20px;min-width:24px">4+</div> Critical</div>
        </div>`;
}

// =============================================
// SCOREBOARD
// =============================================

let sbZoneChart = null;
let sbShiftChart = null;

function renderScoreboard() {
    const incidents = getIncidents();
    const cutoff = new Date(Date.now() - 30 * 86400000);
    const recent = incidents.filter(i => new Date(i.reportedAt) > cutoff);

    const zoneCounts = {};
    recent.forEach(i => { zoneCounts[i.zone] = (zoneCounts[i.zone] || 0) + 1; });
    const topZone = Object.entries(zoneCounts).sort((a, b) => b[1] - a[1])[0];
    document.getElementById('topZone').textContent = topZone ? topZone[0] + ' (' + topZone[1] + ')' : 'None';

    const shiftCounts = {};
    recent.forEach(i => { shiftCounts[i.shift] = (shiftCounts[i.shift] || 0) + 1; });
    const topShift = Object.entries(shiftCounts).sort((a, b) => b[1] - a[1])[0];
    document.getElementById('topShift').textContent = topShift ? topShift[0].split(' ')[0] + ' Shift' : 'None';
    document.getElementById('totalReports30').textContent = recent.length;

    const tbody = document.getElementById('scoreboardTableBody');
    if (tbody) {
        const zones = ['Zone-A', 'Zone-B', 'Zone-C', 'Zone-D', 'Zone-E', 'Zone-F'];
        const shifts = ['Morning (6AM-2PM)', 'Afternoon (2PM-10PM)', 'Night (10PM-6AM)'];

        tbody.innerHTML = zones.map(z => {
            const counts = shifts.map(s => recent.filter(i => i.zone === z && i.shift === s).length);
            const total = counts.reduce((a, b) => a + b, 0);
            const trend = total > 3 ? '📈 Up' : total === 0 ? '—' : '📉 Down';
            const status = total >= 4 ? '🏆 Top' : total >= 2 ? '✅ Active' : total === 0 ? '⚠️ Silent' : '🔵 Low';

            return `<tr>
                <td><strong>${z}</strong></td>
                ${counts.map(c => `<td><strong>${c}</strong></td>`).join('')}
                <td><strong>${total}</strong></td>
                <td>${trend}</td>
                <td>${status}</td>
            </tr>`;
        }).join('');
    }

    renderScoreboardCharts(zoneCounts, shiftCounts);
}

function renderScoreboardCharts(zoneCounts, shiftCounts) {
    const ctxZone = document.getElementById('scoreboardZoneChart');
    const ctxShift = document.getElementById('scoreboardShiftChart');
    if (!ctxZone || !ctxShift) return;

    const zones = ['Zone-A', 'Zone-B', 'Zone-C', 'Zone-D', 'Zone-E', 'Zone-F'];
    const shifts = ['Morning', 'Afternoon', 'Night'];

    if (sbZoneChart) sbZoneChart.destroy();
    if (sbShiftChart) sbShiftChart.destroy();

    sbZoneChart = new Chart(ctxZone, {
        type: 'bar',
        data: {
            labels: zones.map(z => z.replace('Zone-', 'Zone ')),
            datasets: [{ label: 'Reports', data: zones.map(z => zoneCounts[z] || 0), backgroundColor: '#1a73e8' }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
    });

    sbShiftChart = new Chart(ctxShift, {
        type: 'doughnut',
        data: {
            labels: shifts,
            datasets: [{
                data: [
                    shiftCounts['Morning (6AM-2PM)'] || 0,
                    shiftCounts['Afternoon (2PM-10PM)'] || 0,
                    shiftCounts['Night (10PM-6AM)'] || 0
                ],
                backgroundColor: ['#1a73e8', '#f39c12', '#0d8044']
            }]
        },
        options: { responsive: true, maintainAspectRatio: false }
    });
}

// =============================================
// OEM REPORT
// =============================================

function exportOEMReport() {
    const incidents = getIncidents();
    const now = new Date();
    const weekAgo = new Date(now - 7 * 86400000);
    const monthAgo = new Date(now - 30 * 86400000);

    const thisWeek = incidents.filter(i => new Date(i.reportedAt) > weekAgo);
    const thisMonth = incidents.filter(i => new Date(i.reportedAt) > monthAgo);
    const open = incidents.filter(i => i.status !== 'Resolved');
    const closed = incidents.filter(i => i.status === 'Resolved');

    const totalExposure = open.reduce((s, i) => s + i.estimatedImpact, 0);
    const mitigatedExposure = closed.filter(i => new Date(i.resolvedAt || i.reportedAt) > weekAgo).reduce((s, i) => s + i.estimatedImpact, 0);
    const withOwner = open.filter(i => i.owner && i.owner !== 'Anonymous').length;
    const ownerPct = open.length > 0 ? Math.round((withOwner / open.length) * 100) : 100;

    const catBreakdown = {};
    open.forEach(i => { catBreakdown[i.category] = (catBreakdown[i.category] || 0) + 1; });

    const zoneBreakdown = {};
    open.forEach(i => { zoneBreakdown[i.zone] = (zoneBreakdown[i.zone] || 0) + 1; });

    const content = document.getElementById('oemReportContent');
    content.innerHTML = `
        <div class="oem-meta">
            <span><strong>📅 Period:</strong> ${weekAgo.toLocaleDateString('en-IN')} – ${now.toLocaleDateString('en-IN')}</span>
            <span><strong>🏭 Plant:</strong> Sriperumbudur Industrial Corridor</span>
            <span><strong>📋 Report ID:</strong> OEM-RPT-${now.toISOString().split('T')[0]}</span>
        </div>

        <div class="oem-stats">
            <div class="oem-stat"><div class="oem-stat-value">${thisWeek.length}</div><div class="oem-stat-label">Incidents (7 days)</div></div>
            <div class="oem-stat"><div class="oem-stat-value">${open.length}</div><div class="oem-stat-label">Open Issues</div></div>
            <div class="oem-stat"><div class="oem-stat-value">${formatINR(totalExposure)}</div><div class="oem-stat-label">₹ Exposure (Open)</div></div>
            <div class="oem-stat"><div class="oem-stat-value">${ownerPct}%</div><div class="oem-stat-label">Issues with Owner</div></div>
        </div>

        <div class="oem-section">
            <h3>📊 Incident Summary (Last 7 Days)</h3>
            <table class="oem-table">
                <tr><th>Metric</th><th>Value</th></tr>
                <tr><td>Total reports this week</td><td><strong>${thisWeek.length}</strong></td></tr>
                <tr><td>Critical incidents</td><td><strong>${thisWeek.filter(i => i.severity === 'Critical').length}</strong></td></tr>
                <tr><td>Safety-relevant issues</td><td><strong>${thisWeek.filter(i => i.safetyFlag).length}</strong></td></tr>
                <tr><td>Resolved this week</td><td><strong>${thisWeek.filter(i => i.status === 'Resolved').length}</strong></td></tr>
                <tr><td>Risk mitigated (₹)</td><td><strong>${formatINR(mitigatedExposure)}</strong></td></tr>
            </table>
        </div>

        <div class="oem-section">
            <h3>⚠️ Open Issues by Category</h3>
            <table class="oem-table">
                <tr><th>Category</th><th>Count</th><th>Est. ₹ Exposure</th><th>% of Total</th></tr>
                ${Object.entries(catBreakdown).sort((a, b) => b[1] - a[1]).map(([cat, count]) => {
                    const exp = open.filter(i => i.category === cat).reduce((s, i) => s + i.estimatedImpact, 0);
                    return `<tr><td>${cat}</td><td><strong>${count}</strong></td><td>${formatINR(exp)}</td><td>${Math.round((count / open.length) * 100)}%</td></tr>`;
                }).join('')}
            </table>
        </div>

        <div class="oem-section">
            <h3>📍 Open Issues by Zone</h3>
            <table class="oem-table">
                <tr><th>Zone</th><th>Open Issues</th><th>Critical</th><th>Est. ₹ Exposure</th></tr>
                ${['Zone-A', 'Zone-B', 'Zone-C', 'Zone-D', 'Zone-E', 'Zone-F'].map(z => {
                    const zoneOpen = open.filter(i => i.zone === z);
                    const critical = zoneOpen.filter(i => i.severity === 'Critical').length;
                    const exp = zoneOpen.reduce((s, i) => s + i.estimatedImpact, 0);
                    return `<tr><td>${z}</td><td><strong>${zoneOpen.length}</strong></td><td>${critical}</td><td>${formatINR(exp)}</td></tr>`;
                }).join('')}
            </table>
        </div>

        <div class="oem-section">
            <h3>👤 Ownership &amp; Accountability</h3>
            <table class="oem-table">
                <tr><th>Owner</th><th>Open Issues</th><th>Resolved (30d)</th><th>Total ₹ Exposure</th></tr>
                ${['Ramkumar R', 'Priya S', 'Karthik M', 'Sundari P', 'Arun V'].map(owner => {
                    const ownerOpen = open.filter(i => i.owner === owner);
                    const ownerResolved = closed.filter(i => i.owner === owner && new Date(i.resolvedAt || i.reportedAt) > monthAgo).length;
                    const exp = ownerOpen.reduce((s, i) => s + i.estimatedImpact, 0);
                    return `<tr><td>${owner}</td><td><strong>${ownerOpen.length}</strong></td><td>${ownerResolved}</td><td>${formatINR(exp)}</td></tr>`;
                }).join('')}
            </table>
        </div>
    `;

    document.getElementById('oemModal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('oemModal').style.display = 'none';
}

function printReport() {
    window.print();
}

// =============================================
// INCIDENT DETAIL
// =============================================

function openIncidentDetail(id) {
    const incidents = getIncidents();
    const i = incidents.find(inc => inc.id === id);
    if (!i) return;

    const atk = ATTACK_MAP[i.category];
    const playbook = IR_PLAYBOOKS[i.category];

    // ATT&CK section
    const atkSection = atk ? `
        <div class="detail-section">
            <h4>🎯 MITRE ATT&amp;CK for ICS</h4>
            <div style="background:#1a1a2e;border-radius:8px;padding:14px 16px;margin-top:8px">
                <div style="display:flex;gap:16px;flex-wrap:wrap;align-items:center">
                    <span class="attack-badge" style="color:${atk.color};border-color:${atk.color};font-size:13px;padding:4px 12px">${atk.id}</span>
                    <span style="color:white;font-weight:700;font-size:14px">${atk.name}</span>
                    <span style="color:rgba(255,255,255,0.5);font-size:12px">Tactic: ${atk.tactic}</span>
                </div>
                <div style="margin-top:10px">
                    <a href="https://attack.mitre.org/techniques/${atk.id}/" target="_blank" rel="noopener noreferrer"
                       style="color:#60a5fa;font-size:12px;text-decoration:none;font-weight:600">
                        MITRE ATT&amp;CK for ICS →
                    </a>
                </div>
            </div>
        </div>
    ` : '';

    // IR Playbook section
    const playbookSection = playbook ? `
        <div class="detail-section">
            <h4 style="border-top:2px solid #e8eaed;padding-top:16px;margin-top:16px">━━━ INCIDENT RESPONSE PLAYBOOK ━━━</h4>
            <div class="playbook-header">
                <div class="playbook-icon">${playbook.icon}</div>
                <div>
                    <div class="playbook-title">${playbook.title}</div>
                    <div class="playbook-technique">${playbook.technique}</div>
                </div>
            </div>
            <div>
                ${playbook.steps.map((step, idx) => `
                    <div class="playbook-step">
                        <input type="checkbox" id="ps-${i.id}-${idx}">
                        <label for="ps-${i.id}-${idx}">Step ${idx + 1}: ${step}</label>
                    </div>
                `).join('')}
            </div>
        </div>
    ` : '';

    const content = document.getElementById('incidentDetailContent');
    content.innerHTML = `
        <div class="detail-grid">
            <div class="detail-item"><span class="detail-label">Incident ID</span><span class="detail-value table-id">${i.id}</span></div>
            <div class="detail-item"><span class="detail-label">Severity</span><span class="severity-badge severity-${i.severity}">${i.severity}</span></div>
            <div class="detail-item"><span class="detail-label">Zone</span><span class="detail-value">${i.zone}</span></div>
            <div class="detail-item"><span class="detail-label">System</span><span class="detail-value">${i.systemName}</span></div>
            <div class="detail-item"><span class="detail-label">Category</span><span class="detail-value">${i.category}</span></div>
            <div class="detail-item"><span class="detail-label">Safety Flag</span><span class="detail-value" style="color:${i.safetyFlag ? '#c5221f' : '#0d652d'}">${i.safetyFlag ? '⚠ YES' : '✓ No'}</span></div>
            <div class="detail-item"><span class="detail-label">Shift</span><span class="detail-value">${i.shift}</span></div>
            <div class="detail-item"><span class="detail-label">Status</span><span class="status-badge status-${i.status === 'In Progress' ? 'In' : i.status}">${i.status}</span></div>
            <div class="detail-item"><span class="detail-label">Estimated ₹ Impact</span><span class="detail-value impact-money">${formatINR(i.estimatedImpact)}</span></div>
            <div class="detail-item"><span class="detail-label">Estimated Downtime</span><span class="detail-value">${i.estimatedDowntime < 1 ? Math.round(i.estimatedDowntime * 60) + ' min' : i.estimatedDowntime.toFixed(1) + ' hrs'}</span></div>
            <div class="detail-item"><span class="detail-label">Reported</span><span class="detail-value">${new Date(i.reportedAt).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' })}</span></div>
            <div class="detail-item"><span class="detail-label">Owner</span><span class="detail-value">${i.owner}</span></div>
        </div>
        <div class="detail-section">
            <h4>Raw Description</h4>
            <div class="detail-desc">${i.rawDescription}</div>
        </div>
        ${i.selectedTags && i.selectedTags.length > 0 ? `
        <div class="detail-section">
            <h4>Quick Tags</h4>
            <div style="display:flex;gap:8px;flex-wrap:wrap">
                ${i.selectedTags.map(t => `<span style="background:var(--primary-light);color:var(--primary);padding:4px 10px;border-radius:20px;font-size:12px;font-weight:600">${t}</span>`).join('')}
            </div>
        </div>` : ''}
        <div class="detail-section">
            <h4>Update Status</h4>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                <select id="detailStatus" class="status-select" onchange="updateIncidentStatus('${i.id}', this.value)">
                    <option value="Open" ${i.status === 'Open' ? 'selected' : ''}>Open</option>
                    <option value="In Progress" ${i.status === 'In Progress' ? 'selected' : ''}>In Progress</option>
                    <option value="Mitigated" ${i.status === 'Mitigated' ? 'selected' : ''}>Mitigated</option>
                    <option value="Resolved" ${i.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                </select>
            </div>
        </div>
        ${atkSection}
        ${playbookSection}
    `;

    document.getElementById('incidentModal').style.display = 'flex';
}

function closeIncidentModal() {
    document.getElementById('incidentModal').style.display = 'none';
}

function resolveIncident(id) {
    updateIncidentStatus(id, 'Resolved');
    showToast('Incident ' + id + ' marked as Resolved ✓', 'success');
    renderDashboard();
}

function updateIncidentStatus(id, status) {
    const incidents = getIncidents();
    const idx = incidents.findIndex(i => i.id === id);
    if (idx !== -1) {
        incidents[idx].status = status;
        if (status === 'Resolved') incidents[idx].resolvedAt = new Date().toISOString();
        saveIncidents(incidents);
        renderDashboard();
    }
}

// =============================================
// FEATURE 5: PURDUE MODEL TOPOLOGY VIEW
// =============================================

function renderTopology() {
    const incidents = getIncidents();
    const open = incidents.filter(i => i.status !== 'Resolved');

    // Helper: get worst severity for a system
    function getSystemSeverity(sysId) {
        const sysIncidents = open.filter(i => i.system === sysId);
        if (sysIncidents.some(i => i.severity === 'Critical')) return 'Critical';
        if (sysIncidents.some(i => i.severity === 'High')) return 'High';
        if (sysIncidents.some(i => i.severity === 'Medium')) return 'Medium';
        if (sysIncidents.some(i => i.severity === 'Low')) return 'Low';
        return 'clean';
    }

    function getSystemCount(sysId) {
        return open.filter(i => i.system === sysId).length;
    }

    function nodeHTML(sysId, icon, label, gray) {
        if (gray) {
            return `<div class="purdue-node purdue-node-gray" title="${label}">
                <div class="purdue-node-icon">${icon}</div>
                <div class="purdue-node-name">${label}</div>
            </div>`;
        }
        const sev = getSystemSeverity(sysId);
        const cnt = getSystemCount(sysId);
        const badge = cnt > 0 ? `<div class="purdue-node-badge">${cnt}</div>` : '';
        const sevClass = sev !== 'clean' ? `purdue-node-${sev}` : '';
        return `<div class="purdue-node ${sevClass}" onclick="handleTopologyNodeClick('${sysId}', '${label}')" title="${label} — ${cnt > 0 ? cnt + ' open incidents' : 'No open incidents'}">
            ${badge}
            <div class="purdue-node-icon">${icon}</div>
            <div class="purdue-node-name">${label}</div>
        </div>`;
    }

    const container = document.getElementById('topologyContainer');
    if (!container) return;

    container.innerHTML = `
        <div class="purdue-container">
            <div class="purdue-level">
                <div class="purdue-level-header">
                    <div class="purdue-level-num">3</div>
                    <div>
                        <div class="purdue-level-title">Level 3 — Site Operations</div>
                        <div class="purdue-level-sub">Historian, Engineering Workstations, OPC Server</div>
                    </div>
                </div>
                <div class="purdue-nodes">
                    ${nodeHTML('', '📜', 'Historian', true)}
                    ${nodeHTML('', '💻', 'Engineering WS', true)}
                    ${nodeHTML('', '🔌', 'OPC Server', true)}
                </div>
            </div>

            <div class="purdue-divider">🔒 FIREWALL / DMZ BOUNDARY</div>

            <div class="purdue-level">
                <div class="purdue-level-header">
                    <div class="purdue-level-num">2</div>
                    <div>
                        <div class="purdue-level-title">Level 2 — Supervisory Control</div>
                        <div class="purdue-level-sub">SCADA, HMI Systems</div>
                    </div>
                </div>
                <div class="purdue-nodes">
                    ${nodeHTML('SCADA-SERVER', '🖥️', 'SCADA-SERVER', false)}
                    ${nodeHTML('HMI-01', '📺', 'HMI-01', false)}
                    ${nodeHTML('HMI-02', '📺', 'HMI-02', false)}
                    ${nodeHTML('HMI-03', '📺', 'HMI-03', false)}
                </div>
            </div>

            <div class="purdue-level">
                <div class="purdue-level-header">
                    <div class="purdue-level-num">1</div>
                    <div>
                        <div class="purdue-level-title">Level 1 — Basic Control</div>
                        <div class="purdue-level-sub">PLCs, DCS, Network Infrastructure</div>
                    </div>
                </div>
                <div class="purdue-nodes">
                    ${nodeHTML('PLC-01', '⚙️', 'PLC-01', false)}
                    ${nodeHTML('PLC-02', '⚙️', 'PLC-02', false)}
                    ${nodeHTML('PLC-03', '⚙️', 'PLC-03', false)}
                    ${nodeHTML('PLC-04', '⚙️', 'PLC-04', false)}
                    ${nodeHTML('DCS-01', '🎛️', 'DCS-01', false)}
                    ${nodeHTML('NETWORK-SWITCH', '🔀', 'NET-SWITCH', false)}
                    ${nodeHTML('FIRE-SYSTEM', '🔥', 'FIRE-SYSTEM', false)}
                </div>
            </div>

            <div class="purdue-level">
                <div class="purdue-level-header">
                    <div class="purdue-level-num">0</div>
                    <div>
                        <div class="purdue-level-title">Level 0 — Field Devices</div>
                        <div class="purdue-level-sub">Sensors, Actuators, Instruments, Transmitters</div>
                    </div>
                </div>
                <div class="purdue-nodes">
                    ${nodeHTML('', '🌡️', 'Zone A Sensors', true)}
                    ${nodeHTML('', '🔧', 'Zone B Actuators', true)}
                    ${nodeHTML('', '📊', 'Zone C Instruments', true)}
                    ${nodeHTML('', '📡', 'Zone D Transmitters', true)}
                </div>
            </div>
        </div>
    `;

    // Sidebar stats
    const sidebar = document.getElementById('topologySidebar');
    if (!sidebar) return;

    const monitoredSystems = ['PLC-01', 'PLC-02', 'PLC-03', 'PLC-04', 'HMI-01', 'HMI-02', 'HMI-03', 'SCADA-SERVER', 'DCS-01', 'NETWORK-SWITCH', 'FIRE-SYSTEM'];
    const systemsWithAlerts = monitoredSystems.filter(s => getSystemCount(s) > 0).length;

    // Highest risk system
    let highestRisk = { sys: 'None', count: 0 };
    monitoredSystems.forEach(s => {
        const cnt = getSystemCount(s);
        if (cnt > highestRisk.count) highestRisk = { sys: s, count: cnt };
    });

    const campaigns = detectKillChain(incidents, 72);
    const killChainActive = campaigns.length > 0;

    sidebar.innerHTML = `
        <h3 style="font-size:14px;font-weight:700;color:var(--dark);margin-bottom:16px">Topology Summary</h3>
        <div class="topo-stat">
            <span class="topo-stat-label">OT Systems Monitored</span>
            <span class="topo-stat-value">${monitoredSystems.length}</span>
        </div>
        <div class="topo-stat">
            <span class="topo-stat-label">Systems with Active Alerts</span>
            <span class="topo-stat-value" style="${systemsWithAlerts > 0 ? 'color:#dc2626' : 'color:#0d8044'}">${systemsWithAlerts}</span>
        </div>
        <div class="topo-stat">
            <span class="topo-stat-label">Highest Risk System</span>
            <span class="topo-stat-value">${highestRisk.count > 0 ? highestRisk.sys + ' (' + highestRisk.count + ')' : 'None'}</span>
        </div>
        <div class="topo-stat">
            <span class="topo-stat-label">Kill Chain Active</span>
            <span class="topo-stat-value ${killChainActive ? 'campaign-active' : ''}">${killChainActive ? '🔴 YES' : '✅ NO'}</span>
        </div>
        <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border)">
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:12px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px">Legend</div>
            <div style="display:flex;flex-direction:column;gap:8px;font-size:12px">
                <div style="display:flex;align-items:center;gap:8px"><div style="width:14px;height:14px;border-radius:3px;border:2px solid #dc2626;flex-shrink:0"></div> Critical / High risk</div>
                <div style="display:flex;align-items:center;gap:8px"><div style="width:14px;height:14px;border-radius:3px;border:2px solid #f59e0b;flex-shrink:0"></div> Medium risk</div>
                <div style="display:flex;align-items:center;gap:8px"><div style="width:14px;height:14px;border-radius:3px;border:2px solid #10b981;flex-shrink:0"></div> Low risk</div>
                <div style="display:flex;align-items:center;gap:8px"><div style="width:14px;height:14px;border-radius:3px;border:2px solid #e8eaed;flex-shrink:0;opacity:0.4"></div> Not monitored</div>
            </div>
        </div>
    `;
}

function handleTopologyNodeClick(sysId, label) {
    showToast('Filtering for ' + label, 'success');
    showView('dashboard');
    // Optionally pre-set filters — navigate to dashboard filtered by system
}

// =============================================
// ROLE SWITCHING
// =============================================

function switchRole(role) {
    if (role === 'staff') showView('report');
    else if (role === 'engineer') showView('dashboard');
    else if (role === 'manager') showView('dashboard');
    else showView('dashboard');
    showToast('Switched to ' + role.charAt(0).toUpperCase() + role.slice(1) + ' view', 'success');
}

// =============================================
// UTILITIES
// =============================================

function formatINR(num) {
    if (num === 0) return '₹0';
    if (num >= 10000000) return '₹' + (num / 10000000).toFixed(1) + 'Cr';
    if (num >= 100000) return '₹' + (num / 100000).toFixed(1) + 'L';
    if (num >= 1000) return '₹' + (num / 1000).toFixed(1) + 'K';
    return '₹' + num;
}

function showToast(message, type) {
    if (type === undefined) type = 'success';
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = 'toast ' + type;
    toast.style.display = 'flex';
    setTimeout(function() { toast.style.display = 'none'; }, 4000);
}

// =============================================
// INIT
// =============================================

document.addEventListener('DOMContentLoaded', function() {
    renderDashboard();
    renderRecentReportsSidebar();
});
