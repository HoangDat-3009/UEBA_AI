import os

# Read the file
html_path = os.path.join("src", "templates", "index.html")
with open(html_path, "r", encoding="utf-8") as f:
    content = f.read()

# Find the broken section and replace it
old_text = """    if (alertData.severity === 'CRITICAL') {
        const critEl = document.getElementById('histCriticalCount');
        critEl.textContent = parseInt(critEl.textContent || '0') + 1;
})();

(async function init() {
    try {
        // Initialize language (EN default)
        changeLanguage('en');
        
        // Fetch all data in parallel for faster load
        const [data, , ] = await Promise.all([
            fetchData(),
            fetchAlerts(),
            fetchHistory(null, null),
        ]);
        renderAll(data);
        startAutoRefresh();
    } catch (e) {
        console.error('Init failed:', e);
    }
})();
</script>

</body>
</html>"""

new_text = """    if (alertData.severity === 'CRITICAL') {
        const critEl = document.getElementById('histCriticalCount');
        critEl.textContent = parseInt(critEl.textContent || '0') + 1;
    }

    throttledFetchHistory();
}

// ===========================================================================
// Alert Detail Popup
// ===========================================================================

function closeAlertDetail(event) {
    if (event && event.target !== document.getElementById('alertModalOverlay')) return;
    document.getElementById('alertModalOverlay').classList.remove('active');
    document.body.style.overflow = '';
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAlertDetail();
});

async function showAlertDetail(alertId) {
    const overlay = document.getElementById('alertModalOverlay');
    const modalBody = document.getElementById('alertModalBody');

    modalBody.innerHTML = `<div class="alert-modal-loading"><div class="spinner-ring"></div><div>${t('modal_loading')}</div></div>`;
    overlay.classList.add('active');
    document.body.style.overflow = 'hidden';

    const storedAlert = _alertDataStore[alertId];

    let detail = null;
    if (typeof alertId === 'number' || (typeof alertId === 'string' && !alertId.startsWith('local_'))) {
        try {
            const res = await fetch(`/api/alert/${alertId}/detail`);
            if (res.ok) detail = await res.json();
        } catch (e) {
            console.error('Failed to fetch alert detail:', e);
        }
    }

    const alertInfo = detail ? detail.alert : storedAlert;
    const rawLogs = detail ? detail.raw_logs : [];
    const rawLogCount = detail ? detail.raw_log_count : 0;
    const baseline = detail ? detail.baseline : {};

    if (!alertInfo) {
        modalBody.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text-secondary);">Alert data not available.</div>`;
        return;
    }

    const deviations = alertInfo.feature_deviations || alertInfo.deviations || {};
    const severity = alertInfo.severity || 'HIGH';
    const score = alertInfo.anomaly_score || 0;
    const userId = alertInfo.user_id || alertInfo.user || '\\u2014';
    const timestamp = alertInfo.timestamp || '\\u2014';
    const description = alertInfo.description || t('alert_desc_default');

    let html = '';

    const sevClass = severity === 'CRITICAL' ? 'modal-severity-critical' : 'modal-severity-high';
    const sevLabel = severity === 'CRITICAL' ? t('severity_critical') : t('severity_high');
    html += `
    <div class="modal-section">
        <div class="modal-section-title">${t('modal_summary')}</div>
        <div class="modal-summary-grid">
            <div class="modal-summary-item">
                <div class="modal-summary-label">${t('modal_user')}</div>
                <div class="modal-summary-value" style="color:#60a5fa;font-size:18px;">${userId}</div>
            </div>
            <div class="modal-summary-item">
                <div class="modal-summary-label">${t('modal_severity')}</div>
                <div class="modal-summary-value"><span class="modal-sev-badge ${sevClass}">${sevLabel}</span></div>
            </div>
            <div class="modal-summary-item">
                <div class="modal-summary-label">${t('modal_score')}</div>
                <div class="modal-summary-value" style="color:#f87171;font-size:18px;">${typeof score === 'number' ? score.toFixed(4) : score}</div>
            </div>
            <div class="modal-summary-item">
                <div class="modal-summary-label">${t('modal_time')}</div>
                <div class="modal-summary-value" style="font-size:13px;">${timestamp}</div>
            </div>
        </div>
        <div class="modal-description">${description}</div>
    </div>`;

    const riskText = severity === 'CRITICAL' ? t('modal_risk_critical') : t('modal_risk_high');
    let triggerText = t('modal_risk_model');
    if (description.toLowerCase().includes('high-risk')) triggerText = t('modal_risk_highrisk');
    else if (description.toLowerCase().includes('baseline')) triggerText = t('modal_risk_baseline');

    html += `
    <div class="modal-section">
        <div class="modal-section-title">${t('modal_assessment')}</div>
        <div class="modal-assessment ${sevClass}">
            <div class="modal-assessment-text">${riskText}</div>
            <div class="modal-assessment-trigger">${triggerText}</div>
        </div>
    </div>`;

    if (Object.keys(deviations).length > 0) {
        html += `<div class="modal-section"><div class="modal-section-title">${t('modal_deviations')}</div>
            <div class="modal-deviations-table"><table><thead><tr>
                <th style="width:30%">Feature</th><th>${t('modal_feat_observed')}</th>
                <th>${t('modal_feat_baseline_mean')}</th><th>${t('modal_feat_baseline_std')}</th>
                <th>${t('modal_feat_deviation')}</th></tr></thead><tbody>`;
        for (const [feat, dv] of Object.entries(deviations)) {
            const featLabel = FEATURE_MAP[feat] || feat;
            const devSigma = dv.deviation_sigma || 0;
            const barW = Math.min(devSigma / 5 * 100, 100);
            const barC = devSigma >= 3 ? '#ef4444' : devSigma >= 2 ? '#f97316' : '#eab308';
            html += `<tr><td style="font-weight:600;color:#e2e8f0;">${featLabel}</td>
                <td style="color:#f87171;font-weight:700;">${dv.observed}</td><td>${dv.mean}</td>
                <td>${baseline[feat] ? baseline[feat].std : '\\u2014'}</td>
                <td><div style="display:flex;align-items:center;gap:8px;">
                    <div style="flex:1;background:rgba(255,255,255,0.06);border-radius:4px;height:8px;overflow:hidden;">
                        <div style="width:${barW}%;height:100%;background:${barC};border-radius:4px;"></div></div>
                    <span style="color:${barC};font-weight:700;min-width:45px;">${devSigma}\\u03c3</span>
                </div></td></tr>`;
        }
        html += `</tbody></table></div></div>`;
    }

    if (Object.keys(baseline).length > 0) {
        html += `<div class="modal-section"><div class="modal-section-title">${t('modal_baseline')}</div><div class="modal-baseline-grid">`;
        for (const [feat, bv] of Object.entries(baseline)) {
            const featLabel = FEATURE_MAP[feat] || feat;
            html += `<div class="modal-baseline-item"><div class="modal-baseline-feat">${featLabel}</div>
                <div class="modal-baseline-vals"><span>\\u03bc = ${bv.mean}</span><span>\\u03c3 = ${bv.std}</span></div></div>`;
        }
        html += `</div></div>`;
    } else {
        html += `<div class="modal-section"><div class="modal-section-title">${t('modal_baseline')}</div>
            <div style="color:var(--text-secondary);font-size:13px;padding:12px 0;">${t('modal_no_baseline')}</div></div>`;
    }

    html += `<div class="modal-section"><div class="modal-section-title">${t('modal_raw_logs')} <span style="color:var(--text-secondary);font-weight:400;">(${rawLogCount} events)</span></div>`;
    if (rawLogs.length > 0) {
        html += `<div class="modal-raw-logs">`;
        rawLogs.forEach(logEvt => {
            const logStr = JSON.stringify(logEvt, null, 2);
            const evtType = logEvt.type || 'unknown';
            const tColors = { 'logon': '#22c55e', 'device': '#f97316', 'file': '#a78bfa', 'email': '#38bdf8' };
            const tColor = tColors[evtType] || '#94a3b8';
            html += `<div class="modal-log-entry"><div class="modal-log-header">
                <span class="modal-log-time">${logEvt.timestamp || '\\u2014'}</span>
                <span class="modal-log-type" style="background:${tColor}20;color:${tColor};">${evtType.toUpperCase()}</span>
                ${logEvt.source ? `<span class="modal-log-source">${logEvt.source}</span>` : ''}
                ${logEvt.event_id ? `<span class="modal-log-eid">EID: ${logEvt.event_id}</span>` : ''}
            </div><pre class="modal-log-json">${logStr}</pre></div>`;
        });
        html += `</div>`;
    } else {
        html += `<div style="color:var(--text-secondary);font-size:13px;padding:12px 0;">${t('modal_no_logs')}</div>`;
    }
    html += `</div>`;

    modalBody.innerHTML = html;
}

// ===========================================================================
// Init
// ===========================================================================

(function setDefaultDates() {
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('filterDateTo').value = today;
})();

(async function init() {
    try {
        changeLanguage('en');
        const [data, , ] = await Promise.all([
            fetchData(),
            fetchAlerts(),
            fetchHistory(null, null),
        ]);
        renderAll(data);
        startAutoRefresh();
    } catch (e) {
        console.error('Init failed:', e);
    }
})();
</script>

</body>
</html>
"""

if old_text in content:
    content = content.replace(old_text, new_text)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("SUCCESS: Replacement applied.")
else:
    # Try with normalized newlines
    content_lf = content.replace('\r\n', '\n')
    old_lf = old_text.replace('\r\n', '\n')
    if old_lf in content_lf:
        content_lf = content_lf.replace(old_lf, new_text)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(content_lf)
        print("SUCCESS: Replacement applied (normalized newlines).")
    else:
        print("FAILED: Could not find target text.")
        # Debug: show what's around the area
        idx = content_lf.find("critEl.textContent = parseInt")
        if idx >= 0:
            print("FOUND 'critEl' at index", idx)
            print("Context:", repr(content_lf[idx:idx+200]))
