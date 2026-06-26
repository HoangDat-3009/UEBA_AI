import os

css_path = os.path.join("src", "static", "style.css")

modal_css = """
/* ===========================================================================
   Alert Detail Modal
   =========================================================================== */
.alert-modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(8px);
    z-index: 9999;
    display: flex;
    align-items: center;
    justify-content: center;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.3s ease;
}

.alert-modal-overlay.active {
    opacity: 1;
    pointer-events: auto;
}

.alert-modal {
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-radius: var(--radius-lg);
    width: 90%;
    max-width: 800px;
    max-height: 90vh;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
    display: flex;
    flex-direction: column;
    transform: scale(0.95) translateY(20px);
    transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    overflow: hidden;
}

.alert-modal-overlay.active .alert-modal {
    transform: scale(1) translateY(0);
}

.alert-modal-header {
    background: rgba(15, 23, 42, 0.95);
    padding: 16px 24px;
    border-bottom: 1px solid var(--border-primary);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.alert-modal-title {
    font-size: 18px;
    font-weight: 700;
    color: #f8fafc;
    display: flex;
    align-items: center;
    gap: 10px;
}

.alert-modal-close {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 24px;
    cursor: pointer;
    line-height: 1;
    padding: 4px;
    border-radius: 4px;
    transition: all 0.2s;
}

.alert-modal-close:hover {
    color: #fff;
    background: rgba(255, 255, 255, 0.1);
}

.alert-modal-body {
    padding: 24px;
    overflow-y: auto;
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 24px;
}

.alert-modal-loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 60px 0;
    color: var(--text-secondary);
    gap: 16px;
}

.modal-section-title {
    font-size: 14px;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid var(--border-secondary);
    padding-bottom: 8px;
}

.modal-summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    background: rgba(30, 41, 59, 0.5);
    padding: 16px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-secondary);
}

.modal-summary-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
}

.modal-summary-label {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.modal-summary-value {
    font-size: 14px;
    font-weight: 600;
    color: #f1f5f9;
}

.modal-description {
    margin-top: 16px;
    padding: 12px 16px;
    background: rgba(15, 23, 42, 0.5);
    border-left: 4px solid var(--primary);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    font-size: 14px;
    line-height: 1.5;
    color: #e2e8f0;
}

.modal-assessment {
    padding: 16px;
    border-radius: var(--radius-md);
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.modal-assessment.modal-severity-critical {
    background: rgba(239, 68, 68, 0.15);
    border-color: rgba(239, 68, 68, 0.4);
}

.modal-assessment.modal-severity-high {
    background: rgba(249, 115, 22, 0.1);
    border-color: rgba(249, 115, 22, 0.3);
}

.modal-assessment-text {
    font-size: 14px;
    font-weight: 600;
    color: #fca5a5;
    margin-bottom: 8px;
    line-height: 1.4;
}

.modal-severity-high .modal-assessment-text {
    color: #fdba74;
}

.modal-assessment-trigger {
    font-size: 12px;
    color: #cbd5e1;
}

.modal-sev-badge {
    padding: 4px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}

.modal-severity-critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.5); }
.modal-severity-high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.5); }

.modal-deviations-table table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}

.modal-deviations-table th {
    text-align: left;
    padding: 8px 12px;
    color: var(--text-muted);
    border-bottom: 1px solid var(--border-secondary);
    font-weight: 600;
}

.modal-deviations-table td {
    padding: 10px 12px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    color: #cbd5e1;
}

.modal-deviations-table tr:last-child td {
    border-bottom: none;
}

.modal-baseline-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 12px;
}

.modal-baseline-item {
    background: rgba(30, 41, 59, 0.4);
    border: 1px solid var(--border-secondary);
    padding: 12px;
    border-radius: var(--radius-sm);
}

.modal-baseline-feat {
    font-size: 12px;
    font-weight: 600;
    color: #94a3b8;
    margin-bottom: 8px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.modal-baseline-vals {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    color: #e2e8f0;
    font-family: monospace;
}

.modal-raw-logs {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.modal-log-entry {
    background: #0f172a;
    border: 1px solid var(--border-secondary);
    border-radius: var(--radius-sm);
    overflow: hidden;
}

.modal-log-header {
    background: rgba(255, 255, 255, 0.02);
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-secondary);
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 12px;
}

.modal-log-time { color: #94a3b8; font-family: monospace; }
.modal-log-type { padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 10px; }
.modal-log-source { color: #cbd5e1; font-weight: 600; }
.modal-log-eid { color: #8b5cf6; font-family: monospace; }

.modal-log-json {
    margin: 0;
    padding: 12px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    color: #a5b4fc;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
}

/* Make alert rows clickable */
.threats-table tbody tr {
    transition: background 0.2s;
}
.threats-table tbody tr:hover {
    background: rgba(255, 255, 255, 0.03);
}
"""

with open(css_path, "a", encoding="utf-8") as f:
    f.write("\n" + modal_css)

print("CSS appended successfully.")
