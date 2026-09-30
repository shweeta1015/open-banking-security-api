/**
 * Security Audit Log Viewer and Live Streamer
 */

class AuditManager {
    static async fetchLogs(eventType = "") {
        try {
            const url = eventType ? `/api/v1/audit/logs?event_type=${encodeURIComponent(eventType)}` : `/api/v1/audit/logs?limit=40`;
            const resp = await fetch(url);
            if (!resp.ok) return [];
            return await resp.json();
        } catch (e) {
            console.error("Failed to fetch audit logs:", e);
            return [];
        }
    }

    static getEventBadgeClass(eventType) {
        if (eventType.includes("BLOCKED") || eventType.includes("FAILURE") || eventType.includes("REVOKED")) {
            return "badge-danger";
        }
        if (eventType.includes("EXCEEDED") || eventType.includes("VIOLATION")) {
            return "badge-warning";
        }
        if (eventType.includes("GRANTED") || eventType.includes("REGISTERED") || eventType.includes("ISSUED")) {
            return "badge-success";
        }
        return "badge-info";
    }

    static renderLogs(logs, containerId = "auditLogTableBody") {
        const tbody = document.getElementById(containerId);
        if (!tbody) return;

        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#6b7280; padding:24px;">No security events logged yet. Trigger actions above to generate events.</td></tr>`;
            return;
        }

        tbody.innerHTML = logs.map(log => {
            const dateStr = new Date(log.timestamp).toLocaleTimeString();
            const badgeClass = AuditManager.getEventBadgeClass(log.event_type);
            const statusColor = log.status_code >= 400 ? "#f87171" : "#34d399";

            return `
                <tr>
                    <td style="font-family: var(--font-mono); font-size:0.75rem; color:#94a3b8;">${dateStr}</td>
                    <td><span class="badge-event ${badgeClass}">${log.event_type}</span></td>
                    <td style="font-weight:600; color:${statusColor};">${log.status_code}</td>
                    <td style="font-family: var(--font-mono); font-size:0.8rem;">${log.method} ${log.endpoint}</td>
                    <td style="font-size:0.8rem; color:#cbd5e1;">${log.client_id || 'anonymous'}</td>
                    <td style="font-size:0.8rem; color:#94a3b8;">${log.details}</td>
                </tr>
            `;
        }).join('');
    }
}
