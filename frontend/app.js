const API = "http://localhost:8000";

let currentPage  = 0;
let currentStix  = "";
const PAGE_SIZE  = 20;


// INIT
document.addEventListener("DOMContentLoaded", () => {
    checkBackend();
    loadStats();
    loadAlerts();

    // Search on Enter key
    document.getElementById("search-input").addEventListener("keydown", e => {
        if (e.key === "Enter") loadAlerts();
    });
});


// BACKEND HEALTH CHECK

async function checkBackend() {
    try {
        const res = await fetch(`${API}/`);
        if (res.ok) {
            document.getElementById("backend-status").textContent = "Connected ✅";
        } else {
            document.getElementById("backend-status").textContent = "Error ❌";
        }
    } catch {
        document.getElementById("backend-status").textContent = "Offline ❌";
    }
}



// STATS
async function loadStats() {
    try {
        const res  = await fetch(`${API}/api/stats`);
        const data = await res.json();
        document.getElementById("stat-total").textContent    = data.total    || 0;
        document.getElementById("stat-critical").textContent = data.critical || 0;
        document.getElementById("stat-high").textContent     = data.high     || 0;
        document.getElementById("stat-medium").textContent   = data.medium   || 0;
        document.getElementById("stat-low").textContent      = data.low      || 0;
    } catch {
        console.error("Failed to load stats");
    }
}



// LOAD ALERTS

async function loadAlerts(page = 0) {
    currentPage = page;
    const search   = document.getElementById("search-input").value.trim();
    const severity = document.getElementById("severity-filter").value;
    const skip     = page * PAGE_SIZE;

    const container = document.getElementById("alerts-container");
    container.innerHTML = `<div class="loading">⏳ Loading alerts...</div>`;

    try {
        let url = `${API}/api/alerts?skip=${skip}&limit=${PAGE_SIZE}`;
        if (search)   url += `&search=${encodeURIComponent(search)}`;
        if (severity) url += `&severity=${encodeURIComponent(severity)}`;

        const res  = await fetch(url);
        const data = await res.json();

        renderAlerts(data.alerts);
        renderPagination(data.total, page);
        loadStats();
    } catch {
        container.innerHTML = `
            <div class="empty-state">
                <div class="icon">⚠️</div>
                <p>Could not connect to backend. Make sure it is running on port 8000.</p>
            </div>`;
    }
}



// RENDER ALERTS

function renderAlerts(alerts) {
    const container = document.getElementById("alerts-container");

    if (!alerts || alerts.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="icon">🔍</div>
                <p>No alerts found. Try crawling CSK or adjusting your search.</p>
            </div>`;
        return;
    }

    container.innerHTML = alerts.map(alert => `
        <div class="alert-card ${severityClass(alert.severity)}" onclick="openModal('${alert.alert_id}')">
            <div class="alert-header">
                <div class="alert-title">${escapeHtml(alert.title)}</div>
                <span class="badge ${severityClass(alert.severity)}">${alert.severity || "Unknown"}</span>
            </div>
            <div class="alert-meta">
                <span>🗂 ${escapeHtml(alert.threat_type || "Unknown")}</span>
                ${alert.published_at ? `<span>📅 ${escapeHtml(alert.published_at)}</span>` : ""}
                ${alert.cves ? `<span>🔖 ${escapeHtml(alert.cves)}</span>` : ""}
            </div>
            ${alert.summary ? `<div class="alert-summary">${escapeHtml(alert.summary)}</div>` : ""}
            ${renderCveTags(alert.cves)}
        </div>
    `).join("");
}


// PAGINATION

function renderPagination(total, currentPage) {
    const totalPages = Math.ceil(total / PAGE_SIZE);
    const pagination = document.getElementById("pagination");

    if (totalPages <= 1) {
        pagination.innerHTML = "";
        return;
    }

    let html = "";
    if (currentPage > 0) {
        html += `<button class="page-btn" onclick="loadAlerts(${currentPage - 1})">← Prev</button>`;
    }
    for (let i = 0; i < totalPages; i++) {
        html += `<button class="page-btn ${i === currentPage ? "active" : ""}" onclick="loadAlerts(${i})">${i + 1}</button>`;
    }
    if (currentPage < totalPages - 1) {
        html += `<button class="page-btn" onclick="loadAlerts(${currentPage + 1})">Next →</button>`;
    }
    pagination.innerHTML = html;
}



async function openModal(alertId) {
    document.getElementById("modal-overlay").classList.add("active");
    document.getElementById("modal-title").textContent   = "Loading...";
    document.getElementById("modal-summary").textContent = "";
    document.getElementById("modal-stix").textContent    = "Loading STIX bundle...";

    try {
        const res   = await fetch(`${API}/api/alerts/${alertId}`);
        const alert = await res.json();

        document.getElementById("modal-title").textContent = alert.title;
        document.getElementById("modal-source-link").href  = alert.url;

        // Meta
        document.getElementById("modal-meta").innerHTML = `
            <span class="badge ${severityClass(alert.severity)}">${alert.severity || "Unknown"}</span>
            <span>🗂 ${escapeHtml(alert.threat_type || "Unknown")}</span>
            ${alert.published_at ? `<span>📅 ${escapeHtml(alert.published_at)}</span>` : ""}
        `;

        // Summary
        document.getElementById("modal-summary").textContent = alert.summary || "No summary available.";

        // CVEs
        if (alert.cves) {
            document.getElementById("modal-cves-section").style.display = "block";
            document.getElementById("modal-cves").innerHTML = renderCveTags(alert.cves);
        } else {
            document.getElementById("modal-cves-section").style.display = "none";
        }

        // Affected
        if (alert.affected) {
            document.getElementById("modal-affected-section").style.display = "block";
            document.getElementById("modal-affected").textContent = alert.affected;
        } else {
            document.getElementById("modal-affected-section").style.display = "none";
        }

        // STIX
        if (alert.stix_bundle) {
            currentStix = JSON.stringify(alert.stix_bundle, null, 2);
            document.getElementById("modal-stix").textContent = currentStix;
        } else {
            document.getElementById("modal-stix").textContent = "No STIX data available.";
        }

    } catch (e) {
        document.getElementById("modal-title").textContent   = "Error loading alert";
        document.getElementById("modal-summary").textContent = e.message;
    }
}

function closeModal(event) {
    if (event.target === document.getElementById("modal-overlay")) {
        closeModalDirect();
    }
}

function closeModalDirect() {
    document.getElementById("modal-overlay").classList.remove("active");
    currentStix = "";
}



// CRAWL

async function triggerCrawl() {
    showToast("🕷️ Crawl started! Fetching alerts...", false);

    const btn = document.querySelector(".btn-crawl");
    btn.disabled = true;
    btn.textContent = "⏳ Crawling... (0/10)";

    try {
        await fetch(`${API}/api/crawl`, { method: "POST" });

        let attempts     = 0;
        let lastTotal    = parseInt(document.getElementById("stat-total").textContent) || 0;
        let fetchedSoFar = 0;
        const maxWait    = 36; // 36 x 5s = 3 minutes max wait

        const interval = setInterval(async () => {
            attempts++;

            try {
                const statsRes  = await fetch(`${API}/api/stats`);
                const statsData = await statsRes.json();
                const newTotal  = statsData.total;

                // If new alerts came in since last check
                if (newTotal > lastTotal) {
                    const diff    = newTotal - lastTotal;
                    fetchedSoFar += diff;
                    lastTotal     = newTotal;

                    // Update button counter
                    btn.textContent = `⏳ Crawling... (${fetchedSoFar}/10)`;

                    // Show live toast for each new batch
                    showToast(`📥 ${fetchedSoFar}/10 alerts fetched...`, false);

                    // Refresh alerts list immediately
                    loadAlerts();
                    loadStats();
                }

                // Stop when 10 fetched or timeout
                if (fetchedSoFar >= 10 || attempts >= maxWait) {
                    clearInterval(interval);
                    btn.disabled    = false;
                    btn.textContent = "🕷️ Crawl CSK";

                    if (fetchedSoFar > 0) {
                        showToast(`✅ Done! ${fetchedSoFar} new alerts fetched.`, false);
                    } else {
                        showToast("✅ Crawl finished! No new alerts found.", false);
                    }

                    // Final refresh
                    loadAlerts();
                    loadStats();
                }

            } catch {
                // silently retry on network blip
            }

        }, 5000); // check every 5 seconds

    } catch {
        showToast("❌ Crawl failed. Is backend running?", true);
        btn.disabled    = false;
        btn.textContent = "🕷️ Crawl CSK";
    }
}



// COPY STIX

function copyStix() {
    if (!currentStix) return;
    navigator.clipboard.writeText(currentStix)
        .then(() => showToast("✅ STIX bundle copied to clipboard!"))
        .catch(() => showToast("❌ Copy failed", true));
}



// HELPERS

function severityClass(severity) {
    if (!severity) return "unknown";
    return severity.toLowerCase();
}

function renderCveTags(cves) {
    if (!cves) return "";
    return cves.split(",")
        .map(c => c.trim())
        .filter(c => c.startsWith("CVE-"))
        .map(c => `<span class="cve-tag">${escapeHtml(c)}</span>`)
        .join("");
}

function escapeHtml(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

function showToast(msg, isError = false) {
    const toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.className   = "toast show" + (isError ? " error" : "");
    setTimeout(() => { toast.className = "toast"; }, 4000);
}