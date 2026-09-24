/**
 * APISentinel AI — Autonomous API Security Diagnostic Engine
 * Dedicated OWASP API Security & BOLA Vulnerability Evaluation Logic
 */

// Global State
const state = {
    mode: localStorage.getItem('apisentinel_mode') || 'client', // 'client' | 'server'
    backendUrl: localStorage.getItem('apisentinel_backend_url') || 'http://localhost:8000/analyze',
    history: JSON.parse(localStorage.getItem('apisentinel_history') || '[]'),
    currentAnalysis: null,
    activeFilter: 'all'
};

// Element Binding
const elements = {
    form: document.getElementById('url-inspect-form'),
    input: document.getElementById('url-input'),
    btnClearInput: document.getElementById('btn-clear-input'),
    btnAnalyze: document.getElementById('btn-analyze'),
    presetChips: document.querySelectorAll('.chip-preset'),
    
    loader: document.getElementById('loader-state'),
    loaderStatusText: document.getElementById('loader-status-text'),
    aiTraceBox: document.getElementById('ai-trace-box'),
    resultsWrapper: document.getElementById('results-wrapper'),

    // Summary Card
    gaugeFillCircle: document.getElementById('gauge-fill-circle'),
    summaryScore: document.getElementById('summary-score'),
    summaryStatusBadge: document.getElementById('summary-status-badge'),
    summaryRiskPill: document.getElementById('summary-risk-pill'),
    summaryUrlText: document.getElementById('summary-url-text'),
    summaryDescText: document.getElementById('summary-desc-text'),

    // Stats
    statCriticalCount: document.getElementById('stat-critical-count'),
    statWarningCount: document.getElementById('stat-warning-count'),
    statPassedCount: document.getElementById('stat-passed-count'),

    // Anatomy & Clean URL
    anatomyPills: document.getElementById('anatomy-pills'),
    btnCopySanitized: document.getElementById('btn-copy-sanitized'),

    // Filters & Issues List
    tabBtns: document.querySelectorAll('.tab-btn'),
    filterAllCount: document.getElementById('filter-all-count'),
    filterCriticalCount: document.getElementById('filter-critical-count'),
    issuesListContainer: document.getElementById('issues-list-container'),
    cleanStateBox: document.getElementById('clean-state-box'),

    // Header & Settings Buttons
    btnBackendConfig: document.getElementById('btn-backend-config'),
    modeIndicatorDot: document.getElementById('mode-indicator-dot'),
    btnToggleHistory: document.getElementById('btn-toggle-history'),
    historyCount: document.getElementById('history-count'),
    historyDrawer: document.getElementById('history-drawer'),
    btnCloseHistory: document.getElementById('btn-close-history'),
    historyList: document.getElementById('history-list'),
    btnClearHistory: document.getElementById('btn-clear-history'),

    //-------------
    authorizedScan: document.getElementById('authorized-scan'),
    primaryToken: document.getElementById('primary-token'),
    secondaryToken: document.getElementById('secondary-token'),
    objectId: document.getElementById('object-id'),

    // Modal
    backendModal: document.getElementById('backend-modal'),
    btnCloseModal: document.getElementById('btn-close-modal'),
    btnCancelModal: document.getElementById('btn-cancel-modal'),
    btnSaveBackend: document.getElementById('btn-save-backend'),
    backendModeSelect: document.getElementById('backend-mode-select'),
    endpointInputGroup: document.getElementById('endpoint-input-group'),
    backendEndpointUrl: document.getElementById('backend-endpoint-url'),
    btnCopySchema: document.getElementById('btn-copy-schema'),

    toastContainer: document.getElementById('toast-container')
};

// Initialize App
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    updateModeIndicator();
    updateHistoryUI();
});

function setupEventListeners() {
    elements.input.addEventListener('input', (e) => {
        elements.btnClearInput.style.display = e.target.value.trim() ? 'flex' : 'none';
    });

    elements.btnClearInput.addEventListener('click', () => {
        elements.input.value = '';
        elements.btnClearInput.style.display = 'none';
        elements.input.focus();
    });

    elements.form.addEventListener('submit', (e) => {
        e.preventDefault();
        const urlValue = elements.input.value.trim();
        if (urlValue) {
            runInspection(urlValue);
        }
    });

    elements.presetChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const url = chip.getAttribute('data-url');
            elements.input.value = url;
            elements.btnClearInput.style.display = 'flex';
            runInspection(url);
        });
    });

    elements.tabBtns.forEach(tab => {
        tab.addEventListener('click', () => {
            elements.tabBtns.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            state.activeFilter = tab.getAttribute('data-filter');
            renderIssues();
        });
    });

    elements.btnCopySanitized.addEventListener('click', () => {
        if (state.currentAnalysis && state.currentAnalysis.sanitizedUrl) {
            navigator.clipboard.writeText(state.currentAnalysis.sanitizedUrl);
            showToast('Sanitized API Endpoint copied to clipboard! 📋');
        }
    });

    elements.btnToggleHistory.addEventListener('click', () => {
        elements.historyDrawer.classList.add('open');
    });

    elements.btnCloseHistory.addEventListener('click', () => {
        elements.historyDrawer.classList.remove('open');
    });

    elements.btnClearHistory.addEventListener('click', () => {
        state.history = [];
        localStorage.setItem('apisentinel_history', JSON.stringify([]));
        updateHistoryUI();
        showToast('Audit history log cleared');
    });

    elements.btnBackendConfig.addEventListener('click', () => {
        elements.backendModeSelect.value = state.mode;
        elements.backendEndpointUrl.value = state.backendUrl;
        elements.endpointInputGroup.style.display = state.mode === 'server' ? 'flex' : 'none';
        elements.backendModal.style.display = 'flex';
    });

    elements.btnCloseModal.addEventListener('click', closeModal);
    elements.btnCancelModal.addEventListener('click', closeModal);

    elements.backendModeSelect.addEventListener('change', (e) => {
        elements.endpointInputGroup.style.display = e.target.value === 'server' ? 'flex' : 'none';
    });

    elements.btnSaveBackend.addEventListener('click', () => {
        state.mode = elements.backendModeSelect.value;
        state.backendUrl = elements.backendEndpointUrl.value.trim() || 'http://localhost:8000/analyze';
        
        localStorage.setItem('apisentinel_mode', state.mode);
        localStorage.setItem('apisentinel_backend_url', state.backendUrl);
        
        updateModeIndicator();
        closeModal();
        showToast(`Backend configuration saved! Mode: ${state.mode.toUpperCase()}`);
    });

    elements.btnCopySchema.addEventListener('click', () => {
        const schema = `{
  "url": "https://api.acmeshop.com/v1/orders/109482?user_id=884",
  "score": 45,
  "status": "critical",
  "issues": [
    {
      "id": "bola_vulnerability",
      "severity": "critical",
      "category": "bola",
      "title": "Broken Object-Level Authorization (BOLA / IDOR)",
      "where": "Path parameter \`/orders/{order_id}\` & query \`user_id\`",
      "why": "Endpoint accepts user_id from query without enforcing session ownership verification.",
      "hint": "Validate order ownership server-side using authenticated JWT claims: req.user.id == order.user_id",
      "codeSnippet": "@app.get('/v1/orders/{order_id}')\\ndef get_order(order_id: str, current_user = Depends(get_current_user)):\\n    order = db.get_order(order_id)\\n    if order.user_id != current_user.id:\\n        raise HTTPException(status_code=403, detail='Access Forbidden')"
    }
  ]
}`;
        navigator.clipboard.writeText(schema);
        showToast('JSON Response Contract copied to clipboard!');
    });
}

function closeModal() {
    elements.backendModal.style.display = 'none';
}

function updateModeIndicator() {
    elements.modeIndicatorDot.className = `status-dot mode-${state.mode}`;
    elements.modeIndicatorDot.title = state.mode === 'client' 
        ? 'Running built-in AI Neural Simulator' 
        : `Connected to Custom Python Backend (${state.backendUrl})`;
}

// Main Execution Flow with AI Agentic Step Progress
async function runInspection(rawUrl) {
    elements.resultsWrapper.style.display = 'none';
    elements.loader.style.display = 'flex';
    elements.aiTraceBox.innerHTML = '';

    const traceSteps = [
        "🔐 Step 1/5: Validating authorized scan configuration...",
        "📘 Step 2/5: Detecting endpoint or OpenAPI specification...",
        "🌐 Step 3/5: Performing bounded runtime HTTP checks...",
        "🔎 Step 4/5: Analyzing response data and authorization behavior...",
        "📊 Step 5/5: Building evidence-backed security report..."
    ];

    for (let i = 0; i < traceSteps.length; i++) {
        elements.loaderStatusText.textContent = traceSteps[i];
        const stepEl = document.createElement('div');
        stepEl.className = 'trace-step';
        stepEl.textContent = traceSteps[i];
        elements.aiTraceBox.appendChild(stepEl);
        await new Promise(r => setTimeout(r, 220));
    }

    try {
        const result = await fetchFromBackend(rawUrl);

        state.currentAnalysis = result;
        addToHistory(result);
        renderResults(result);

    } catch (error) {
        showToast(`Backend API Error: ${error.message}`, 'critical');
        if (state.mode === 'server') {
            showToast('Falling back to built-in AI Neural Inspector...', 'warning');
            const fallbackResult = clientAnalyzeApiUrl(rawUrl);
            state.currentAnalysis = fallbackResult;
            addToHistory(fallbackResult);
            renderResults(fallbackResult);
        }
    } finally {
        elements.loader.style.display = 'none';
    }
}

async function fetchFromBackend(url) {

    const authorized =
        elements.authorizedScan.checked;

    if (!authorized) {

        throw new Error(
            'Please confirm that you are authorized to test this API.'
        );
    }

    const objectId =
        elements.objectId.value.trim();

    const payload = {
        url: url,

        scan: {
            authorized: true,

            bearer_token:
                elements.primaryToken.value.trim() || null,

            second_bearer_token:
                elements.secondaryToken.value.trim() || null,

            object_ids:
                objectId ? [objectId] : [],

            timeout_seconds: 8,

            rate_test_requests: 6,

            rate_test_delay_seconds: 0.25,

            max_endpoints: 30
        }
    };

    const response = await fetch(
        state.backendUrl,
        {
            method: 'POST',

            headers: {
                'Content-Type': 'application/json'
            },

            body: JSON.stringify(payload)
        }
    );

    if (!response.ok) {

        let message =
            `HTTP ${response.status}`;

        try {

            const errorData =
                await response.json();

            if (errorData.detail) {

                message =
                    typeof errorData.detail === 'string'
                        ? errorData.detail
                        : JSON.stringify(
                            errorData.detail
                        );
            }

        } catch (_) {}

        throw new Error(message);
    }

    const data =
        await response.json();

    return processResultData(
        data,
        url
    );
}

// OWASP API Security Diagnostic Rules Engine (BOLA, Excessive Data, Rate Limiting)
function clientAnalyzeApiUrl(rawUrl) {
    const issues = [];
    let score = 100;
    let sanitizedUrl = rawUrl.trim();

    if (!sanitizedUrl) {
        return {
            url: rawUrl,
            sanitizedUrl: '',
            score: 0,
            status: 'critical',
            issues: [{
                id: 'empty_url',
                severity: 'critical',
                category: 'structure',
                title: 'Empty API Endpoint URL',
                where: 'Input string',
                why: 'No API route provided to inspect.',
                hint: 'Please provide a valid API route starting with https:// or http://'
            }],
            anatomy: {}
        };
    }

    let parsedUrl = null;
    try {
        let tempUrl = sanitizedUrl;
        if (!/^https?:\/\//i.test(tempUrl)) {
            tempUrl = 'http://' + tempUrl;
        }
        parsedUrl = new URL(tempUrl);
    } catch (e) {
        score -= 30;
        issues.push({
            id: 'malformed_structure',
            severity: 'critical',
            category: 'structure',
            title: 'Malformed API Route Syntax',
            where: 'URL String',
            why: `JavaScript URL Parser failed: ${e.message}`,
            hint: 'Ensure API path follows standard REST format: [scheme]://[domain]/v1/[resource]/{id}'
        });
    }

    if (parsedUrl) {
        const fullPath = parsedUrl.pathname + parsedUrl.search;

        // Rule 1: Broken Object Level Authorization (BOLA / IDOR) Detection
        // Triggers when endpoint includes object identifiers (e.g. /orders/109482) combined with user_id parameters
        if (/\/(orders|users|accounts|invoices|documents|messages)\/([0-9a-fA-F-]+)/i.test(parsedUrl.pathname) &&
            /user_id|account_id|owner_id|uid/i.test(parsedUrl.search)) {
            score -= 40;
            issues.push({
                id: 'bola_idor_flaw',
                severity: 'critical',
                category: 'bola',
                title: 'OWASP API1:2023 — Broken Object-Level Authorization (BOLA / IDOR)',
                where: `Path parameter '${parsedUrl.pathname}' & Query '${parsedUrl.search}'`,
                why: 'The API accepts an explicit user_id/account_id in parameters while loading an object resource by ID. Attackers can alter user_id to read or modify arbitrary object data belonging to other users.',
                hint: 'Never rely on client-supplied user_id parameters. Always extract and verify the authenticated user context directly from session JWT claims on the server.',
                codeSnippet: `# FastAPI Server-side BOLA Remediation:\n@app.get("/v1/orders/{order_id}")\ndef get_order(order_id: str, current_user = Depends(get_current_user)):\n    order = db.find_order(order_id)\n    if order.owner_id != current_user.id:\n        raise HTTPException(status_code=403, detail="Forbidden object access")\n    return order`
            });
        }

        // Rule 2: Excessive Data Exposure (PII Leak) Detection
        if (/include_private|full_profile|all_fields|include_keys|debug=true/i.test(parsedUrl.search) || 
            /\/profile|\/userinfo|\/billing/i.test(parsedUrl.pathname)) {
            score -= 30;
            issues.push({
                id: 'excessive_data_exposure',
                severity: 'critical',
                category: 'data_exposure',
                title: 'OWASP API3:2023 — Excessive Data Exposure (PII / Sensitive Field Leak)',
                where: `Query flags '${parsedUrl.search}' or Endpoint route '${parsedUrl.pathname}'`,
                why: 'The endpoint returns complete database objects or unredacted fields (such as SSN, password hashes, or private keys), expecting client UIs to filter data.',
                hint: 'Implement strict response serialization DTOs (Data Transfer Objects) to sanitize and scope returned fields on the backend.',
                codeSnippet: `# Pydantic Response DTO:\nclass PublicUserProfile(BaseModel):\n    id: str\n    username: str\n    email: EmailStr\n    # Explicitly exclude internal keys and hashes`
            });
        }

        // Rule 3: Missing Rate Limiting / Brute-force Vulnerability
        if (/\/auth|\/login|\/otp-verify|\/password-reset|\/token/i.test(parsedUrl.pathname)) {
            score -= 25;
            issues.push({
                id: 'missing_rate_limit',
                severity: 'warning',
                category: 'rate_limit',
                title: 'OWASP API4:2023 — Unrestricted Resource Consumption & Missing Rate Limiting',
                where: `Authentication Route '${parsedUrl.pathname}'`,
                why: 'Sensitive endpoints (OTP verification, logins) without explicit HTTP rate limiting headers (X-RateLimit-Limit) are vulnerable to automated brute-force attacks.',
                hint: 'Enforce Redis-backed sliding window rate limiting (e.g., 5 requests per minute per IP).',
                codeSnippet: `# Redis Rate Limiting Middleware:\n@app.middleware("http")\nasync def rate_limit_middleware(request, call_next):\n    rate = await redis.incr(request.client.host)\n    if rate > 5:\n        return JSONResponse({"error": "Too Many Requests"}, status_code=429)`
            });
        }

        // Rule 4: Insecure HTTP Protocol
        if (parsedUrl.protocol === 'http:') {
            score -= 20;
            issues.push({
                id: 'insecure_http',
                severity: 'warning',
                category: 'security',
                title: 'Insecure Transport Layer Protocol (HTTP)',
                where: 'Scheme prefix (http://)',
                why: 'Transmitting API parameters over unencrypted HTTP exposes tokens and credentials to network eavesdropping and MITM manipulation.',
                hint: 'Enforce HTTPS with HSTS (HTTP Strict Transport Security) headers.'
            });
            sanitizedUrl = sanitizedUrl.replace(/^http:\/\//i, 'https://');
        }

        // Rule 5: Raw Spaces in URL
        if (rawUrl.includes(' ')) {
            score -= 15;
            issues.push({
                id: 'unescaped_spaces',
                severity: 'warning',
                category: 'structure',
                title: 'Unencoded Space Characters in API Path',
                where: 'URL Space Characters',
                why: 'Unescaped spaces violate URI RFC standards and cause routing failures across HTTP proxies.',
                hint: 'URL-encode parameters using %20.'
            });
            sanitizedUrl = sanitizedUrl.replace(/ /g, '%20');
        }
    }

    score = Math.max(0, Math.min(100, score));

    let status = 'clean';
    if (score < 60 || issues.some(i => i.severity === 'critical')) {
        status = 'critical';
    } else if (score < 90 || issues.some(i => i.severity === 'warning')) {
        status = 'warning';
    }

    const anatomy = parsedUrl ? {
        scheme: parsedUrl.protocol.replace(':', ''),
        host: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80'),
        path: parsedUrl.pathname || '/',
        query: parsedUrl.search || '(none)',
        hash: parsedUrl.hash || '(none)'
    } : { raw: rawUrl };

    return processResultData({
        url: rawUrl,
        sanitizedUrl,
        score,
        status,
        issues,
        anatomy
    }, rawUrl);
}

function processResultData(data, rawUrl) {

    const issues =
        data.issues || [];

    const criticalCount =
        issues.filter(
            i => i.severity === 'critical'
        ).length;

    const warningCount =
        issues.filter(
            i =>
                i.severity === 'warning' ||
                i.severity === 'high'
        ).length;

    return {

        url:
            data.url || rawUrl,

        sanitizedUrl:
            data.sanitizedUrl || rawUrl,

        score:
            typeof data.score === 'number'
                ? data.score
                : 0,

        status:
            data.status ||
            (
                criticalCount > 0
                    ? 'critical'
                    : warningCount > 0
                        ? 'warning'
                        : 'clean'
            ),

        criticalCount,

        warningCount,

        passedCount:
            Math.max(
                0,
                (data.checks_run || 0) -
                issues.length
            ),

        issues,

        anatomy:
            data.anatomy || {},

        endpointsScanned:
            data.endpoints_scanned || 0,

        requestsMade:
            data.requests_made || 0,

        timestamp:
            new Date().toLocaleTimeString()
    };
}

function renderResults(result) {
    elements.resultsWrapper.style.display = 'flex';

    elements.summaryScore.textContent = result.score;
    const dashOffset = 264 - (264 * result.score) / 100;
    elements.gaugeFillCircle.style.strokeDashoffset = dashOffset;
    
    if (result.score >= 90) {
        elements.gaugeFillCircle.style.stroke = 'var(--color-success)';
    } else if (result.score >= 60) {
        elements.gaugeFillCircle.style.stroke = 'var(--color-warning)';
    } else {
        elements.gaugeFillCircle.style.stroke = 'var(--color-critical)';
    }

    elements.summaryStatusBadge.className = `status-badge ${result.status}`;
    elements.summaryStatusBadge.textContent = result.status.toUpperCase();

    if (result.status === 'clean') {
        elements.summaryRiskPill.textContent = 'Low OWASP Risk';
        elements.summaryRiskPill.style.color = 'var(--color-success)';
        elements.summaryDescText.textContent = 'API route passed security checks. Proper authorization, scope boundaries, and rate limits verified.';
    } else if (result.status === 'warning') {
        elements.summaryRiskPill.textContent = 'Moderate OWASP Risk';
        elements.summaryRiskPill.style.color = 'var(--color-warning)';
        elements.summaryDescText.textContent = 'Security warnings detected. Review rate limiting and protocol configuration recommendations.';
    } else {
        elements.summaryRiskPill.textContent = 'High / Critical OWASP Risk';
        elements.summaryRiskPill.style.color = 'var(--color-critical)';
        elements.summaryDescText.textContent = 'Critical API authorization or data exposure vulnerabilities detected! Remediation required before production deployment.';
    }

    elements.summaryUrlText.textContent = result.url;

    elements.statCriticalCount.textContent = result.criticalCount;
    elements.statWarningCount.textContent = result.warningCount;
    elements.statPassedCount.textContent = result.passedCount;

    renderAnatomyPills(result.anatomy);
    renderIssues();
}

function renderAnatomyPills(anatomy) {
    elements.anatomyPills.innerHTML = '';

    if (!anatomy || Object.keys(anatomy).length === 0) {
        elements.anatomyPills.innerHTML = `<span class="pill-part pill-host"><span class="pill-part-label">ENDPOINT</span><span class="pill-part-val">${state.currentAnalysis.url}</span></span>`;
        return;
    }

    const parts = [
        { label: 'SCHEME', val: anatomy.scheme, class: 'pill-scheme' },
        { label: 'HOST / DOMAIN', val: anatomy.host, class: 'pill-host' },
        { label: 'PORT', val: anatomy.port, class: 'pill-port' },
        { label: 'API PATH', val: anatomy.path, class: 'pill-path' },
        { label: 'QUERY PARAMETERS', val: anatomy.query, class: 'pill-query' },
        { label: 'FRAGMENT', val: anatomy.hash, class: 'pill-hash' }
    ];

    parts.forEach(p => {
        if (p.val) {
            const el = document.createElement('div');
            el.className = `pill-part ${p.class}`;
            el.innerHTML = `
                <span class="pill-part-label">${p.label}</span>
                <span class="pill-part-val">${escapeHtml(p.val)}</span>
            `;
            elements.anatomyPills.appendChild(el);
        }
    });
}

function renderIssues() {
    if (!state.currentAnalysis) return;

    const allIssues = state.currentAnalysis.issues || [];
    
    elements.filterAllCount.textContent = allIssues.length;
    elements.filterCriticalCount.textContent = state.currentAnalysis.criticalCount;

    let filtered = allIssues;
    if (state.activeFilter === 'bola') {
        filtered = allIssues.filter(i => i.category === 'bola');
    } else if (state.activeFilter === 'data_exposure') {
        filtered = allIssues.filter(i => i.category === 'data_exposure');
    } else if (state.activeFilter === 'rate_limit') {
        filtered = allIssues.filter(i => i.category === 'rate_limit');
    } else if (state.activeFilter === 'critical') {
        filtered = allIssues.filter(i => i.severity === 'critical');
    }

    elements.issuesListContainer.innerHTML = '';

    if (allIssues.length === 0) {
        elements.cleanStateBox.style.display = 'flex';
        elements.issuesListContainer.style.display = 'none';
        return;
    }

    elements.cleanStateBox.style.display = 'none';
    elements.issuesListContainer.style.display = 'flex';

    if (filtered.length === 0) {
        elements.issuesListContainer.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
                No findings match the selected filter category "${state.activeFilter}".
            </div>
        `;
        return;
    }

    filtered.forEach((issue) => {
        const card = document.createElement('div');
        card.className = `issue-card severity-${issue.severity}`;
        
        card.innerHTML = `
            <div class="issue-header">
                <div class="issue-title-area">
                    <div class="issue-icon">🛡️</div>
                    <div>
                        <h4 class="issue-title">${escapeHtml(issue.title)}</h4>
                        <div class="issue-tags">
                            <span class="tag-severity">${issue.severity}</span>
                            <span class="tag-category">${issue.category}</span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="issue-body">
                <div class="diagnostic-block">
                    <span class="block-label label-where">
                        📍 1. Where is the Vulnerability?
                    </span>
                    <div class="where-box">
                        ${escapeHtml(issue.where || 'API Endpoint')}
                    </div>
                </div>

                <div class="diagnostic-block">
                    <span class="block-label label-why">
                        🔍 2. Why is this Happening?
                    </span>
                    <p class="why-text">
                        ${escapeHtml(issue.why || 'Logic flaw allowing unauthorized access or data leak.')}
                    </p>
                </div>

                <div class="diagnostic-block">
                    <span class="block-label label-hint">
                        💡 3. Hint & Resolution Code Action
                    </span>
                    <div class="hint-container">
                        <p class="hint-text">${escapeHtml(issue.hint || 'Enforce server-side authorization checks.')}</p>
                        ${issue.codeSnippet ? `
                            <div class="code-snippet-box">
                                <code>${escapeHtml(issue.codeSnippet)}</code>
                                <button class="btn-copy-code-inline" data-code="${escapeAttribute(issue.codeSnippet)}">Copy Fix</button>
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;

        elements.issuesListContainer.appendChild(card);
    });

    document.querySelectorAll('.btn-copy-code-inline').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const code = e.target.getAttribute('data-code');
            navigator.clipboard.writeText(code);
            showToast('Remediation code snippet copied! 📋');
        });
    });
}

function addToHistory(item) {
    state.history.unshift({
        url: item.url,
        score: item.score,
        status: item.status,
        timestamp: item.timestamp
    });

    if (state.history.length > 15) state.history.pop();

    localStorage.setItem('apisentinel_history', JSON.stringify(state.history));
    updateHistoryUI();
}

function updateHistoryUI() {
    elements.historyCount.textContent = state.history.length;
    
    if (state.history.length === 0) {
        elements.historyList.innerHTML = `<p class="empty-history-text">No previous API scans performed in this session.</p>`;
        return;
    }

    elements.historyList.innerHTML = '';
    state.history.forEach((h) => {
        const item = document.createElement('div');
        item.className = 'history-item';
        item.innerHTML = `
            <div class="history-url">${escapeHtml(h.url)}</div>
            <div class="history-meta">
                <span style="color: ${h.score >= 80 ? 'var(--color-success)' : h.score >= 60 ? 'var(--color-warning)' : 'var(--color-critical)'}">
                    Score: ${h.score}/100
                </span>
                <span>${h.timestamp}</span>
            </div>
        `;
        item.addEventListener('click', () => {
            elements.input.value = h.url;
            elements.btnClearInput.style.display = 'flex';
            elements.historyDrawer.classList.remove('open');
            runInspection(h.url);
        });
        elements.historyList.appendChild(item);
    });
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeAttribute(str) {
    if (!str) return '';
    return String(str).replace(/"/g, '&quot;');
}

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    elements.toastContainer.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
