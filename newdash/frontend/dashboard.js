// SPFBL Dashboard JavaScript
// API Configuration
const API_URL = "/api";
const REFRESH_INTERVAL = 60000; // 60 seconds para reduzir carga
const THEME_KEY = 'dashboardTheme';
const MOBILE_BREAKPOINT = 768;
const SUN_ICON = `
<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
  <circle cx="12" cy="12" r="4"></circle>
  <line x1="12" y1="2" x2="12" y2="5"></line>
  <line x1="12" y1="19" x2="12" y2="22"></line>
  <line x1="4.22" y1="4.22" x2="6.34" y2="6.34"></line>
  <line x1="17.66" y1="17.66" x2="19.78" y2="19.78"></line>
  <line x1="2" y1="12" x2="5" y2="12"></line>
  <line x1="19" y1="12" x2="22" y2="12"></line>
  <line x1="4.22" y1="19.78" x2="6.34" y2="17.66"></line>
  <line x1="17.66" y1="6.34" x2="19.78" y2="4.22"></line>
</svg>`;
const MOON_ICON = `
<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
  <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"></path>
</svg>`;

// Global state
let charts = {};
let queries = [];
let refreshTimer;
let selectedQueryId = null;

const HTML_ESCAPE_MAP = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
};

function escapeHtml(value) {
    if (value === null || value === undefined) {
        return '';
    }
    return value.toString().replace(/[&<>"']/g, char => HTML_ESCAPE_MAP[char]);
}

function isMobileViewport() {
    return window.innerWidth <= MOBILE_BREAKPOINT;
}

function safeString(value) {
    if (value === null || value === undefined) {
        return '';
    }
    return String(value);
}

function generateRowId(index) {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return `query-${index}-${crypto.randomUUID()}`;
    }
    return `query-${index}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeQuery(rawQuery, index) {
    const normalized = {
        ...rawQuery,
        timestamp: rawQuery?.timestamp ? safeString(rawQuery.timestamp).trim() : null,
        ip: safeString(rawQuery?.ip),
        sender: safeString(rawQuery?.sender),
        recipient: safeString(rawQuery?.recipient),
        helo: safeString(rawQuery?.helo),
        result: safeString(rawQuery?.result || 'N/A').toUpperCase(),
        fraud: rawQuery?.fraud === true,
        reason: safeString(rawQuery?.reason || ''),
        reporter: safeString(rawQuery?.reporter || ''),
        _rowId: rawQuery?._rowId || generateRowId(index)
    };
    return normalized;
}

function normalizeQueries(rawQueries) {
    return (rawQueries || []).map((query, index) => normalizeQuery(query, index));
}

// Parse timestamp safely with timezone support
function parseTimestampSafely(timestamp) {
    if (!timestamp) return null;

    try {
        // Converte +0000 para +00:00 se necessário (suporte para timezone)
        const normalized = String(timestamp).replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
        const date = new Date(normalized);

        if (isNaN(date.getTime())) {
            return null;
        }
        return date;
    } catch (error) {
        return null;
    }
}

function formatRelativeTime(timestamp) {
    if (!timestamp) {
        return '';
    }
    try {
        const date = parseTimestampSafely(timestamp);

        if (!date || isNaN(date.getTime())) {
            return '';
        }

        const diffMs = Date.now() - date.getTime();
        if (diffMs < 0) {
            return '';
        }
        const minutes = Math.floor(diffMs / 60000);
        if (minutes < 1) {
            return 'há instantes';
        }
        if (minutes < 60) {
            return `há ${minutes}m`;
        }
        const hours = Math.floor(minutes / 60);
        if (hours < 24) {
            const restMinutes = minutes % 60;
            return restMinutes > 0 ? `há ${hours}h ${restMinutes}m` : `há ${hours}h`;
        }
        const days = Math.floor(hours / 24);
        return `há ${days}d`;
    } catch (error) {
        return '';
    }
}

// Sidebar Toggle
function setSidebarLogoSize(isCompact) {
    const logo = document.querySelector('.logo img');
    if (!logo) {
        return;
    }
    if (isCompact) {
        logo.style.maxWidth = '40px';
        logo.style.maxHeight = '40px';
    } else {
        logo.style.maxWidth = '200px';
        logo.style.maxHeight = '50px';
    }
}

function toggleSidebar() {
    if (isMobileViewport()) {
        return;
    }
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) {
        return;
    }
    const willCollapse = !sidebar.classList.contains('collapsed');
    sidebar.classList.toggle('collapsed');
    setSidebarLogoSize(willCollapse);
    localStorage.setItem('sidebarCollapsed', willCollapse ? 'true' : 'false');
}

function applyDesktopSidebarState() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) {
        return;
    }
    const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
    sidebar.classList.toggle('collapsed', isCollapsed);
    setSidebarLogoSize(isCollapsed);
}

function applySidebarLayout() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) {
        return;
    }

    if (isMobileViewport()) {
        sidebar.classList.remove('collapsed');
        sidebar.classList.add('mobile-top');
        setSidebarLogoSize(true);
        return;
    }

    sidebar.classList.remove('mobile-top');
    applyDesktopSidebarState();
}

function initializeSidebar() {
    applySidebarLayout();
    window.addEventListener('resize', applySidebarLayout);
}

// Theme Toggle
function applyTheme(theme) {
    const body = document.body;
    if (theme === 'dark') {
        body.classList.add('theme-dark');
    } else {
        body.classList.remove('theme-dark');
    }
    renderThemeIcon();
    localStorage.setItem(THEME_KEY, theme);
}

function restoreTheme() {
    const stored = localStorage.getItem(THEME_KEY) || 'light';
    applyTheme(stored);
}

function toggleTheme() {
    const isDark = document.body.classList.contains('theme-dark');
    applyTheme(isDark ? 'light' : 'dark');
}

function renderThemeIcon() {
    const icon = document.getElementById('theme-toggle-icon');
    if (!icon) return;
    const isDark = document.body.classList.contains('theme-dark');
    icon.innerHTML = isDark ? SUN_ICON : MOON_ICON;
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeSidebar();
    restoreTheme();
    renderThemeIcon();
    initCharts();
    loadDashboardData();
    startAutoRefresh();
    setupFilters();
    setupServerSelection();
});

// Navigation
function showSection(sectionName, navEvent) {
    if (navEvent && typeof navEvent.preventDefault === 'function') {
        navEvent.preventDefault();
    }

    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => item.classList.remove('active'));

    const clickedNav = navEvent?.currentTarget || navEvent?.target?.closest('.nav-item');
    if (clickedNav) {
        clickedNav.classList.add('active');
    } else {
        const fallbackNav = document.querySelector(`.nav-item[href="#${sectionName}"]`);
        fallbackNav?.classList.add('active');
    }

    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });

    const targetSection = document.getElementById(`section-${sectionName}`);
    if (!targetSection) {
        if (sectionName === 'settings') {
            window.location.href = '/settings';
            return;
        }
        console.warn(`Section not found: ${sectionName}`);
        return;
    }

    targetSection.classList.add('active');

    const titles = {
        dashboard: 'Dashboard',
        queries: 'Consultas Recentes',
        servers: 'Servidores Conectados',
        users: 'Usuários do Sistema',
        stats: 'Estatísticas Detalhadas',
        lists: 'Listas de Bloqueio e Whitelist',
        settings: 'Configurações',
        logs: 'Logs do SPFBL'
    };
    document.getElementById('page-title').textContent = titles[sectionName] || 'Dashboard';

    // Load section data
    if (sectionName === 'queries') {
        loadQueries();
    } else if (sectionName === 'servers') {
        loadServers();
    } else if (sectionName === 'users') {
        loadUsers();
    } else if (sectionName === 'stats') {
        loadDetailedStats();
    } else if (sectionName === 'lists') {
        loadLists();
    } else if (sectionName === 'logs') {
        loadLogs();
    }
}

// Initialize Charts
function initCharts() {
    // Hourly Chart
    const hourlyCtx = document.getElementById('hourly-chart').getContext('2d');
    charts.hourly = new Chart(hourlyCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Total',
                    data: [],
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    tension: 0.4
                },
                {
                    label: 'Bloqueados',
                    data: [],
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // Results Pie Chart
    const resultsCtx = document.getElementById('results-chart').getContext('2d');
    charts.results = new Chart(resultsCtx, {
        type: 'doughnut',
        data: {
            labels: ['PASS', 'BLOCKED', 'SOFTFAIL', 'FAIL'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#10b981',
                    '#ef4444',
                    '#f59e0b',
                    '#dc2626'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

// Load Dashboard Data
async function loadDashboardData() {
    try {
        // Load stats
        const statsResponse = await fetch(`${API_URL}/stats`);
        const stats = await statsResponse.json();

        updateStatsCards(stats);

        // Load hourly queries
        const hourlyResponse = await fetch(`${API_URL}/queries/today`);
        const hourlyData = await hourlyResponse.json();

        updateHourlyChart(hourlyData);
        updateResultsChart(stats);

        // Load recent activity
        const queriesResponse = await fetch(`${API_URL}/queries`);
        const queriesData = await queriesResponse.json();

        updateRecentActivity(queriesData.queries.slice(0, 10));

        // Load server memory
        const memoryResponse = await fetch(`${API_URL}/server/memory`);
        const memoryData = await memoryResponse.json();

        updateMemoryCard(memoryData);

        // Update uptime
        if (stats.uptime) {
            updateUptimeInfo(stats.uptime);
        }

        // Update last update time
        updateLastUpdateTime();

    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showError('Erro ao carregar dados do dashboard');
    }
}

// Update Stats Cards
function updateStatsCards(stats) {
    document.getElementById('total-queries').textContent = stats.total_queries || 0;
    document.getElementById('passed-queries').textContent = stats.passed || 0;
    document.getElementById('blocked-queries').textContent = stats.blocked || 0;
    document.getElementById('active-clients').textContent = stats.clients_connected || 0;

    // Calculate percentages
    const total = stats.total_queries || 1;
    const passedPercent = ((stats.passed / total) * 100).toFixed(1);
    const blockedPercent = ((stats.blocked / total) * 100).toFixed(1);

    document.getElementById('passed-percent').textContent = `${passedPercent}%`;
    document.getElementById('blocked-percent').textContent = `${blockedPercent}%`;
}

// Update Memory Card
function updateMemoryCard(memoryData) {
    if (memoryData.error) {
        document.getElementById('memory-percent').textContent = 'Erro';
        document.getElementById('memory-used').textContent = 'Não disponível';
        return;
    }

    const percent = memoryData.percent.toFixed(1);
    const usedGB = (memoryData.used / (1024 * 1024 * 1024)).toFixed(2);
    const totalGB = (memoryData.total / (1024 * 1024 * 1024)).toFixed(2);

    document.getElementById('memory-percent').textContent = `${percent}%`;
    document.getElementById('memory-used').textContent = `${usedGB}GB / ${totalGB}GB`;
}

// Update Uptime Info
function updateUptimeInfo(uptimeStr) {
    const uptimeElement = document.getElementById('uptime');
    if (!uptimeElement) return;

    // Parse uptime string
    try {
        // The uptime string from systemctl looks like: ActiveEnterTimestamp=Tue 2024-11-19 23:34:52 UTC
        // We'll just show a friendly uptime format
        const now = new Date();
        const uptime = parseUptimeString(uptimeStr);
        uptimeElement.textContent = uptime;
    } catch (error) {
        console.error('Error parsing uptime:', error);
        uptimeElement.textContent = 'Serviço ativo';
    }
}

function parseUptimeString(uptimeStr) {
    // Extract timestamp from systemctl output
    // Format: "ActiveEnterTimestamp=Tue 2024-11-19 23:34:52 UTC"
    const parts = uptimeStr.split('=');
    if (parts.length < 2) return 'Serviço ativo';

    try {
        const dateStr = parts[1].replace(' UTC', '').trim();
        const startTime = new Date(dateStr);
        const now = new Date();
        const diffMs = now - startTime;

        const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));

        if (days > 0) {
            return `${days}d ${hours}h ativo`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m ativo`;
        } else {
            return `${minutes}m ativo`;
        }
    } catch (error) {
        return 'Serviço ativo';
    }
}

// Update Hourly Chart
function updateHourlyChart(data) {
    charts.hourly.data.labels = data.hours.map(h => `${h}:00`);
    charts.hourly.data.datasets[0].data = data.total;
    charts.hourly.data.datasets[1].data = data.blocked;
    charts.hourly.update();
}

// Update Results Chart
function updateResultsChart(stats) {
    charts.results.data.datasets[0].data = [
        stats.passed || 0,
        stats.blocked || 0,
        stats.softfail || 0,
        stats.failed || 0
    ];
    charts.results.update();
}

// Update Recent Activity
function updateRecentActivity(queries) {
    const container = document.getElementById('recent-activity');

    if (!queries || queries.length === 0) {
        container.innerHTML = '<p class="loading">Nenhuma atividade recente</p>';
        return;
    }

    container.innerHTML = queries.map(q => {
        const resultClass = q.result.toLowerCase();
        const badgeClass = `badge-${resultClass}`;
        const activityClass = resultClass === 'blocked' || resultClass === 'banned' ? 'blocked' :
                             resultClass === 'pass' ? 'passed' : '';

        const time = formatTimestamp(q.timestamp);

        return `
            <div class="activity-item ${activityClass}">
                <div class="activity-time">${time}</div>
                <div class="activity-details">
                    <span class="activity-badge ${badgeClass}">${q.result}</span>
                    <strong>${q.ip}</strong> → <strong>${q.recipient}</strong>
                    <br>
                    <small>From: ${q.sender} (${q.helo})</small>
                </div>
            </div>
        `;
    }).join('');
}

// Load Queries
async function loadQueries() {
    try {
        const response = await fetch(`${API_URL}/queries`);
        const data = await response.json();
        queries = normalizeQueries(data.queries || []);
        selectedQueryId = null;
        updateSelectedQueryPanel();
        displayQueries(queries);
    } catch (error) {
        console.error('Error loading queries:', error);
        showError('Erro ao carregar consultas');
    }
}

// Display Queries
function displayQueries(queriesToDisplay) {
    const tbody = document.getElementById('queries-tbody');

    if (!queriesToDisplay || queriesToDisplay.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading">Nenhuma consulta encontrada</td></tr>';
        updateSelectedQueryPanel();
        return;
    }

    if (selectedQueryId && !queriesToDisplay.some(q => q._rowId === selectedQueryId)) {
        selectedQueryId = null;
    }

    const placeholder = '<span class="muted-text">--</span>';

    tbody.innerHTML = queriesToDisplay.map(q => {
        const rowId = q._rowId;
        const isSelected = rowId === selectedQueryId;
        const isFraud = q.fraud === true;
        const time = q.timestamp ? escapeHtml(formatTimestamp(q.timestamp)) : placeholder;
        const relativeTime = q.timestamp ? formatRelativeTime(q.timestamp) : '';
        const relativeHtml = relativeTime ? `<span class="query-meta-sub">${escapeHtml(relativeTime)}</span>` : '';
        const ip = q.ip ? escapeHtml(q.ip) : '';
        const ipDisplay = q.ip && q.ip.length > 18 ? `${escapeHtml(q.ip.slice(0, 18))}...` : ip;
        const helo = q.helo ? escapeHtml(q.helo) : '';
        const sender = q.sender ? escapeHtml(q.sender) : '';
        const recipient = q.recipient ? escapeHtml(q.recipient) : '';
        const result = q.result || 'N/A';
        const resultSlug = result.replace(/[^a-z0-9_-]/gi, '') || 'UNKNOWN';
        const fraudBadge = isFraud ? `<span class="fraud-indicator" title="Evento de Fraude: ${escapeHtml(q.reason || '')}">[FRAUDE]</span>` : '';
        const resultBadge = `<span class="result-badge result-chip result-${resultSlug}">${escapeHtml(result)}</span>`;

        return `
            <tr
                class="query-row ${isSelected ? 'selected' : ''} ${isFraud ? 'fraud-row' : ''}"
                data-row-id="${rowId}"
                data-is-fraud="${isFraud}"
                tabindex="0"
                role="button"
                aria-pressed="${isSelected ? 'true' : 'false'}"
                onclick="selectQuery('${rowId}')"
                onkeydown="handleQueryRowKey(event, '${rowId}')"
            >
                <td class="cell-time" data-label="Horário">
                    <div class="query-meta">
                        <span class="query-select-indicator" aria-hidden="true"></span>
                        <div class="query-meta-details">
                            <span class="query-time">${time}</span>
                            ${relativeHtml}
                        </div>
                    </div>
                </td>
                <td class="cell-result" data-label="Resultado">
                    ${fraudBadge} ${resultBadge}
                </td>
                <td class="cell-ip" data-label="IP Origem">
                    ${ip ? `<code class="mono mono-truncate" title="${ip}">${ipDisplay}</code>` : placeholder}
                </td>
                <td class="cell-sender" data-label="Remetente">
                    ${sender ? `<span class="address-pill subtle" title="${sender}">${sender}</span>` : placeholder}
                </td>
                <td class="cell-recipient" data-label="Destinatário">
                    ${recipient ? `<span class="address-pill subtle" title="${recipient}">${recipient}</span>` : placeholder}
                </td>
                <td class="cell-helo" data-label="HELO">
                    ${helo ? `<span class="text-truncate" title="${helo}">${helo}</span>` : placeholder}
                </td>
            </tr>
        `;
    }).join('');

    updateRowSelectionState();
    updateSelectedQueryPanel();
}

function handleQueryRowKey(event, rowId) {
    if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        selectQuery(rowId);
    }
}

function selectQuery(rowId) {
    if (!rowId) {
        return;
    }

    selectedQueryId = selectedQueryId === rowId ? null : rowId;
    updateRowSelectionState();
    updateSelectedQueryPanel();
}

function clearSelectedQuery() {
    selectedQueryId = null;
    updateRowSelectionState();
    updateSelectedQueryPanel();
}

function updateRowSelectionState() {
    const rows = document.querySelectorAll('#queries-tbody .query-row');
    rows.forEach(row => {
        const isSelected = row.dataset.rowId === selectedQueryId;
        row.classList.toggle('selected', isSelected);
        row.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
    });
}

function getSelectedQuery() {
    if (!selectedQueryId) {
        return null;
    }
    return queries.find(q => q._rowId === selectedQueryId) || null;
}

function updateSelectedQueryPanel() {
    const info = document.getElementById('selected-query-info');
    const panel = document.getElementById('selected-query-panel');
    const blockIpBtn = document.getElementById('action-block-ip');
    const whitelistBtn = document.getElementById('action-whitelist-ip');
    const blockSenderBtn = document.getElementById('action-block-sender');
    const clearBtn = document.getElementById('action-clear-selection');

    if (!info || !panel) {
        return;
    }

    const selected = getSelectedQuery();

    if (!selected) {
        info.innerHTML = '<span class="placeholder">Nenhuma consulta selecionada</span>';
        panel.classList.remove('has-selection');
        [blockIpBtn, whitelistBtn, blockSenderBtn, clearBtn].forEach(btn => {
            if (btn) {
                btn.disabled = true;
            }
        });
        return;
    }

    panel.classList.add('has-selection');
    const resultSlug = selected.result.replace(/[^a-z0-9_-]/gi, '') || 'UNKNOWN';
    const resultBadge = `<span class="result-badge result-chip result-${resultSlug} selected-query-result">${escapeHtml(selected.result)}</span>`;
    const formattedTime = selected.timestamp ? escapeHtml(formatTimestamp(selected.timestamp)) : '--:--';

    // Mostrar detalhes de fraude se aplicável
    let fraudInfo = '';
    if (selected.fraud === true) {
        fraudInfo = `
            <div class="fraud-details">
                <strong style="color: #dc2626;">🚨 Evento de Fraude</strong>
                ${selected.reason ? `<br><small>Motivo: ${escapeHtml(selected.reason)}</small>` : ''}
                ${selected.reporter ? `<br><small>Reportado por: ${escapeHtml(selected.reporter)}</small>` : ''}
            </div>
        `;
    }

    const summary = `
        ${resultBadge}
        <strong>${escapeHtml(selected.ip || '--')}</strong>
        <span class="selected-query-arrow">&rarr;</span>
        <strong>${escapeHtml(selected.recipient || '--')}</strong>
        <span class="selected-query-meta">${formattedTime}</span>
        ${fraudInfo}
    `;
    info.innerHTML = summary;

    [blockIpBtn, whitelistBtn, blockSenderBtn, clearBtn].forEach(btn => {
        if (btn) {
            btn.disabled = false;
        }
    });
}

function handleSelectedAction(action) {
    const selected = getSelectedQuery();
    if (!selected) {
        return;
    }

    if ((action === 'block-ip' || action === 'whitelist-ip') && !selected.ip) {
        alert('A consulta selecionada não possui IP válido.');
        return;
    }

    if (action === 'block-sender' && !selected.sender) {
        alert('A consulta selecionada não possui remetente válido.');
        return;
    }

    if (action === 'block-ip') {
        handleBlockIP(selected.ip);
    } else if (action === 'whitelist-ip') {
        handleWhitelistIP(selected.ip);
    } else if (action === 'block-sender') {
        handleBlockSender(selected.sender);
    }
}

// Load Servers
async function loadServers() {
    try {
        const response = await fetch(`${API_URL}/clients`);
        const data = await response.json();

        const tbody = document.getElementById('servers-tbody');
        const servers = data.clients || [];

        if (servers.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading">Nenhum servidor conectado</td></tr>';
            return;
        }

        tbody.innerHTML = servers.map(c => `
            <tr>
                <td class="select-column">
                    <input
                        type="checkbox"
                        class="server-select-checkbox"
                        data-ip="${c.ip}"
                    >
                </td>
                <td><strong>${c.hostname}</strong></td>
                <td><code>${c.ip}</code></td>
                <td>${c.type}</td>
                <td><span class="result-badge result-PASS">${c.status}</span></td>
                <td><small>${c.raw}</small></td>
            </tr>
        `).join('');

        updateRemoveServersButton();
    } catch (error) {
        console.error('Error loading servers:', error);
        showError('Erro ao carregar servidores');
    }
}

function setupServerSelection() {
    const tbody = document.getElementById('servers-tbody');
    if (!tbody) return;

    tbody.addEventListener('change', (event) => {
        if (event.target.classList.contains('server-select-checkbox')) {
            updateRemoveServersButton();
        }
    });
}

function getSelectedServerIps() {
    const checkboxes = document.querySelectorAll('#servers-tbody .server-select-checkbox:checked');
    return Array.from(checkboxes).map(cb => cb.dataset.ip);
}

function updateRemoveServersButton() {
    const btn = document.getElementById('btn-remove-servers');
    if (!btn) return;

    const hasSelection = getSelectedServerIps().length > 0;
    btn.disabled = !hasSelection;
}

async function handleRemoveServers() {
    const ips = getSelectedServerIps();
    if (ips.length === 0) {
        return;
    }

    const confirmMessage = ips.length === 1
        ? 'Tem certeza que deseja remover o servidor selecionado?'
        : `Tem certeza que deseja remover ${ips.length} servidores selecionados?`;

    if (!confirm(confirmMessage)) {
        return;
    }

    const btn = document.getElementById('btn-remove-servers');
    if (!btn) return;

    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Removendo...';

    try {
        const response = await fetch(`${API_URL}/clients/remove`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ ips })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(data.message || 'Servidores removidos com sucesso.');
            await loadServers();
        } else {
            const errorMsg = (data && (data.error || data.message)) || 'Erro ao remover servidores.';
            alert(errorMsg);
        }
    } catch (error) {
        console.error('Remove servers error:', error);
        alert('Erro ao conectar com o servidor. Tente novamente.');
    } finally {
        btn.textContent = originalText;
        btn.disabled = false;
        updateRemoveServersButton();
    }
}

// Load Detailed Stats
async function loadDetailedStats() {
    try {
        const response = await fetch(`${API_URL}/queries/today`);
        const data = await response.json();

        // Create detailed chart if not exists
        if (!charts.detailed) {
            const ctx = document.getElementById('detailed-stats-chart').getContext('2d');
            charts.detailed = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.hours.map(h => `${h}:00`),
                    datasets: [
                        {
                            label: 'PASS',
                            data: data.passed,
                            backgroundColor: '#10b981'
                        },
                        {
                            label: 'BLOCKED',
                            data: data.blocked,
                            backgroundColor: '#ef4444'
                        },
                        {
                            label: 'SOFTFAIL',
                            data: data.softfail,
                            backgroundColor: '#f59e0b'
                        },
                        {
                            label: 'FAIL',
                            data: data.failed,
                            backgroundColor: '#dc2626'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    },
                    scales: {
                        x: {
                            stacked: true
                        },
                        y: {
                            stacked: true,
                            beginAtZero: true
                        }
                    }
                }
            });
        } else {
            charts.detailed.data.labels = data.hours.map(h => `${h}:00`);
            charts.detailed.data.datasets[0].data = data.passed;
            charts.detailed.data.datasets[1].data = data.blocked;
            charts.detailed.data.datasets[2].data = data.softfail;
            charts.detailed.data.datasets[3].data = data.failed;
            charts.detailed.update();
        }

        // Update summary
        const total = data.total.reduce((a, b) => a + b, 0);
        const passed = data.passed.reduce((a, b) => a + b, 0);
        const blocked = data.blocked.reduce((a, b) => a + b, 0);
        const softfail = data.softfail.reduce((a, b) => a + b, 0);
        const failed = data.failed.reduce((a, b) => a + b, 0);

        document.getElementById('stats-summary-content').innerHTML = `
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-info">
                        <h3>Total de Consultas</h3>
                        <p class="stat-value">${total}</p>
                    </div>
                </div>
                <div class="stat-card success">
                    <div class="stat-info">
                        <h3>Aprovados (PASS)</h3>
                        <p class="stat-value">${passed}</p>
                        <span class="stat-percentage">${((passed/total)*100).toFixed(1)}%</span>
                    </div>
                </div>
                <div class="stat-card danger">
                    <div class="stat-info">
                        <h3>Bloqueados</h3>
                        <p class="stat-value">${blocked}</p>
                        <span class="stat-percentage">${((blocked/total)*100).toFixed(1)}%</span>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-info">
                        <h3>SOFTFAIL</h3>
                        <p class="stat-value">${softfail}</p>
                        <span class="stat-percentage">${((softfail/total)*100).toFixed(1)}%</span>
                    </div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading detailed stats:', error);
    }
}

// Setup Filters
function setupFilters() {
    const searchInput = document.getElementById('search-queries');
    const filterSelect = document.getElementById('filter-result');

    if (searchInput) {
        searchInput.addEventListener('input', applyFilters);
    }

    if (filterSelect) {
        filterSelect.addEventListener('change', applyFilters);
    }
}

// Apply Filters
function applyFilters() {
    const searchText = document.getElementById('search-queries').value.toLowerCase();
    const filterResult = document.getElementById('filter-result').value;

    let filtered = queries;

    // Apply text search
    if (searchText) {
        filtered = filtered.filter(q =>
            q.ip.toLowerCase().includes(searchText) ||
            q.sender.toLowerCase().includes(searchText) ||
            q.recipient.toLowerCase().includes(searchText) ||
            q.helo.toLowerCase().includes(searchText)
        );
    }

    // Apply result filter
    if (filterResult) {
        filtered = filtered.filter(q => q.result === filterResult);
    }

    displayQueries(filtered);
}

// Auto Refresh
function startAutoRefresh() {
    refreshTimer = setInterval(() => {
        const activeSection = document.querySelector('.content-section.active').id.replace('section-', '');

        if (activeSection === 'dashboard') {
            loadDashboardData();
        } else if (activeSection === 'queries') {
            loadQueries();
        } else if (activeSection === 'clients') {
            loadClients();
        } else if (activeSection === 'stats') {
            loadDetailedStats();
        }

        // Atualizar horário em todas as seções
        updateLastUpdateTime();
    }, REFRESH_INTERVAL);
}

function refreshData() {
    const activeSection = document.querySelector('.content-section.active').id.replace('section-', '');

    if (activeSection === 'dashboard') {
        loadDashboardData();
    } else if (activeSection === 'queries') {
        loadQueries();
    } else if (activeSection === 'servers') {
        loadServers();
    } else if (activeSection === 'stats') {
        loadDetailedStats();
    }

    // Atualizar horário ao fazer refresh manual
    updateLastUpdateTime();
}

// Utility Functions
function formatTimestamp(timestamp) {
    const date = parseTimestampSafely(timestamp);

    if (!date) {
        return '--:--:--';
    }

    return date.toLocaleString('pt-BR', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function updateLastUpdateTime() {
    const now = new Date();
    document.getElementById('last-update').textContent = now.toLocaleTimeString('pt-BR');
}

function showError(message) {
    console.error(message);
    // You can implement a toast notification here
}

// ===========================
// Modal Add Client Functions
// ===========================

function openAddClientModal() {
    const modal = document.getElementById('addClientModal');
    modal.classList.add('show');
    document.body.style.overflow = 'hidden';
    
    // Limpar formulário
    document.getElementById('addClientForm').reset();
    document.getElementById('modal-error-message').style.display = 'none';
    document.getElementById('modal-success-message').style.display = 'none';
}

function closeAddClientModal() {
    const modal = document.getElementById('addClientModal');
    modal.classList.remove('show');
    document.body.style.overflow = 'auto';
}

// Fechar modal ao clicar fora
window.onclick = function(event) {
    const modal = document.getElementById('addClientModal');
    if (event.target === modal) {
        closeAddClientModal();
    }
}

// Fechar modal com tecla ESC
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        closeAddClientModal();
    }
});

async function handleAddClient(event) {
    event.preventDefault();
    
    const form = event.target;
    const submitBtn = document.getElementById('btn-submit-client');
    const errorDiv = document.getElementById('modal-error-message');
    const successDiv = document.getElementById('modal-success-message');
    
    // Limpar mensagens anteriores
    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';
    
    // Obter dados do formulário
    const formData = {
        ip: form.ip.value.trim(),
        domain: form.domain.value.trim(),
        option: form.option.value,
        email: form.email.value.trim()
    };
    
    // Validação adicional de IP
    const ipParts = formData.ip.split('/')[0].split('.');
    if (ipParts.length !== 4) {
        showModalError('IP inválido. Formato correto: x.x.x.x ou x.x.x.x/xx');
        return;
    }
    
    for (let part of ipParts) {
        const num = parseInt(part);
        if (isNaN(num) || num < 0 || num > 255) {
            showModalError('IP inválido. Cada octeto deve estar entre 0 e 255');
            return;
        }
    }
    
    // Validar CIDR se presente
    if (formData.ip.includes('/')) {
        const cidr = parseInt(formData.ip.split('/')[1]);
        if (isNaN(cidr) || cidr < 0 || cidr > 32) {
            showModalError('CIDR inválido. Deve estar entre 0 e 32');
            return;
        }
    }
    
    // Desabilitar botão e mostrar loading
    submitBtn.disabled = true;
    submitBtn.classList.add('loading');
    submitBtn.textContent = '';
    
    try {
        const response = await fetch(`${API_URL}/clients/add`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            // Sucesso
            showModalSuccess(data.message || 'Cliente adicionado com sucesso!');
            
            // Limpar formulário
            form.reset();
            
            // Recarregar lista de clientes após 1.5 segundos
            setTimeout(() => {
                loadClients();
                closeAddClientModal();
            }, 1500);
            
        } else {
            // Erro retornado pela API
            showModalError(data.error || 'Erro ao adicionar cliente');
        }
        
    } catch (error) {
        showModalError('Erro ao conectar com o servidor. Tente novamente.');
        console.error('Add client error:', error);
    } finally {
        // Reabilitar botão
        submitBtn.disabled = false;
        submitBtn.classList.remove('loading');
        submitBtn.textContent = 'Adicionar Cliente';
    }
}

function showModalError(message) {
    const errorDiv = document.getElementById('modal-error-message');
    const successDiv = document.getElementById('modal-success-message');
    
    successDiv.style.display = 'none';
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    
    // Scroll para a mensagem
    errorDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showModalSuccess(message) {
    const errorDiv = document.getElementById('modal-error-message');
    const successDiv = document.getElementById('modal-success-message');
    
    errorDiv.style.display = 'none';
    successDiv.textContent = message;
    successDiv.style.display = 'block';
    
    // Scroll para a mensagem
    successDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

console.log('Add Client Modal: initialized');

// ===========================
// Block and Whitelist Functions
// ===========================

async function handleBlockIP(ip) {
    if (!confirm(`Tem certeza que deseja BLOQUEAR o IP ${ip}?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/block/add`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ token: ip })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(`✅ ${data.message}`);
            loadQueries(); // Recarregar consultas
        } else {
            alert(`❌ ${data.error || 'Erro ao bloquear IP'}`);
        }
    } catch (error) {
        console.error('Block IP error:', error);
        alert('❌ Erro ao conectar com o servidor');
    }
}

async function handleWhitelistIP(ip) {
    if (!confirm(`Tem certeza que deseja adicionar o IP ${ip} à WHITELIST?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/white/add`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ token: ip })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(`✅ ${data.message}`);
            loadQueries(); // Recarregar consultas
        } else {
            alert(`❌ ${data.error || 'Erro ao adicionar à whitelist'}`);
        }
    } catch (error) {
        console.error('Whitelist IP error:', error);
        alert('❌ Erro ao conectar com o servidor');
    }
}

async function handleBlockSender(sender) {
    if (!confirm(`Tem certeza que deseja BLOQUEAR o remetente ${sender}?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/block/add`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ token: sender })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(`✅ ${data.message}`);
            loadQueries(); // Recarregar consultas
        } else {
            alert(`❌ ${data.error || 'Erro ao bloquear remetente'}`);
        }
    } catch (error) {
        console.error('Block sender error:', error);
        alert('❌ Erro ao conectar com o servidor');
    }
}

async function handleUnblockToken() {
    const token = prompt('Digite o IP, domínio ou email para DESBLOQUEAR:');
    if (!token || !token.trim()) {
        return;
    }

    if (!confirm(`Tem certeza que deseja DESBLOQUEAR: ${token}?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/block/drop`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ token: token.trim() })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(`✅ ${data.message}`);
        } else {
            alert(`❌ ${data.error || 'Erro ao desbloquear'}`);
        }
    } catch (error) {
        console.error('Unblock error:', error);
        alert('❌ Erro ao conectar com o servidor');
    }
}

async function handleRemoveFromWhitelist() {
    const token = prompt('Digite o IP, domínio ou email para REMOVER DA WHITELIST:');
    if (!token || !token.trim()) {
        return;
    }

    if (!confirm(`Tem certeza que deseja remover da whitelist: ${token}?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/white/drop`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ token: token.trim() })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(`✅ ${data.message}`);
        } else {
            alert(`❌ ${data.error || 'Erro ao remover da whitelist'}`);
        }
    } catch (error) {
        console.error('Remove from whitelist error:', error);
        alert('❌ Erro ao conectar com o servidor');
    }
}

// ===========================
// Lists Management Functions
// ===========================

async function loadLists() {
    await loadBlocklist();
    await loadWhitelist();
}

async function refreshLists() {
    loadLists();
}

async function loadBlocklist() {
    try {
        const response = await fetch(`${API_URL}/block/list`, {
            credentials: 'include'
        });
        const data = await response.json();

        if (response.ok && data.success) {
            displayBlocklist(data.blocklist || []);
            document.getElementById('blocklist-count').textContent = `${data.count || 0} itens`;
        } else {
            console.error('Error loading blocklist:', data.error);
            document.getElementById('blocklist-tbody').innerHTML =
                '<tr><td colspan="3" class="error">Erro ao carregar blacklist</td></tr>';
        }
    } catch (error) {
        console.error('Load blocklist error:', error);
        document.getElementById('blocklist-tbody').innerHTML =
            '<tr><td colspan="3" class="error">Erro ao conectar com o servidor</td></tr>';
    }
}

async function loadWhitelist() {
    try {
        const response = await fetch(`${API_URL}/white/list`, {
            credentials: 'include'
        });
        const data = await response.json();

        if (response.ok && data.success) {
            displayWhitelist(data.whitelist || []);
            document.getElementById('whitelist-count').textContent = `${data.count || 0} itens`;
        } else {
            console.error('Error loading whitelist:', data.error);
            document.getElementById('whitelist-tbody').innerHTML =
                '<tr><td colspan="3" class="error">Erro ao carregar whitelist</td></tr>';
        }
    } catch (error) {
        console.error('Load whitelist error:', error);
        document.getElementById('whitelist-tbody').innerHTML =
            '<tr><td colspan="3" class="error">Erro ao conectar com o servidor</td></tr>';
    }
}

function displayBlocklist(blocklist) {
    const tbody = document.getElementById('blocklist-tbody');

    if (!blocklist || blocklist.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty">Nenhum item bloqueado</td></tr>';
        return;
    }

    tbody.innerHTML = blocklist.map(item => `
        <tr>
            <td><code>${item.token}</code></td>
            <td><span class="type-badge type-${item.type}">${getTypeLabel(item.type)}</span></td>
            <td class="action-cell">
                <button
                    class="btn-action btn-block"
                    onclick="removeFromBlocklist('${item.token.replace(/'/g, "\\'")}')"
                    title="Remover da blacklist"
                >
                    <span class="icon">🗑️</span>
                </button>
            </td>
        </tr>
    `).join('');
}

function displayWhitelist(whitelist) {
    const tbody = document.getElementById('whitelist-tbody');

    if (!whitelist || whitelist.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty">Nenhum item na whitelist</td></tr>';
        return;
    }

    tbody.innerHTML = whitelist.map(item => `
        <tr>
            <td><code>${item.token}</code></td>
            <td><span class="type-badge type-${item.type}">${getTypeLabel(item.type)}</span></td>
            <td class="action-cell">
                <button
                    class="btn-action btn-block"
                    onclick="removeFromWhitelist('${item.token.replace(/'/g, "\\'")}')"
                    title="Remover da whitelist"
                >
                    <span class="icon">🗑️</span>
                </button>
            </td>
        </tr>
    `).join('');
}

function getTypeLabel(type) {
    const labels = {
        'ip': 'IP',
        'email': 'Email',
        'domain': 'Domínio'
    };
    return labels[type] || type.toUpperCase();
}

async function removeFromBlocklist(token) {
    if (!confirm(`Tem certeza que deseja REMOVER "${token}" da blacklist?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/block/drop`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ token })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(`✅ ${data.message}`);
            loadBlocklist(); // Recarregar lista
        } else {
            alert(`❌ ${data.error || 'Erro ao remover da blacklist'}`);
        }
    } catch (error) {
        console.error('Remove from blocklist error:', error);
        alert('❌ Erro ao conectar com o servidor');
    }
}

async function removeFromWhitelist(token) {
    if (!confirm(`Tem certeza que deseja REMOVER "${token}" da whitelist?`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/white/drop`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({ token })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(`✅ ${data.message}`);
            loadWhitelist(); // Recarregar lista
        } else {
            alert(`❌ ${data.error || 'Erro ao remover da whitelist'}`);
        }
    } catch (error) {
        console.error('Remove from whitelist error:', error);
        alert('❌ Erro ao conectar com o servidor');
    }
}


// ===========================
// Server Modal Functions
// ===========================

function openAddServerModal() {
    const modal = document.getElementById('addServerModal');
    modal.classList.add('show');
    document.body.style.overflow = 'hidden';
    document.getElementById('addServerForm').reset();
    document.getElementById('modal-error-message').style.display = 'none';
    document.getElementById('modal-success-message').style.display = 'none';
}

function closeAddServerModal() {
    const modal = document.getElementById('addServerModal');
    modal.classList.remove('show');
    document.body.style.overflow = 'auto';
}

async function handleAddServer(event) {
    event.preventDefault();
    const form = event.target;
    const submitBtn = document.getElementById('btn-submit-server');
    const errorDiv = document.getElementById('modal-error-message');
    const successDiv = document.getElementById('modal-success-message');
    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';
    const formData = {
        ip: form.ip.value.trim(),
        domain: form.domain.value.trim(),
        option: form.option.value,
        email: form.email.value.trim()
    };
    submitBtn.disabled = true;
    submitBtn.textContent = 'Adicionando...';
    try {
        const response = await fetch(`${API_URL}/clients/add`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify(formData)
        });
        const data = await response.json();
        if (response.ok && data.success) {
            successDiv.textContent = data.message || 'Servidor adicionado com sucesso!';
            successDiv.style.display = 'block';
            form.reset();
            setTimeout(() => { loadServers(); closeAddServerModal(); }, 1500);
        } else {
            errorDiv.textContent = data.error || 'Erro ao adicionar servidor';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        errorDiv.textContent = 'Erro ao conectar com o servidor';
        errorDiv.style.display = 'block';
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Adicionar Servidor';
    }
}

// ===========================
// Users Management Functions
// ===========================

async function loadUsers() {
    try {
        const response = await fetch(`${API_URL}/users/list`, {credentials: 'include'});
        const data = await response.json();
        if (response.ok && data.success) {
            displayUsers(data.users || []);
        } else {
            document.getElementById('users-tbody').innerHTML = '<tr><td colspan="5" class="error">Erro ao carregar usuários</td></tr>';
        }
    } catch (error) {
        document.getElementById('users-tbody').innerHTML = '<tr><td colspan="5" class="error">Erro ao conectar com o servidor</td></tr>';
    }
}

function displayUsers(users) {
    const tbody = document.getElementById('users-tbody');
    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">Nenhum usuário cadastrado</td></tr>';
        return;
    }
    tbody.innerHTML = users.map(u => {
        const safeEmail = u.email.replace(/'/g, "\\'");
        const safeName = u.name || '';
        return `
        <tr>
            <td class="select-column"></td>
            <td>
                <span class="address-pill">
                    <span class="mono">${u.email}</span>
                </span>
            </td>
            <td>${safeName}</td>
            <td>
                <span class="result-badge result-PASS">Ativo</span>
            </td>
            <td class="action-cell">
                <div class="action-buttons user-actions">
                    <button
                        class="btn-action btn-white"
                        type="button"
                        title="Reenviar e-mail TOTP"
                        onclick="resendUserTotp('${safeEmail}')"
                    >
                        <span class="icon">🔑</span>
                    </button>
                    <button
                        class="btn-action btn-block"
                        type="button"
                        title="Remover usuário"
                        onclick="removeSingleUser('${safeEmail}')"
                    >
                        <span class="icon">🗑️</span>
                    </button>
                </div>
            </td>
        </tr>
        `;
    }).join('');

    // Sem seleção em massa; botão de remover múltiplos permanece desabilitado
    updateRemoveUsersButton();
}

function getSelectedUserEmails() {
    // Seleção em massa desativada no momento
    return [];
}

function updateRemoveUsersButton() {
    // Mantido por compatibilidade; não há botão global de remoção no momento
    return;
}

async function handleRemoveUsers() {
    // Remoção em massa desativada; usar ícone de lixeira em cada linha
    return;
}

async function removeSingleUser(email) {
    if (!confirm(`Tem certeza que deseja remover o usuário "${email}"?`)) return;
    try {
        const response = await fetch(`${API_URL}/users/remove`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({ emails: [email] })
        });
        const data = await response.json();
        if (response.ok && data.success) {
            alert(`✅ ${data.message}`);
            loadUsers();
        } else {
            alert(`❌ ${data.error || 'Erro ao remover usuário'}`);
        }
    } catch (error) {
        alert('❌ Erro ao conectar com o servidor');
    }
}

async function resendUserTotp(email) {
    if (!email) return;

    const confirmMessage = `Reenviar o e-mail de TOTP para "${email}"?`;
    if (!confirm(confirmMessage)) return;

    try {
        const response = await fetch(`${API_URL}/users/send-totp`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({ email })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            alert(data.message || 'E-mail TOTP reenviado com sucesso.');
        } else {
            alert(data.error || 'Erro ao reenviar e-mail TOTP.');
        }
    } catch (error) {
        alert('Erro ao conectar com o servidor.');
    }
}

// ===========================
// Logs Functions
// ===========================

async function loadLogs() {
    await Promise.all([
        loadLogsByType('email'),
        loadLogsByType('users')
    ]);
}

async function loadLogsByType(type) {
    try {
        const response = await fetch(`${API_URL}/logs?type=${encodeURIComponent(type)}`, { credentials: 'include' });
        const data = await response.json();

        const isEmail = type === 'email';
        const contentEl = document.getElementById(isEmail ? 'logs-email-content' : 'logs-users-content');
        const fileEl = document.getElementById(isEmail ? 'logs-email-file-label' : 'logs-users-file-label');

        if (response.ok && data.success) {
            const text = (data.lines || []).join('\n') || 'Nenhuma linha de log encontrada para este tipo.';
            contentEl.textContent = text;
            fileEl.textContent = `Arquivo: ${data.file}`;
        } else {
            contentEl.textContent = data.error || 'Erro ao carregar logs.';
            if (data.file) {
                fileEl.textContent = `Arquivo: ${data.file}`;
            }
        }
    } catch (error) {
        const isEmail = type === 'email';
        const contentEl = document.getElementById(isEmail ? 'logs-email-content' : 'logs-users-content');
        contentEl.textContent = 'Erro ao conectar com o servidor para ler logs.';
    }
}

function refreshLogs() {
    loadLogs();
}

// ===========================
// Settings Functions
// ===========================


function openAddUserModal() {
    const modal = document.getElementById('addUserModal');
    modal.classList.add('show');
    document.body.style.overflow = 'hidden';
    document.getElementById('addUserForm').reset();
    document.getElementById('user-modal-error-message').style.display = 'none';
    document.getElementById('user-modal-success-message').style.display = 'none';
}

function closeAddUserModal() {
    const modal = document.getElementById('addUserModal');
    modal.classList.remove('show');
    document.body.style.overflow = 'auto';
}

async function handleAddUser(event) {
    event.preventDefault();
    const form = event.target;
    const submitBtn = document.getElementById('btn-submit-user');
    const errorDiv = document.getElementById('user-modal-error-message');
    const successDiv = document.getElementById('user-modal-success-message');
    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';
    const formData = {email: form.email.value.trim(), name: form.name.value.trim()};
    submitBtn.disabled = true;
    submitBtn.textContent = 'Adicionando...';
    try {
        const response = await fetch(`${API_URL}/users/add`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify(formData)
        });
        const data = await response.json();
        if (response.ok && data.success) {
            successDiv.textContent = data.message || 'Usuário adicionado com sucesso!';
            successDiv.style.display = 'block';
            form.reset();
            setTimeout(() => { loadUsers(); closeAddUserModal(); }, 1500);
        } else {
            errorDiv.textContent = data.error || 'Erro ao adicionar usuário';
            errorDiv.style.display = 'block';
        }
    } catch (error) {
        errorDiv.textContent = 'Erro ao conectar com o servidor';
        errorDiv.style.display = 'block';
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Adicionar Usuário';
    }
}
