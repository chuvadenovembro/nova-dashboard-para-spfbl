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

const SMTP_ICON_ON = `
<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
  <rect x="3" y="5" width="18" height="14" rx="2" ry="2"></rect>
  <polyline points="3 7 12 13 21 7"></polyline>
</svg>`;

const SMTP_ICON_OFF = `
<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
  <rect x="3" y="5" width="18" height="14" rx="2" ry="2"></rect>
  <polyline points="3 7 12 13 21 7"></polyline>
  <line x1="4" y1="20" x2="20" y2="4"></line>
</svg>`;

// Global state
let charts = {};
let currentUserContext = null;
let smtpEnabled = null;
let queries = [];
let refreshTimer;
let selectedQueryId = null;
let blocklistData = [];
let whitelistData = [];
const LIST_PAGE_SIZE = 20;
const blocklistPagination = { page: 1, totalPages: 1, total: 0, pageSize: LIST_PAGE_SIZE };
const whitelistPagination = { page: 1, totalPages: 1, total: 0, pageSize: LIST_PAGE_SIZE };
let blocklistSearchTerm = '';
let blocklistSearchTimer = null;
const BLOCKLIST_SEARCH_DELAY = 300;
let blocklistTypeFilter = 'all';
const ALLOWED_BLOCKLIST_TYPES = new Set(['all', 'ip', 'domain', 'email', 'pair']);
const ADMIN_ONLY_SECTIONS = new Set(['servers', 'users', 'logs', 'subdomain-campaign', 'settings']);

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

function getSafePageSize(size) {
    return (typeof size === 'number' && size > 0) ? size : LIST_PAGE_SIZE;
}

function calculateTotalPages(total, pageSize) {
    if (!total) {
        return 1;
    }
    const safeSize = getSafePageSize(pageSize);
    return Math.max(1, Math.ceil(total / safeSize));
}

function formatListRange(page, pageSize, total) {
    if (!total) {
        return 'Nenhum item';
    }
    const safeSize = getSafePageSize(pageSize);
    const safePage = Math.max(1, page || 1);
    const start = ((safePage - 1) * safeSize) + 1;
    const end = Math.min(total, start + safeSize - 1);
    return `${start}-${end} de ${total}`;
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

function isAdminUser() {
    return currentUserContext?.is_admin === true;
}

function updateSmtpToggleButton() {
    const btn = document.getElementById('smtp-toggle');
    if (!btn) {
        return;
    }
    const enabled = smtpEnabled !== false;
    btn.classList.toggle('smtp-disabled', !enabled);
    btn.innerHTML = enabled ? SMTP_ICON_ON : SMTP_ICON_OFF;
    btn.title = enabled
        ? 'Envio de e-mails do SPFBL está ATIVO. Clique para desativar.'
        : 'Envio de e-mails do SPFBL está DESATIVADO. Clique para ativar.';
}

async function loadSmtpStatus() {
    if (!isAdminUser()) {
        return;
    }
    try {
        const response = await fetch(`${API_URL}/settings/smtp-status`, { credentials: 'include' });
        if (!response.ok) {
            return;
        }
        const data = await response.json();
        smtpEnabled = data.enabled === true;
        updateSmtpToggleButton();
    } catch (error) {
        console.warn('Unable to load SMTP status:', error);
    }
}

async function toggleSmtpNotifications() {
    if (!isAdminUser()) {
        showNotification('Acesso restrito ao administrador.', 'warning', 3000);
        return;
    }
    if (smtpEnabled === null) {
        await loadSmtpStatus();
        if (smtpEnabled === null) {
            showNotification('Não foi possível verificar o estado do SMTP.', 'error', 3500);
            return;
        }
    }

    const desiredEnabled = !smtpEnabled;
    const btn = document.getElementById('smtp-toggle');
    if (btn) {
        btn.disabled = true;
    }

    try {
        const response = await fetch(`${API_URL}/settings/smtp-toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ enabled: desiredEnabled })
        });
        const data = await response.json();
        if (response.ok && data.success) {
            smtpEnabled = data.enabled === true;
            updateSmtpToggleButton();
            showNotification(
                smtpEnabled
                    ? 'Envio de e-mails ativado.'
                    : 'Envio de e-mails desativado (abuse/TOTP).',
                'success',
                3500
            );
            if (data.service_restarted === false) {
                showNotification('Configuração salva, mas SPFBL não reiniciou automaticamente.', 'warning', 4500);
            }
        } else {
            showNotification(data.error || 'Falha ao alterar envio de e-mails.', 'error', 4000);
        }
    } catch (error) {
        showNotification('Erro ao conectar para alterar SMTP.', 'error', 4000);
    } finally {
        if (btn) {
            btn.disabled = false;
        }
    }
}

async function loadCurrentUserContext() {
    try {
        const response = await fetch(`${API_URL}/user`, { credentials: 'include' });
        if (response.ok) {
            currentUserContext = await response.json();
        }
    } catch (error) {
        console.warn('Unable to load user context:', error);
    }
    return currentUserContext;
}

function applyRoleVisibility() {
    if (!currentUserContext || isAdminUser()) {
        return;
    }

    const adminNavSelectors = [
        '.nav-item[href="#servers"]',
        '.nav-item[href="#users"]',
        '.nav-item[href="/settings"]',
        '.nav-item[href="#logs"]',
        '.nav-item[href="#subdomain-campaign"]'
    ];

    adminNavSelectors.forEach(selector => {
        document.querySelectorAll(selector).forEach(el => el.classList.add('is-hidden'));
    });

    const adminSectionIds = [
        'section-servers',
        'section-users',
        'section-logs',
        'section-subdomain-campaign'
    ];

    adminSectionIds.forEach(id => {
        document.getElementById(id)?.classList.add('is-hidden');
    });

    const memoryCard = document.getElementById('memory-percent')?.closest('.stat-card');
    memoryCard?.classList.add('is-hidden');

    document.getElementById('smtp-toggle')?.classList.add('is-hidden');

    document.querySelector('.add-forms-container')?.classList.add('is-hidden');
    document.getElementById('blocklist-select-all')?.closest('label')?.classList.add('is-hidden');
    document.getElementById('whitelist-select-all')?.closest('label')?.classList.add('is-hidden');
    document.querySelectorAll('#section-lists .list-toolbar .btn-group').forEach(group => group.classList.add('is-hidden'));

    ['#action-block-ip', '#action-whitelist-ip', '#action-block-sender'].forEach(selector => {
        document.querySelector(selector)?.classList.add('is-hidden');
    });
    document.querySelector('.selected-button-group.global')?.classList.add('is-hidden');

    const activeNav = document.querySelector('.nav-item.active');
    if (activeNav?.classList.contains('is-hidden')) {
        document.querySelector('.nav-item[href="#dashboard"]')?.classList.add('active');
        document.getElementById('section-dashboard')?.classList.add('active');
        document.getElementById('page-title').textContent = 'Dashboard';
    }
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeSidebar();
    restoreTheme();
    renderThemeIcon();

    (async () => {
        await loadCurrentUserContext();
        applyRoleVisibility();
        updateSmtpToggleButton();
        await loadSmtpStatus();
        initCharts();
        loadDashboardData();
        loadDetailedStats();
        loadSpamBlockStats();
        startAutoRefresh();
        setupFilters();
        setupServerSelection();
        setupBlocklistSearch();
        setupBlocklistTypeFilter();
    })();
});

// Navigation
function showSection(sectionName, navEvent) {
    if (navEvent && typeof navEvent.preventDefault === 'function') {
        navEvent.preventDefault();
    }

    if (!isAdminUser() && ADMIN_ONLY_SECTIONS.has(sectionName)) {
        showNotification('Acesso restrito ao administrador.', 'warning', 3000);
        sectionName = 'dashboard';
        navEvent = null;
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
        lists: 'Listas de Bloqueio e Whitelist',
        settings: 'Configurações',
        logs: 'Logs do SPFBL',
        'subdomain-campaign': 'Campanhas de Spam'
    };
    document.getElementById('page-title').textContent = titles[sectionName] || 'Dashboard';

    // Load section data
    if (sectionName === 'dashboard') {
        loadDashboardData();
        loadSpamBlockStats();
    } else if (sectionName === 'queries') {
        loadQueries();
    } else if (sectionName === 'servers') {
        loadServers();
    } else if (sectionName === 'users') {
        loadUsers();
    } else if (sectionName === 'lists') {
        loadLists();
    } else if (sectionName === 'logs') {
        loadLogs();
    } else if (sectionName === 'subdomain-campaign') {
        loadSubdomainCampaignConfig();
    }
}

// Initialize Charts
function initCharts() {
    // Detailed Stats Chart
    const detailedCtx = document.getElementById('detailed-stats-chart').getContext('2d');
    charts.detailed = new Chart(detailedCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'PASS',
                    data: [],
                    backgroundColor: '#10b981'
                },
                {
                    label: 'BLOCKED',
                    data: [],
                    backgroundColor: '#ef4444'
                },
                {
                    label: 'SOFTFAIL',
                    data: [],
                    backgroundColor: '#f59e0b'
                },
                {
                    label: 'FAIL',
                    data: [],
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
            },
            animation: {
                duration: 800,
                easing: 'easeOutQuart'
            },
            animations: {
                y: {
                    type: 'number',
                    easing: 'easeOutQuart',
                    duration: 800,
                    from: 0
                },
                x: {
                    type: 'number',
                    duration: 0
                }
            }
        }
    });

    // SPAM Hourly Chart
    const spamHourlyCtx = document.getElementById('spam-hourly-chart').getContext('2d');
    charts.spamHourly = new Chart(spamHourlyCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Host Bloqueado',
                    data: [],
                    backgroundColor: '#3b82f6'
                },
                {
                    label: 'Domínio Bloqueado',
                    data: [],
                    backgroundColor: '#f59e0b'
                },
                {
                    label: 'IP Bloqueado',
                    data: [],
                    backgroundColor: '#ef4444'
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
            },
            animation: {
                duration: 800,
                easing: 'easeOutQuart'
            },
            animations: {
                y: {
                    type: 'number',
                    easing: 'easeOutQuart',
                    duration: 800,
                    from: 0
                },
                x: {
                    type: 'number',
                    duration: 0
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

        updateDetailedChart(hourlyData);

        // Load SPAM blocks by hour
        const spamHourlyResponse = await fetch(`${API_URL}/stats/spam-blocks/hourly`);
        if (spamHourlyResponse.ok) {
            const spamHourlyData = await spamHourlyResponse.json();
            updateSpamHourlyChart(spamHourlyData);
            checkSpamBlockAlerts(spamHourlyData);
        }

        // Load server memory (admin only)
        if (isAdminUser()) {
            const memoryResponse = await fetch(`${API_URL}/server/memory`);
            const memoryData = await memoryResponse.json();
            updateMemoryCard(memoryData);
        }

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

// Update SPAM Blocks Summary
function updateSpamBlocksCard(spamData) {
    if (!spamData || !spamData.success) {
        document.getElementById('spam-total-direct').textContent = '0';
        document.getElementById('spam-host-direct').textContent = '0';
        document.getElementById('spam-domain-direct').textContent = '0';
        document.getElementById('spam-ip-direct').textContent = '0';
        return;
    }

    const hostBlocked = spamData.host_blocked || 0;
    const domainBlocked = spamData.domain_blocked || 0;
    const ipBlocked = spamData.ip_blocked || 0;
    const totalBlocked = ipBlocked; // total de eventos na janela

    document.getElementById('spam-total-direct').textContent = totalBlocked.toLocaleString('pt-BR');
    document.getElementById('spam-host-direct').textContent = hostBlocked.toLocaleString('pt-BR');
    document.getElementById('spam-domain-direct').textContent = domainBlocked.toLocaleString('pt-BR');
    document.getElementById('spam-ip-direct').textContent = ipBlocked.toLocaleString('pt-BR');
}

// Update SPAM Hourly Chart
function updateSpamHourlyChart(spamHourlyData) {
    if (!spamHourlyData || !charts.spamHourly) return;

    const labels = spamHourlyData.labels && spamHourlyData.labels.length
        ? spamHourlyData.labels
        : (spamHourlyData.hours || []).map(h => `${h}:00`);

    charts.spamHourly.data.labels = labels;
    charts.spamHourly.data.datasets[0].data = spamHourlyData.host_blocked || [];
    charts.spamHourly.data.datasets[1].data = spamHourlyData.domain_blocked || [];
    charts.spamHourly.data.datasets[2].data = spamHourlyData.ip_blocked || [];
    charts.spamHourly.update();
}

// Check SPAM Block Alerts
function checkSpamBlockAlerts(spamHourlyData) {
    if (!spamHourlyData) return;

    const ALERT_THRESHOLD = 50;
    const lastIndex = (spamHourlyData.host_blocked || []).length - 1;
    const currentHour = lastIndex >= 0 ? lastIndex : 0;
    const currentHourData = {
        host: spamHourlyData.host_blocked[currentHour] || 0,
        domain: spamHourlyData.domain_blocked[currentHour] || 0,
        ip: spamHourlyData.ip_blocked[currentHour] || 0
    };

    const totalCurrentHour = currentHourData.host + currentHourData.domain + currentHourData.ip;

    if (totalCurrentHour > ALERT_THRESHOLD) {
        triggerSpamAlert(totalCurrentHour, currentHourData);
    }

    // ML: Detect anomalous patterns
    detectSpamAnomalies(spamHourlyData);
}

// Trigger SPAM Alert (Disabled)
function triggerSpamAlert(totalBlocks, breakdown) {
    // Alerta desabilitado
}

// Detect SPAM Anomalies (ML Pattern Detection)
function detectSpamAnomalies(spamHourlyData) {
    if (!spamHourlyData.host_blocked || spamHourlyData.host_blocked.length === 0) return;

    const allHours = spamHourlyData.host_blocked.map((h, i) => ({
        hour: i,
        host: h || 0,
        domain: (spamHourlyData.domain_blocked[i] || 0),
        ip: (spamHourlyData.ip_blocked[i] || 0)
    }));

    const totalPerHour = allHours.map(h => h.host + h.domain + h.ip);
    const avgBlocks = totalPerHour.reduce((a, b) => a + b, 0) / totalPerHour.length;
    const stdDev = Math.sqrt(
        totalPerHour.reduce((sq, n) => sq + Math.pow(n - avgBlocks, 2), 0) / totalPerHour.length
    );

    const anomalies = totalPerHour.map((total, hour) => {
        const zScore = (total - avgBlocks) / (stdDev || 1);
        return { hour, total, zScore, isAnomaly: Math.abs(zScore) > 2 };
    }).filter(a => a.isAnomaly);

    if (anomalies.length > 0) {
        console.warn('🤖 Anomalias SPAM detectadas:', anomalies.map(a => `${a.hour}:00 (${a.total} bloqueios, zscore: ${a.zScore.toFixed(2)})`).join(', '));
        localStorage.setItem('spam_anomalies_' + new Date().toISOString().split('T')[0], JSON.stringify(anomalies));
    }
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

// Update Detailed Stats Chart
function updateDetailedChart(data) {
    charts.detailed.data.labels = data.hours.map(h => `${h}:00`);
    charts.detailed.data.datasets[0].data = data.passed;
    charts.detailed.data.datasets[1].data = data.blocked;
    charts.detailed.data.datasets[2].data = data.softfail;
    charts.detailed.data.datasets[3].data = data.failed;
    charts.detailed.update();
}

// SPAM Block Statistics
async function loadSpamBlockStats() {
    try {
        const response = await fetch(`${API_URL}/stats/spam-blocks`, {credentials: 'include'});
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                updateSpamBlocksCard(data);
            }
        }
    } catch (error) {
        console.error('Error loading SPAM block stats:', error);
    }
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

    // Apply result filter with SPAM block types
    if (filterResult) {
        if (filterResult.startsWith('SPAM_')) {
            filtered = filtered.filter(q => {
                const spamType = extractSpamBlockType(q.reason || q.result);
                if (filterResult === 'SPAM_HOST_BLOCKED') return spamType === 'HOST_BLOCKED';
                if (filterResult === 'SPAM_DOMAIN_BLOCKED') return spamType === 'DOMAIN_BLOCKED';
                if (filterResult === 'SPAM_IP_BLOCKED') return spamType === 'IP_BLOCKED';
                return false;
            });
        } else {
            filtered = filtered.filter(q => q.result === filterResult);
        }
    }

    displayQueries(filtered);
}

// Extract SPAM block type from reason or result
function extractSpamBlockType(text) {
    if (!text) return null;
    const textStr = String(text);
    if (textStr.includes('Host Blocked')) return 'HOST_BLOCKED';
    if (textStr.includes('Domain Blocked')) return 'DOMAIN_BLOCKED';
    if (textStr.includes('IP Blocked')) return 'IP_BLOCKED';
    return null;
}

// Auto Refresh
function startAutoRefresh() {
    refreshTimer = setInterval(() => {
        const activeSection = document.querySelector('.content-section.active').id.replace('section-', '');

        if (activeSection === 'dashboard') {
            loadDashboardData();
            loadSpamBlockStats();
        } else if (activeSection === 'queries') {
            loadQueries();
        } else if (activeSection === 'lists') {
            loadLists();
        } else if (activeSection === 'servers') {
            loadServers();
        } else if (activeSection === 'users') {
            loadUsers();
        } else if (activeSection === 'logs') {
            loadLogs();
        }

        // Atualizar horário em todas as seções
        updateLastUpdateTime();
    }, REFRESH_INTERVAL);
}

function refreshData() {
    const activeSection = document.querySelector('.content-section.active').id.replace('section-', '');

    if (!isAdminUser() && ADMIN_ONLY_SECTIONS.has(activeSection)) {
        showNotification('Acesso restrito ao administrador.', 'warning', 3000);
        showSection('dashboard');
        return;
    }

    if (activeSection === 'dashboard') {
        loadDashboardData();
        loadSpamBlockStats();
    } else if (activeSection === 'queries') {
        loadQueries();
    } else if (activeSection === 'lists') {
        loadLists();
    } else if (activeSection === 'servers') {
        loadServers();
    } else if (activeSection === 'users') {
        loadUsers();
    } else if (activeSection === 'logs') {
        loadLogs();
    }

    // Atualizar horário ao fazer refresh manual
    updateLastUpdateTime();
}

// Utility Functions
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
            showNotification(data.message, 'success');
            await loadLists();
        } else {
            showNotification(data.error || 'Erro ao desbloquear', 'error');
        }
    } catch (error) {
        console.error('Unblock error:', error);
        showNotification('Erro ao conectar com o servidor', 'error');
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
            showNotification(data.message, 'success');
            await loadLists();
        } else {
            showNotification(data.error || 'Erro ao remover da whitelist', 'error');
        }
    } catch (error) {
        console.error('Remove from whitelist error:', error);
        showNotification('Erro ao conectar com o servidor', 'error');
    }
}

// ===========================
// Lists Management Functions
// ===========================

function setupBlocklistSearch() {
    const input = document.getElementById('blocklist-search');
    if (!input) {
        return;
    }
    input.addEventListener('input', (event) => {
        const value = event.target.value || '';
        if (blocklistSearchTimer) {
            clearTimeout(blocklistSearchTimer);
        }
        updateBlocklistSearchControls();
        blocklistSearchTimer = setTimeout(() => {
            blocklistSearchTerm = value.trim();
            blocklistPagination.page = 1;
            loadBlocklist(1);
        }, BLOCKLIST_SEARCH_DELAY);
    });
    input.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            clearBlocklistSearch();
        }
    });
    updateBlocklistSearchControls();
}

function setupBlocklistTypeFilter() {
    const filterContainer = document.getElementById('blocklist-filter');
    if (!filterContainer) {
        return;
    }
    filterContainer.addEventListener('click', (event) => {
        const button = event.target.closest('[data-type]');
        if (!button) {
            return;
        }
        const type = safeString(button.dataset.type || 'all').toLowerCase();
        setBlocklistTypeFilter(type);
    });
    updateBlocklistFilterUI();
}

function setBlocklistTypeFilter(type) {
    const normalized = safeString(type || 'all').toLowerCase();
    blocklistTypeFilter = ALLOWED_BLOCKLIST_TYPES.has(normalized) ? normalized : 'all';
    blocklistPagination.page = 1;
    updateBlocklistFilterUI();
    loadBlocklist(1);
}

function updateBlocklistFilterUI() {
    const filterContainer = document.getElementById('blocklist-filter');
    if (!filterContainer) {
        return;
    }
    filterContainer.querySelectorAll('[data-type]').forEach((btn) => {
        const isActive = safeString(btn.dataset.type).toLowerCase() === blocklistTypeFilter;
        btn.classList.toggle('active', isActive);
        btn.setAttribute('aria-pressed', isActive ? 'true' : 'false');
    });
}

function clearBlocklistSearch() {
    if (blocklistSearchTimer) {
        clearTimeout(blocklistSearchTimer);
        blocklistSearchTimer = null;
    }
    blocklistSearchTerm = '';
    blocklistPagination.page = 1;
    const input = document.getElementById('blocklist-search');
    if (input && input.value) {
        input.value = '';
    }
    if (input) {
        input.focus();
    }
    updateBlocklistSearchControls();
    loadBlocklist(1);
}

function updateBlocklistSearchControls() {
    const input = document.getElementById('blocklist-search');
    const clearBtn = document.getElementById('blocklist-search-clear');
    const hasValue = !!input?.value?.trim();
    if (clearBtn) {
        clearBtn.disabled = !hasValue;
    }
}

async function loadLists(options = {}) {
    const blockPromise = loadBlocklist(options.blocklistPage);
    const whitePromise = loadWhitelist(options.whitelistPage);
    await Promise.all([blockPromise, whitePromise]);
}

async function refreshLists() {
    return loadLists();
}

async function loadBlocklist(pageOverride) {
    const requestedPage = Number.isFinite(pageOverride) ? pageOverride : (blocklistPagination.page || 1);
    const page = Math.max(1, requestedPage);
    const pageSize = getSafePageSize(blocklistPagination.pageSize);
    const loadingMessage = blocklistSearchTerm ? 'Buscando na blacklist...' : 'Carregando blacklist...';
    setListStatus('blocklist', loadingMessage);
    const searchParam = blocklistSearchTerm ? `&search=${encodeURIComponent(blocklistSearchTerm)}` : '';
    const typeParam = blocklistTypeFilter && blocklistTypeFilter !== 'all'
        ? `&type=${encodeURIComponent(blocklistTypeFilter)}`
        : '';
    try {
        const response = await fetch(`${API_URL}/block/list?page=${page}&page_size=${pageSize}${searchParam}${typeParam}`, {
            credentials: 'include'
        });
        const data = await response.json();

        if (response.ok && data.success) {
            blocklistData = data.blocklist || [];
            const total = data.count ?? blocklistData.length;
            const totalAll = data.total_all ?? total;
            const safePageSize = getSafePageSize(data.page_size || pageSize);
            const totalPages = calculateTotalPages(total, safePageSize);
            blocklistPagination.total = total;
            blocklistPagination.pageSize = safePageSize;
            blocklistPagination.page = total > 0 ? Math.min(data.page || page, totalPages) : 1;
            blocklistPagination.totalPages = totalPages;
            displayBlocklist(blocklistData);
            const countLabel = blocklistSearchTerm
                ? `${total} itens encontrados${totalAll > total ? ` (de ${totalAll})` : ''}`
                : `${total} itens`;
            document.getElementById('blocklist-count').textContent = countLabel;
            updatePaginationControls('blocklist');
            const typeLabel = blocklistTypeFilter !== 'all' ? getTypeLabel(blocklistTypeFilter) : '';
            let statusMessage;
            if (total > 0) {
                statusMessage = `Mostrando ${formatListRange(blocklistPagination.page, safePageSize, total)}`;
                if (blocklistSearchTerm) {
                    statusMessage += ` filtrado por "${blocklistSearchTerm}"`;
                }
                if (typeLabel) {
                    statusMessage += ` • Tipo: ${typeLabel}`;
                }
            } else {
                statusMessage = blocklistSearchTerm
                    ? `Nenhum item encontrado para "${blocklistSearchTerm}"`
                    : typeLabel
                        ? `Nenhum item para tipo: ${typeLabel}`
                        : 'Nenhum item bloqueado';
            }
            setListStatus('blocklist', statusMessage);
        } else {
            console.error('Error loading blocklist:', data.error);
            document.getElementById('blocklist-tbody').innerHTML =
                '<tr><td colspan="3" class="error">Erro ao carregar blacklist</td></tr>';
            resetListPagination('blocklist');
            updatePaginationControls('blocklist');
            setListStatus('blocklist', data.error || 'Erro ao carregar blacklist', true);
        }
    } catch (error) {
        console.error('Load blocklist error:', error);
        document.getElementById('blocklist-tbody').innerHTML =
            '<tr><td colspan="3" class="error">Erro ao conectar com o servidor</td></tr>';
        resetListPagination('blocklist');
        updatePaginationControls('blocklist');
        setListStatus('blocklist', 'Erro ao conectar com o servidor', true);
    }
}

async function loadWhitelist(pageOverride) {
    const requestedPage = Number.isFinite(pageOverride) ? pageOverride : (whitelistPagination.page || 1);
    const page = Math.max(1, requestedPage);
    const pageSize = getSafePageSize(whitelistPagination.pageSize);
    setListStatus('whitelist', 'Carregando whitelist...');
    try {
        const response = await fetch(`${API_URL}/white/list?page=${page}&page_size=${pageSize}`, {
            credentials: 'include'
        });
        const data = await response.json();

        if (response.ok && data.success) {
            whitelistData = data.whitelist || [];
            const total = data.count ?? whitelistData.length;
            const safePageSize = getSafePageSize(data.page_size || pageSize);
            const totalPages = calculateTotalPages(total, safePageSize);
            whitelistPagination.total = total;
            whitelistPagination.pageSize = safePageSize;
            whitelistPagination.page = total > 0 ? Math.min(data.page || page, totalPages) : 1;
            whitelistPagination.totalPages = totalPages;
            displayWhitelist(whitelistData);
            document.getElementById('whitelist-count').textContent = `${total} itens`;
            updatePaginationControls('whitelist');
            const statusMessage = total > 0
                ? `Mostrando ${formatListRange(whitelistPagination.page, safePageSize, total)}`
                : 'Nenhum item na whitelist';
            setListStatus('whitelist', statusMessage);
        } else {
            console.error('Error loading whitelist:', data.error);
            document.getElementById('whitelist-tbody').innerHTML =
                '<tr><td colspan="3" class="error">Erro ao carregar whitelist</td></tr>';
            resetListPagination('whitelist');
            updatePaginationControls('whitelist');
            setListStatus('whitelist', data.error || 'Erro ao carregar whitelist', true);
        }
    } catch (error) {
        console.error('Load whitelist error:', error);
        document.getElementById('whitelist-tbody').innerHTML =
            '<tr><td colspan="3" class="error">Erro ao conectar com o servidor</td></tr>';
        resetListPagination('whitelist');
        updatePaginationControls('whitelist');
        setListStatus('whitelist', 'Erro ao conectar com o servidor', true);
    }
}

function formatTimestamp(timestamp) {
    if (!timestamp) {
        return '<span style="color: #888;">-</span>';
    }

    try {
        // Parse ISO format: 2025-11-25T20:17:01.160091
        const date = new Date(timestamp);

        // Format as DD/MM/YYYY HH:MM:SS
        const day = String(date.getDate()).padStart(2, '0');
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const year = date.getFullYear();
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');

        return `${day}/${month}/${year} ${hours}:${minutes}:${seconds}`;
    } catch (e) {
        return '<span style="color: #888;">-</span>';
    }
}

function formatBlockToken(item) {
    const token = safeString(item?.token);
    if (item?.type === 'pair' && token.includes('>@')) {
        const [from, to] = token.split('>@');
        const fromSafe = escapeHtml(from);
        const toSafe = escapeHtml(to);
        return `<span class="pair-token"><code>${fromSafe}</code><span class="pair-arrow">→</span><code>${toSafe}</code></span>`;
    }
    return `<code>${escapeHtml(token)}</code>`;
}

function displayBlocklist(blocklist) {
    const tbody = document.getElementById('blocklist-tbody');
    const selectAll = document.getElementById('blocklist-select-all');
    if (selectAll) selectAll.checked = false;

    if (!blocklist || blocklist.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="empty">Nenhum item bloqueado</td></tr>';
        return;
    }

    // Otimização: usar DocumentFragment para reduzir reflows
    const fragment = document.createDocumentFragment();
    const template = document.createElement('template');

    blocklist.forEach(item => {
	        template.innerHTML = `
	            <tr>
	                <td><input type="checkbox" class="list-checkbox blocklist-checkbox" data-token="${escapeHtml(item.token)}"></td>
	                <td>${formatBlockToken(item)}</td>
	                <td><span class="type-badge type-${escapeHtml(item.type)}">${getTypeLabel(item.type)}</span></td>
	                <td style="font-size: 0.85em;">${formatTimestamp(item.timestamp)}</td>
	            </tr>
	        `;
        fragment.appendChild(template.content.firstElementChild);
    });

    tbody.innerHTML = '';
    tbody.appendChild(fragment);
}

function displayWhitelist(whitelist) {
    const tbody = document.getElementById('whitelist-tbody');
    const selectAll = document.getElementById('whitelist-select-all');
    if (selectAll) selectAll.checked = false;

    if (!whitelist || whitelist.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty">Nenhum item na whitelist</td></tr>';
        return;
    }

    // Otimização: usar DocumentFragment para reduzir reflows
    const fragment = document.createDocumentFragment();
    const template = document.createElement('template');

    whitelist.forEach(item => {
        template.innerHTML = `
            <tr>
                <td><input type="checkbox" class="list-checkbox whitelist-checkbox" data-token="${escapeHtml(item.token)}"></td>
                <td><code>${escapeHtml(item.token)}</code></td>
                <td><span class="type-badge type-${escapeHtml(item.type)}">${getTypeLabel(item.type)}</span></td>
            </tr>
        `;
        fragment.appendChild(template.content.firstElementChild);
    });

    tbody.innerHTML = '';
    tbody.appendChild(fragment);
}

function getListState(listType) {
    return listType === 'blocklist' ? blocklistPagination : whitelistPagination;
}

function resetListPagination(listType) {
    const state = getListState(listType);
    if (!state) return;
    state.page = 1;
    state.total = 0;
    state.totalPages = 1;
    state.pageSize = LIST_PAGE_SIZE;
}

function updatePaginationControls(listType) {
    const state = getListState(listType);
    if (!state) return;
    const prevBtn = document.getElementById(`${listType}-page-prev`);
    const nextBtn = document.getElementById(`${listType}-page-next`);
    const info = document.getElementById(`${listType}-page-info`);
    const hasItems = state.total > 0;
    if (prevBtn) {
        prevBtn.disabled = !hasItems || state.page <= 1;
    }
    if (nextBtn) {
        nextBtn.disabled = !hasItems || state.page >= state.totalPages;
    }
    if (info) {
        info.textContent = hasItems
            ? `Página ${state.page}/${state.totalPages} • ${formatListRange(state.page, state.pageSize, state.total)}`
            : 'Nenhum item';
    }
}

function changeListPage(listType, direction) {
    const state = getListState(listType);
    if (!state) return;
    const target = Math.min(state.totalPages, Math.max(1, state.page + direction));
    if (target === state.page || state.total === 0) {
        return;
    }
    if (listType === 'blocklist') {
        loadBlocklist(target);
    } else {
        loadWhitelist(target);
    }
}

function getTypeLabel(type) {
    const labels = {
        'ip': 'IP',
        'email': 'Email',
        'domain': 'Domínio',
        'pair': 'Campanha',
        'all': 'Todos'
    };
    return labels[type] || type.toUpperCase();
}

function getSelectedTokens(listType) {
    const selector = listType === 'block' ? '.blocklist-checkbox' : '.whitelist-checkbox';
    return Array.from(document.querySelectorAll(`${selector}:checked`)).map(cb => cb.dataset.token);
}

function toggleSelectAll(listType) {
    const selectAll = document.getElementById(`${listType}list-select-all`);
    const selector = listType === 'block' ? '.blocklist-checkbox' : '.whitelist-checkbox';
    const checked = !!selectAll?.checked;
    document.querySelectorAll(selector).forEach(cb => { cb.checked = checked; });
}

async function apiBlockAdd(token) {
    const response = await fetch(`${API_URL}/block/add`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify({ token })
    });
    const data = await response.json();
    return { ok: response.ok && data.success, message: data.message, error: data.error };
}

async function apiBlockDrop(token) {
    const response = await fetch(`${API_URL}/block/drop`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify({ token })
    });
    const data = await response.json();
    return { ok: response.ok && data.success, message: data.message, error: data.error };
}

async function apiWhiteAdd(token) {
    const response = await fetch(`${API_URL}/white/add`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify({ token })
    });
    const data = await response.json();
    return { ok: response.ok && data.success, message: data.message, error: data.error };
}

async function apiWhiteDrop(token) {
    const response = await fetch(`${API_URL}/white/drop`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify({ token })
    });
    const data = await response.json();
    return { ok: response.ok && data.success, message: data.message, error: data.error };
}

async function addToBlocklist() {
    const input = document.getElementById('blocklist-add-input');
    const token = input.value.trim();

    if (!token) {
        showNotification('Digite um IP, domínio ou email para bloquear', 'warning');
        return;
    }

    // Validação básica
    if (token.length < 3) {
        showNotification('Token inválido (muito curto)', 'error');
        return;
    }

    setListStatus('blocklist', `Bloqueando "${token}"...`);

    const result = await apiBlockAdd(token);

    if (result.ok) {
        showNotification(`✅ ${result.message || 'Item bloqueado com sucesso'}`, 'success');
        input.value = ''; // Limpar campo
        await loadBlocklist(); // Recarregar lista
    } else {
        showNotification(`❌ ${result.error || 'Erro ao bloquear'}`, 'error');
        setListStatus('blocklist', result.error || 'Erro ao bloquear', true);
    }
}

async function bulkUnblock() {
    const tokens = getSelectedTokens('block');
    if (tokens.length === 0) {
        showNotification('Selecione itens para desbloquear', 'warning');
        return;
    }
    let ok = 0, fail = 0;
    for (const token of tokens) {
        const res = await apiBlockDrop(token.trim());
        if (res.ok) ok++; else fail++;
    }
    await loadLists();
    if (fail > 0) {
        showNotification(`Desbloqueio: ${ok} ok, ${fail} falhas`, 'warning');
    } else {
        showNotification(`${ok} ${ok === 1 ? 'item' : 'itens'} desbloqueado(s)`, 'success');
    }
}

async function bulkUnblockAndWhitelist() {
    const tokens = getSelectedTokens('block');
    if (tokens.length === 0) {
        showNotification('Selecione itens para desbloquear e colocar na whitelist', 'warning');
        return;
    }
    let ok = 0, fail = 0;
    for (const token of tokens) {
        const drop = await apiBlockDrop(token.trim());
        const add = await apiWhiteAdd(token.trim());
        if (drop.ok && add.ok) {
            ok++;
        } else {
            fail++;
        }
    }
    await loadLists();
    if (fail > 0) {
        showNotification(`Desbloqueio + whitelist: ${ok} ok, ${fail} falhas`, 'warning');
    } else {
        showNotification(`${ok} ${ok === 1 ? 'item' : 'itens'} desbloqueado(s) e adicionado(s) à whitelist`, 'success');
    }
}

async function bulkWhitelist() {
    const tokens = getSelectedTokens('block');
    if (tokens.length === 0) {
        showNotification('Selecione itens para adicionar à whitelist', 'warning');
        return;
    }
    let ok = 0, fail = 0;
    for (const token of tokens) {
        await apiBlockDrop(token.trim());
        const add = await apiWhiteAdd(token.trim());
        if (add.ok) ok++; else fail++;
    }
    await loadLists();
    if (fail > 0) {
        showNotification(`Whitelist: ${ok} ok, ${fail} falhas`, 'warning');
    } else {
        showNotification(`${ok} ${ok === 1 ? 'item' : 'itens'} adicionado(s) à whitelist`, 'success');
    }
}

async function addToWhitelist() {
    const input = document.getElementById('whitelist-add-input');
    const token = input.value.trim();

    if (!token) {
        showNotification('Digite um IP, domínio ou email para adicionar', 'warning');
        return;
    }

    // Validação básica
    if (token.length < 3) {
        showNotification('Token inválido (muito curto)', 'error');
        return;
    }

    setListStatus('whitelist', `Adicionando "${token}" à whitelist...`);

    const result = await apiWhiteAdd(token);

    if (result.ok) {
        showNotification(`✅ ${result.message || 'Item adicionado à whitelist com sucesso'}`, 'success');
        input.value = ''; // Limpar campo
        await loadWhitelist(); // Recarregar lista
    } else {
        showNotification(`❌ ${result.error || 'Erro ao adicionar à whitelist'}`, 'error');
        setListStatus('whitelist', result.error || 'Erro ao adicionar', true);
    }
}

async function bulkRemoveWhitelist() {
    const tokens = getSelectedTokens('white');
    if (tokens.length === 0) {
        setListStatus('whitelist', 'Selecione itens para remover da whitelist', true);
        return;
    }
    setListStatus('whitelist', 'Removendo da whitelist...');
    let ok = 0, fail = 0;
    for (const token of tokens) {
        const res = await apiWhiteDrop(token.trim());
        if (res.ok) ok++; else fail++;
    }
    await loadLists();
    setListStatus('whitelist', `Remoção concluída: ${ok} ok, ${fail} falhas`, fail > 0);
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

// ===========================
// Helpers de listas
// ===========================

function setListStatus(listName, message, isError = false) {
    const el = document.getElementById(`${listName}-status`);
    if (!el) return;
    el.textContent = message || '';
    el.style.color = isError ? '#ef4444' : 'var(--text-secondary)';
}

/* ========== Sistema de Notificações ========== */

function showNotification(message, type, duration) {
    type = type || 'success';
    duration = duration || 2500;

    const container = document.getElementById('notification-container');
    if (!container) {
        return;
    }

    const notification = document.createElement('div');
    notification.className = 'notification ' + type;

    const colors = {
        'success': { bg: '#22c55e', text: '#ffffff', border: '#15803d' },
        'error': { bg: '#ef4444', text: '#ffffff', border: '#dc2626' },
        'info': { bg: '#3b82f6', text: '#ffffff', border: '#1d4ed8' },
        'warning': { bg: '#f59e0b', text: '#ffffff', border: '#d97706' }
    };

    const color = colors[type] || colors['success'];

    notification.style.backgroundColor = color.bg;
    notification.style.color = color.text;
    notification.style.padding = '18px 24px';
    notification.style.borderLeft = '6px solid ' + color.border;
    notification.style.borderTop = '2px solid ' + color.border;
    notification.style.borderRight = '2px solid ' + color.border;
    notification.style.borderBottom = '2px solid ' + color.border;
    notification.style.borderRadius = '12px';
    notification.style.boxShadow = '0 12px 32px rgba(0, 0, 0, 0.35), 0 6px 14px rgba(0, 0, 0, 0.2)';
    notification.style.display = 'flex';
    notification.style.alignItems = 'center';
    notification.style.gap = '14px';
    notification.style.minWidth = '280px';
    notification.style.maxWidth = '380px';
    notification.style.fontSize = '0.95rem';
    notification.style.fontWeight = '500';

    const icons = { 'success': '✓', 'error': '✕', 'info': 'ℹ', 'warning': '⚠' };

    notification.innerHTML = '<span class="notification-icon" style="flex-shrink: 0; font-size: 1.6em; line-height: 1;">' + (icons[type] || '•') + '</span>' +
        '<span class="notification-message" style="flex: 1; line-height: 1.5;">' + escapeHtml(message) + '</span>';

    container.appendChild(notification);

    setTimeout(function() {
        notification.classList.add('exit');
        setTimeout(function() {
            notification.remove();
        }, 300);
    }, duration);
}

/* ========== Subdomain Campaign Blocker ========== */

// Load subdomain campaign configuration
async function loadSubdomainCampaignConfig() {
    try {
        const response = await fetch('/api/addon/subdomain-campaign/config');
        if (!response.ok) {
            throw new Error('Falha ao carregar configuração');
        }

        const data = await response.json();
        const config = data.config || data;

        // Update UI with config values
        document.getElementById('subdomain-campaign-enabled').checked = config.enabled || false;
        document.getElementById('subdomain-campaign-auto-block').checked = config.auto_block_enabled || false;
        document.getElementById('subdomain-campaign-dry-run').checked = config.dry_run !== false;

        document.getElementById('subdomain-campaign-window').value = config.window_hours || 6;
        document.getElementById('subdomain-campaign-min-subdomains').value = config.min_subdomains || 3;
        document.getElementById('subdomain-campaign-min-events').value = config.min_events_per_domain || 10;
        document.getElementById('subdomain-campaign-poll').value = config.poll_seconds || 60;

        const riskThresholdSlider = document.getElementById('subdomain-campaign-risk-threshold');
        const riskThresholdValue = document.getElementById('subdomain-campaign-risk-threshold-value');
        if (riskThresholdSlider && riskThresholdValue) {
            riskThresholdSlider.value = config.risk_score_threshold || 70;
            riskThresholdValue.textContent = config.risk_score_threshold || 70;
        }

        const blockAction = config.block_action || 'superblock';
        document.getElementById('subdomain-campaign-block-action-superblock').checked = blockAction === 'superblock';
        document.getElementById('subdomain-campaign-block-action-block').checked = blockAction === 'block';

        // Update whitelist
        const whitelist = config.local_whitelist || [];
        document.getElementById('subdomain-campaign-whitelist').value = whitelist.join('\n');

    } catch (error) {
        console.error('Erro ao carregar configuração:', error);
        showNotification('Erro ao carregar configuração: ' + error.message, 'error');
    }
}

// Save subdomain campaign configuration
async function saveSubdomainCampaignConfig() {
    try {
        const whitelistText = document.getElementById('subdomain-campaign-whitelist').value;
        const whitelist = whitelistText.split('\n').map(line => line.trim()).filter(line => line.length > 0);

        const blockAction = document.getElementById('subdomain-campaign-block-action-superblock').checked ? 'superblock' : 'block';

        const config = {
            enabled: document.getElementById('subdomain-campaign-enabled').checked,
            auto_block_enabled: document.getElementById('subdomain-campaign-auto-block').checked,
            dry_run: document.getElementById('subdomain-campaign-dry-run').checked,
            window_hours: parseInt(document.getElementById('subdomain-campaign-window').value),
            min_subdomains: parseInt(document.getElementById('subdomain-campaign-min-subdomains').value),
            min_events_per_domain: parseInt(document.getElementById('subdomain-campaign-min-events').value),
            risk_score_threshold: parseInt(document.getElementById('subdomain-campaign-risk-threshold').value),
            poll_seconds: parseInt(document.getElementById('subdomain-campaign-poll').value),
            block_action: blockAction,
            local_whitelist: whitelist
        };

        const response = await fetch('/api/addon/subdomain-campaign/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        if (!response.ok) {
            throw new Error('Falha ao salvar configuração');
        }

        showNotification('Configuração salva com sucesso!', 'success');

    } catch (error) {
        console.error('Erro ao salvar configuração:', error);
        showNotification('Erro ao salvar configuração: ' + error.message, 'error');
    }
}

// Run subdomain campaign scan
async function runSubdomainCampaignScan() {
    const button = document.getElementById('subdomain-campaign-scan-button');
    const originalText = button ? button.textContent : '';

    try {
        if (button) {
            button.disabled = true;
            button.textContent = '⏳ Executando scan...';
        }

        const autoBlockCheckbox = document.getElementById('subdomain-campaign-auto-block');
        const autoBlock = autoBlockCheckbox ? autoBlockCheckbox.checked : false;
        const response = await fetch('/api/addon/subdomain-campaign/scan?auto_block=' + (autoBlock ? 'true' : 'false'));

        if (!response.ok) {
            throw new Error('Falha ao executar scan');
        }

        const result = await response.json();

        showNotification('Scan concluído! Campanhas detectadas: ' + result.total_campaigns, 'success');

        // Render results
        renderSubdomainCampaignResults(result);

    } catch (error) {
        console.error('Erro ao executar scan:', error);
        showNotification('Erro ao executar scan: ' + error.message, 'error');
    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = originalText;
        }
    }
}

// Render subdomain campaign scan results
function renderSubdomainCampaignResults(result) {
    const container = document.getElementById('subdomain-campaign-results');
    if (!container) return;

    if (!result || !result.campaigns || result.campaigns.length === 0) {
        container.innerHTML = '<div class="info-box" style="background: #f0f9ff; border-left: 4px solid #3b82f6;"><p style="margin: 0; color: #1e40af;">ℹ️ Nenhuma campanha detectada no último scan.</p></div>';
        return;
    }

    let html = '<div style="margin-bottom: 1.5rem;">';
    html += '<h3 style="color: #1f2937; margin: 0 0 1rem 0;">📊 Resumo do Scan</h3>';
    html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem;">';
    html += '<div style="background: #f0f9ff; padding: 1rem; border-radius: 8px; border-left: 4px solid #3b82f6;">';
    html += '<div style="font-size: 0.875rem; color: #64748b; margin-bottom: 0.5rem;">Total de Campanhas</div>';
    html += '<div style="font-size: 1.5rem; font-weight: bold; color: #1e40af;">' + result.total_campaigns + '</div>';
    html += '</div>';
    html += '<div style="background: #fef2f2; padding: 1rem; border-radius: 8px; border-left: 4px solid #ef4444;">';
    html += '<div style="font-size: 0.875rem; color: #64748b; margin-bottom: 0.5rem;">Alto Risco (≥70)</div>';
    html += '<div style="font-size: 1.5rem; font-weight: bold; color: #dc2626;">' + result.high_risk_campaigns + '</div>';
    html += '</div>';
    html += '<div style="background: #f0fdf4; padding: 1rem; border-radius: 8px; border-left: 4px solid #22c55e;">';
    html += '<div style="font-size: 0.875rem; color: #64748b; margin-bottom: 0.5rem;">Bloqueios Realizados</div>';
    html += '<div style="font-size: 1.5rem; font-weight: bold; color: #15803d;">' + (result.blocks_performed || 0) + '</div>';
    html += '</div>';
    html += '</div>';
    html += '</div>';

    html += '<h3 style="color: #1f2937; margin: 0 0 1rem 0;">🎯 Campanhas Detectadas</h3>';

    result.campaigns.forEach((campaign, index) => {
        const riskColor = campaign.risk_score >= 70 ? '#ef4444' : campaign.risk_score >= 50 ? '#f59e0b' : '#3b82f6';
        const actionColor = campaign.recommended_action === 'BLOCK_SUPERBLOCK' ? '#dc2626' :
                           campaign.recommended_action === 'BLOCK_DOMAIN' ? '#f59e0b' : '#64748b';

        html += '<div class="campaign-card" style="background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">';

        // Header
        html += '<div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 1rem;">';
        html += '<div style="flex: 1;">';
        html += '<h4 style="margin: 0 0 0.5rem 0; color: #1f2937; font-size: 1.125rem;">🎯 ' + escapeHtml(campaign.base_domain) + '</h4>';
        html += '<div style="display: flex; gap: 1rem; flex-wrap: wrap;">';
        html += '<span style="font-size: 0.875rem; color: #64748b;">📅 ' + campaign.unique_subdomains + ' subdomínios</span>';
        html += '<span style="font-size: 0.875rem; color: #64748b;">📧 ' + campaign.total_events + ' eventos</span>';
        html += '<span style="font-size: 0.875rem; color: #64748b;">🌐 ' + campaign.unique_ips + ' IPs</span>';
        html += '</div>';
        html += '</div>';
        html += '<div style="text-align: right;">';
        html += '<div style="background: ' + riskColor + '; color: white; padding: 0.5rem 1rem; border-radius: 8px; font-weight: bold; margin-bottom: 0.5rem;">';
        html += 'Score: ' + campaign.risk_score + '/100';
        html += '</div>';
        html += '<div style="color: ' + actionColor + '; font-size: 0.875rem; font-weight: 600;">';
        html += campaign.recommended_action.replace('_', ' ');
        html += '</div>';
        html += '</div>';
        html += '</div>';

        // Risk factors
        if (campaign.risk_factors && campaign.risk_factors.length > 0) {
            html += '<div style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">';
            html += '<div style="font-weight: 600; color: #dc2626; margin-bottom: 0.5rem;">⚠️ Fatores de Risco:</div>';
            html += '<ul style="margin: 0; padding-left: 1.5rem; color: #991b1b;">';
            campaign.risk_factors.forEach(factor => {
                html += '<li style="margin-bottom: 0.25rem;">' + escapeHtml(factor) + '</li>';
            });
            html += '</ul>';
            html += '</div>';
        }

        // Details toggle
        html += '<div style="margin-top: 1rem;">';
        html += '<button onclick="toggleSubdomainCampaignDetails(' + index + ')" style="background: #f3f4f6; border: 1px solid #d1d5db; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.875rem; color: #374151; width: 100%;">';
        html += '<span id="subdomain-campaign-toggle-icon-' + index + '">▼</span> Ver detalhes';
        html += '</button>';
        html += '<div id="subdomain-campaign-details-' + index + '" style="display: none; margin-top: 1rem; padding: 1rem; background: #f9fafb; border-radius: 8px;">';

        // Statistics
        html += '<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem;">';
        html += '<div><span style="color: #64748b; font-size: 0.875rem;">Padrão numérico:</span> <strong>' + campaign.subdomains_with_pattern + ' (' + Math.round(campaign.pattern_percentage) + '%)</strong></div>';
        html += '<div><span style="color: #64748b; font-size: 0.875rem;">Taxa PASS:</span> <strong>' + Math.round(campaign.pass_rate * 100) + '%</strong></div>';
        html += '<div><span style="color: #64748b; font-size: 0.875rem;">Velocidade:</span> <strong>' + campaign.events_per_hour.toFixed(1) + ' eventos/hora</strong></div>';
        html += '<div><span style="color: #64748b; font-size: 0.875rem;">Janela:</span> <strong>' + campaign.window_hours.toFixed(1) + ' horas</strong></div>';
        html += '</div>';

        // Top subdomains
        if (campaign.top_subdomains && campaign.top_subdomains.length > 0) {
            html += '<div style="margin-top: 1rem;">';
            html += '<div style="font-weight: 600; color: #374151; margin-bottom: 0.5rem;">📋 Top Subdomínios:</div>';
            html += '<div style="max-height: 200px; overflow-y: auto; background: white; border: 1px solid #e5e7eb; border-radius: 6px; padding: 0.5rem;">';
            campaign.top_subdomains.forEach(sub => {
                html += '<div style="padding: 0.5rem; border-bottom: 1px solid #f3f4f6; font-size: 0.875rem;">';
                html += '<div style="font-family: monospace; color: #1e40af; margin-bottom: 0.25rem;">' + escapeHtml(sub.subdomain);
                if (sub.pattern) {
                    html += ' <span style="color: #dc2626;">[padrão: ' + escapeHtml(sub.pattern) + ']</span>';
                }
                html += '</div>';
                html += '<div style="color: #64748b; font-size: 0.8125rem;">Eventos: ' + sub.count + ' | IPs: ' + sub.unique_ips + '</div>';
                html += '</div>';
            });
            html += '</div>';
            html += '</div>';
        }

        html += '</div>';
        html += '</div>';
        html += '</div>';
    });

    container.innerHTML = html;
}

// Toggle campaign details
function toggleSubdomainCampaignDetails(index) {
    const detailsDiv = document.getElementById('subdomain-campaign-details-' + index);
    const icon = document.getElementById('subdomain-campaign-toggle-icon-' + index);

    if (!detailsDiv || !icon) return;

    if (detailsDiv.style.display === 'none') {
        detailsDiv.style.display = 'block';
        icon.textContent = '▲';
    } else {
        detailsDiv.style.display = 'none';
        icon.textContent = '▼';
    }
}

// Switch subdomain campaign tabs
function switchSubdomainCampaignTab(tabName, event) {
    // Remove active class from all tabs
    const tabs = document.querySelectorAll('#subdomain-campaign .tab-content');
    tabs.forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active class from all buttons
    const buttons = document.querySelectorAll('#subdomain-campaign .tab-button');
    buttons.forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    const selectedTab = document.getElementById('subdomain-campaign-tab-' + tabName);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Add active class to clicked button
    if (event && event.target) {
        event.target.classList.add('active');
    }
}

// Update slider value display
function updateSubdomainCampaignSliderValue(sliderId, valueId) {
    const slider = document.getElementById(sliderId);
    const valueDisplay = document.getElementById(valueId);

    if (slider && valueDisplay) {
        valueDisplay.textContent = slider.value;
    }
}

// Initialize subdomain campaign listeners
document.addEventListener('DOMContentLoaded', function() {
    // Risk threshold slider listener
    const riskSlider = document.getElementById('subdomain-campaign-risk-threshold');
    const riskValue = document.getElementById('subdomain-campaign-risk-threshold-value');

    if (riskSlider && riskValue) {
        riskSlider.addEventListener('input', function() {
            riskValue.textContent = this.value;
        });
    }
});
