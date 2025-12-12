(function () {
    async function loadDashboardVersion() {
        const elements = document.querySelectorAll('[data-dashboard-version]');
        if (!elements.length) return;

        let localVersion = 'v0.00';

        // Carregar versão local
        try {
            const response = await fetch('/version.txt', { cache: 'no-store' });
            if (response.ok) {
                const text = (await response.text()).trim();
                if (text) {
                    localVersion = text.toLowerCase().startsWith('v') ? text : `v${text}`;
                }
            }
        } catch (error) {
            console.warn('Erro ao carregar versão local:', error);
        }

        // Exibir versão local
        elements.forEach((el) => {
            el.textContent = localVersion;
        });

        // Verificar atualizações disponíveis
        try {
            const response = await fetch('/api/check-update', { credentials: 'include' });
            if (response.ok) {
                const data = await response.json();

                if (data.success && data.update_available) {
                    appendUpdateBadge(localVersion, data.latest_version, data.changelog_url);
                }
            }
        } catch (error) {
            console.warn('Erro ao verificar atualizações:', error);
        }
    }

    function appendUpdateBadge(currentVersion, latestVersion, changelogUrl) {
        const versionElements = document.querySelectorAll('[data-dashboard-version]');
        if (versionElements.length === 0) return;

        const versionElement = versionElements[0];

        // Criar o badge de atualização
        const badge = document.createElement('span');
        badge.className = 'version-update-badge';

        const link = document.createElement('a');
        link.className = 'version-update-link';
        link.href = changelogUrl;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = `→ v${latestVersion}`;

        badge.appendChild(link);
        versionElement.appendChild(badge);
    }

    document.addEventListener('DOMContentLoaded', loadDashboardVersion);
})();
