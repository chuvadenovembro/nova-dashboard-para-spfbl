(function () {
    async function loadDashboardVersion() {
        const elements = document.querySelectorAll('[data-dashboard-version]');

        if (!elements.length) {
            return;
        }

        let versionLabel = 'v0.00';

        try {
            const response = await fetch('/version.txt', { cache: 'no-store' });
            if (response.ok) {
                const text = (await response.text()).trim();
                if (text) {
                    versionLabel = text.toLowerCase().startsWith('v') ? text : `v${text}`;
                }
            }
        } catch (error) {
            console.warn('Não foi possível carregar a versão da dashboard:', error);
        }

        elements.forEach((el) => {
            el.textContent = versionLabel;
        });
    }

    document.addEventListener('DOMContentLoaded', loadDashboardVersion);
})();
