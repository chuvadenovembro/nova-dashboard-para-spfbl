#!/usr/bin/env bash
set -euo pipefail

# === Configurações básicas ===================================================
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$PROJECT_ROOT/newdash"
BACKUP_DIR="$PROJECT_ROOT/backup_spfbl"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_FILE="$BACKUP_DIR/dashboard-$TIMESTAMP.tar.gz"
CHANGELOG_FILE="$PROJECT_ROOT/CHANGELOG.md"

TARGET_SPFBL_DIR="/opt/spfbl"
TARGET_WEB_DIR="$TARGET_SPFBL_DIR/web"
TARGET_SYSTEMD_DIR="/etc/systemd/system"

# === Funções auxiliares ======================================================
abort() {
    echo "Erro: $1" >&2
    exit 1
}

check_requirements() {
    for cmd in tar cp systemctl; do
        command -v "$cmd" >/dev/null 2>&1 || abort "Comando obrigatório '$cmd' não encontrado."
    done
}

ensure_layout() {
    [[ -d "$SOURCE_DIR/backend" ]] || abort "Diretório backend não encontrado em $SOURCE_DIR."
    [[ -d "$SOURCE_DIR/frontend" ]] || abort "Diretório frontend não encontrado em $SOURCE_DIR."
    [[ -d "$SOURCE_DIR/systemd" ]] || abort "Diretório systemd não encontrado em $SOURCE_DIR."

    # Verificar arquivos mínimos necessários (permite arquivos extras)
    [[ -f "$SOURCE_DIR/backend/spfbl-api.py" ]] || abort "Arquivo backend/spfbl-api.py não encontrado."
    [[ -f "$SOURCE_DIR/frontend/dashboard.html" ]] || abort "Arquivo frontend/dashboard.html não encontrado."
    [[ -f "$SOURCE_DIR/frontend/dashboard.css" ]] || abort "Arquivo frontend/dashboard.css não encontrado."
    [[ -f "$SOURCE_DIR/frontend/dashboard.js" ]] || abort "Arquivo frontend/dashboard.js não encontrado."
    [[ -f "$SOURCE_DIR/frontend/login.html" ]] || abort "Arquivo frontend/login.html não encontrado."
    [[ -f "$SOURCE_DIR/frontend/login.css" ]] || abort "Arquivo frontend/login.css não encontrado."
    [[ -f "$SOURCE_DIR/frontend/settings.html" ]] || abort "Arquivo frontend/settings.html não encontrado."
    [[ -f "$SOURCE_DIR/systemd/spfbl-api.service" ]] || abort "Arquivo systemd/spfbl-api.service não encontrado."

    # Validar addon TLD (opcional)
    ADDON_DIR="$PROJECT_ROOT/addon"
    [[ -d "$ADDON_DIR" ]] && [[ -f "$ADDON_DIR/tld_addon.py" ]] || {
        echo "[WARN] Addon TLD não encontrado em $ADDON_DIR (opcional, continuando...)" >&2
    }

    mkdir -p "$BACKUP_DIR"
}

ensure_target_dirs() {
    mkdir -p "$TARGET_SPFBL_DIR" "$TARGET_WEB_DIR" "$TARGET_SYSTEMD_DIR"
}

deploy_addon() {
    local addon_src="$PROJECT_ROOT/addon"
    local addon_target="$TARGET_SPFBL_DIR/addon"

    if [[ ! -d "$addon_src" ]]; then
        echo "[SKIP] Diretório addon não encontrado em $addon_src (opcional)"
        return 0
    fi

    echo ">> Copiando addons de $addon_src para $addon_target"
    mkdir -p "$addon_target"

    # Copiar TLD addon (se existir)
    if [[ -f "$addon_src/tld_addon.py" ]]; then
        cp -a "$addon_src/tld_addon.py" "$addon_target/"
        chmod 644 "$addon_target/tld_addon.py"
        echo "   ✓ tld_addon.py instalado"
    fi

    # Copiar Subdomain Campaign Blocker (se existir)
    if [[ -f "$addon_src/subdomain_campaign_blocker.py" ]]; then
        cp -a "$addon_src/subdomain_campaign_blocker.py" "$addon_target/"
        chmod 644 "$addon_target/subdomain_campaign_blocker.py"
        echo "   ✓ subdomain_campaign_blocker.py instalado"
    fi

    if [[ -f "$addon_src/subdomain_pattern_analyzer.py" ]]; then
        cp -a "$addon_src/subdomain_pattern_analyzer.py" "$addon_target/"
        chmod 644 "$addon_target/subdomain_pattern_analyzer.py"
        echo "   ✓ subdomain_pattern_analyzer.py instalado"
    fi

    # Copiar whitelist.csv (se existir e não houver em produção)
    if [[ -f "$addon_src/whitelist.csv" ]]; then
        if [[ ! -f "$addon_target/whitelist.csv" ]]; then
            cp -a "$addon_src/whitelist.csv" "$addon_target/"
            echo "   ✓ whitelist.csv instalado"
        else
            echo "   ℹ Preservando whitelist.csv existente em produção"
        fi
    fi

    # Copiar/preservar configurações do addon
    if [[ -d "$addon_src/config" ]]; then
        mkdir -p "$addon_target/config"
        # tld_addon.json
        if [[ -f "$addon_target/config/tld_addon.json" ]]; then
            echo "   ℹ Preservando tld_addon.json existente"
        elif [[ -f "$addon_src/config/tld_addon.json" ]]; then
            cp "$addon_src/config/tld_addon.json" "$addon_target/config/"
            echo "   ✓ tld_addon.json instalado"
        fi
        # subdomain_campaign_blocker.json - SEMPRE preserva se existir em produção
        if [[ -f "$addon_target/config/subdomain_campaign_blocker.json" ]]; then
            echo "   ℹ Preservando subdomain_campaign_blocker.json existente"
        elif [[ -f "$addon_src/config/subdomain_campaign_blocker.json" ]]; then
            cp "$addon_src/config/subdomain_campaign_blocker.json" "$addon_target/config/"
            echo "   ✓ subdomain_campaign_blocker.json instalado"
        fi
    fi

    echo "   ✓ Addons instalados em $addon_target"
}

# === Execução =================================================================
check_requirements
ensure_layout
ensure_target_dirs

echo ">> Criando backup local do pacote da dashboard em $BACKUP_FILE"
tar -czf "$BACKUP_FILE" -C "$SOURCE_DIR" .

echo ">> Copiando backend (tudo de backend/) para $TARGET_SPFBL_DIR"
cp -a "$SOURCE_DIR/backend/." "$TARGET_SPFBL_DIR/"
chmod 700 "$TARGET_SPFBL_DIR/spfbl-api.py"

echo ">> Copiando frontend (tudo de frontend/) para $TARGET_WEB_DIR"
cp -a "$SOURCE_DIR/frontend/." "$TARGET_WEB_DIR/"
echo "   ✓ Arquivos estáticos atualizados em $TARGET_WEB_DIR"

if [[ -f "$CHANGELOG_FILE" ]]; then
    DASHBOARD_VERSION="$(sed -n 's/^## \[v\([0-9][0-9\.]*\)\].*/\1/p' "$CHANGELOG_FILE" | head -n1)"
fi
DASHBOARD_VERSION="${DASHBOARD_VERSION:-0.00}"
printf '%s\n' "$DASHBOARD_VERSION" > "$TARGET_WEB_DIR/version.txt"
echo "   ✓ Versão da dashboard registrada como v$DASHBOARD_VERSION"

echo ">> Instalando unidades systemd (tudo de systemd/) em $TARGET_SYSTEMD_DIR"
cp -a "$SOURCE_DIR/systemd/." "$TARGET_SYSTEMD_DIR/"
chmod 644 "$TARGET_SYSTEMD_DIR"/spfbl-api.service

echo ">> Instalando addon TLD (se disponível)"
deploy_addon

echo ">> Aplicando atualizações do serviço local spfbl-api"
systemctl daemon-reload
systemctl restart spfbl-api
systemctl status spfbl-api --no-pager -l

echo ""
echo "✓ Deploy concluído com sucesso!"
echo ""
echo "Acesse a dashboard em:"
echo "  http://localhost:8002/login"
echo "  http://localhost:8002/settings"
