#!/usr/bin/env bash
#
# Instala e configura um servidor SPFBL dedicado a atuar como policy/RBL
# para MTAs externos (Exim/DirectAdmin, Postfix etc) e provê um Exim local
# básico para notificações. Execute como root em um Ubuntu 22.04 recém
# provisionado.

set -euo pipefail
umask 022

###############################
# Variáveis editáveis
###############################

# ===================================================================
# CONFIGURAÇÕES PRINCIPAIS - EDITE ESTAS VARIÁVEIS ANTES DE INSTALAR
# ===================================================================

# Domínio principal do servidor de email
# Exemplo: "meudominio.com" ou "empresa.com.br"
MAIL_DOMAIN="3iatlas.privatedns.com.br"

# Hostname do servidor (deixe vazio para detecção automática)
MAIL_HOSTNAME="3iatlas.privatedns.com.br"

# ===================================================================
# ACESSO À DASHBOARD - CREDENCIAIS DE ADMINISTRADOR
# ===================================================================

# Email do administrador do SPFBL
# Este será o login para acessar o painel de administração
# Exemplo: "admin@meudominio.com" ou "suporte@empresa.com.br"
SPFBL_ADMIN_EMAIL="admin@ogigante.com"

# Senha do administrador da dashboard
# IMPORTANTE: Altere esta senha! Use uma senha forte e segura.
# Exemplo: "MinhaS3nh@F0rt3!" ou "P@ssw0rd!2025"
# ATENÇÃO: Esta senha será usada para login no painel web!
SPFBL_ADMIN_PASSWORD="hrp4CKV_wxz5gfc!ehbvbk!pzt6QUZ7unx9ecf"

# ===================================================================
# CONFIGURAÇÕES DE REDE E PORTAS
# ===================================================================

SPFBL_HTTP_PORT="8001"
DASHBOARD_HTTP_PORT="8002"
SPFBL_DNS_PROVIDER_PRIMARY="8.8.8.8"
SPFBL_POLICY_PORT="9877"
SPFBL_ADMIN_PORT="9875"
SPFBL_CLIENT_CIDR="127.0.0.1/32"
SPFBL_CLIENT_LABEL=""  # Será preenchido automaticamente
SPFBL_HTTP_USE_TLS="no"

# Lista de servidores DirectAdmin/Exim autorizados a consultar o SPFBL.
# Formato: "CIDR:identificador:contato"
# Adicione um por linha dentro dos parênteses.
#
# EXEMPLOS:
#   AUTHORIZED_SERVERS=(
#     "203.0.113.10/32:mail1.exemplo.com:admin@exemplo.com"
#     "203.0.113.20/32:mail2.exemplo.com:admin@exemplo.com"
#   )
#
# Para facilitar, você também pode usar este formato simplificado:
#   AUTHORIZED_SERVERS_SIMPLE=(
#     "203.0.113.10"
#     "203.0.113.20"
#   )
# (Neste caso, o script criará identificadores automaticamente)
#
AUTHORIZED_SERVERS=()

# OU use o formato simplificado (apenas IPs):
AUTHORIZED_SERVERS_SIMPLE=()

# MANTER para compatibilidade (DEPRECATED - use AUTHORIZED_SERVERS)
POLICY_CLIENTS=()

# Lista opcional de domínios que terão conta postmaster dedicada.
# Formato: ("dominio.tld:SenhaForte123")
POSTMASTER_DOMAINS=()

# ===================================================================
# CONFIGURAÇÃO DO EXIM4 (Instalação silenciosa)
# ===================================================================
#
# Seguindo: https://reintech.io/blog/installing-configuring-exim-mail-server-ubuntu
#
# O Exim4 será instalado e configurado automaticamente de forma silenciosa.
#
# Tipo de configuração: internet site (SMTP local)
# Interfaces: 127.0.0.1 (apenas localhost, recomendado para SPFBL)
# Domínios: $MAIL_DOMAIN (configurado acima)
#
EXIM_CONFIG_TYPE="internet site; mail is sent and received directly using SMTP"
EXIM_LOCAL_INTERFACES="127.0.0.1"
EXIM_SMTP_PORT="587"

# ===================================================================
# EMAIL DE CONTATO PARA REGISTRO AUTOMÁTICO (OPCIONAL)
# ===================================================================

# Email usado para registrar automaticamente servidores DirectAdmin
# que se conectarem ao SPFBL pela primeira vez.
#
# Deixe VAZIO para usar o padrão: auto@<hostname_do_servidor_DirectAdmin>
# Ou defina um email específico: "contato@meudominio.com"
#
# Esta configuração é OPCIONAL e só afeta o registro automático.
DIRECTADMIN_CLIENT_EMAIL=""

# ===================================================================
# CONFIGURAÇÃO DE FIREWALL
# ===================================================================
#
# Ativar configuração automática de firewall (UFW e CSF)
# Se 'yes', o script abrirá automaticamente as portas necessárias
# Se 'no', você precisará configurar manualmente
#
FIREWALL_AUTO_CONFIG="yes"

# Porta SSH detectada automaticamente (leave empty for auto-detection)
FIREWALL_SSH_PORT=""

# Portas SPFBL que devem ser abertas no firewall
# Nota: EXIM_SMTP_PORT é dinâmica e será adicionada em configure_firewall()
FIREWALL_SPFBL_PORTS=(
  "$SPFBL_POLICY_PORT"      # Policy port (9877)
  "$SPFBL_HTTP_PORT"        # HTTP SPFBL (8001)
  "$DASHBOARD_HTTP_PORT"    # Dashboard HTTP (8002)
)

# Permitir porta administrativa (9875) apenas de localhost
FIREWALL_ADMIN_PORT_LOOPBACK_ONLY="yes"

# CSF Firewall - configuração automática
CSF_AUTO_CONFIG="yes"

# UFW Firewall - configuração automática
UFW_AUTO_CONFIG="yes"

# ===================================================================
# CONFIGURAÇÃO DE MEMÓRIA PARA SPFBL
# ===================================================================
#
# Configuração automática de memória JVM baseada na RAM disponível
# Deixe em branco "" para detecção automática (RECOMENDADO)
# Ou especifique manualmente: "1g" (1GB mín), "2g" (2GB máx), etc
#
SPFBL_JVM_MIN_MEMORY=""    # Mínimo (auto-detectado se vazio)
SPFBL_JVM_MAX_MEMORY=""    # Máximo (auto-detectado se vazio)

###############################
# Constantes
###############################
SPFBL_SOURCE_URL="https://github.com/leonamp/SPFBL/archive/master.zip"
SPFBL_INSTALL_DIR="/opt/spfbl"
SPFBL_SERVICE_SCRIPT="/etc/init.d/spfbl-init"
SPFBL_CLIENT_BIN="/sbin/spfbl"
SPFBL_CLIENT_TEMPLATE="/opt/spfbl/tools/spfbl-client-template.sh"
REMOTE_GUIDE_FILE="/opt/spfbl/REMOTE_INTEGRATION.md"
SPFBL_LOG_DIR="/var/log/spfbl"
SPFBL_HISTORY_DIR="$SPFBL_INSTALL_DIR/history"
SPFBL_WEB_DIR="$SPFBL_INSTALL_DIR/web"
SPFBL_PUBLIC_DIR="$SPFBL_WEB_DIR/public"
DIRECTADMIN_DOC_URL="https://docs.directadmin.com/other-hosting-services/exim/configuring-exim.html"

###############################
# Variáveis internas
###############################
SERVER_INTERFACE=""
SERVER_IP=""
PUBLIC_IP=""
BUILD_TMP_DIR=""
IS_PRIVATE_NETWORK=""
DETECTED_HOSTNAME=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DATE="$(date +'%Y-%m-%d_%H-%M-%S')"

###############################
# Funções utilitárias
###############################
cleanup() {
  if [[ -n "${BUILD_TMP_DIR}" && -d "${BUILD_TMP_DIR}" ]]; then
    rm -rf "${BUILD_TMP_DIR}"
  fi
}
trap cleanup EXIT

log() {
  printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
}

die() {
  log "ERRO: $*"
  exit 1
}

require_root() {
  [[ $EUID -eq 0 ]] || die "este script precisa ser executado como root."
}

backup_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  local backup="${file}.$(date +'%Y%m%d%H%M%S')~"
  cp -a "$file" "$backup"
  log "Backup criado: $backup"
}

set_conf_kv() {
  local file="$1" key="$2" value="$3"
  python3 - "$file" "$key" "$value" <<'PY'
import sys
path, key, value = sys.argv[1:4]
lines = []
found = False
try:
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            if line.startswith(f"{key}="):
                lines.append(f"{key}={value}\n")
                found = True
            else:
                lines.append(line)
except FileNotFoundError:
    pass
if not found:
    lines.append(f"{key}={value}\n")
with open(path, 'w', encoding='utf-8') as fh:
    fh.writelines(lines)
PY
}

wait_for_port() {
  local host="$1" port="$2" timeout="${3:-60}"
  local start_time elapsed

  start_time=$(date +%s)

  while true; do
    elapsed=$(($(date +%s) - start_time))

    # Tentar conectar usando nc
    if nc -z "$host" "$port" >/dev/null 2>&1; then
      log "✓ Porta $port respondendo após ${elapsed}s"
      return 0
    fi

    # Tentar conexão alternativa com /dev/tcp (caso nc falhe)
    if bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
      log "✓ Porta $port respondendo (via /dev/tcp) após ${elapsed}s"
      return 0
    fi

    if [[ $elapsed -ge $timeout ]]; then
      log "✗ Timeout aguardando porta $port (${timeout}s excedido)"
      return 1
    fi

    sleep 1
  done

  return 1
}

is_private_ip() {
  local ip="$1"
  # Verifica se é rede privada (RFC1918) ou localhost
  if [[ "$ip" =~ ^10\. ]] || \
     [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || \
     [[ "$ip" =~ ^192\.168\. ]] || \
     [[ "$ip" =~ ^127\. ]]; then
    return 0
  fi
  return 1
}

setup_local_hostname() {
  local sys_hostname

  # Tentar obter hostname do sistema
  sys_hostname="$(hostname -s 2>/dev/null || true)"

  # Se vazio ou 'localhost', gerar um nome único
  if [[ -z "$sys_hostname" ]] || [[ "$sys_hostname" == "localhost" ]]; then
    sys_hostname="spfbl-$(date +%s | tail -c 6)"
    log "⚠ Hostname não configurado, usando: $sys_hostname"
  fi

  DETECTED_HOSTNAME="${sys_hostname}.local"

  # Adiciona ao /etc/hosts se não existir
  if ! grep -q "$DETECTED_HOSTNAME" /etc/hosts 2>/dev/null; then
    log "Adicionando $DETECTED_HOSTNAME ao /etc/hosts..."
    printf '%s\t%s %s\n' "$SERVER_IP" "$DETECTED_HOSTNAME" "$sys_hostname" >> /etc/hosts
  fi

  log "Hostname configurado: $DETECTED_HOSTNAME (IP: $SERVER_IP)"
}

###############################
# Etapas principais
###############################
detect_network() {
  local route_line
  route_line="$(ip route get 1.1.1.1 2>/dev/null | head -n1 || true)"
  SERVER_INTERFACE="$(awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}' <<< "$route_line")"
  SERVER_IP="$(awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}' <<< "$route_line")"
  if [[ -z "$SERVER_INTERFACE" ]]; then
    SERVER_INTERFACE="$(ip -o link show | awk -F': ' '!/ lo:/{print $2; exit}')"
  fi
  if [[ -z "$SERVER_IP" && -n "$SERVER_INTERFACE" ]]; then
    SERVER_IP="$(ip -o -4 addr show dev "$SERVER_INTERFACE" | awk '{split($4,a,\"/\"); print a[1]; exit}')"
  fi
  SERVER_INTERFACE="${SERVER_INTERFACE:-lo}"
  SERVER_IP="${SERVER_IP:-127.0.0.1}"
  log "Interface detectada: $SERVER_INTERFACE ($SERVER_IP)"
}

detect_public_ip() {
  PUBLIC_IP="$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"

  # Verifica se o SERVER_IP é privado
  if is_private_ip "$SERVER_IP"; then
    IS_PRIVATE_NETWORK="yes"
    log "Rede privada detectada: $SERVER_IP"

    # Se não conseguiu obter IP público ou se é igual ao privado, usa o privado
    if [[ -z "$PUBLIC_IP" ]] || is_private_ip "$PUBLIC_IP"; then
      PUBLIC_IP="$SERVER_IP"
      log "Servidor em rede interna. Usando IP local: $PUBLIC_IP"
    else
      log "IP público detectado: $PUBLIC_IP (mas servidor está em rede privada)"
    fi
  else
    IS_PRIVATE_NETWORK="no"
    if [[ -z "$PUBLIC_IP" ]]; then
      PUBLIC_IP="$SERVER_IP"
    fi
    log "IP público: $PUBLIC_IP"
  fi
}

install_packages() {
  log "Instalando dependências do sistema..."
  export DEBIAN_FRONTEND=noninteractive

  # Atualizar cache de pacotes
  apt-get update -y -qq

  # Instalar debconf-utils primeiro
  apt-get install -y -qq debconf-utils

  # PRÉ-CONFIGURAR EXIM4 para instalação silenciosa (via debconf)
  # Isso evita prompts interativos durante apt-get install
  log "Pré-configurando Exim4 para instalação silenciosa..."

  # Configuração via debconf-set-selections para não solicitar input
  {
    echo "exim4-config exim4/dc_eximconfig_configtype select $EXIM_CONFIG_TYPE"
    echo "exim4-config exim4/dc_other_hostnames string $MAIL_DOMAIN"
    echo "exim4-config exim4/dc_local_interfaces string $EXIM_LOCAL_INTERFACES"
    echo "exim4-config exim4/dc_readhost string"
    echo "exim4-config exim4/dc_relay_domains string"
    echo "exim4-config exim4/dc_relay_nets string"
    echo "exim4-config exim4/dc_smarthost string"
    echo "exim4-config exim4/dc_minimaldns boolean false"
    echo "exim4-config exim4/dc_use_split_config boolean true"
    echo "exim4-config exim4/dc_hide_mailname boolean false"
    echo "exim4-config exim4/dc_mailname_in_oh boolean true"
    echo "exim4-config exim4/dc_localdelivery select mail_spool"
  } | debconf-set-selections

  # Definir variável para instalação não-interativa
  export DEBIAN_FRONTEND=noninteractive

  # Instalar pacotes
  log "Instalando pacotes necessários..."
  apt-get install -y -qq \
    openjdk-17-jre python3 unzip wget curl tar perl bc \
    nmap ncat netcat-openbsd gnupg dnsutils \
    exim4 exim4-daemon-heavy ufw logrotate

  # Instalar Python 2.7 se disponível (pode não estar em Ubuntu 22.04)
  apt-get install -y -qq python2.7 2>/dev/null || log "⚠ Python 2.7 não disponível, continuando sem ele"

  log "✓ Pacotes instalados com sucesso"
}

ensure_python2_default() {
  # Verificar se python2.7 existe
  if [[ -f /usr/bin/python2.7 ]]; then
    if [[ -e /usr/bin/python && ! -L /usr/bin/python ]]; then
      mv /usr/bin/python "/usr/bin/python.$(date +'%Y%m%d%H%M%S').bak"
    fi
    ln -sf /usr/bin/python2.7 /usr/bin/python
    log "✓ Python 2.7 configurado como padrão"
  elif [[ -f /usr/bin/python3 ]]; then
    # Se python2.7 não existe, usar python3
    if [[ ! -e /usr/bin/python ]]; then
      ln -sf /usr/bin/python3 /usr/bin/python
      log "⚠ Python 2.7 não disponível, usando Python 3"
    fi
  else
    log "⚠ Nenhuma versão do Python encontrada, mas continuando..."
  fi
}

stop_existing_spfbl() {
  log "Verificando se há SPFBL em execução..."

  # Tentar parar via systemctl
  if systemctl is-active --quiet spfbl 2>/dev/null; then
    log "Parando serviço SPFBL..."
    systemctl stop spfbl >/dev/null 2>&1 || {
      log "⚠ Aviso: systemctl stop falhou, tentando kill..."
    }

    # Aguardar parada graciosa
    sleep 2
  fi

  # Procurar e matar processos Java do SPFBL
  local pids
  pids=$(pgrep -f "java.*SPFBL" 2>/dev/null || true)

  if [[ -n "$pids" ]]; then
    log "Encontrados processos SPFBL em execução: $pids"
    log "Matando processos..."

    # Tentar SIGTERM primeiro (gracioso)
    echo "$pids" | xargs kill -TERM 2>/dev/null || true
    sleep 3

    # Se ainda estiverem rodando, usar SIGKILL
    pids=$(pgrep -f "java.*SPFBL" 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
      log "Processo ainda ativo, forçando término..."
      echo "$pids" | xargs kill -KILL 2>/dev/null || true
      sleep 1
    fi

    # Verificar se foram realmente mortos
    if pgrep -f "java.*SPFBL" >/dev/null 2>&1; then
      log "⚠ Aviso: Alguns processos SPFBL podem ainda estar rodando"
      log "  Execute manualmente: sudo pkill -9 -f 'java.*SPFBL'"
    else
      log "✓ Processos SPFBL foram encerrados com sucesso"
    fi
  else
    log "✓ Nenhum processo SPFBL em execução"
  fi
}

detect_and_configure_jvm_memory() {
  # Detectar memória do sistema e configurar JVM automaticamente
  # Estratégia: SPFBL precisa de heap suficiente para carregar cache (domain.map, etc)
  # Deixar ~300-500MB para SO é seguro mesmo em servidores pequenos

  local total_memory_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  local total_memory_mb=$((total_memory_kb / 1024))
  local total_memory_gb=$((total_memory_kb / 1024 / 1024))

  log "Detectando configuração de memória para SPFBL..."
  log "  Memória total do sistema: ${total_memory_gb}GB (${total_memory_mb}MB)"

  # Se usuário forneceu valores manualmente, usar esses
  if [[ -n "$SPFBL_JVM_MIN_MEMORY" && -n "$SPFBL_JVM_MAX_MEMORY" ]]; then
    log "  Usando valores customizados:"
    log "    Mínimo: $SPFBL_JVM_MIN_MEMORY"
    log "    Máximo: $SPFBL_JVM_MAX_MEMORY"
    return 0
  fi

  # Auto-detectar baseado na RAM disponível
  # Princípio: SPFBL PRECISA de heap suficiente para carregar os caches
  # Recomendações do SPFBL:
  #   - Mínimo 512MB para funcionamento básico
  #   - Ideal 1-2GB para carga normal
  #   - >2GB para carga alta
  #
  # Estratégia conservadora:
  #   - Deixar sempre 300-500MB para SO/buffer/cache
  #   - Usar resto para SPFBL JVM
  #   - Min = 25-30% da RAM, Max = 70-80% da RAM

  local os_reserve_mb=400  # Sempre reservar 400MB para SO
  local available_for_jvm=$((total_memory_mb - os_reserve_mb))

  local min_memory_mb
  local max_memory_mb

  if [[ $available_for_jvm -lt 256 ]]; then
    # Servidor muito pequeno (< 656MB total)
    log "  ⚠ Aviso: Servidor muito pequeno, funcionalidade pode ser limitada"
    min_memory_mb=128
    max_memory_mb=$available_for_jvm
  else
    # Usar percentual da memória disponível (após reserva de SO)
    min_memory_mb=$((available_for_jvm * 25 / 100))  # 25% do disponível
    max_memory_mb=$available_for_jvm                  # Use todo o restante

    # Garantir mínimo de 256MB (SPFBL precisa de pelo menos isso)
    [[ $min_memory_mb -lt 256 ]] && min_memory_mb=256

    # Limitar máximo a 16GB (limite prático)
    [[ $max_memory_mb -gt 16384 ]] && max_memory_mb=16384
  fi

  # Garantir sanidade: max >= min
  [[ $max_memory_mb -lt $min_memory_mb ]] && max_memory_mb=$min_memory_mb

  # Converter para formato apropriado
  local jvm_min_str
  local jvm_max_str

  if [[ $min_memory_mb -ge 1024 ]]; then
    jvm_min_str="$((min_memory_mb / 1024))g"
  else
    jvm_min_str="${min_memory_mb}m"
  fi

  if [[ $max_memory_mb -ge 1024 ]]; then
    jvm_max_str="$((max_memory_mb / 1024))g"
  else
    jvm_max_str="${max_memory_mb}m"
  fi

  SPFBL_JVM_MIN_MEMORY="$jvm_min_str"
  SPFBL_JVM_MAX_MEMORY="$jvm_max_str"

  log "  Configuração automática detectada:"
  log "    Total de RAM: ${total_memory_mb}MB"
  log "    Reservado para SO: ${os_reserve_mb}MB"
  log "    Disponível para SPFBL: ${available_for_jvm}MB"
  log "    JVM Mínimo: $SPFBL_JVM_MIN_MEMORY (${min_memory_mb}MB)"
  log "    JVM Máximo: $SPFBL_JVM_MAX_MEMORY (${max_memory_mb}MB)"
}

deploy_spfbl() {
  log "Baixando e instalando SPFBL..."
  BUILD_TMP_DIR="$(mktemp -d)"

  log "Baixando SPFBL do GitHub..."
  if ! wget -q -O "$BUILD_TMP_DIR/master.zip" "$SPFBL_SOURCE_URL"; then
    die "Falha ao baixar SPFBL. Verifique sua conexão com a internet."
  fi

  log "Extraindo arquivos..."
  if ! unzip -q "$BUILD_TMP_DIR/master.zip" -d "$BUILD_TMP_DIR"; then
    die "Falha ao extrair arquivos SPFBL"
  fi

  local src="$BUILD_TMP_DIR/SPFBL-master"
  [[ -d "$src" ]] || die "Pacote SPFBL não encontrado após download."
  log "✓ SPFBL baixado com sucesso"

  if [[ -d "$SPFBL_INSTALL_DIR" ]]; then
    backup_file "$SPFBL_INSTALL_DIR"
    rm -rf "$SPFBL_INSTALL_DIR"
  fi

  mkdir -p "$SPFBL_INSTALL_DIR"
  cp -a "$src/dist/SPFBL.jar" "$SPFBL_INSTALL_DIR/"
  cp -a "$src/run/spfbl.conf" "$SPFBL_INSTALL_DIR/"
  cp -a "$src/lib" "$SPFBL_INSTALL_DIR/"
  cp -a "$src/data" "$SPFBL_INSTALL_DIR/"
  cp -a "$src/web" "$SPFBL_INSTALL_DIR/"
  cp -a "$src/client/spfblpostfix.pl" "$SPFBL_INSTALL_DIR/"
  chmod +x "$SPFBL_INSTALL_DIR/spfblpostfix.pl"
  mkdir -p "$SPFBL_HISTORY_DIR" "$SPFBL_LOG_DIR"

  cp "$src/client/spfbl.sh" "$SPFBL_CLIENT_BIN"
  chmod +x "$SPFBL_CLIENT_BIN"
  cp "$src/run/spfbl-init.sh" "$SPFBL_SERVICE_SCRIPT"
  chmod 755 "$SPFBL_SERVICE_SCRIPT"

  mkdir -p "$SPFBL_INSTALL_DIR/tools"
  cp "$src/client/spfbl.sh" "$SPFBL_CLIENT_TEMPLATE"
  mkdir -p "$SPFBL_INSTALL_DIR/client-samples"
  cp -a "$src/client/." "$SPFBL_INSTALL_DIR/client-samples/"

  sed -i "s|^IP_SERVIDOR=.*|IP_SERVIDOR=\"127.0.0.1\"|" "$SPFBL_CLIENT_BIN"

  # Configurar JVM com memória detectada
  sed -i "s/-Xms[0-9a-zA-Z]* -Xmx[0-9a-zA-Z]*/-Xms${SPFBL_JVM_MIN_MEMORY} -Xmx${SPFBL_JVM_MAX_MEMORY}/" "$SPFBL_SERVICE_SCRIPT"
  log "✓ JVM configurado: -Xms${SPFBL_JVM_MIN_MEMORY} -Xmx${SPFBL_JVM_MAX_MEMORY}"
}

configure_spfbl_conf() {
  log "Ajustando spfbl.conf..."
  local conf="$SPFBL_INSTALL_DIR/spfbl.conf"

  # SEMPRE configurar hostname local primeiro
  setup_local_hostname

  # Determina qual hostname usar
  local use_hostname="$MAIL_HOSTNAME"
  if [[ -z "$use_hostname" ]]; then
    use_hostname="$DETECTED_HOSTNAME"
  fi

  # Garantir que use_hostname não esteja vazio
  if [[ -z "$use_hostname" ]]; then
    use_hostname="localhost.localdomain"
    log "⚠ Usando hostname padrão: $use_hostname"
  fi

  # Atualiza SPFBL_CLIENT_LABEL se estiver vazio
  if [[ -z "$SPFBL_CLIENT_LABEL" ]]; then
    SPFBL_CLIENT_LABEL="$use_hostname"
  fi

  set_conf_kv "$conf" "dns_provider_primary" "$SPFBL_DNS_PROVIDER_PRIMARY"
  set_conf_kv "$conf" "hostname" "$use_hostname"
  set_conf_kv "$conf" "interface" "$SERVER_INTERFACE"
  set_conf_kv "$conf" "http_port" "$SPFBL_HTTP_PORT"
  set_conf_kv "$conf" "admin_email" "$SPFBL_ADMIN_EMAIL"
  set_conf_kv "$conf" "smtp_auth" "true"
  set_conf_kv "$conf" "smtp_starttls" "$SPFBL_HTTP_USE_TLS"
  set_conf_kv "$conf" "smtp_host" "$use_hostname"
  set_conf_kv "$conf" "smtp_port" "587"
  set_conf_kv "$conf" "smtp_user" "$SPFBL_ADMIN_EMAIL"
  set_conf_kv "$conf" "smtp_password" "$SPFBL_ADMIN_PASSWORD"
  set_conf_kv "$conf" "peer_limit" "127"
  set_conf_kv "$conf" "dnsbl_limit" "127"
  set_conf_kv "$conf" "spfbl_limit" "127"
  set_conf_kv "$conf" "defer_time_softfail" "0"
  set_conf_kv "$conf" "defer_time_yellow" "0"
  set_conf_kv "$conf" "cache_time_store" "120"

  log "Hostname configurado no SPFBL: $use_hostname"
}

install_new_dashboard() {
  log "Instalando dashboard personalizada (API e frontend)..."

  local src_base="$SCRIPT_DIR/newdash"
  local src_backend="$src_base/backend"
  local src_frontend="$src_base/frontend"
  local src_systemd="$src_base/systemd"

  # Verificar se os arquivos mínimos necessários existem no pacote de instalação
  if [[ ! -f "$src_backend/spfbl-api.py" ]]; then
    log "⚠ Arquivo backend da dashboard não encontrado em $src_backend/spfbl-api.py - pulando instalação da nova dashboard"
    return 0
  fi

  if [[ ! -f "$src_frontend/dashboard.html" ]] || [[ ! -f "$src_frontend/dashboard.css" ]] || [[ ! -f "$src_frontend/dashboard.js" ]] || [[ ! -f "$src_frontend/login.html" ]] || [[ ! -f "$src_frontend/login.css" ]] || [[ ! -f "$src_frontend/settings.html" ]]; then
    log "⚠ Arquivos frontend da dashboard incompletos em $src_frontend - pulando instalação da nova dashboard"
    return 0
  fi

  mkdir -p "$SPFBL_WEB_DIR"

  # Backups dos arquivos antigos (se existirem)
  backup_file "$SPFBL_INSTALL_DIR/spfbl-api.py"
  backup_file "$SPFBL_WEB_DIR/dashboard.html"
  backup_file "$SPFBL_WEB_DIR/dashboard.css"
  backup_file "$SPFBL_WEB_DIR/dashboard.js"
  backup_file "$SPFBL_WEB_DIR/login.html"
  backup_file "$SPFBL_WEB_DIR/login.css"
  backup_file "$SPFBL_WEB_DIR/settings.html"

  # Copiar backend da API (todo o conteúdo de backend/)
  cp -a "$src_backend/." "$SPFBL_INSTALL_DIR/"
  chmod 700 "$SPFBL_INSTALL_DIR/spfbl-api.py"

  # Copiar frontend (todo o conteúdo de frontend/)
  cp -a "$src_frontend/." "$SPFBL_WEB_DIR/"

  # Configurar serviço systemd da API da dashboard, se disponível
  if [[ -f "$src_systemd/spfbl-api.service" ]]; then
    backup_file "/etc/systemd/system/spfbl-api.service"
    # Copiar todos os arquivos de systemd/ (inclui spfbl-api.service)
    cp -a "$src_systemd/." "/etc/systemd/system/"
    chmod 644 "/etc/systemd/system/spfbl-api.service"
    systemctl daemon-reload
    systemctl enable spfbl-api >/dev/null 2>&1 || true
    if ! systemctl restart spfbl-api >/dev/null 2>&1; then
      log "⚠ Não foi possível iniciar o serviço spfbl-api. Verifique 'journalctl -u spfbl-api -n 50'."
    else
      log "✓ Serviço spfbl-api (dashboard) instalado e iniciado (porta $DASHBOARD_HTTP_PORT)"
    fi
  else
    log "⚠ Arquivo systemd da dashboard não encontrado em $src_systemd - serviço spfbl-api não foi configurado automaticamente"
  fi
}

configure_spfbl_template() {
  if [[ -f "$SPFBL_CLIENT_TEMPLATE" ]]; then
    # Para redes privadas, use o IP local; caso contrário, use o público
    local client_ip="$SERVER_IP"
    if [[ "$IS_PRIVATE_NETWORK" != "yes" ]] && [[ -n "$PUBLIC_IP" ]]; then
      client_ip="$PUBLIC_IP"
    fi

    sed -i "s|^IP_SERVIDOR=.*|IP_SERVIDOR=\"$client_ip\"|" "$SPFBL_CLIENT_TEMPLATE"
    sed -i "s|^PORTA_SERVIDOR=.*|PORTA_SERVIDOR=\"$SPFBL_POLICY_PORT\"|" "$SPFBL_CLIENT_TEMPLATE"
    sed -i "s|^PORTA_ADMIN=.*|PORTA_ADMIN=\"$SPFBL_ADMIN_PORT\"|" "$SPFBL_CLIENT_TEMPLATE"
    log "Template cliente configurado para: $client_ip:$SPFBL_POLICY_PORT"
  fi
}

setup_spfbl_service() {
  log "Registrando serviço SPFBL..."
  cat >/etc/systemd/system/spfbl.service <<EOF
[Unit]
Description=SPFBL Anti-spam Service
After=network.target

[Service]
Type=forking
ExecStart=$SPFBL_SERVICE_SCRIPT start
ExecStop=$SPFBL_SERVICE_SCRIPT stop
ExecReload=$SPFBL_SERVICE_SCRIPT restart

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable spfbl >/dev/null 2>&1
}

setup_spfbl_cron() {
  local cron_line="0 1 * * * root $SPFBL_CLIENT_BIN store"
  grep -qxF "$cron_line" /etc/crontab || printf '%s\n' "$cron_line" >> /etc/crontab
}

start_spfbl_service() {
  log "Iniciando SPFBL..."

  # Tentar iniciar o serviço
  if ! systemctl restart spfbl 2>/dev/null; then
    log "⚠ Aviso: systemctl restart falhou, tentando iniciar..."
    systemctl start spfbl >/dev/null 2>&1
  fi

  # Aguardar a porta ficar disponível
  if wait_for_port "127.0.0.1" "$SPFBL_ADMIN_PORT" 120; then
    log "✓ SPFBL iniciado com sucesso na porta $SPFBL_ADMIN_PORT"
    return 0
  fi

  # Se falhou, fazer diagnóstico detalhado
  log ""
  log "✗ ERRO: SPFBL não respondeu na porta administrativa ($SPFBL_ADMIN_PORT)"
  log ""
  log "Executando diagnóstico..."
  log ""

  # Verificar se o serviço está rodando
  log "1. Status do serviço SPFBL:"
  systemctl status spfbl 2>&1 | sed 's/^/   /'

  log ""
  log "2. Verificar se a porta está aberta:"
  netstat -tlnp 2>/dev/null | grep -E "($SPFBL_ADMIN_PORT|$SPFBL_POLICY_PORT|$SPFBL_HTTP_PORT)" || \
    ss -tlnp 2>/dev/null | grep -E "($SPFBL_ADMIN_PORT|$SPFBL_POLICY_PORT|$SPFBL_HTTP_PORT)" || \
    log "   ⚠ Nenhuma porta respondendo"

  log ""
  log "3. Últimas linhas do log do SPFBL:"
  tail -20 "$SPFBL_LOG_DIR"/spfbl.*.log 2>/dev/null | sed 's/^/   /' || \
    log "   ⚠ Arquivo de log não encontrado"

  log ""
  log "4. Verificar permissões de /opt/spfbl:"
  ls -ld "$SPFBL_INSTALL_DIR" 2>/dev/null | sed 's/^/   /'

  log ""
  log "5. Verificar se Java está disponível:"
  java -version 2>&1 | sed 's/^/   /'

  log ""
  log "6. Memória disponível:"
  free -h 2>/dev/null | sed 's/^/   /'

  log ""
  log "SOLUÇÃO SUGERIDA:"
  log "  1. Verifique os logs: tail -f $SPFBL_LOG_DIR/spfbl.*.log"
  log "  2. Reinicie manualmente: sudo systemctl restart spfbl"
  log "  3. Aguarde 30-60 segundos e verifique o status"
  log "  4. Verifique memória e recursos do sistema"
  log ""

  return 1
}

configure_spfbl_accounts() {
  log "Configurando conta administrativa do SPFBL..."

  # Adicionar usuário admin
  $SPFBL_CLIENT_BIN user add "$SPFBL_ADMIN_EMAIL" admin >/dev/null 2>&1 || true

  # Definir senha
  printf 'USER SET %s PASSWORD %s\n' "$SPFBL_ADMIN_EMAIL" "$SPFBL_ADMIN_PASSWORD" | nc 127.0.0.1 "$SPFBL_ADMIN_PORT" >/dev/null

  # Garantir que SPFBL_CLIENT_LABEL não está vazio
  if [[ -z "$SPFBL_CLIENT_LABEL" ]]; then
    SPFBL_CLIENT_LABEL="localhost"
    log "⚠ SPFBL_CLIENT_LABEL vazio, usando: localhost"
  fi

  # Adicionar cliente local
  log "Autorizando cliente local: $SPFBL_CLIENT_CIDR ($SPFBL_CLIENT_LABEL)"
  $SPFBL_CLIENT_BIN client add "$SPFBL_CLIENT_CIDR" "$SPFBL_CLIENT_LABEL" SPFBL "$SPFBL_ADMIN_EMAIL" >/dev/null 2>&1 || true
}

configure_authorized_servers() {
  local total_servers=0
  local authorized_list=()

  # Processar AUTHORIZED_SERVERS (formato completo)
  for entry in "${AUTHORIZED_SERVERS[@]}"; do
    [[ -n "$entry" ]] || continue
    authorized_list+=("$entry")
    ((total_servers++))
  done

  # Processar AUTHORIZED_SERVERS_SIMPLE (formato simplificado: apenas IP)
  for ip in "${AUTHORIZED_SERVERS_SIMPLE[@]}"; do
    [[ -n "$ip" ]] || continue
    # Adicionar /32 se não tiver máscara
    if [[ ! "$ip" =~ / ]]; then
      ip="$ip/32"
    fi
    # Gerar identificador automático
    local clean_ip="${ip//\//_}"
    local ident="mail-${clean_ip//\./_}"
    authorized_list+=("$ip:$ident:$SPFBL_ADMIN_EMAIL")
    ((total_servers++))
  done

  # Processar POLICY_CLIENTS (compatibilidade retroativa)
  for entry in "${POLICY_CLIENTS[@]}"; do
    [[ -n "$entry" ]] || continue
    authorized_list+=("$entry")
    ((total_servers++))
  done

  # Se não houver servidores, retornar
  [[ $total_servers -gt 0 ]] || return 0

  log "Autorizando $total_servers servidor(es) a consultar o SPFBL..."

  # Autorizar cada servidor
  for entry in "${authorized_list[@]}"; do
    IFS=':' read -r cidr ident contact <<<"$entry"
    cidr="${cidr:-}"
    ident="${ident:-external-client}"
    contact="${contact:-$SPFBL_ADMIN_EMAIL}"

    [[ -n "$cidr" ]] || continue

    log "  → Autorizando: $cidr ($ident)"
    $SPFBL_CLIENT_BIN client add "$cidr" "$ident" SPFBL "$contact" >/dev/null 2>&1 || true
  done

  log "Servidores autorizados com sucesso!"
}

# Manter para compatibilidade
configure_postmaster_accounts() {
  [[ ${#POSTMASTER_DOMAINS[@]} -gt 0 ]] || return 0
  log "Criando contas de postmaster no SPFBL..."
  for entry in "${POSTMASTER_DOMAINS[@]}"; do
    [[ -n "$entry" ]] || continue
    IFS=':' read -r domain password <<<"$entry"
    [[ -n "$domain" && -n "$password" ]] || continue
    local account="postmaster@$domain"
    $SPFBL_CLIENT_BIN user add "$account" postmaster >/dev/null 2>&1 || true
    printf 'USER SET %s PASSWORD %s\n' "$account" "$password" | nc 127.0.0.1 "$SPFBL_ADMIN_PORT" >/dev/null
  done
}

install_exim() {
  log "Configurando Exim4 com instalação silenciosa..."

  # Atualizar a configuração baseado nas pré-configurações via debconf
  update-exim4.conf >/dev/null 2>&1 || log "⚠ Aviso ao atualizar configuração Exim4"

  # Habilitar e iniciar o serviço
  systemctl enable exim4 >/dev/null 2>&1
  systemctl start exim4 >/dev/null 2>&1

  # Aguardar serviço iniciar
  sleep 2

  # Verificar se iniciou corretamente
  if systemctl is-active --quiet exim4; then
    log "✓ Exim4 configurado e iniciado com sucesso"
    log "  - Tipo: Internet site (SMTP local)"
    log "  - Interfaces: $EXIM_LOCAL_INTERFACES"
    log "  - Domínio: $MAIL_DOMAIN"
    log "  - Porta SMTP: $EXIM_SMTP_PORT"
  else
    log "⚠ Aviso: Exim4 pode ter problemas ao iniciar"
    log "  Verifique com: sudo systemctl status exim4"
    log "  Ou consulte logs: sudo tail -f /var/log/exim4/mainlog"
  fi
}

configure_exim_smtp_port() {
  # Configurar porta SMTP do Exim4 dinamicamente
  log "Configurando porta SMTP do Exim4..."

  # Validar porta
  if [[ ! "$EXIM_SMTP_PORT" =~ ^[0-9]+$ ]] || [[ $EXIM_SMTP_PORT -lt 1 ]] || [[ $EXIM_SMTP_PORT -gt 65535 ]]; then
    log "⚠ Aviso: EXIM_SMTP_PORT inválida ($EXIM_SMTP_PORT), usando padrão 25"
    EXIM_SMTP_PORT=25
  fi

  # Criar arquivo de configuração para definir a porta SMTP
  # Este arquivo será lido pelo update-exim4.conf
  mkdir -p /etc/exim4/conf.d/main
  cat > /etc/exim4/conf.d/main/02_exim4-config_ports <<EOFEXIM
# Configuração de portas Exim4 - customizada para $EXIM_SMTP_PORT
.ifdef MAIN_DAEMON_SMTP_PORTS
daemon_smtp_ports = MAIN_DAEMON_SMTP_PORTS
.else
daemon_smtp_ports = $EXIM_SMTP_PORT
.endif
EOFEXIM

  log "✓ Arquivo de portas criado: /etc/exim4/conf.d/main/02_exim4-config_ports"

  # Também configurar a macro no arquivo de macros
  local exim_macros="/etc/exim4/conf.d/main/01_exim4-config_listmacrosdefs"

  if [[ -f "$exim_macros" ]]; then
    log "✓ Configurando macro de porta em: $exim_macros"

    # Remover qualquer configuração anterior de porta
    sed -i '/^MAIN_DAEMON_SMTP_PORTS.*/d' "$exim_macros"

    # Inserir a macro ANTES da linha de debconf
    sed -i '/UPEX4CmacrosUPEX4C = 1/i\
# Configuração de porta SMTP customizada\
MAIN_DAEMON_SMTP_PORTS = '"$EXIM_SMTP_PORT"'
' "$exim_macros"
  fi

  # Recarregar configuração do Exim
  log "Recarregando configuração Exim4..."
  update-exim4.conf >/dev/null 2>&1 || log "⚠ Aviso ao recarregar Exim4"

  # Reiniciar Exim para aplicar a porta
  log "Reiniciando Exim4..."
  systemctl restart exim4 >/dev/null 2>&1 || log "⚠ Aviso ao reiniciar Exim4"

  # Aguardar restart
  sleep 3

  # Verificar se porta está configurada corretamente
  local check_port=$(exim4 -bP 2>/dev/null | grep "daemon_smtp_ports")

  if echo "$check_port" | grep -q "$EXIM_SMTP_PORT"; then
    log "✓ Exim4 configurado para porta $EXIM_SMTP_PORT (SMTP)"
    log "  Confirmação: $check_port"
  elif ss -tlnp 2>/dev/null | grep -q ":$EXIM_SMTP_PORT"; then
    log "✓ Exim4 listening na porta $EXIM_SMTP_PORT"
  elif netstat -tlnp 2>/dev/null | grep -q ":$EXIM_SMTP_PORT"; then
    log "✓ Exim4 listening na porta $EXIM_SMTP_PORT"
  else
    log "⚠ Aviso: Exim4 pode não estar respondendo na porta $EXIM_SMTP_PORT"
    log "  Verificação: exim4 -bP | grep daemon_smtp_ports"
    log "  Resultado: $check_port"
    log "  Verifique com: sudo exim4 -bP | grep daemon_smtp_ports"
    log "  Ou: sudo ss -tlnp | grep exim"
  fi
}

detect_ssh_port() {
  # Detectar porta SSH automáticamente se não foi configurada
  if [[ -z "$FIREWALL_SSH_PORT" ]]; then
    FIREWALL_SSH_PORT=$(grep -E "^#?Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $NF}' | tail -1)
    FIREWALL_SSH_PORT="${FIREWALL_SSH_PORT:-22}"
    log "✓ Porta SSH detectada: $FIREWALL_SSH_PORT"
  fi
}

configure_firewall() {
  # Retornar se configuração automática está desativada
  if [[ "$FIREWALL_AUTO_CONFIG" != "yes" ]]; then
    log "⚠ Configuração automática de firewall desativada"
    log "  Para ativar, defina FIREWALL_AUTO_CONFIG=\"yes\" no topo do script"
    return 0
  fi

  detect_ssh_port

  # Configurar UFW (instalando se necessário)
  if [[ "$UFW_AUTO_CONFIG" == "yes" ]]; then
    configure_ufw_firewall
  fi

  # Configurar CSF (se disponível)
  if [[ -f /etc/csf/csf.conf ]] && [[ "$CSF_AUTO_CONFIG" == "yes" ]]; then
    log "Configurando CSF Firewall..."
    configure_csf_firewall
    log "✓ CSF configurado com sucesso"
  fi
}

configure_ufw_firewall() {
  # Verificar se UFW está instalado
  if ! command -v ufw >/dev/null 2>&1; then
    log "UFW não encontrado, instalando..."
    apt-get update >/dev/null 2>&1
    apt-get install -y ufw >/dev/null 2>&1 || {
      log "✗ Erro ao instalar UFW"
      return 1
    }
    log "✓ UFW instalado com sucesso"
  fi

  log "Configurando UFW Firewall..."

  # Verificar status do UFW
  local ufw_status=$(ufw status 2>&1 | grep "Status:" | awk '{print $NF}')

  # Se UFW não está ativo, ativar
  if [[ "$ufw_status" != "active" ]]; then
    log "  UFW não está ativo, ativando..."

    # Usar --force enable para não pedir confirmação
    ufw --force enable >/dev/null 2>&1
    local enable_result=$?

    if [[ $enable_result -eq 0 ]]; then
      log "  ✓ UFW ativado com sucesso"
    else
      log "⚠ Aviso: UFW pode não ter sido ativado corretamente (código: $enable_result)"
    fi
  else
    log "  ✓ UFW já está ativo"
  fi

  # Permitir SSH (detectado automaticamente)
  ufw allow "$FIREWALL_SSH_PORT"/tcp >/dev/null 2>&1 || true
  log "  ✓ Porta SSH ($FIREWALL_SSH_PORT) permitida"

  # Permitir porta SMTP (Exim) - dinâmica
  ufw allow "$EXIM_SMTP_PORT"/tcp >/dev/null 2>&1 || true
  log "  ✓ Porta SMTP Exim ($EXIM_SMTP_PORT) permitida"

  # Permitir portas SPFBL
  for port in "${FIREWALL_SPFBL_PORTS[@]}"; do
    [[ -n "$port" ]] || continue
    ufw allow "$port"/tcp >/dev/null 2>&1 || true
    log "  ✓ Porta $port permitida"
  done

  # Permitir porta administrativa apenas de localhost
  if [[ "$FIREWALL_ADMIN_PORT_LOOPBACK_ONLY" == "yes" ]]; then
    ufw allow from 127.0.0.1 to any port "$SPFBL_ADMIN_PORT" proto tcp >/dev/null 2>&1 || true
    log "  ✓ Porta administrativa ($SPFBL_ADMIN_PORT) permitida apenas de localhost"
  fi

  # Recarregar UFW para aplicar mudanças
  ufw reload >/dev/null 2>&1 || true

  log "✓ UFW configurado e ativado com sucesso"
}

configure_csf_firewall() {
  # Detectar porta SSH para CSF
  detect_ssh_port

  # TCP_IN - portas que aceitam conexões de entrada
  local all_in_ports="${FIREWALL_SSH_PORT},${EXIM_SMTP_PORT}"  # SSH e SMTP (dinâmica)
  for port in "${FIREWALL_SPFBL_PORTS[@]}"; do
    # Evitar duplicação de portas
    [[ "$port" == "${EXIM_SMTP_PORT}" ]] && continue
    [[ -n "$port" ]] && all_in_ports+=",${port}"
  done
  all_in_ports+=",${SPFBL_ADMIN_PORT}"

  # TCP_OUT - portas que aceitam conexões de saída (geralmente 1:65535 ou todas)
  local all_out_ports="$all_in_ports"

  # Atualizar TCP_IN
  if ! grep -q "TCP_IN.*${FIREWALL_SSH_PORT}" /etc/csf/csf.conf; then
    sed -i "s/^TCP_IN = \"\(.*\)\"/TCP_IN = \"${all_in_ports}\"/" /etc/csf/csf.conf
    log "  ✓ TCP_IN (entrada) atualizado com portas: $all_in_ports"
  fi

  # Atualizar TCP_OUT
  if ! grep -q "TCP_OUT.*${FIREWALL_SSH_PORT}" /etc/csf/csf.conf; then
    sed -i "s/^TCP_OUT = \"\(.*\)\"/TCP_OUT = \"${all_out_ports}\"/" /etc/csf/csf.conf
    log "  ✓ TCP_OUT (saída) atualizado com portas: $all_out_ports"
  fi

  # Reiniciar CSF
  csf -r >/dev/null 2>&1 || true
}

verify_installation() {
  log "Verificando instalação..."
  local errors=0

  # Verifica se o serviço está rodando
  if ! systemctl is-active --quiet spfbl; then
    log "AVISO: Serviço SPFBL não está ativo"
    ((errors++))
  fi

  # Verifica se as portas estão abertas
  if ! wait_for_port "127.0.0.1" "$SPFBL_ADMIN_PORT" 5; then
    log "AVISO: Porta administrativa ($SPFBL_ADMIN_PORT) não está respondendo"
    ((errors++))
  fi

  if ! wait_for_port "127.0.0.1" "$SPFBL_POLICY_PORT" 5; then
    log "AVISO: Porta de policy ($SPFBL_POLICY_PORT) não está respondendo"
    ((errors++))
  fi

  if ! wait_for_port "127.0.0.1" "$SPFBL_HTTP_PORT" 5; then
    log "AVISO: Porta HTTP ($SPFBL_HTTP_PORT) não está respondendo"
    log "Verifique os logs em /var/log/spfbl/ para mais detalhes"
    ((errors++))
  fi

  if [[ $errors -eq 0 ]]; then
    log "✓ Todas as verificações passaram com sucesso"
  else
    log "⚠ $errors verificação(ões) falharam. Verifique os logs."
  fi

  return $errors
}

generate_directadmin_installer() {
  local installer_file="$SCRIPT_DIR/install_spfbl_directadmin_${SERVER_IP//./_}.sh"

  log "Gerando script de instalação para DirectAdmin..."

  cat >"$installer_file" <<'EOFINSTALLER'
#!/bin/bash
#
# Script de Instalação SPFBL para DirectAdmin
# Gerado automaticamente pelo instalador SPFBL RBL
#
# IMPORTANTE: Este script faz backup de todas as configurações antes de modificar
#
# Uso: bash install_spfbl_directadmin.sh [install|uninstall|test]
#

set -euo pipefail

# CONFIGURAÇÕES (NÃO MODIFIQUE - Gerado automaticamente)
EOFINSTALLER

  # Adicionar configurações
  cat >>"$installer_file" <<EOFCONFIG
SPFBL_SERVER_IP="$SERVER_IP"
SPFBL_POLICY_PORT="$SPFBL_POLICY_PORT"
SPFBL_ADMIN_PORT="$SPFBL_ADMIN_PORT"
SPFBL_CLIENT_URL="http://$SERVER_IP:$SPFBL_HTTP_PORT"
BACKUP_DIR="/root/spfbl_backups"
INSTALL_DATE="\$(date +'%Y-%m-%d_%H-%M-%S')"
DIRECTADMIN_DOC_URL="https://docs.directadmin.com/other-hosting-services/exim/configuring-exim.html"
CUSTOMBUILD_DIR="/usr/local/directadmin/custombuild"

EOFCONFIG

  # Adicionar funções do script
  cat >>"$installer_file" <<'EOFSCRIPT'
###############################
# Funções Auxiliares
###############################

log() {
  printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
}

die() {
  log "ERRO: $*"
  exit 1
}

require_root() {
  [[ $EUID -eq 0 ]] || die "Este script precisa ser executado como root."
}

check_directadmin() {
  if [[ ! -f /usr/local/directadmin/directadmin ]]; then
    die "DirectAdmin não encontrado. Este script é apenas para servidores DirectAdmin."
  fi
  log "✓ DirectAdmin encontrado"
}

create_backup() {
  local file="$1"
  [[ -f "$file" ]] || return 0

  mkdir -p "$BACKUP_DIR"
  local backup_file="$BACKUP_DIR/$(basename "$file").backup.$INSTALL_DATE"
  cp -a "$file" "$backup_file"
  log "✓ Backup criado: $backup_file"
}

test_connectivity() {
  log "Testando conectividade com servidor SPFBL..."

  if command -v nc >/dev/null 2>&1; then
    if timeout 3 bash -c "echo '' | nc -w 1 $SPFBL_SERVER_IP $SPFBL_POLICY_PORT" >/dev/null 2>&1; then
      log "✓ Conectividade OK com $SPFBL_SERVER_IP:$SPFBL_POLICY_PORT"
      return 0
    fi
  fi

  log "⚠ AVISO: Não foi possível conectar ao servidor SPFBL"
  log "  Verifique se o servidor está rodando e se o firewall permite a conexão"
  return 1
}

print_exim_manual_steps() {
  log ""
  log "⚠ PASSO MANUAL NECESSÁRIO: recompilar e reiniciar o Exim"
  log "  Referência: $DIRECTADMIN_DOC_URL"
  if [[ -x "$CUSTOMBUILD_DIR/build" ]]; then
    log "  cd $CUSTOMBUILD_DIR"
    log "  ./build rewrite_confs"
    log "  ./build exim_conf"
  else
    log "  da build exim_conf"
  fi
  log "  systemctl restart exim  # ou service exim restart"
}

###############################
# Funções de Instalação
###############################

install_dependencies() {
  log "Instalando dependências..."

  if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y nmap ncat wget >/dev/null 2>&1
  elif command -v yum >/dev/null; then
    yum install -y nmap nc wget >/dev/null 2>&1
  else
    die "Gerenciador de pacotes não identificado (apt-get ou yum)"
  fi

  log "✓ Dependências instaladas"
}

install_spfbl_client() {
  log "Instalando cliente SPFBL..."

  local template_source="/opt/spfbl/tools/spfbl-client-template.sh"
  local target_path="/usr/local/bin/spfbl"

  while true; do
    read -rp "O cliente SPFBL já está presente em $target_path? [y/N] " copied
    if [[ "$copied" =~ ^[Yy] ]]; then
      if [[ -f "$target_path" ]]; then
        break
      fi
      log "⚠ Arquivo $target_path não encontrado, mesmo depois da cópia."
      log "  Verifique se o arquivo foi transferido corretamente para $target_path."
    fi
    log "⚠ Copiar o template do SPFBL é necessário para prosseguir."
    log "  scp root@$SPFBL_SERVER_IP:$template_source $target_path"
    log "  chmod +x $target_path"
    log "  Reexecute este script após concluir a cópia."
    read -rp "Deseja continuar a instalação (para repetir a pergunta) ou encerrar agora? [c/E] " decision
    if [[ "$decision" =~ ^[Cc] ]]; then
      continue
    fi
    log "Instalação interrompida. Copie o arquivo e execute novamente quando estiver pronto."
    exit 1
  done

  if [[ -f "$target_path" ]]; then
    chmod +x "$target_path"
    log "✓ Cliente em $target_path pronto para uso"
  else
    log "⚠ Arquivo esperado ($target_path) não encontrado; coloque o cliente neste caminho e execute novamente."
    exit 1
  fi

  # Configurar IP do servidor
  sed -i "s|^IP_SERVIDOR=.*|IP_SERVIDOR=\"$SPFBL_SERVER_IP\"|" /usr/local/bin/spfbl
  sed -i "s|^PORTA_SERVIDOR=.*|PORTA_SERVIDOR=\"$SPFBL_POLICY_PORT\"|" /usr/local/bin/spfbl
  sed -i "s|^PORTA_ADMIN=.*|PORTA_ADMIN=\"$SPFBL_ADMIN_PORT\"|" /usr/local/bin/spfbl

  log "✓ Cliente SPFBL instalado e configurado"
}

test_spfbl_client() {
  log "Testando cliente SPFBL..."

  local result
  result=$(/usr/local/bin/spfbl query 8.8.8.8 teste@gmail.com google.com destinatario@teste.com 2>&1 || true)

  if [[ "$result" =~ (PASS|NEUTRAL|NONE|WHITE) ]]; then
    log "✓ Cliente SPFBL funcionando: $result"
    return 0
  else
    log "⚠ AVISO: Resposta inesperada do SPFBL: $result"
    return 1
  fi
}

create_exim_integration() {
  log "Criando configuração de integração com Exim (método DirectAdmin)..."

  # Fazer backups
  create_backup /etc/exim.conf
  create_backup /etc/exim.acl_check_recipient.pre.conf
  create_backup /etc/exim.variables.conf.custom

  # Criar arquivo ACL no local RECOMENDADO pelo DirectAdmin
  log "Criando /etc/exim.acl_check_recipient.pre.conf..."
  cat >/etc/exim.acl_check_recipient.pre.conf <<'EOFACL'
# ============================================
# INTEGRAÇÃO SPFBL - Consulta ao RBL
# ============================================
# Este arquivo é incluído na configuração do Exim
# e realiza consultas ao servidor SPFBL

# Armazenar resultado da consulta SPFBL
warn
  set acl_m_spfbl = ${run{/usr/local/bin/spfbl query \
    $sender_host_address \
    $sender_address \
    $sender_helo_name \
    $local_part@$domain}{$value}{TIMEOUT}}

# Log da consulta
warn
  log_message = SPFBL-CHECK: $acl_m_spfbl

# Rejeitar se BLOCKED ou BANNED
deny
  condition = ${if match{$acl_m_spfbl}{^(BLOCKED|BANNED)}{yes}{no}}
  message = Message rejected by SPFBL security policy

# Aceitar imediatamente se WHITE (whitelist)
accept
  condition = ${if match{$acl_m_spfbl}{^WHITE}{yes}{no}}

# Implementar GREYLIST
defer
  condition = ${if match{$acl_m_spfbl}{^GREYLIST}{yes}{no}}
  message = Greylisted - please try again later

# Rejeitar se LISTED (em blacklist temporária)
deny
  condition = ${if match{$acl_m_spfbl}{^LISTED}{yes}{no}}
  message = Temporarily listed in blacklist

# Descartar silenciosamente SPAMTRAP
discard
  condition = ${if match{$acl_m_spfbl}{^SPAMTRAP}{yes}{no}}

# FLAG: Marcar como spam mas aceitar
warn
  condition = ${if match{$acl_m_spfbl}{^FLAG}{yes}{no}}
  add_header = X-Spam-Flag: YES
  add_header = X-Spam-Status: Yes, flagged by SPFBL

# Adicionar cabeçalho com resultado
warn
  add_header = X-SPFBL-Result: $acl_m_spfbl

EOFACL

  log "✓ Arquivo ACL criado: /etc/exim.acl_check_recipient.pre.conf"

  log "⚠ Alterações aplicadas. Execute a recompilação/recarga do Exim manualmente para que a ACL entre em vigor."
  print_exim_manual_steps
  log "✓ Integração com Exim preparada usando os arquivos recomendados pelo DirectAdmin"
}

show_integration_instructions() {
  log ""
  log "═══════════════════════════════════════════════════════════"
  log "✓ PREPARO CONCLUÍDO COM SUCESSO!"
  log "═══════════════════════════════════════════════════════════"
  log ""
  log "Integração criada seguindo o método recomendado pelo DirectAdmin:"
  log ""
  log "  • ACL dedicada: /etc/exim.acl_check_recipient.pre.conf"
  log "  • Backups armazenados em: $BACKUP_DIR"
  log "  • Cliente SPFBL: /usr/local/bin/spfbl"
  log ""
  log "Para aplicar as mudanças, execute a recompilação e reinício do Exim:"
  print_exim_manual_steps
  log ""
  log "O DirectAdmin inclui automaticamente os arquivos:"
  log "  • /etc/exim.acl_check_recipient.pre.conf"
  log "  • /etc/exim.variables.conf.custom (se existir)"
  log ""
  log "Estes arquivos são PRESERVADOS durante atualizações do DirectAdmin."
  log ""
  log "═══════════════════════════════════════════════════════════"
  log "VERIFICAÇÃO E MONITORAMENTO:"
  log "═══════════════════════════════════════════════════════════"
  log ""
  log "1. Testar cliente SPFBL:"
  log "   /usr/local/bin/spfbl query 8.8.8.8 test@gmail.com google.com user@domain.com"
  log ""
  log "2. Monitorar logs em tempo real:"
  log "   tail -f /var/log/exim/mainlog | grep SPFBL"
  log ""
  log "3. Ver configuração ativa do Exim:"
  log "   grep -A 20 'acl_check_rcpt:' /etc/exim.conf"
  log ""
  log "4. Verificar se o arquivo foi incluído:"
  log "   grep 'exim.acl_check_rcpt.pre.conf' /etc/exim.conf"
  log ""
  log "═══════════════════════════════════════════════════════════"
  log "EM CASO DE PROBLEMAS:"
  log "═══════════════════════════════════════════════════════════"
  log ""
  log "Reaplique os comandos de recompilação/reinício acima após qualquer ajuste."
  log "Documentação oficial: $DIRECTADMIN_DOC_URL"
  log ""
  log "BACKUPS CRIADOS EM: $BACKUP_DIR"
  log "═══════════════════════════════════════════════════════════"
}

###############################
# Função de Desinstalação
###############################

uninstall() {
  log "Desinstalando integração SPFBL..."

  # Fazer backup antes de remover
  create_backup /etc/exim.acl_check_rcpt.pre.conf

  # Remover cliente
  if [[ -f /usr/local/bin/spfbl ]]; then
    rm -f /usr/local/bin/spfbl
    log "✓ Cliente SPFBL removido"
  fi

  # Remover arquivo ACL do DirectAdmin
  if [[ -f /etc/exim.acl_check_rcpt.pre.conf ]]; then
    rm -f /etc/exim.acl_check_rcpt.pre.conf
    log "✓ Arquivo ACL removido: /etc/exim.acl_check_rcpt.pre.conf"
  fi

  # Remover diretório antigo se existir (retrocompatibilidade)
  if [[ -d /etc/exim.spfbl ]]; then
    rm -rf /etc/exim.spfbl
    log "✓ Diretório antigo removido: /etc/exim.spfbl"
  fi

  log "⚠ Para concluir a remoção, execute novamente a recompilação/reinício do Exim."
  print_exim_manual_steps

  log ""
  log "✓ Desinstalação concluída com sucesso!"
  log ""
  log "Os backups permanecem em: $BACKUP_DIR"
}

###############################
# Função Principal
###############################

main() {
  local action="${1:-install}"

  require_root

  case "$action" in
    install)
      log "Iniciando instalação SPFBL para DirectAdmin..."
      check_directadmin
      test_connectivity || log "⚠ Continuando apesar da falha de conectividade..."
      install_dependencies
      install_spfbl_client
      test_spfbl_client || log "⚠ Continuando apesar da falha no teste..."
      create_exim_integration
      show_integration_instructions
      ;;

    uninstall)
      uninstall
      ;;

    test)
      log "Testando integração SPFBL..."
      test_connectivity
      if [[ -f /usr/local/bin/spfbl ]]; then
        test_spfbl_client
      else
        log "✗ Cliente SPFBL não está instalado"
        exit 1
      fi
      log "✓ Todos os testes passaram!"
      ;;

    *)
      echo "Uso: $0 [install|uninstall|test]"
      echo ""
      echo "  install   - Instala e configura integração SPFBL"
      echo "  uninstall - Remove integração SPFBL"
      echo "  test      - Testa conectividade e cliente"
      exit 1
      ;;
  esac
}

main "$@"
EOFSCRIPT

  chmod +x "$installer_file"
  log "✓ Script de instalação gerado: $installer_file"
}

setup_web_distribution() {
  log "Configurando distribuição web de arquivos..."

  # Criar diretório público se não existir
  mkdir -p "$SPFBL_PUBLIC_DIR"

  # Determinar IP de acesso
  local access_ip="$SERVER_IP"
  if [[ "$IS_PRIVATE_NETWORK" != "yes" ]] && [[ -n "$PUBLIC_IP" ]]; then
    access_ip="$PUBLIC_IP"
  fi

  local base_url="http://${access_ip}:${SPFBL_HTTP_PORT}"

  # Copiar cliente SPFBL para diretório público
  if [[ -f "$SPFBL_CLIENT_TEMPLATE" ]]; then
    cp "$SPFBL_CLIENT_TEMPLATE" "$SPFBL_PUBLIC_DIR/spfbl-client"
    chmod +x "$SPFBL_PUBLIC_DIR/spfbl-client"
    log "✓ Cliente disponível em: ${base_url}/public/spfbl-client"
  fi

  # Criar instalador DirectAdmin one-liner
  create_oneliner_installer "$access_ip"

  # Criar página de boas-vindas
  create_welcome_page "$access_ip"

  log "✓ Distribuição web configurada em: $SPFBL_PUBLIC_DIR"
}

create_oneliner_installer() {
  local server_ip="$1"
  local installer_path="$SPFBL_PUBLIC_DIR/install-directadmin.sh"

  cat >"$installer_path" <<'ONELINER_HEADER'
#!/bin/bash
#
# Instalador SPFBL para DirectAdmin - One-Liner Edition
# Instalação automática com auto-registro
#
# Uso: curl -sSL http://SEU_SERVIDOR:8001/public/install-directadmin.sh | sudo bash
#

set -euo pipefail

ONELINER_HEADER

  # Adicionar variáveis de configuração
  cat >>"$installer_path" <<ONELINER_CONFIG
# Configuração do servidor SPFBL (NÃO MODIFIQUE)
SPFBL_SERVER="$server_ip"
SPFBL_POLICY_PORT="$SPFBL_POLICY_PORT"
SPFBL_ADMIN_PORT="$SPFBL_ADMIN_PORT"
SPFBL_HTTP_PORT="$SPFBL_HTTP_PORT"
BASE_URL="http://\${SPFBL_SERVER}:\${SPFBL_HTTP_PORT}"

# Email de contato para registro automático do cliente no SPFBL (opcional).
# Se vazio, será usado auto@<hostname_do_DirectAdmin>.
CLIENT_REGISTER_EMAIL="$DIRECTADMIN_CLIENT_EMAIL"

ONELINER_CONFIG

  # Adicionar corpo do instalador
  cat >>"$installer_path" <<'ONELINER_BODY'
###############################
# Funções
###############################

log() {
  printf '[%s] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*"
}

die() {
  log "ERRO: $*"
  exit 1
}

detect_my_ip() {
  # Tentar detectar IP público
  local public_ip
  public_ip="$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"

  # Se não conseguiu, tentar via ip route
  if [[ -z "$public_ip" ]]; then
    public_ip="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); exit}}}')"
  fi

  echo "$public_ip"
}

configure_csf_firewall() {
  # Ajusta o CSF no servidor DirectAdmin para liberar as portas do SPFBL
  local conf="/etc/csf/csf.conf"
  if [[ ! -f "$conf" ]]; then
    log "CSF não encontrado neste servidor (continuando sem ajustes de firewall)."
    return 0
  fi

  local changed=0

  add_port() {
    local key="$1" port="$2"
    [[ -z "$port" ]] && return
    local current new
    current=$(grep -E "^${key}[[:space:]]*=" "$conf" | head -1 | sed -E 's/^.*= *"?([^"]*)"?.*/\1/' | tr -d ' ')
    # Se já contém a porta, nada a fazer
    if [[ ",${current}," == *",${port},"* ]]; then
      return
    fi
    new="${current:+${current},}${port}"
    sed -i "s/^${key}[[:space:]]*=.*/${key} = \"${new}\"/" "$conf"
    changed=1
  }

  # Liberar saídas para as portas usadas pelo SPFBL (IPv4/IPv6)
  add_port "TCP_OUT" "$SPFBL_POLICY_PORT"
  add_port "TCP_OUT" "$SPFBL_HTTP_PORT"
  add_port "TCP_OUT" "$SPFBL_ADMIN_PORT"
  add_port "TCP6_OUT" "$SPFBL_POLICY_PORT"
  add_port "TCP6_OUT" "$SPFBL_HTTP_PORT"
  add_port "TCP6_OUT" "$SPFBL_ADMIN_PORT"

  if [[ $changed -eq 1 ]]; then
    if csf -r >/dev/null 2>&1; then
      log "✓ CSF atualizado para liberar as portas $SPFBL_POLICY_PORT, $SPFBL_HTTP_PORT e $SPFBL_ADMIN_PORT (saída)."
    else
      log "⚠ CSF não pôde ser recarregado automaticamente; verifique manualmente."
    fi
  else
    log "✓ CSF já possuía as portas do SPFBL liberadas."
  fi
}

###############################
# Verificações
###############################

[[ $EUID -eq 0 ]] || die "Este script precisa ser executado como root."

if [[ ! -f /usr/local/directadmin/directadmin ]]; then
  die "DirectAdmin não encontrado. Este script é apenas para servidores DirectAdmin."
fi

log "✓ DirectAdmin encontrado"

# Detectar IP deste servidor
MY_IP="$(detect_my_ip)"
[[ -n "$MY_IP" ]] || die "Não foi possível detectar o IP deste servidor"
log "✓ IP detectado: $MY_IP"

###############################
# Instalação
###############################

log "Instalando dependências..."
if command -v apt-get >/dev/null; then
  apt-get update -qq
  apt-get install -y curl wget netcat-openbsd >/dev/null 2>&1
elif command -v yum >/dev/null; then
  yum install -y curl wget nc >/dev/null 2>&1
else
  die "Gerenciador de pacotes não identificado"
fi

log "✓ Dependências instaladas"

# Liberar portas no CSF (caso esteja em uso no DirectAdmin)
configure_csf_firewall

# Testar conectividade
log "Testando conectividade com servidor SPFBL..."
if ! timeout 3 bash -c "echo '' | nc -w 1 $SPFBL_SERVER $SPFBL_POLICY_PORT" >/dev/null 2>&1; then
  log "⚠ AVISO: Não foi possível conectar ao servidor SPFBL"
  log "  Verifique se o firewall permite conexões TCP na porta $SPFBL_POLICY_PORT"
fi

# Baixar cliente SPFBL
log "Baixando cliente SPFBL..."
if ! curl -sSL "${BASE_URL}/public/spfbl-client" -o /usr/local/bin/spfbl; then
  die "Falha ao baixar cliente SPFBL"
fi

chmod +x /usr/local/bin/spfbl
log "✓ Cliente SPFBL instalado"

# Configurar cliente
sed -i "s|^IP_SERVIDOR=.*|IP_SERVIDOR=\"$SPFBL_SERVER\"|" /usr/local/bin/spfbl
sed -i "s|^PORTA_SERVIDOR=.*|PORTA_SERVIDOR=\"$SPFBL_POLICY_PORT\"|" /usr/local/bin/spfbl
sed -i "s|^PORTA_ADMIN=.*|PORTA_ADMIN=\"$SPFBL_ADMIN_PORT\"|" /usr/local/bin/spfbl

# Testar cliente
log "Testando cliente SPFBL..."
result=$(/usr/local/bin/spfbl query 8.8.8.8 teste@gmail.com google.com destinatario@teste.com 2>&1 || true)

# Todas as respostas válidas do SPFBL (incluindo SOFTFAIL, FAIL, etc.)
if [[ "$result" =~ ^(PASS|FAIL|SOFTFAIL|NEUTRAL|NONE|WHITE|LISTED|GREYLIST|BLOCKED|BANNED|FLAG|SPAMTRAP|HOLD) ]]; then
  log "✓ Cliente SPFBL funcionando: $result"
elif [[ -z "$result" ]]; then
  log "⚠ AVISO: Cliente SPFBL não retornou resposta (possível erro de conectividade)"
else
  log "⚠ AVISO: Resposta inesperada do SPFBL: $result"
fi

# Auto-registrar este servidor no SPFBL
log "Auto-registrando servidor no SPFBL..."
HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

# Definir email de contato usado no registro (padrão: auto@<hostname_do_DirectAdmin>)
CLIENT_EMAIL="${CLIENT_REGISTER_EMAIL:-auto@${HOSTNAME}}"

# Tentar registrar via comando direto (requer que porta admin esteja acessível)
# Normalmente a porta admin está bloqueada externamente, então fornecemos o comando
AUTO_REGISTER_CMD="CLIENT ADD ${MY_IP}/32 ${HOSTNAME} SPFBL ${CLIENT_EMAIL}"

# Tentar via netcat (pode não funcionar se porta admin estiver bloqueada)
if echo "$AUTO_REGISTER_CMD" | timeout 2 nc -w 1 $SPFBL_SERVER $SPFBL_ADMIN_PORT 2>/dev/null | grep -q "OK"; then
  log "✓ Servidor registrado automaticamente no SPFBL"
else
  # Auto-registro via porta admin não funcionou (esperado por segurança)
  # Criar um arquivo de solicitação
  REGISTER_REQUEST="/tmp/spfbl-register-request-${MY_IP//\./_}.txt"
  cat > "$REGISTER_REQUEST" <<EOFREQ
╔════════════════════════════════════════════════════════════════╗
║          SOLICITAÇÃO DE REGISTRO NO SERVIDOR SPFBL             ║
╚════════════════════════════════════════════════════════════════╝

IP do cliente:    ${MY_IP}
Hostname:         ${HOSTNAME}
Data/Hora:        $(date)

────────────────────────────────────────────────────────────────

COMANDO PARA EXECUTAR NO SERVIDOR SPFBL ($SPFBL_SERVER):

  /sbin/spfbl client add ${MY_IP}/32 ${HOSTNAME} SPFBL ${CLIENT_EMAIL}

────────────────────────────────────────────────────────────────

INSTRUÇÕES:

1. Copie este arquivo para o servidor SPFBL ou
2. Execute o comando acima diretamente no servidor SPFBL

Após registrar, teste a conexão com:
  /usr/local/bin/spfbl query 8.8.8.8 test@example.com example.com user@domain.com

────────────────────────────────────────────────────────────────
EOFREQ

  log "⚠ Auto-registro via rede não disponível (porta admin protegida)"
  log ""
  log "  Arquivo de solicitação criado: $REGISTER_REQUEST"
  log ""
  log "  EXECUTE NO SERVIDOR SPFBL ($SPFBL_SERVER):"
  log "  /sbin/spfbl client add ${MY_IP}/32 ${HOSTNAME} SPFBL ${CLIENT_EMAIL}"
  log ""
fi

# Criar backup
BACKUP_DIR="/root/spfbl_backups"
mkdir -p "$BACKUP_DIR"
BACKUP_TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"

for file in /etc/exim.conf /etc/exim.acl_check_recipient.pre.conf /etc/exim.variables.conf.custom; do
  if [[ -f "$file" ]]; then
    cp -a "$file" "${BACKUP_DIR}/$(basename "$file").${BACKUP_TIMESTAMP}.bak"
    log "✓ Backup: $file"
  fi
done

# Criar configuração Exim
log "Configurando integração com Exim..."

cat >/etc/exim.acl_check_recipient.pre.conf <<'EOFACL'
# ============================================
# INTEGRAÇÃO SPFBL - Consulta ao RBL
# ============================================
# Instalado automaticamente via SPFBL One-Liner

# Armazenar resultado da consulta SPFBL
warn
  set acl_m_spfbl = ${run{/usr/local/bin/spfbl query \
    $sender_host_address \
    $sender_address \
    $sender_helo_name \
    $local_part@$domain}{$value}{TIMEOUT}}

# Log da consulta
warn
  log_message = SPFBL-CHECK: $acl_m_spfbl

# Rejeitar se BLOCKED ou BANNED
deny
  condition = ${if match{$acl_m_spfbl}{^(BLOCKED|BANNED)}{yes}{no}}
  message = Message rejected by SPFBL security policy

# Aceitar imediatamente se WHITE (whitelist)
accept
  condition = ${if match{$acl_m_spfbl}{^WHITE}{yes}{no}}

# Implementar GREYLIST
defer
  condition = ${if match{$acl_m_spfbl}{^GREYLIST}{yes}{no}}
  message = Greylisted - please try again later

# Rejeitar se LISTED (em blacklist temporária)
deny
  condition = ${if match{$acl_m_spfbl}{^LISTED}{yes}{no}}
  message = Temporarily listed in blacklist

# Descartar silenciosamente SPAMTRAP
discard
  condition = ${if match{$acl_m_spfbl}{^SPAMTRAP}{yes}{no}}

# FLAG: Marcar como spam mas aceitar (compatível com SpamAssassin)
warn
  condition = ${if match{$acl_m_spfbl}{^FLAG}{yes}{no}}
  add_header = X-Spam-Flag: YES
  add_header = X-Spam-Status: Yes, flagged by SPFBL

# Adicionar cabeçalho com resultado
warn
  add_header = X-SPFBL-Result: $acl_m_spfbl

EOFACL

log "✓ Configuração Exim criada: /etc/exim.acl_check_recipient.pre.conf"

# Recompilar e reiniciar Exim automaticamente
log ""
log "Recompilando configuração do Exim..."
cd /usr/local/directadmin/custombuild && ./build rewrite_confs >/dev/null 2>&1 || log "⚠ Aviso: build rewrite_confs falhou"

log "Reiniciando Exim..."
systemctl restart exim
if [[ $? -eq 0 ]]; then
  log "✓ Exim reiniciado com sucesso"
else
  log "⚠ Aviso: Falha ao reiniciar Exim - verifique os logs"
fi

# Instruções finais
log ""
log "═══════════════════════════════════════════════════════════"
log "✓ INSTALAÇÃO E CONFIGURAÇÃO CONCLUÍDAS!"
log "═══════════════════════════════════════════════════════════"
log ""
log "O SPFBL foi instalado e o Exim já foi reconfigurado automaticamente."
log ""
log "VERIFICAÇÃO:"
log ""
log "1. Monitorar consultas em tempo real:"
log "   tail -f /var/log/exim/mainlog | grep SPFBL"
log ""
log "2. Ver estatísticas no servidor SPFBL:"
log "   ssh root@$SPFBL_SERVER 'grep SPF /var/log/spfbl/*.log | grep \$(hostname -I | awk \"{print \\\$1}\")'"
log ""
log "BACKUPS salvos em: $BACKUP_DIR"
log ""
log "O SPFBL está integrado e funcionará JUNTO com outros filtros anti-spam."
log "═══════════════════════════════════════════════════════════"
ONELINER_BODY

  chmod +x "$installer_path"
  log "✓ Instalador one-liner criado: ${base_url}/public/install-directadmin.sh"
}

create_welcome_page() {
  local server_ip="$1"
  local welcome_path="$SPFBL_PUBLIC_DIR/index.html"
  local base_url="http://${server_ip}:${SPFBL_HTTP_PORT}"

  cat >"$welcome_path" <<WELCOME_HTML
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPFBL RBL Server - Pronto!</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .status {
            display: inline-block;
            background: #10b981;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 10px;
        }
        .content {
            padding: 40px;
        }
        .section {
            margin-bottom: 30px;
        }
        .section h2 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.5em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .code-box {
            background: #1e293b;
            color: #10b981;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 15px 0;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .info-card {
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .info-card h3 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        .info-card p {
            color: #64748b;
            font-size: 1.2em;
            font-weight: bold;
        }
        .warning {
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }
        .success {
            background: #d1fae5;
            border-left: 4px solid #10b981;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }
        a {
            color: #667eea;
            text-decoration: none;
            font-weight: bold;
        }
        a:hover {
            text-decoration: underline;
        }
        .step {
            background: #f8fafc;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #10b981;
        }
        .step strong {
            color: #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SPFBL RBL Server</h1>
            <div class="status">✓ OPERACIONAL</div>
            <p style="margin-top: 15px;">Servidor: <strong>$server_ip</strong></p>
        </div>

        <div class="content">
            <div class="success">
                <strong>✓ Servidor SPFBL configurado e pronto para uso!</strong>
            </div>

            <div class="section">
                <h2>📊 Informações do Servidor</h2>
                <div class="info-grid">
                    <div class="info-card">
                        <h3>IP do Servidor</h3>
                        <p>$server_ip</p>
                    </div>
                    <div class="info-card">
                        <h3>Porta Policy</h3>
                        <p>$SPFBL_POLICY_PORT</p>
                    </div>
                    <div class="info-card">
                        <h3>Porta HTTP</h3>
                        <p>$SPFBL_HTTP_PORT</p>
                    </div>
                    <div class="info-card">
                        <h3>Porta Admin</h3>
                        <p>$SPFBL_ADMIN_PORT</p>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>🚀 Instalação Rápida no DirectAdmin</h2>
                <p>Execute este comando único no seu servidor DirectAdmin:</p>
                <div class="code-box">curl -sSL ${base_url}/public/install-directadmin.sh | sudo bash</div>

                <div class="warning">
                    <strong>⚠️ Importante:</strong> Este comando irá:
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Criar backups automáticos das configurações</li>
                        <li>Instalar o cliente SPFBL</li>
                        <li>Auto-registrar o servidor</li>
                        <li>Configurar integração com Exim</li>
                        <li>Funcionar junto com SpamAssassin existente</li>
                    </ul>
                </div>
            </div>

            <div class="section">
                <h2>📝 Instalação Manual (passo a passo)</h2>

                <div class="step">
                    <strong>1. Baixar o cliente SPFBL:</strong>
                    <div class="code-box">curl -sSL ${base_url}/public/spfbl-client -o /usr/local/bin/spfbl
chmod +x /usr/local/bin/spfbl</div>
                </div>

                <div class="step">
                    <strong>2. Configurar o cliente:</strong>
                    <p>Edite <code>/usr/local/bin/spfbl</code> e configure:</p>
                    <div class="code-box">IP_SERVIDOR="$server_ip"
PORTA_SERVIDOR="$SPFBL_POLICY_PORT"
PORTA_ADMIN="$SPFBL_ADMIN_PORT"</div>
                </div>

                <div class="step">
                    <strong>3. Registrar no servidor SPFBL:</strong>
                    <p>No servidor SPFBL ($server_ip), execute:</p>
                    <div class="code-box">/sbin/spfbl client add &lt;IP_DIRECTADMIN&gt;/32 &lt;hostname&gt; SPFBL &lt;email&gt;</div>
                </div>

                <div class="step">
                    <strong>4. Baixar o instalador completo:</strong>
                    <div class="code-box">curl -sSL ${base_url}/public/install-directadmin.sh -o install-spfbl.sh
bash install-spfbl.sh</div>
                </div>
            </div>

            <div class="section">
                <h2>🔗 Links Úteis</h2>
                <ul style="margin-left: 20px; line-height: 2;">
                    <li><a href="${base_url}/$SPFBL_ADMIN_EMAIL">Painel de Administração</a></li>
                    <li><a href="${base_url}/public/spfbl-client">Baixar Cliente SPFBL</a></li>
                    <li><a href="${base_url}/public/install-directadmin.sh">Baixar Instalador DirectAdmin</a></li>
                    <li><a href="https://spfbl.net/">Documentação Oficial SPFBL</a></li>
                </ul>
            </div>

            <div class="section">
                <h2>🔐 Credenciais de Acesso</h2>
                <div class="warning">
                    <p><strong>Email Admin:</strong> $SPFBL_ADMIN_EMAIL</p>
                    <p><strong>⚠️ ALTERE A SENHA PADRÃO após o primeiro acesso!</strong></p>
                </div>
            </div>

            <div class="section">
                <h2>📞 Comandos Úteis</h2>
                <div class="code-box"># Ver status do serviço
systemctl status spfbl

# Ver logs em tempo real
tail -f /var/log/spfbl/*.log

# Listar clientes autorizados
/sbin/spfbl client show

# Ver estatísticas
/sbin/spfbl stats</div>
            </div>
        </div>
    </div>
</body>
</html>
WELCOME_HTML

  log "✓ Página de boas-vindas criada: ${base_url}/public/"
}

write_local_instructions() {
  local local_file="$SCRIPT_DIR/SPFBL_ACESSO_${SERVER_IP//./_}_${INSTALL_DATE}.txt"

  # IP preferencial de acesso (público quando disponível)
  local access_ip="$SERVER_IP"
  if [[ "$IS_PRIVATE_NETWORK" != "yes" ]] && [[ -n "$PUBLIC_IP" ]]; then
    access_ip="$PUBLIC_IP"
  fi

  local directadmin_url="http://${access_ip}:${SPFBL_HTTP_PORT}/public/install-directadmin.sh"
  local dashboard_url="http://${access_ip}:${DASHBOARD_HTTP_PORT}/login"

  cat >"$local_file" <<EOF
SPFBL - INFORMAÇÕES DE ACESSO
=============================

Data da instalação: $(date '+%d/%m/%Y às %H:%M:%S')
Servidor SPFBL: $SERVER_IP

1) URL para uso no servidor DirectAdmin
---------------------------------------
One-liner de instalação (executar no servidor DirectAdmin):

  curl -sSL $directadmin_url | sudo bash

URL direta do instalador:

  $directadmin_url

2) URL de acesso à nova dashboard
---------------------------------
Acesse a dashboard segura pelo navegador em:

  $dashboard_url

3) Login e senha padrão
-----------------------
Email (login): $SPFBL_ADMIN_EMAIL
Senha:         $SPFBL_ADMIN_PASSWORD

IMPORTANTE: altere a senha após o primeiro acesso.

4) Comandos úteis no servidor SPFBL
-----------------------------------
Ver status dos serviços:
  systemctl status spfbl
  systemctl status spfbl-api

Reiniciar serviços:
  systemctl restart spfbl
  systemctl restart spfbl-api

Ver logs:
  tail -f /var/log/spfbl/*.log

Listar clientes autorizados:
  /sbin/spfbl client show
EOF

  log "Arquivo de instruções criado: $local_file"

  # Tornar o arquivo legível por todos
  chmod 644 "$local_file" 2>/dev/null || true
}

write_remote_guidance() {
  mkdir -p "$(dirname "$REMOTE_GUIDE_FILE")"

  local access_info=""
  local panel_url=""
  if [[ "$IS_PRIVATE_NETWORK" == "yes" ]]; then
    panel_url="http://$SERVER_IP:$SPFBL_HTTP_PORT/$SPFBL_ADMIN_EMAIL"
    access_info="Rede: PRIVADA (RFC1918)
IP do servidor: $SERVER_IP
URL do painel admin: $panel_url

IMPORTANTE: Este servidor está em uma rede privada.
- O painel HTTP só estará acessível a partir de dispositivos na mesma rede local
- Para acesso externo, configure port forwarding no seu roteador ou use uma VPN"
  else
    panel_url="http://$PUBLIC_IP:$SPFBL_HTTP_PORT/$SPFBL_ADMIN_EMAIL"
    access_info="Rede: PÚBLICA
IP público: $PUBLIC_IP
URL do painel admin: $panel_url"
  fi

  cat >"$REMOTE_GUIDE_FILE" <<EOF
╔════════════════════════════════════════════════════════════════════╗
║           INSTALAÇÃO SPFBL CONCLUÍDA COM SUCESSO                   ║
╚════════════════════════════════════════════════════════════════════╝

Data: $(date)
Hostname: ${DETECTED_HOSTNAME:-$MAIL_HOSTNAME}

$access_info

ACESSO AO PAINEL WEB:
  URL do painel admin: $panel_url

  IMPORTANTE: O painel SPFBL requer o email na URL!
  Formato: http://ip:porta/email@dominio.com

  A página principal (sem email) só mostra informações gerais.
  Para acessar seu painel de controle, use a URL completa acima.

CREDENCIAIS DE LOGIN:
  • Email admin:        $SPFBL_ADMIN_EMAIL
  • Senha admin:        $SPFBL_ADMIN_PASSWORD

PORTAS DO SERVIÇO:
  • Painel HTTP:        $SPFBL_HTTP_PORT
  • Policy (consultas): $SPFBL_POLICY_PORT
  • Administrativa:     $SPFBL_ADMIN_PORT

CLIENTES AUTORIZADOS:
$(if [[ ${#POLICY_CLIENTS[@]} -gt 0 ]]; then
    for entry in "${POLICY_CLIENTS[@]}"; do
      [[ -n "$entry" ]] && echo "  • $entry"
    done
  else
    echo "  • Nenhum cliente remoto configurado ainda"
  fi)

═══════════════════════════════════════════════════════════════════════
INTEGRAÇÃO COM DIRECTADMIN/EXIM
═══════════════════════════════════════════════════════════════════════

1. COPIAR CLIENTE PARA O SERVIDOR REMOTO:
   Template disponível em: $SPFBL_CLIENT_TEMPLATE
   Exemplos adicionais em: $SPFBL_INSTALL_DIR/client-samples/

2. CONFIGURAR NO SERVIDOR REMOTO:
   - Edite o script cliente e ajuste:
     IP_SERVIDOR="$SERVER_IP"
     PORTA_SERVIDOR="$SPFBL_POLICY_PORT"
     PORTA_ADMIN="$SPFBL_ADMIN_PORT"

3. INTEGRAR COM EXIM:
   - Aplique os templates de ACL disponíveis em:
     $SPFBL_INSTALL_DIR/client-samples/directadmin.*
   - Configure em: acl_check_recipient, acl_check_message, etc.

4. AUTORIZAR NOVO CLIENTE:
   Sempre que um novo IP precisar consultar este SPFBL, execute:

   $SPFBL_CLIENT_BIN client add <CIDR> <identificador> SPFBL <contato@dominio>

   Exemplo:
   $SPFBL_CLIENT_BIN client add 203.0.113.10/32 mail.example.com SPFBL admin@example.com

═══════════════════════════════════════════════════════════════════════
COMANDOS ÚTEIS
═══════════════════════════════════════════════════════════════════════

• Verificar status:     systemctl status spfbl
• Ver logs:             tail -f /var/log/spfbl/*.log
• Reiniciar serviço:    systemctl restart spfbl
• Cliente CLI:          $SPFBL_CLIENT_BIN
• Listar clientes:      $SPFBL_CLIENT_BIN client show

═══════════════════════════════════════════════════════════════════════

Para mais informações: http://spfbl.net/
EOF

  # Exibe o resumo no console também
  local access_ip="$SERVER_IP"
  if [[ "$IS_PRIVATE_NETWORK" != "yes" ]] && [[ -n "$PUBLIC_IP" ]]; then
    access_ip="$PUBLIC_IP"
  fi

  log ""
  log "╔════════════════════════════════════════════════════════════════╗"
  log "║          ✓ INSTALAÇÃO SPFBL CONCLUÍDA COM SUCESSO!            ║"
  log "╚════════════════════════════════════════════════════════════════╝"
  log ""
  log "🌐 PAINEL WEB DE BOAS-VINDAS:"
  log "   http://${access_ip}:${SPFBL_HTTP_PORT}/public/"
  log ""
  log "🔐 PAINEL DE ADMINISTRAÇÃO:"
  if [[ "$IS_PRIVATE_NETWORK" == "yes" ]]; then
    log "   http://$SERVER_IP:$SPFBL_HTTP_PORT/$SPFBL_ADMIN_EMAIL"
    log ""
    log "   ⚠ ATENÇÃO: Servidor em rede privada"
    log "   O painel só é acessível dentro da rede local"
  else
    log "   http://$PUBLIC_IP:$SPFBL_HTTP_PORT/$SPFBL_ADMIN_EMAIL"
  fi
  log ""
  log "   Email:    $SPFBL_ADMIN_EMAIL"
  log "   Senha:    $SPFBL_ADMIN_PASSWORD"
  log ""
  log "════════════════════════════════════════════════════════════════"
  log "🚀 INSTALAÇÃO RÁPIDA NO DIRECTADMIN (ONE-LINER):"
  log "════════════════════════════════════════════════════════════════"
  log ""
  log "Execute este comando ÚNICO no seu servidor DirectAdmin:"
  log ""
  log "  curl -sSL http://${access_ip}:${SPFBL_HTTP_PORT}/public/install-directadmin.sh | sudo bash"
  log ""
  log "Este comando irá:"
  log "  ✓ Instalar e configurar o cliente SPFBL automaticamente"
  log "  ✓ Criar backups de todas as configurações"
  log "  ✓ Integrar com Exim (compatível com SpamAssassin existente)"
  log "  ✓ Mostrar comando de registro caso necessário"
  log ""
  log "════════════════════════════════════════════════════════════════"
  log "📁 ARQUIVOS GERADOS:"
  log "════════════════════════════════════════════════════════════════"
  log ""
  log "  📄 Documentação completa:"
  log "     $REMOTE_GUIDE_FILE"
  log ""
  log "  📄 Instruções de acesso:"
  log "     $SCRIPT_DIR/SPFBL_ACESSO_${SERVER_IP//./_}_${INSTALL_DATE}.txt"
  log ""
  log "  📄 Instalador DirectAdmin (modo tradicional):"
  log "     $SCRIPT_DIR/install_spfbl_directadmin_${SERVER_IP//./_}.sh"
  log ""
  log "  🌐 Arquivos web disponíveis em:"
  log "     http://${access_ip}:${SPFBL_HTTP_PORT}/public/spfbl-client"
  log "     http://${access_ip}:${SPFBL_HTTP_PORT}/public/install-directadmin.sh"
  log ""
  log "════════════════════════════════════════════════════════════════"
  log "💡 PRÓXIMOS PASSOS:"
  log "════════════════════════════════════════════════════════════════"
  log ""
  log "1. Acesse o painel web para verificar o status:"
  log "   http://${access_ip}:${SPFBL_HTTP_PORT}/public/"
  log ""
  log "2. No servidor DirectAdmin, execute o comando one-liner acima"
  log ""
  log "3. Após a instalação no DirectAdmin, recompile o Exim:"
  log "   cd /usr/local/directadmin/custombuild"
  log "   ./build rewrite_confs && ./build exim_conf"
  log "   systemctl restart exim"
  log ""
  log "4. Monitore os logs:"
  log "   tail -f /var/log/exim/mainlog | grep SPFBL"
  log ""
  log "════════════════════════════════════════════════════════════════"
  log "⚠️  IMPORTANTE: ALTERE A SENHA PADRÃO APÓS O PRIMEIRO ACESSO!"
  log "════════════════════════════════════════════════════════════════"
}

create_auto_register_script() {
  log "Criando script de auto-registro..."

  local auto_register_script="$SPFBL_PUBLIC_DIR/auto-register"

  cat >"$auto_register_script" <<'AUTOREG_SCRIPT'
#!/bin/bash
#
# Script de auto-registro para clientes SPFBL
# Este script é chamado via HTTP pelo instalador DirectAdmin
#
# Uso: curl "http://servidor:8001/public/auto-register?ip=1.2.3.4&hostname=mail.example.com"
#

# Extrair parâmetros da query string
IFS='&' read -ra PARAMS <<< "$QUERY_STRING"
CLIENT_IP=""
CLIENT_HOSTNAME=""

for param in "${PARAMS[@]}"; do
  key="${param%%=*}"
  value="${param#*=}"
  case "$key" in
    ip) CLIENT_IP="$value" ;;
    hostname) CLIENT_HOSTNAME="$value" ;;
  esac
done

# Validar parâmetros
if [[ -z "$CLIENT_IP" ]]; then
  echo "Status: 400 Bad Request"
  echo "Content-Type: text/plain"
  echo ""
  echo "ERROR: IP not provided"
  exit 1
fi

# Usar hostname padrão se não fornecido
CLIENT_HOSTNAME="${CLIENT_HOSTNAME:-unknown-host}"

# Log do registro
logger -t spfbl-autoregister "Auto-registering client: $CLIENT_IP ($CLIENT_HOSTNAME)"

# Adicionar cliente ao SPFBL
if /sbin/spfbl client add "${CLIENT_IP}/32" "$CLIENT_HOSTNAME" SPFBL "auto-registered@$CLIENT_HOSTNAME" >/dev/null 2>&1; then
  echo "Content-Type: text/plain"
  echo ""
  echo "OK: Client $CLIENT_IP registered successfully"
  logger -t spfbl-autoregister "SUCCESS: $CLIENT_IP registered"
else
  # Pode já estar registrado, o que é ok
  echo "Content-Type: text/plain"
  echo ""
  echo "OK: Client already registered or registration attempted"
  logger -t spfbl-autoregister "INFO: $CLIENT_IP registration attempted (may already exist)"
fi
AUTOREG_SCRIPT

  chmod +x "$auto_register_script"
  log "✓ Script de auto-registro criado (requer configuração CGI no servidor web)"

  # Criar uma versão simplificada como endpoint de informação
  cat >"$SPFBL_PUBLIC_DIR/register-info.txt" <<REGINFO
Para registrar um novo cliente manualmente, execute no servidor SPFBL:

  /sbin/spfbl client add <IP>/32 <hostname> SPFBL <email>

Exemplo:
  /sbin/spfbl client add 203.0.113.50/32 mail.example.com SPFBL admin@example.com

Para listar clientes já registrados:
  /sbin/spfbl client show
REGINFO

  log "✓ Informações de registro disponíveis em: public/register-info.txt"
}

main() {
  require_root
  log "Iniciando instalação do SPFBL RBL..."
  detect_network
  detect_public_ip
  install_packages
  ensure_python2_default
  stop_existing_spfbl
  detect_and_configure_jvm_memory
  deploy_spfbl
  configure_spfbl_conf
  configure_spfbl_template
  setup_spfbl_service
  setup_spfbl_cron

  # Iniciar SPFBL com tratamento melhorado de erro
  start_spfbl_service || {
    log "⚠ AVISO: SPFBL pode não ter iniciado corretamente"
    log "  A instalação continuará, mas você deve verificar manualmente:"
    log "  - sudo systemctl status spfbl"
    log "  - sudo tail -f /var/log/spfbl/spfbl.*.log"
    log ""
    # Aguardar mais um pouco antes de tentar configurar
    sleep 10
  }

  configure_spfbl_accounts
  configure_authorized_servers
  configure_postmaster_accounts
  install_exim
  configure_exim_smtp_port
  configure_firewall
  verify_installation
  setup_web_distribution
  create_auto_register_script
  install_new_dashboard
  write_remote_guidance
  write_local_instructions
  generate_directadmin_installer
}

main "$@"
