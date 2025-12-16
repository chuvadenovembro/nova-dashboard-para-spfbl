#!/usr/bin/env python3
"""
SPFBL Dashboard API - Versão Segura com Autenticação
Provides REST API endpoints and serves the dashboard frontend with authentication
"""

import subprocess
import json
import re
import os
import sys
import hmac
import hashlib
import secrets
import time
import urllib.parse
import urllib.request
import http.cookiejar
import shutil
import html
import ipaddress
import math
import glob
import threading
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie
from socketserver import ThreadingMixIn

# Caminhos base configuráveis (mantém defaults da instalação SPFBL)
SPFBL_HOME = os.environ.get('SPFBL_HOME', '/opt/spfbl')
WEB_DIR = os.path.join(SPFBL_HOME, 'web')
DATA_DIR = os.path.join(SPFBL_HOME, 'data')
ADDON_PATH = os.path.join(SPFBL_HOME, 'addon')
LOG_DIR = os.environ.get('SPFBL_LOG_DIR', '/var/log/spfbl')
CONF_FILE = os.path.join(SPFBL_HOME, 'spfbl.conf')
CONF_LOCK_FILE = os.path.join(SPFBL_HOME, 'spfbl.conf.lock')
REMOTE_INTEGRATION_FILE = os.path.join(SPFBL_HOME, 'REMOTE_INTEGRATION.md')
DASHBOARD_USERS_FILE = os.environ.get(
    'SPFBL_DASHBOARD_USERS_FILE',
    os.path.join(SPFBL_HOME, 'dashboard_users.conf')
)
FRAUD_EVENTS_FILE = os.environ.get(
    'SPFBL_FRAUD_EVENTS_FILE',
    os.path.join(DATA_DIR, 'fraud-events.json')
)
FRAUD_TOKEN_FILE = os.environ.get(
    'SPFBL_FRAUD_TOKEN_FILE',
    os.path.join(DATA_DIR, 'fraud_token')
)
MAX_FRAUD_EVENTS = 500

# Cache para relatório do addon (evita reprocessamento frequente)
ADDON_REPORT_CACHE = {
    'data': None,
    'timestamp': 0,
    'ttl': 30  # 30 segundos de cache
}
ADDON_REPORT_CACHE_LOCK = threading.Lock()

# Backup persistente para toggle de SMTP/alerts
SMTP_BACKUP_FILE = os.environ.get(
    'SPFBL_SMTP_BACKUP_FILE',
    os.path.join(SPFBL_HOME, 'smtp-settings.backup.json')
)

# Configurações de Sessão (somente em memória)
# NOTA: Para produção, considere usar Redis ou banco de dados para persistência
SESSION_TIMEOUT = 3600  # 1 hora em segundos
MAX_LOGIN_ATTEMPTS = 3  # Máximo de tentativas de login (reduzido para segurança)
LOCKOUT_TIME = 1800  # 30 minutos de bloqueio após exceder tentativas (aumentado)

# Configurações de Rate Limiting para /api/user/check-status
MAX_CHECK_STATUS_ATTEMPTS = 3  # Máximo de verificações por minuto
RATE_LIMIT_WINDOW = 60  # Janela de 1 minuto em segundos

# Configurações de Segurança de Cookies
# Definir como True se estiver usando HTTPS em produção
USE_SECURE_COOKIES = os.environ.get('SPFBL_USE_HTTPS', 'false').lower() == 'true'

# Configurações de CORS - Origens permitidas
# IMPORTANTE: Adicione aqui apenas as origens confiáveis
def load_allowed_origins():
    raw = (os.environ.get('SPFBL_ALLOWED_ORIGINS') or '').strip()
    origins = set()
    if not raw:
        return origins
    for part in raw.split(','):
        origin = part.strip()
        if origin:
            origins.add(origin.rstrip('/'))
    return origins

ALLOWED_ORIGINS = load_allowed_origins()

# Cache para evitar fetch constante ao GitHub (endpoint público de update)
try:
    UPDATE_CACHE_SECONDS = int(os.environ.get('SPFBL_UPDATE_CACHE_SECONDS', '600'))
except Exception:
    UPDATE_CACHE_SECONDS = 600

update_cache = {'checked_at': 0.0, 'payload': None}
update_cache_lock = threading.Lock()

# Addons (caminho único, relativo à instalação)
# Nenhum addon carregado no momento

# Armazenamento em memória (dicionários simples, sem chave secreta global)
sessions = {}  # {token: {'email': 'user@domain', 'created': timestamp}}
login_attempts = {}  # {ip: {'count': 0, 'locked_until': timestamp}}
check_status_attempts = {}  # {ip: {'count': 0, 'reset_at': timestamp}} - Rate limiting para /api/user/check-status

class SPFBLSecureAPIHandler(BaseHTTPRequestHandler):
    # Timeout de segurança para prevenir conexões travadas
    timeout = 30

    # ===========================
    # Auth / Roles / Scoping
    # ===========================

    def _get_session(self):
        cookies = SimpleCookie(self.headers.get('Cookie', ''))
        if 'session_token' not in cookies:
            return None
        token = cookies['session_token'].value
        return sessions.get(token)

    def _get_session_email(self):
        session = self._get_session()
        email = session.get('email') if session else None
        return (email or '').strip().lower()

    def is_admin_email(self, email):
        admin_email = (self.get_admin_email() or '').strip().lower()
        candidate = (email or '').strip().lower()
        return bool(admin_email) and candidate == admin_email

    def is_admin_session(self):
        return self.is_admin_email(self._get_session_email())

    def require_admin(self):
        if self.is_admin_session():
            return True
        self.send_json_response({'error': 'Forbidden'}, 403)
        return False

    def _parse_clients_for_scope(self):
        output = self.run_spfbl_command('client show') or ''
        clients = []
        for raw_line in output.split('\n'):
            line = raw_line.strip()
            if not line or line.startswith('ERROR'):
                continue
            try:
                first = line.split()[0]
                if ':' not in first:
                    continue
                hostname, cidr = first.rsplit(':', 1)
                network = ipaddress.ip_network(cidr, strict=False)
            except Exception:
                continue
            email_match = re.search(r'<([^>]+@[^>]+)>', line)
            email = email_match.group(1).strip().lower() if email_match else None
            clients.append({
                'hostname': hostname.strip(),
                'network': network,
                'email': email
            })
        return clients

    def get_user_allowed_networks(self, email):
        if self.is_admin_email(email):
            return None
        candidate = (email or '').strip().lower()
        if not candidate:
            return []
        networks = []
        for client in self._parse_clients_for_scope():
            if client.get('email') == candidate:
                networks.append(client['network'])
        return networks

    def get_user_allowed_hostnames(self, email):
        if self.is_admin_email(email):
            return None
        candidate = (email or '').strip().lower()
        if not candidate:
            return []
        hosts = []
        for client in self._parse_clients_for_scope():
            if client.get('email') == candidate:
                hosts.append(client['hostname'])
        return hosts

    def _extract_client_ip_from_log_line(self, line):
        if not line:
            return None
        match = re.search(r'\bSPFBL\b[^\n]*?\s(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?\s', line)
        if match:
            return match.group(1)
        return None

    def _line_matches_allowed_networks(self, line, networks):
        if networks is None:
            return True
        if not networks:
            return False
        ip_str = self._extract_client_ip_from_log_line(line)
        if not ip_str:
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(ip_obj in net for net in networks)

    def get_list_pagination(self, default_page_size=100):
        """Return page and page_size when pagination params are present."""
        try:
            params = parse_qs(urlparse(self.path).query)
        except Exception:
            params = {}

        if 'page' not in params and 'page_size' not in params:
            return None, None

        try:
            page = int((params.get('page') or ['1'])[0])
        except (TypeError, ValueError):
            page = 1

        try:
            page_size = int((params.get('page_size') or [str(default_page_size)])[0])
        except (TypeError, ValueError):
            page_size = default_page_size

        page = max(1, page)
        page_size = max(1, min(page_size, 500))
        return page, page_size

    def get_allowed_origin(self, origin):
        """
        Valida e retorna a origem se estiver na lista de permitidas.
        Retorna None se a origem não for permitida.
        """
        if not origin:
            return None

        # Verificar se a origem está na lista de permitidas
        origin_candidate = origin.rstrip('/')
        if origin_candidate in ALLOWED_ORIGINS:
            return origin_candidate

        # Permitir qualquer origem de localhost/127.0.0.1 em desenvolvimento
        if (
            origin.startswith('http://localhost:') or origin.startswith('http://127.0.0.1:')
            or origin.startswith('https://localhost:') or origin.startswith('https://127.0.0.1:')
        ):
            return origin

        # Não permitir outras origens
        return None

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        origin = self.headers.get('Origin')
        allowed_origin = self.get_allowed_origin(origin)

        self.send_response(200)

        # Só configurar CORS se a origem for permitida
        if allowed_origin:
            self.send_header('Access-Control-Allow-Origin', allowed_origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            self.send_header('Access-Control-Allow-Credentials', 'true')

        self.end_headers()

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        # Rotas públicas (não requerem autenticação)
        if path in ['/login', '/login.html']:
            self.serve_login_page()
            return
        if path == '/login.css':
            self.serve_file(os.path.join(WEB_DIR, 'login.css'), 'text/css')
            return
        if path == '/logo.png':
            self.serve_file(os.path.join(WEB_DIR, 'logo.png'), 'image/png')
            return
        if path == '/version.js':
            self.serve_file(os.path.join(WEB_DIR, 'version.js'), 'application/javascript')
            return
        if path == '/version.txt':
            self.serve_file(os.path.join(WEB_DIR, 'version.txt'), 'text/plain')
            return

        # Extrair email da query string para verificação de status (público)
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if path == '/api/user/check-status':
            email = (params.get('email') or [''])[0]
            if email:
                self.check_user_totp_status(email)
            else:
                self.send_json_response({'error': 'Email is required'}, 400)
            return

        # Endpoint público para verificar update (usa cache interno)
        if path == '/api/check-update':
            self.check_github_update()
            return

        # Endpoint público para obter configuração do reCAPTCHA
        if path == '/api/config/recaptcha':
            recaptcha_config = self.get_recaptcha_keys()
            # Retornar apenas a site_key e se está habilitado (não expor secret_key)
            self.send_json_response({
                'enabled': recaptcha_config['enabled'],
                'site_key': recaptcha_config['site_key'] if recaptcha_config['enabled'] else None
            })
            return

        # Verificar autenticação para todas as outras rotas
        if not self.is_authenticated():
            self.send_json_response({'error': 'Unauthorized', 'redirect': '/login'}, 401)
            return

        # Rotas administrativas (GET)
        admin_only_get = {
            '/api/clients',
            '/api/users/list',
            '/api/logs',
            '/api/settings/config',
            '/api/settings/smtp-status',
            '/api/server/memory',
            '/api/fraud-events',
            '/api/addons',
            '/api/addons/subdomain-campaign/report',
            '/api/addons/subdomain-campaign/whitelist',
        }
        if path in admin_only_get:
            if not self.require_admin():
                return
        if path in {'/settings', '/settings.html'} and not self.is_admin_session():
            self.send_response(302)
            self.send_header('Location', '/dashboard.html')
            self.end_headers()
            return

        # API Routes
        if path == '/api/stats':
            self.get_stats()
        elif path == '/api/clients':
            self.get_clients()
        elif path == '/api/queries':
            self.get_recent_queries()
        elif path == '/api/queries/today':
            self.get_today_queries()
        elif path == '/api/user':
            self.get_current_user()
        elif path == '/api/settings/smtp-status':
            self.get_smtp_status()
        elif path == '/api/block/list':
            self.get_blocklist()
        elif path == '/api/white/list':
            self.get_whitelist()
        elif path == '/api/users/list':
            self.get_users()
        elif path == '/api/logs':
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            log_type = (params.get('type') or ['all'])[0]
            self.get_logs(log_type)
        elif path == '/api/fraud-events':
            self.get_fraud_events()
        elif path == '/api/server/memory':
            self.get_server_memory()
        elif path == '/api/stats/spam-blocks':
            self.get_spam_block_stats()
        elif path == '/api/stats/spam-blocks/hourly':
            self.get_spam_blocks_hourly()
        elif path == '/api/addons':
            self.get_addons()
        elif path == '/api/addons/subdomain-campaign/report':
            self.get_subdomain_campaign_report()
        elif path == '/api/addons/subdomain-campaign/whitelist':
            self.get_subdomain_campaign_whitelist()
        elif path == '/api/settings/config':
            self.handle_config()
        # Serve static files / dynamic settings page
        elif path in ['/', '/dashboard', '/dashboard.html']:
            self.serve_file(os.path.join(WEB_DIR, 'dashboard.html'), 'text/html')
        elif path == '/settings' or path == '/settings.html':
            self.serve_settings_page()
        elif path == '/dashboard.css':
            self.serve_file(os.path.join(WEB_DIR, 'dashboard.css'), 'text/css')
        elif path == '/dashboard.js':
            self.serve_file(os.path.join(WEB_DIR, 'dashboard.js'), 'application/javascript')
        elif path == '/login.css':
            self.serve_file(os.path.join(WEB_DIR, 'login.css'), 'text/css')
        else:
            self.send_error(404, "Not found")

    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path == '/api/login':
            self.handle_login()
        elif path == '/api/user/request-totp':
            self.handle_request_totp()
        elif path == '/api/fraud-events':
            self.handle_fraud_event_report()
        elif path == '/api/logout':
            self.handle_logout()
        elif path == '/api/clients/add':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_add_client()
        elif path == '/api/clients/remove':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_remove_clients()
        elif path == '/api/block/add':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_block_add()
        elif path == '/api/block/drop':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_block_drop()
        elif path == '/api/white/add':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_white_add()
        elif path == '/api/white/drop':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_white_drop()
        elif path == '/api/users/add':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_add_user()
        elif path == '/api/users/remove':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_remove_users()
        elif path == '/api/settings/config':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_config_update()
        elif path == '/settings' or path == '/settings.html':
            if not self.is_authenticated():
                # Para acesso HTML, redirecionar para login se não autenticado
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return
            if not self.is_admin_session():
                self.send_response(302)
                self.send_header('Location', '/dashboard.html')
                self.end_headers()
                return
            self.handle_settings_form_post()
        elif path == '/api/users/send-totp':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_send_totp()
        elif path == '/api/settings/smtp-toggle':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_smtp_toggle()
        elif path == '/api/server/memory':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.get_server_memory()
        elif path == '/api/addons/subdomain-campaign/whitelist':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.handle_subdomain_campaign_whitelist()
        elif path == '/api/addons/subdomain-campaign/reset-simulation':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            if not self.require_admin():
                return
            self.reset_subdomain_campaign_simulation()
        else:
            self.send_error(404, "Not found")

    def check_user_totp_status(self, email):
        """Check if user has TOTP enabled (public endpoint)"""
        # Rate limiting: 3 tentativas por minuto por IP
        client_ip = self.client_address[0]

        if self.is_check_status_rate_limited(client_ip):
            self.send_json_response({
                'error': 'Too many requests',
                'message': f'Rate limit exceeded. Maximum {MAX_CHECK_STATUS_ATTEMPTS} requests per minute.',
                'retry_after': 60
            }, 429)
            return

        # Incrementar contador de tentativas
        self.increment_check_status_attempts(client_ip)

        if not email or not self.is_valid_email(email):
            self.send_json_response({'error': 'Invalid email format'}, 400)
            return

        try:
            # PRIMEIRO: Verificar se é admin - pegar email do admin do spfbl.conf
            admin_email = self.get_admin_email()
            if admin_email and email.lower() == admin_email.lower():
                # Admin sempre é considerado com TOTP (desabilita tela de primeiro acesso)
                self.send_json_response({
                    'success': True,
                    'has_totp': True,
                    'message': 'Admin user - TOTP check bypassed'
                })
                return

            # O painel legado sempre retorna a página de login sem credenciais,
            # então não é possível detectar TOTP de forma confiável via HTTP.
            # Para evitar falsos negativos, retornamos has_totp=True aqui.
            self.send_json_response({
                'success': True,
                'has_totp': True,
                'message': 'TOTP status not detectable via API'
            })
            return

        except Exception as e:
            self.send_json_response({'error': f'Error checking status: {str(e)}'}, 500)

    def handle_request_totp(self):
        """Handle TOTP request for new users (with reCAPTCHA validation)"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_json_response({'error': 'Invalid JSON'}, 400)
                return

            email = self.sanitize_input(data.get('email', ''))
            recaptcha_token = data.get('recaptcha_token', '')

            # Validar formato de email
            if not self.is_valid_email(email):
                self.send_json_response({'error': 'Invalid email format'}, 400)
                return

            # Verificar reCAPTCHA se configurado em spfbl.conf
            recaptcha_config = self.get_recaptcha_keys()
            if recaptcha_config['enabled']:
                # reCAPTCHA está habilitado, validar token
                if not recaptcha_token:
                    self.send_json_response({
                        'error': 'reCAPTCHA token is required'
                    }, 400)
                    return

                if not self.verify_recaptcha(recaptcha_token, recaptcha_config['secret_key']):
                    self.send_json_response({
                        'error': 'reCAPTCHA verification failed'
                    }, 400)
                    return

            # Verificar se usuário existe
            result = subprocess.run(
                ['/sbin/spfbl', 'user', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if email not in result.stdout:
                self.send_json_response({
                    'error': 'User not found',
                }, 404)
                return

            # Executar comando para enviar TOTP
            result = subprocess.run(
                ['/sbin/spfbl', 'user', 'send-totp', email],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = (result.stdout + result.stderr).strip()

            if 'TOTP' in output.upper() or result.returncode == 0:
                self.send_json_response({
                    'success': True,
                    'message': 'TOTP code sent to your email. Please check your inbox.',
                    'email': email
                })
            else:
                self.send_json_response({
                    'error': 'Failed to send TOTP code',
                    'details': output
                }, 500)

        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout sending TOTP'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Error: {str(e)}'}, 500)

    def get_admin_email(self):
        """Get admin email from multiple sources with fallback"""
        # Tentar primeiro em spfbl.conf
        email = self._get_admin_email_from_conf()
        if email:
            return email

        # Se falhar, tentar em REMOTE_INTEGRATION.md
        email = self._get_admin_email_from_remote_integration()
        if email:
            return email

        return None

    def _get_admin_email_from_conf(self):
        """Extract admin email from spfbl.conf using regex"""
        try:
            with open(CONF_FILE, 'r') as f:
                content = f.read()
                # Usar regex para encontrar admin_email=...
                match = re.search(r'^\s*admin_email\s*=\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*$',
                                content, re.MULTILINE | re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return None

    def _get_admin_email_from_remote_integration(self):
        """Extract admin email from REMOTE_INTEGRATION.md using regex"""
        try:
            with open(REMOTE_INTEGRATION_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
                # Procurar padrão: "Email admin:" seguido de email
                # Procura "• Email admin:" ou similar
                match = re.search(r'(?:Email\s+admin|email\s+admin)\s*:?\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                                content, re.IGNORECASE)
                if match:
                    return match.group(1).strip()

                # Fallback: procurar http://.../.../email@dominio no URL do painel
                match = re.search(r'http://[^/]+/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                                content, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        except Exception:
            pass
        return None

    def get_recaptcha_keys(self):
        """Get reCAPTCHA keys from spfbl.conf (only if not commented)"""
        try:
            with open(CONF_FILE, 'r') as f:
                content = f.read()

                # Buscar site key (ignora linhas comentadas)
                site_key_match = re.search(
                    r'^\s*(?!#)recaptcha_key_site\s*=\s*(.+?)\s*$',
                    content,
                    re.MULTILINE
                )

                # Buscar secret key (ignora linhas comentadas)
                secret_key_match = re.search(
                    r'^\s*(?!#)recaptcha_key_secret\s*=\s*(.+?)\s*$',
                    content,
                    re.MULTILINE
                )

                site_key = site_key_match.group(1).strip() if site_key_match else None
                secret_key = secret_key_match.group(1).strip() if secret_key_match else None

                # Só retorna se AMBAS as chaves estiverem configuradas
                if site_key and secret_key:
                    return {
                        'site_key': site_key,
                        'secret_key': secret_key,
                        'enabled': True
                    }

        except Exception:
            pass

        return {
            'site_key': None,
            'secret_key': None,
            'enabled': False
        }

    def verify_recaptcha(self, token, secret):
        """Verify reCAPTCHA token"""
        try:
            data = urllib.parse.urlencode({'secret': secret, 'response': token}).encode('utf-8')
            request = urllib.request.Request(
                'https://www.google.com/recaptcha/api/siteverify',
                data=data,
                headers={'User-Agent': 'spfbl-dashboard/2.0'}
            )
            response = urllib.request.urlopen(request, timeout=5)
            result = json.loads(response.read().decode('utf-8'))

            # v2 não devolve score; v3 usa score. Aceitar sucesso simples quando não houver score.
            success = result.get('success', False)
            score = result.get('score')

            if not success:
                return False

            if score is None:
                return True

            return score >= 0.5
        except Exception:
            return False

    # ===========================
    # SMTP / Abuse notifications toggle
    # ===========================

    def _read_spfbl_conf_lines(self):
        try:
            with open(CONF_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                return f.readlines()
        except Exception:
            return []

    def _parse_spfbl_conf_kv(self, lines=None):
        if lines is None:
            lines = self._read_spfbl_conf_lines()
        kv = {}
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('#') or '=' not in stripped:
                continue
            key, value = stripped.split('=', 1)
            kv[key.strip().lower()] = value.strip()
        return kv

    def _compute_smtp_enabled(self, kv):
        admin_email = (kv.get('admin_email') or '').strip()
        smtp_host = (kv.get('smtp_host') or '').strip()
        if not admin_email:
            return False
        if not smtp_host or smtp_host.lower() in {'none', 'false', '0', 'null'}:
            return False
        return True

    def _set_conf_key_value(self, lines, key, value):
        pattern = re.compile(rf'^\s*(?!#){re.escape(key)}\s*=', re.IGNORECASE)
        found = False
        new_lines = []
        for line in lines:
            if pattern.match(line):
                prefix = line.split('=', 1)[0].rstrip()
                new_lines.append(f"{prefix}={value}\n")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"{key}={value}\n")
        return new_lines

    def get_smtp_status(self):
        try:
            kv = self._parse_spfbl_conf_kv()
            enabled = self._compute_smtp_enabled(kv)
            self.send_json_response({'success': True, 'enabled': enabled})
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 500)

    def handle_smtp_toggle(self):
        """Enable/disable SPFBL outgoing SMTP (abuse reports, TOTP, etc.)."""
        if self.is_config_locked():
            self.send_json_response({
                'error': 'Configuração protegida: arquivo spfbl.conf.lock existe. Remova o arquivo lock para editar.',
                'locked': True
            }, 403)
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b'{}'
            data = json.loads(body.decode('utf-8'))
        except Exception:
            self.send_json_response({'error': 'JSON inválido'}, 400)
            return

        desired_enabled = bool(data.get('enabled'))

        lines = self._read_spfbl_conf_lines()
        kv = self._parse_spfbl_conf_kv(lines)
        current_enabled = self._compute_smtp_enabled(kv)

        if desired_enabled == current_enabled:
            self.send_json_response({
                'success': True,
                'enabled': current_enabled,
                'message': 'SMTP já está no estado desejado'
            })
            return

        smtp_keys = [
            'admin_email',
            'smtp_auth',
            'smtp_starttls',
            'smtp_host',
            'smtp_port',
            'smtp_user',
            'smtp_password',
            'dkim_selector',
            'dkim_private',
            'abuse_email'
        ]

        if not desired_enabled:
            backup_data = {k: kv.get(k) for k in smtp_keys if k in kv}
            try:
                with open(SMTP_BACKUP_FILE, 'w', encoding='utf-8') as f:
                    json.dump(backup_data, f, ensure_ascii=False, indent=2)
                try:
                    os.chmod(SMTP_BACKUP_FILE, 0o600)
                except Exception:
                    pass
            except Exception as e:
                self.send_json_response({'error': f'Erro ao salvar backup SMTP: {str(e)}'}, 500)
                return

            # Desativa envio esvaziando host/porta/usuário e desabilitando auth.
            # NÃO altera smtp_password para manter compatibilidade de login legado.
            lines = self._set_conf_key_value(lines, 'smtp_host', '')
            lines = self._set_conf_key_value(lines, 'smtp_port', '')
            lines = self._set_conf_key_value(lines, 'smtp_user', '')
            lines = self._set_conf_key_value(lines, 'smtp_auth', 'false')
            lines = self._set_conf_key_value(lines, 'smtp_starttls', 'no')
            if 'abuse_email' in kv:
                lines = self._set_conf_key_value(lines, 'abuse_email', '')
        else:
            if not os.path.exists(SMTP_BACKUP_FILE):
                self.send_json_response({
                    'error': 'Não há backup SMTP para restaurar. Reconfigure manualmente no spfbl.conf.',
                    'enabled': current_enabled
                }, 400)
                return
            try:
                with open(SMTP_BACKUP_FILE, 'r', encoding='utf-8') as f:
                    backup_data = json.load(f) or {}
            except Exception as e:
                self.send_json_response({'error': f'Backup SMTP inválido: {str(e)}'}, 500)
                return

            for key, val in backup_data.items():
                if val is None:
                    continue
                lines = self._set_conf_key_value(lines, key, str(val))

        backup_file = f'{CONF_FILE}.backup-{int(time.time())}'
        try:
            shutil.copy2(CONF_FILE, backup_file)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao fazer backup da configuração: {str(e)}'}, 500)
            return

        try:
            with open(CONF_FILE, 'w', encoding='utf-8') as f:
                f.writelines(lines)
        except Exception as e:
            try:
                shutil.copy2(backup_file, CONF_FILE)
            except Exception:
                pass
            self.send_json_response({'error': f'Erro ao salvar configuração: {str(e)}'}, 500)
            return

        restarted = True
        restart_error = None
        try:
            subprocess.run(['systemctl', 'restart', 'spfbl'], timeout=10)
        except Exception as e:
            restarted = False
            restart_error = str(e)

        self.send_json_response({
            'success': True,
            'enabled': desired_enabled,
            'config_backup': backup_file,
            'service_restarted': restarted,
            'restart_error': restart_error
        })

    def is_authenticated(self):
        """Verify if user is authenticated via session token"""
        cookies = SimpleCookie(self.headers.get('Cookie', ''))

        if 'session_token' not in cookies:
            return False

        token = cookies['session_token'].value

        if token not in sessions:
            return False

        session = sessions[token]
        current_time = time.time()
        session_age = current_time - session['created']

        # Verificar timeout da sessão
        if session_age > SESSION_TIMEOUT:
            del sessions[token]
            return False

        # Renovação automática de sessão (se estiver nos últimos 10 minutos)
        # Isso previne session fixation e melhora a segurança
        if session_age > (SESSION_TIMEOUT - 600):  # 10 minutos antes de expirar
            session['created'] = current_time
            session['renewed'] = True

        return True

    def get_current_user(self):
        """Get current authenticated user info"""
        session = self._get_session()
        if not session:
            self.send_json_response({'error': 'Not authenticated'}, 401)
            return
        email = (session.get('email') or '').strip()
        is_admin = self.is_admin_email(email)
        allowed_hosts = self.get_user_allowed_hostnames(email)
        self.send_json_response({
            'email': email,
            'authenticated': True,
            'is_admin': is_admin,
            'allowed_hosts': allowed_hosts if allowed_hosts is not None else None
        })

    def handle_login(self):
        """Handle login authentication"""
        try:
            client_ip = self.client_address[0]

            # Verificar se IP está bloqueado por tentativas excessivas
            if self.is_ip_locked(client_ip):
                self.send_json_response({
                    'error': 'Too many failed attempts. Please try again later.',
                    'locked_until': login_attempts[client_ip]['locked_until']
                }, 429)
                return

            # Ler dados do POST
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')

            try:
                data = json.loads(post_data)
            except json.JSONDecodeError:
                self.send_json_response({'error': 'Invalid JSON'}, 400)
                return

            email = self.sanitize_input(data.get('email', ''))
            password = data.get('password', '')

            # Validar formato de email
            if not self.is_valid_email(email):
                self.increment_login_attempts(client_ip)
                self.send_json_response({'error': 'Invalid email format'}, 400)
                return

            if not password:
                self.increment_login_attempts(client_ip)
                self.send_json_response({'error': 'Password or TOTP code is required'}, 400)
                return

            authenticated = False
            auth_method = 'password'

            # Primeiro tenta autenticar via senha tradicional
            if self.verify_credentials(email, password):
                authenticated = True
                auth_method = 'password'
            else:
                # Se falhou e a "senha" parece um código TOTP (6 dígitos), tentar autenticar via painel HTTP original
                if password.isdigit() and len(password) == 6:
                    if self.verify_totp_with_spfbl(email, password):
                        authenticated = True
                        auth_method = 'totp'

            if authenticated:
                # Login bem-sucedido
                self.reset_login_attempts(client_ip)

                # Criar sessão
                token = secrets.token_urlsafe(32)
                sessions[token] = {
                    'email': email,
                    'created': time.time(),
                    'ip': client_ip,
                    'auth_method': auth_method
                }

                # Limpar sessões antigas periodicamente
                self.cleanup_old_sessions()

                # Enviar resposta com cookie seguro
                origin = self.headers.get('Origin')
                allowed_origin = self.get_allowed_origin(origin)

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')

                # Configurar CORS apenas para origens permitidas
                if allowed_origin:
                    self.send_header('Access-Control-Allow-Origin', allowed_origin)
                    self.send_header('Access-Control-Allow-Credentials', 'true')

                # Cookie seguro
                cookie = SimpleCookie()
                cookie['session_token'] = token
                cookie['session_token']['httponly'] = True
                cookie['session_token']['secure'] = USE_SECURE_COOKIES  # True se HTTPS habilitado
                cookie['session_token']['samesite'] = 'Strict'
                cookie['session_token']['max-age'] = SESSION_TIMEOUT
                cookie['session_token']['path'] = '/'

                self.send_header('Set-Cookie', cookie['session_token'].OutputString())
                self.end_headers()

                response = {
                    'success': True,
                    'email': email,
                    'auth_method': auth_method,
                    'message': 'Login successful'
                }
                self.wfile.write(json.dumps(response).encode())

            else:
                # Login falhou
                self.increment_login_attempts(client_ip)
                remaining = MAX_LOGIN_ATTEMPTS - login_attempts.get(client_ip, {}).get('count', 0)

                self.send_json_response({
                    'error': 'Invalid credentials',
                    'remaining_attempts': max(0, remaining)
                }, 401)

        except Exception as e:
            self.send_json_response({'error': f'Login error: {str(e)}'}, 500)

    def handle_logout(self):
        """Handle logout"""
        cookies = SimpleCookie(self.headers.get('Cookie', ''))

        if 'session_token' in cookies:
            token = cookies['session_token'].value
            if token in sessions:
                del sessions[token]

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Set-Cookie', 'session_token=; Max-Age=0; Path=/')
        self.end_headers()
        self.wfile.write(json.dumps({'success': True}).encode())

    def handle_add_client(self):
        """Handle adding a new SPFBL client"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            # Validar campos obrigatórios
            required_fields = ['ip', 'domain']
            for field in required_fields:
                if field not in data or not data[field].strip():
                    self.send_json_response({
                        'error': f'Campo obrigatório ausente: {field}'
                    }, 400)
                    return

            ip = data['ip'].strip()
            domain = data['domain'].strip()
            email = data.get('email', '').strip()
            option = data.get('option', 'SPFBL').strip()

            # Validar formato de IP (IPv4 simples ou CIDR)
            import re
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
            if not re.match(ip_pattern, ip):
                self.send_json_response({
                    'error': 'Formato de IP inválido. Use: x.x.x.x ou x.x.x.x/xx'
                }, 400)
                return

            # Validar IP range
            ip_parts = ip.split('/')[0].split('.')
            for part in ip_parts:
                if int(part) > 255:
                    self.send_json_response({
                        'error': 'IP inválido. Cada octeto deve ser 0-255'
                    }, 400)
                    return

            # Validar CIDR se presente
            if '/' in ip:
                cidr = int(ip.split('/')[1])
                if cidr < 0 or cidr > 32:
                    self.send_json_response({
                        'error': 'CIDR inválido. Deve ser 0-32'
                    }, 400)
                    return
            else:
                # Se não tem CIDR, adicionar /32 (single IP)
                ip = ip + '/32'

            # Validar domínio
            domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-_.]+[a-zA-Z0-9]$'
            if not re.match(domain_pattern, domain):
                self.send_json_response({
                    'error': 'Formato de domínio inválido'
                }, 400)
                return

            # Validar email se fornecido
            if email:
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_pattern, email):
                    self.send_json_response({
                        'error': 'Formato de email inválido'
                    }, 400)
                    return

            # Validar opção
            valid_options = ['SPFBL', 'DNSBL', 'NONE']
            if option not in valid_options:
                self.send_json_response({
                    'error': f'Opção inválida. Use: {", ".join(valid_options)}'
                }, 400)
                return

            # Montar comando SPFBL
            cmd = ['/sbin/spfbl', 'client', 'add', ip, domain, option]
            if email:
                cmd.append(email)

            # Executar comando
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            # SPFBL retorna mensagens no stdout/stderr independente do returncode
            # Verificar se a operação foi bem-sucedida pela mensagem
            output = (result.stdout + result.stderr).strip()

            if 'ADDED' in output or result.returncode == 0:
                self.send_json_response({
                    'success': True,
                    'message': f'Cliente {domain} ({ip}) adicionado com sucesso',
                    'client': {
                        'ip': ip,
                        'domain': domain,
                        'option': option,
                        'email': email or 'N/A'
                    }
                })
            elif 'ALREADY EXISTS' in output or 'EXISTS' in output:
                self.send_json_response({
                    'error': f'Cliente {domain} ({ip}) já existe no sistema'
                }, 409)
            else:
                error_msg = output or 'Erro desconhecido'
                self.send_json_response({
                    'error': f'Erro ao adicionar cliente: {error_msg}'
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao adicionar cliente: {str(e)}'}, 500)

    def handle_remove_clients(self):
        """Handle removing SPFBL clients"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            ips = data.get('ips', [])
            if not isinstance(ips, list) or not ips:
                self.send_json_response({
                    'error': 'Lista de clientes vazia ou inválida'
                }, 400)
                return

            removed = []
            errors = []

            for ip in ips:
                ip_str = str(ip).strip()
                if not ip_str:
                    continue

                try:
                    result = subprocess.run(
                        ['/sbin/spfbl', 'client', 'drop', ip_str],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    output = (result.stdout + result.stderr).strip()

                    if 'DROPPED' in output or result.returncode == 0:
                        removed.append(ip_str)
                    else:
                        errors.append({
                            'ip': ip_str,
                            'error': output or 'Erro desconhecido'
                        })
                except subprocess.TimeoutExpired:
                    errors.append({
                        'ip': ip_str,
                        'error': 'Timeout ao executar comando SPFBL'
                    })
                except Exception as e:
                    errors.append({
                        'ip': ip_str,
                        'error': str(e)
                    })

            if removed:
                self.send_json_response({
                    'success': True,
                    'removed': removed,
                    'errors': errors,
                    'message': f'{len(removed)} cliente(s) removido(s) com sucesso'
                })
            else:
                self.send_json_response({
                    'success': False,
                    'error': 'Nenhum cliente foi removido',
                    'details': errors
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao remover clientes: {str(e)}'}, 500)

    def verify_credentials(self, email, password):
        """Verify credentials against SPFBL user database"""
        try:
            # PRIMEIRO: Tentar validar contra arquivo de configuração (inclui admin padrão)
            if self.verify_against_config(email, password):
                return True

            # SEGUNDO: Tentar autenticar via painel HTTP original (senha normal)
            if self.verify_password_with_spfbl(email, password):
                return True

        except Exception:
            return False

    def verify_totp_with_spfbl(self, email, otp_code):
        """Verify TOTP/OTP code against original SPFBL HTTP control panel.

        AVISO DE SEGURANÇA:
        - Esta função delega autenticação ao painel legado em http://127.0.0.1:8001
        - Certifique-se que a porta 8001 NÃO está exposta publicamente
        - Use firewall para bloquear acesso externo à porta 8001
        - Considere migrar para autenticação nativa no futuro

        Fluxo:
        1. POST http://127.0.0.1:8001/<email> com body otp=<codigo>.
        2. GET a mesma URL com o cookie retornado.
        3. Considera autenticado se a resposta não for a página de login.
        """
        base_url = os.environ.get('SPFBL_PANEL_URL', 'http://127.0.0.1:8001')

        # VALIDAÇÃO: Garantir que o painel legado está em localhost
        if base_url and '127.0.0.1' not in base_url and 'localhost' not in base_url:
            # Não permitir acesso a painéis externos
            return False

        try:
            parsed = urllib.parse.urlparse(base_url)
            if not parsed.scheme:
                base_url = 'http://' + base_url
        except Exception:
            base_url = 'http://127.0.0.1:8001'

        email_path = '/' + urllib.parse.quote(email)

        return self._verify_legacy_otp_login(base_url, email_path, otp_code)

    def verify_password_with_spfbl(self, email, password):
        """Verify password/OTP using the legacy SPFBL HTTP login.

        AVISO DE SEGURANÇA:
        - Esta função delega autenticação ao painel legado em http://127.0.0.1:8001
        - Certifique-se que a porta 8001 NÃO está exposta publicamente
        - Use firewall para bloquear acesso externo à porta 8001
        - Considere migrar para autenticação nativa no futuro

        Fluxo:
        1. POST http://127.0.0.1:8001/<email> com body otp=<codigo ou senha>.
        2. GET a mesma URL com o cookie retornado.
        3. Considera autenticado se a resposta não for a página de login.
        """
        base_url = os.environ.get('SPFBL_PANEL_URL', 'http://127.0.0.1:8001')

        # VALIDAÇÃO: Garantir que o painel legado está em localhost
        if base_url and '127.0.0.1' not in base_url and 'localhost' not in base_url:
            # Não permitir acesso a painéis externos
            return False

        try:
            parsed = urllib.parse.urlparse(base_url)
            if not parsed.scheme:
                base_url = 'http://' + base_url
        except Exception:
            base_url = 'http://127.0.0.1:8001'

        email_path = '/' + urllib.parse.quote(email)

        # Em versões atuais do painel legado, o campo de login é "otp".
        # Para compatibilidade com versões antigas, enviamos otp e password com o mesmo valor.
        return self._verify_legacy_otp_login(base_url, email_path, password)

    def _is_legacy_authenticated_html(self, html_text):
        """Verifica se o HTML retornado indica autenticação bem-sucedida.

        SEGURANÇA: Esta função deve ser RESTRITIVA - só retorna True
        se encontrar marcadores POSITIVOS de autenticação.
        Nunca usar fallback permissivo!
        """
        if not html_text:
            return False
        html_lower = html_text.lower()

        # MARCADORES NEGATIVOS - Indicam que NÃO está autenticado
        # Página de login explícita (qualquer variação)
        if 'spfbl login' in html_lower:
            return False
        # Se contém campo otp/password, ainda está na página de login
        if re.search(r'name=["\']?(otp|password)\b', html_lower):
            return False
        # Mensagens de erro conhecidas
        if 'could not send' in html_lower or 'totp secret' in html_lower:
            return False
        # Solicitar TOTP
        if 'does not have a' in html_lower and 'totp' in html_lower:
            return False

        # MARCADOR POSITIVO - Única forma de confirmar autenticação
        # Só retorna True se encontrar o painel de controle explicitamente
        if 'painel de controle do spfbl' in html_lower or 'spfbl control panel' in html_lower:
            return True

        # SEGURANÇA: Se não encontrou marcador positivo, retorna False
        # Nunca assumir autenticado por padrão!
        return False

    def _verify_legacy_otp_login(self, base_url, email_path, secret):
        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        opener.addheaders = [('User-Agent', 'spfbl-dashboard/2.0')]

        try:
            payload = urllib.parse.urlencode({'otp': secret, 'password': secret}).encode('utf-8')
            opener.open(f"{base_url}{email_path}", data=payload, timeout=3)
            panel_resp = opener.open(f"{base_url}{email_path}", timeout=3)
            html_text = panel_resp.read().decode('utf-8', errors='ignore')
        except Exception:
            return False

        return self._is_legacy_authenticated_html(html_text)

    def verify_against_config(self, email, password):
        """Verify against a secure configuration file"""
        # Arquivo de senhas hash (criar separadamente)
        config_file = DASHBOARD_USERS_FILE

        if not os.path.exists(config_file):
            # Se arquivo não existe, criar com usuário padrão do spfbl.conf
            return self.verify_spfbl_default_user(email, password)

        try:
            with open(config_file, 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split(':')
                        if len(parts) == 2:
                            stored_email, stored_hash = parts
                            if stored_email == email:
                                # Verificar hash da senha
                                return self.verify_password_hash(password, stored_hash)
        except:
            pass

        return False

    def verify_spfbl_default_user(self, email, password):
        """Verify against default SPFBL admin user"""
        try:
            # SEGURANÇA: Credenciais hardcoded foram REMOVIDAS
            # Se você precisa de um usuário padrão, configure em spfbl.conf

            # Procurar configuração de admin_email no spfbl.conf
            with open(CONF_FILE, 'r') as f:
                content = f.read()

                # CORREÇÃO DE SEGURANÇA: Usar regex para validação exata da linha
                # Evita bypass via substring injection (ex: "admin_email=user@domain.com")
                # IMPORTANTE: Ignora linhas comentadas (começando com #)
                admin_email_pattern = r'^\s*(?!#)admin_email\s*=\s*(' + re.escape(email) + r')\s*$'
                admin_match = re.search(admin_email_pattern, content, re.MULTILINE | re.IGNORECASE)

                if admin_match:
                    # CORREÇÃO DE SEGURANÇA: Usar regex para extrair senha também
                    # Evita injeção e garante que pegamos a linha correta
                    # IMPORTANTE: Ignora linhas comentadas
                    smtp_password_pattern = r'^\s*(?!#)smtp_password\s*=\s*(.+?)\s*$'
                    password_match = re.search(smtp_password_pattern, content, re.MULTILINE)

                    if password_match:
                        stored_password = password_match.group(1).strip()
                        # Usar comparação com timing constante para evitar timing attacks
                        return hmac.compare_digest(password.encode('utf-8'), stored_password.encode('utf-8'))

        except FileNotFoundError:
            # Arquivo de configuração não encontrado
            pass
        except Exception as e:
            # Log erro mas não exponha detalhes
            pass

        return False

    def verify_password_hash(self, password, password_hash):
        """Verify password against hash"""
        # Usar PBKDF2 ou similar
        import hashlib

        parts = password_hash.split('$')
        if len(parts) != 4:
            return False

        algorithm, iterations, salt, stored_hash = parts

        if algorithm != 'pbkdf2_sha256':
            return False

        # Calcular hash da senha fornecida
        computed_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            int(iterations)
        ).hex()

        return hmac.compare_digest(computed_hash, stored_hash)

    def is_ip_locked(self, ip):
        """Check if IP is locked due to failed login attempts"""
        if ip not in login_attempts:
            return False

        attempts = login_attempts[ip]

        if 'locked_until' in attempts:
            if time.time() < attempts['locked_until']:
                return True
            else:
                # Tempo de bloqueio expirou
                del login_attempts[ip]
                return False

        return False

    def increment_login_attempts(self, ip):
        """Increment failed login attempts for IP"""
        if ip not in login_attempts:
            login_attempts[ip] = {'count': 0}

        login_attempts[ip]['count'] += 1

        if login_attempts[ip]['count'] >= MAX_LOGIN_ATTEMPTS:
            login_attempts[ip]['locked_until'] = time.time() + LOCKOUT_TIME

    def reset_login_attempts(self, ip):
        """Reset login attempts for IP"""
        if ip in login_attempts:
            del login_attempts[ip]

    def is_check_status_rate_limited(self, ip):
        """Check if IP is rate limited for /api/user/check-status endpoint"""
        if ip not in check_status_attempts:
            return False

        attempts = check_status_attempts[ip]
        current_time = time.time()

        # Se a janela de tempo expirou, resetar contador
        if current_time > attempts.get('reset_at', 0):
            del check_status_attempts[ip]
            return False

        # Verificar se excedeu o limite
        if attempts.get('count', 0) >= MAX_CHECK_STATUS_ATTEMPTS:
            return True

        return False

    def increment_check_status_attempts(self, ip):
        """Increment check-status attempts for IP with 1-minute window"""
        current_time = time.time()

        if ip not in check_status_attempts:
            check_status_attempts[ip] = {
                'count': 0,
                'reset_at': current_time + RATE_LIMIT_WINDOW
            }

        # Se a janela expirou, resetar
        if current_time > check_status_attempts[ip].get('reset_at', 0):
            check_status_attempts[ip] = {
                'count': 0,
                'reset_at': current_time + RATE_LIMIT_WINDOW
            }

        check_status_attempts[ip]['count'] += 1

    def cleanup_old_sessions(self):
        """Remove expired sessions"""
        current_time = time.time()
        expired = [token for token, data in sessions.items()
                  if current_time - data['created'] > SESSION_TIMEOUT]

        for token in expired:
            del sessions[token]

    def sanitize_input(self, input_string):
        """
        Sanitize user input to prevent XSS and command injection.

        IMPORTANTE: Esta função é para sanitizar emails, nomes, etc.
        NÃO use para sanitizar senhas, pois pode quebrar senhas válidas!
        """
        if not input_string:
            return ''

        # Remover caracteres perigosos que podem ser usados em ataques
        # Lista completa: < > " ' ; ( ) & | ` $ { } \ e caracteres de controle
        # NOTA: Não removemos @ . - _ + pois são válidos em emails
        dangerous_chars = r'[<>"\';()&|`${}\\]'
        sanitized = re.sub(dangerous_chars, '', input_string)

        # Remover caracteres de controle (newline, tab, etc) separadamente
        # usando \x00-\x1F (caracteres de controle ASCII)
        sanitized = re.sub(r'[\x00-\x1F\x7F]', '', sanitized)

        # Remover espaços extras e retornar
        return sanitized.strip()

    def escape_html(self, text):
        """
        Escape HTML special characters to prevent XSS when displaying user data.
        Use this when you need to display user-provided data in HTML context.
        """
        if not text:
            return ''
        return html.escape(str(text), quote=True)

    def is_valid_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def build_csp_policy(self):
        """Centraliza a política CSP para reutilização"""
        return (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; "
            "style-src 'self' 'unsafe-inline' https://www.gstatic.com/recaptcha/; "
            "img-src 'self' data: https://www.gstatic.com/recaptcha/; "
            "frame-src 'self' https://www.google.com/recaptcha/; "
            "connect-src 'self' https://www.google.com/recaptcha/; "
            "font-src 'self' https://fonts.gstatic.com;"
        )

    def serve_login_page(self):
        """Serve login page"""
        self.serve_file(os.path.join(WEB_DIR, 'login.html'), 'text/html')

    def serve_file(self, file_path, content_type):
        """Serve static files with correct Content-Type and security headers"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(content))
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')

            # Security headers
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-XSS-Protection', '1; mode=block')
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')

            # Permitir domínios necessários para o reCAPTCHA sem abrir o restante da política
            self.send_header('Content-Security-Policy', self.build_csp_policy())

            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, "File not found")
        except Exception as e:
            self.send_error(500, f"Error serving file: {str(e)}")

    def send_json_response(self, data, status=200):
        """Send JSON response with security headers"""
        origin = self.headers.get('Origin')
        allowed_origin = self.get_allowed_origin(origin)

        self.send_response(status)
        self.send_header('Content-Type', 'application/json')

        # Configurar CORS apenas para origens permitidas
        if allowed_origin:
            self.send_header('Access-Control-Allow-Origin', allowed_origin)
            self.send_header('Access-Control-Allow-Credentials', 'true')

        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def get_authorized_networks(self):
        """Return list of authorized client networks excluding loopback"""
        networks = []
        output = self.run_spfbl_command('client show') or ''

        if output.startswith('ERROR'):
            return networks

        for raw_line in output.strip().split('\n'):
            line = raw_line.strip()
            if not line or ':' not in line:
                continue

            try:
                ident_cidr = line.split()[0]
            except IndexError:
                continue

            if ':' not in ident_cidr:
                continue

            _, cidr = ident_cidr.rsplit(':', 1)

            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue

            if network.is_loopback:
                continue

            networks.append(network)

        return networks

    def is_authorized_client_ip(self, ip_str, networks=None):
        """Check if provided IP belongs to an authorized client network"""
        if not ip_str:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        if networks is None:
            networks = self.get_authorized_networks()

        for network in networks:
            if ip_obj in network:
                return True
        return False

    def run_spfbl_command(self, command):
        """Execute SPFBL CLI command and return output"""
        try:
            result = subprocess.run(
                ['/sbin/spfbl'] + command.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout
        except Exception as e:
            return f"ERROR: {str(e)}"

    def get_fraud_token(self):
        """Return shared token for fraud event reporting"""
        try:
            with open(FRAUD_TOKEN_FILE, 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            return None

    def load_fraud_events(self):
        """Load stored fraud events"""
        try:
            with open(FRAUD_EVENTS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except FileNotFoundError:
            return []
        except json.JSONDecodeError:
            return []
        return []

    def write_fraud_events(self, events):
        """Persist fraud events safely"""
        os.makedirs(os.path.dirname(FRAUD_EVENTS_FILE), exist_ok=True)
        tmp_file = f"{FRAUD_EVENTS_FILE}.tmp"
        with open(tmp_file, 'w') as f:
            json.dump(events, f)
        os.replace(tmp_file, FRAUD_EVENTS_FILE)

    def append_fraud_event(self, event):
        """Append event to store respecting max size"""
        events = self.load_fraud_events()
        events.append(event)
        events = events[-MAX_FRAUD_EVENTS:]
        self.write_fraud_events(events)

    def get_fraud_events(self):
        """Return fraud events for authenticated dashboard users"""
        if not self.is_authenticated():
            self.send_json_response({'error': 'Unauthorized'}, 401)
            return

        events = self.load_fraud_events()
        self.send_json_response({'events': events[-100:]})

    def handle_fraud_event_report(self):
        """Accept fraud blocking reports from remote servers"""
        expected_token = self.get_fraud_token()
        auth_header = self.headers.get('Authorization', '')
        provided_token = ''
        if auth_header.lower().startswith('bearer '):
            provided_token = auth_header.split(' ', 1)[1].strip()

        if not expected_token or provided_token != expected_token:
            self.send_json_response({'error': 'Unauthorized'}, 401)
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length).decode('utf-8') if content_length else ''
            content_type = self.headers.get('Content-Type', '')

            if 'application/json' in content_type:
                body = json.loads(raw_body or '{}')
            else:
                body = {k: v[0] for k, v in parse_qs(raw_body).items()}
        except Exception:
            self.send_json_response({'error': 'Invalid payload'}, 400)
            return

        timestamp = datetime.utcnow().isoformat() + 'Z'
        reason = body.get('reason') or 'FRAUD'

        event = {
            'timestamp': timestamp,
            'ip': body.get('ip', ''),
            'sender': body.get('sender', ''),
            'helo': body.get('helo', ''),
            'recipient': body.get('recipient', ''),
            'result': reason,
            'reason': reason,
            'reporter': self.client_address[0]
        }

        self.append_fraud_event(event)
        self.send_json_response({'success': True})

    def get_stats(self):
        """Get SPFBL statistics"""
        try:
            log_file = os.path.join(LOG_DIR, f"spfbl.{datetime.now().strftime('%Y-%m-%d')}.log")
            total_queries = 0
            blocked = 0
            passed = 0
            softfail = 0
            failed = 0

            session_email = self._get_session_email()
            allowed_networks = self.get_user_allowed_networks(session_email)
            if allowed_networks is not None and not allowed_networks:
                stats = {
                    'total_queries': 0,
                    'blocked': 0,
                    'passed': 0,
                    'softfail': 0,
                    'failed': 0,
                    'clients_connected': 0,
                    'uptime': self.get_uptime()
                }
                self.send_json_response(stats)
                return

            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if not self._line_matches_allowed_networks(line, allowed_networks):
                            continue
                        if 'SPF' in line and '=>' in line:
                            total_queries += 1
                            if '=> BLOCKED' in line or '=> BANNED' in line:
                                blocked += 1
                            elif '=> PASS' in line:
                                passed += 1
                            elif '=> SOFTFAIL' in line:
                                softfail += 1
                            elif '=> FAIL' in line:
                                failed += 1

            # Count connected clients
            clients_connected = 0
            if allowed_networks is None:
                output = self.run_spfbl_command('client show') or ''
                if output and not output.startswith('ERROR'):
                    clients_connected = len([line for line in output.strip().split('\n') if line.strip() and ':' in line])

            stats = {
                'total_queries': total_queries,
                'blocked': blocked,
                'passed': passed,
                'softfail': softfail,
                'failed': failed,
                'clients_connected': clients_connected,
                'uptime': self.get_uptime()
            }

            self.send_json_response(stats)
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)

    def get_clients(self):
        """Get list of connected clients"""
        try:
            output = self.run_spfbl_command('client show')
            clients = []

            for line in output.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        hostname_ip = parts[0].split(':')
                        clients.append({
                            'hostname': hostname_ip[0] if len(hostname_ip) > 0 else 'unknown',
                            'ip': hostname_ip[1] if len(hostname_ip) > 1 else 'unknown',
                            'type': parts[1] if len(parts) > 1 else 'unknown',
                            'status': 'active',
                            'raw': line
                        })

            self.send_json_response({'clients': clients})
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)

    def _validate_query(self, query):
        """Validate and sanitize query data"""
        return {
            'timestamp': (query.get('timestamp') or '').strip(),
            'ip': (query.get('ip') or '').strip(),
            'sender': (query.get('sender') or '').strip(),
            'helo': (query.get('helo') or '').strip(),
            'recipient': (query.get('recipient') or '').strip(),
            'result': (query.get('result') or 'UNKNOWN').strip().upper(),
            'fraud': query.get('fraud', False),
            'reason': (query.get('reason') or '').strip(),
            'reporter': (query.get('reporter') or '').strip()
        }

    def get_recent_queries(self):
        """Get recent queries from log, prioritizing fraud events"""
        try:
            log_file = os.path.join(LOG_DIR, f"spfbl.{datetime.now().strftime('%Y-%m-%d')}.log")
            queries = []
            max_spf_queries = 50  # Reserve space for fraud events
            session_email = self._get_session_email()
            allowed_networks = self.get_user_allowed_networks(session_email)

            if os.path.exists(log_file):
                from collections import deque
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = deque(f, maxlen=20000)

                count = 0
                for line in reversed(lines):
                    if count >= max_spf_queries:
                        break
                    if not self._line_matches_allowed_networks(line, allowed_networks):
                        continue
                    if 'SPF' in line and '=>' in line:
                        # Improved regex: captures result only up to first space or special char
                        match = re.search(
                            r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4}).*SPF\s+\'([^\']*?)\'.*\'([^\']*?)\'.*\'([^\']*?)\'.*\'([^\']*?)\'.*=>\s+([A-Z\-]+)',
                            line
                        )
                        if match:
                            timestamp, ip, sender, helo, recipient, result = match.groups()
                            query_data = {
                                'timestamp': timestamp.strip(),
                                'ip': ip.strip(),
                                'sender': sender.strip(),
                                'helo': helo.strip(),
                                'recipient': recipient.strip(),
                                'result': result.strip()
                            }
                            validated = self._validate_query(query_data)
                            queries.append(validated)
                            count += 1

            # Load fraud events (up to 50)
            fraud_entries = []
            fraud_events = self.load_fraud_events()
            for event in reversed(fraud_events[-50:]):
                if allowed_networks is not None:
                    reporter_ip = event.get('reporter') or ''
                    if not reporter_ip:
                        continue
                    try:
                        reporter_obj = ipaddress.ip_address(reporter_ip)
                    except ValueError:
                        continue
                    if not any(reporter_obj in net for net in allowed_networks):
                        continue
                fraud_data = {
                    'timestamp': event.get('timestamp', ''),
                    'ip': event.get('ip', ''),
                    'sender': event.get('sender', ''),
                    'helo': event.get('helo', ''),
                    'recipient': event.get('recipient', ''),
                    'result': event.get('result', 'FRAUD'),
                    'fraud': True,
                    'reason': event.get('reason'),
                    'reporter': event.get('reporter')
                }
                validated = self._validate_query(fraud_data)
                fraud_entries.append(validated)

            # Combine and sort correctly (50 SPF + 50 fraud = 100 total)
            combined = queries + fraud_entries

            # Sort by timestamp in reverse order (newest first)
            def get_sort_key(item):
                ts = item.get('timestamp', '')
                return ts if ts else ''

            combined.sort(key=get_sort_key, reverse=True)
            combined = combined[:100]

            self.send_json_response({'queries': combined})
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)

    def get_today_queries(self):
        """Get query statistics for today grouped by hour"""
        try:
            log_file = os.path.join(LOG_DIR, f"spfbl.{datetime.now().strftime('%Y-%m-%d')}.log")
            hourly_stats = {}
            session_email = self._get_session_email()
            allowed_networks = self.get_user_allowed_networks(session_email)

            for hour in range(24):
                hourly_stats[hour] = {
                    'total': 0,
                    'blocked': 0,
                    'passed': 0,
                    'softfail': 0,
                    'failed': 0
                }

            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    for line in f:
                        if not self._line_matches_allowed_networks(line, allowed_networks):
                            continue
                        if 'SPF' in line and '=>' in line:
                            match = re.search(r'T(\d{2}):', line)
                            if match:
                                hour = int(match.group(1))
                                hourly_stats[hour]['total'] += 1

                                if '=> BLOCKED' in line or '=> BANNED' in line:
                                    hourly_stats[hour]['blocked'] += 1
                                elif '=> PASS' in line:
                                    hourly_stats[hour]['passed'] += 1
                                elif '=> SOFTFAIL' in line:
                                    hourly_stats[hour]['softfail'] += 1
                                elif '=> FAIL' in line:
                                    hourly_stats[hour]['failed'] += 1

            result = {
                'hours': list(range(24)),
                'total': [hourly_stats[h]['total'] for h in range(24)],
                'blocked': [hourly_stats[h]['blocked'] for h in range(24)],
                'passed': [hourly_stats[h]['passed'] for h in range(24)],
                'softfail': [hourly_stats[h]['softfail'] for h in range(24)],
                'failed': [hourly_stats[h]['failed'] for h in range(24)]
            }

            self.send_json_response(result)
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)

    def get_spam_block_stats(self):
        """Get SPAM blocking statistics from logs"""
        try:
            session_email = self._get_session_email()
            allowed_networks = self.get_user_allowed_networks(session_email)
            stats = self._calculate_spam_blocks(window_hours=24, allowed_networks=allowed_networks)
            self.send_json_response(stats)
        except Exception as e:
            self.send_json_response({'error': str(e), 'success': False}, 500)

    def get_spam_blocks_hourly(self):
        """Get SPAM blocking statistics by hour of current day (0-23h)"""
        try:
            session_email = self._get_session_email()
            allowed_networks = self.get_user_allowed_networks(session_email)
            hourly = self._calculate_spam_blocks_today(allowed_networks=allowed_networks)
            self.send_json_response(hourly)
        except Exception as e:
            self.send_json_response({'error': str(e), 'success': False}, 500)

    def get_addons(self):
        """Lista addons disponíveis e status básico."""
        try:
            cfg_path, cfg = self._load_subdomain_campaign_addon_config()
            addon_present = os.path.isdir(ADDON_PATH)
            log_path = os.path.join(LOG_DIR, 'addon-subdomain-campaign.log')
            whitelist_path = os.path.join(ADDON_PATH, 'whitelist.csv')

            addons = [
                {
                    'id': 'subdomain_campaign_blocker',
                    'name': 'Subdomain Campaign Blocker',
                    'available': bool(addon_present),
                    'enabled': bool(cfg.get('enabled', False)),
                    'dry_run': bool(cfg.get('dry_run', True)),
                    'config_path': cfg_path,
                    'log_path': log_path,
                    'whitelist_path': whitelist_path,
                }
            ]

            self.send_json_response({
                'success': True,
                'addons_path': ADDON_PATH,
                'folder_exists': bool(addon_present),
                'addons': addons
            })
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 500)

    def _subdomain_campaign_whitelist_csv_path(self):
        return os.path.join(ADDON_PATH, 'whitelist.csv')

    def _normalize_whitelist_domain(self, token):
        value = (token or '').strip().lower()
        if not value:
            return None
        value = value.split(',', 1)[0].strip()
        value = value.lstrip('.').rstrip('.')
        if not value or '@' in value or ' ' in value or '/' in value:
            return None
        if self._looks_like_ip_or_cidr(value):
            return None
        # Domínio simples (pelo menos 1 ponto)
        if '.' not in value:
            return None
        if not re.fullmatch(r'[a-z0-9.-]{1,253}', value):
            return None
        return value

    def _load_subdomain_campaign_whitelist_csv(self):
        entries = set()
        path = self._subdomain_campaign_whitelist_csv_path()
        if not os.path.exists(path):
            return entries
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                for raw in fh:
                    line = (raw or '').strip()
                    if not line or line.startswith('#'):
                        continue
                    d = self._normalize_whitelist_domain(line)
                    if d:
                        entries.add(d)
        except Exception:
            pass
        return entries

    def _write_subdomain_campaign_whitelist_csv(self, entries):
        path = self._subdomain_campaign_whitelist_csv_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
        except Exception:
            pass
        tmp = f'{path}.tmp'
        ordered = sorted(set(entries or set()))
        with open(tmp, 'w', encoding='utf-8') as fh:
            for item in ordered:
                fh.write(f'{item}\n')
        os.replace(tmp, path)
        return ordered

    def _is_domain_whitelisted(self, domain, whitelist_set):
        d = (domain or '').strip().lower().lstrip('.').rstrip('.')
        if not d:
            return False
        if d in whitelist_set or f'.{d}' in whitelist_set:
            return True
        parts = d.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in whitelist_set or f'.{parent}' in whitelist_set:
                return True
        return False

    def get_subdomain_campaign_whitelist(self):
        """Retorna a whitelist local do addon (CSV)."""
        try:
            if not os.path.isdir(ADDON_PATH):
                self.send_json_response({
                    'success': True,
                    'available': False,
                    'addons_path': ADDON_PATH
                })
                return

            path = self._subdomain_campaign_whitelist_csv_path()
            entries = sorted(self._load_subdomain_campaign_whitelist_csv())
            total_items = len(entries)

            page, page_size = self.get_list_pagination(default_page_size=20)
            pagination_enabled = page is not None and page_size is not None

            if total_items == 0:
                current_page = 1
                total_pages = 1
                paginated = []
                current_page_size = page_size if pagination_enabled else 0
            elif pagination_enabled:
                total_pages = max(1, math.ceil(total_items / page_size))
                current_page = min(page, total_pages)
                start = (current_page - 1) * page_size
                paginated = entries[start:start + page_size]
                current_page_size = page_size
            else:
                current_page = 1
                total_pages = 1
                paginated = entries
                current_page_size = total_items

            self.send_json_response({
                'success': True,
                'available': True,
                'path': path,
                'count': total_items,
                'whitelist': paginated,
                'page': current_page,
                'page_size': current_page_size,
                'total_pages': total_pages,
            })
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 500)

    def handle_subdomain_campaign_whitelist(self):
        """Adiciona/remove um domínio da whitelist local do addon (CSV)."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8') or '{}')

            action = (data.get('action') or '').strip().lower()
            token = data.get('domain') or data.get('token') or ''
            domain = self._normalize_whitelist_domain(token)

            if action not in {'add', 'remove', 'delete', 'drop'}:
                self.send_json_response({'success': False, 'error': 'Ação inválida (use add/remove).'}, 400)
                return
            if not domain:
                self.send_json_response({'success': False, 'error': 'Domínio inválido.'}, 400)
                return

            entries = self._load_subdomain_campaign_whitelist_csv()
            before = len(entries)

            if action == 'add':
                entries.add(domain)
                changed = len(entries) != before
            else:
                # remove / delete / drop
                if domain in entries:
                    entries.remove(domain)
                    changed = True
                else:
                    changed = False

            ordered = self._write_subdomain_campaign_whitelist_csv(entries)
            self.send_json_response({
                'success': True,
                'action': 'add' if action == 'add' else 'remove',
                'domain': domain,
                'changed': changed,
                'count': len(ordered),
                'whitelist': ordered
            })
        except json.JSONDecodeError:
            self.send_json_response({'success': False, 'error': 'JSON inválido'}, 400)
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 500)

    def _subdomain_campaign_simulation_reset_path(self):
        return os.path.join(ADDON_PATH, 'config', 'subdomain_campaign_simulation_reset.json')

    def _load_subdomain_campaign_simulation_reset_at(self):
        path = self._subdomain_campaign_simulation_reset_path()
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                payload = json.load(fh) or {}
            ts_text = (payload.get('reset_at') or '').strip()
            if not ts_text:
                return None
            ts = datetime.fromisoformat(ts_text)
            if ts.tzinfo is None:
                ts = ts.astimezone()
            else:
                ts = ts.astimezone()
            return ts
        except Exception:
            return None

    def reset_subdomain_campaign_simulation(self):
        """Reseta o baseline da simulação (zera contagem histórica do addon no dashboard)."""
        try:
            session_email = self._get_session_email()
            now = datetime.now().astimezone()
            path = self._subdomain_campaign_simulation_reset_path()
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
            except Exception:
                pass
            payload = {
                'reset_at': now.isoformat(),
                'reset_by': session_email,
            }
            tmp = f'{path}.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
            os.replace(tmp, path)
            self.send_json_response({
                'success': True,
                'reset_at': now.isoformat(),
                'path': path
            })
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 500)

    def get_subdomain_campaign_report(self):
        """Relatório do addon de campanhas por subdomínios (domínios, hosts e IPs).

        Usa cache de 30 segundos para evitar reprocessamento frequente dos logs.
        """
        try:
            if not os.path.isdir(ADDON_PATH):
                self.send_json_response({
                    'success': True,
                    'available': False,
                    'addons_path': ADDON_PATH
                })
                return

            now_ts = time.time()

            # Verifica cache
            with ADDON_REPORT_CACHE_LOCK:
                cache_valid = (
                    ADDON_REPORT_CACHE['data'] is not None and
                    (now_ts - ADDON_REPORT_CACHE['timestamp']) < ADDON_REPORT_CACHE['ttl']
                )
                if cache_valid:
                    self.send_json_response(ADDON_REPORT_CACHE['data'])
                    return

            # Cache expirado ou inexistente - gera novo relatório
            cfg_path, cfg = self._load_subdomain_campaign_addon_config()

            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)

            def get_int(name, default, min_value=None, max_value=None):
                raw = (params.get(name) or [str(default)])[0]
                try:
                    value = int(raw)
                except Exception:
                    value = int(default)
                if min_value is not None:
                    value = max(min_value, value)
                if max_value is not None:
                    value = min(max_value, value)
                return value

            max_domains = get_int('max_domains', 200, 10, 1000)
            max_hosts = get_int('max_hosts', 500, 10, 5000)
            max_ips = get_int('max_ips', 500, 10, 5000)

            window_hours = int(cfg.get('window_hours', 6) or 6)
            min_subdomains = int(cfg.get('min_subdomains', 3) or 3)
            min_events = int(cfg.get('min_events_per_domain', 10) or 10)
            min_clients = int(cfg.get('min_clients', 1) or 1)
            risk_threshold = int(cfg.get('risk_score_threshold', 70) or 70)
            max_lines = int(cfg.get('max_lines_per_scan', 200000) or 200000)

            now = datetime.now().astimezone()
            start_time = now - timedelta(hours=window_hours)

            addon_stats = self._calculate_subdomain_campaign_addon_window(start_time, now)
            whitelist_set = self._load_subdomain_campaign_whitelist_csv()

            analysis_error = None
            domains = []
            host_agg = {}
            ip_agg = {}

            try:
                if ADDON_PATH not in sys.path:
                    sys.path.insert(0, ADDON_PATH)
                from subdomain_pattern_analyzer import analyze_subdomain_patterns

                campaigns = analyze_subdomain_patterns(
                    window_hours=window_hours,
                    min_subdomains=min_subdomains,
                    min_events_per_domain=min_events,
                    min_clients=min_clients,
                    max_lines=max_lines,
                    verbose=False,
                )

                high_risk = [c for c in campaigns if int(getattr(c, 'risk_score', 0) or 0) >= risk_threshold]
                high_risk.sort(key=lambda c: int(getattr(c, 'risk_score', 0) or 0), reverse=True)

                for c in high_risk[:max_domains]:
                    base_domain = getattr(c, 'base_domain', '')
                    whitelisted = self._is_domain_whitelisted(base_domain, whitelist_set) if whitelist_set else False
                    domains.append({
                        'base_domain': base_domain,
                        'risk_score': int(getattr(c, 'risk_score', 0) or 0),
                        'unique_subdomains': int(getattr(c, 'unique_subdomains', 0) or 0),
                        'total_events': int(getattr(c, 'total_events', 0) or 0),
                        'unique_ips': int(getattr(c, 'unique_ips', 0) or 0),
                        'unique_clients': int(getattr(c, 'unique_clients', 0) or 0),
                        'events_per_hour': float(getattr(c, 'events_per_hour', 0.0) or 0.0),
                        'pattern_ratio': float(getattr(c, 'pattern_ratio', 0.0) or 0.0),
                        'pass_ratio': float(getattr(c, 'pass_ratio', 0.0) or 0.0),
                        'recommended_action': getattr(c, 'recommended_action', ''),
                        'whitelisted': bool(whitelisted),
                        'risk_factors': list(getattr(c, 'risk_factors', []) or []),
                        'top_hosts': [d.get('full_domain') for d in (getattr(c, 'subdomain_details', []) or [])[:5] if d.get('full_domain')],
                        'top_ips': list((getattr(c, 'top_ips', []) or [])[:5]),
                    })

                    for d in (getattr(c, 'subdomain_details', []) or []):
                        full_domain = d.get('full_domain')
                        if not full_domain:
                            continue
                        entry = host_agg.get(full_domain)
                        if not entry:
                            host_agg[full_domain] = {
                                'full_domain': full_domain,
                                'base_domain': base_domain,
                                'subdomain': d.get('subdomain'),
                                'count': int(d.get('count', 0) or 0),
                                'unique_ips': int(d.get('unique_ips', 0) or 0),
                                'unique_clients': int(d.get('unique_clients', 0) or 0),
                                'has_pattern': bool(d.get('has_pattern', False)),
                                'pattern': d.get('pattern'),
                                'first_seen': d.get('first_seen'),
                                'last_seen': d.get('last_seen'),
                            }
                        else:
                            entry['count'] += int(d.get('count', 0) or 0)

                    for ip_info in (getattr(c, 'top_ips', []) or []):
                        ip_value = (ip_info.get('ip') or '').strip()
                        if not ip_value:
                            continue
                        entry = ip_agg.get(ip_value)
                        if not entry:
                            ip_agg[ip_value] = {
                                'ip': ip_value,
                                'count': int(ip_info.get('count', 0) or 0),
                                'domains': {base_domain} if base_domain else set(),
                            }
                        else:
                            entry['count'] += int(ip_info.get('count', 0) or 0)
                            if base_domain:
                                entry['domains'].add(base_domain)

            except Exception as e:
                analysis_error = str(e)

            hosts = list(host_agg.values())
            hosts.sort(key=lambda x: int(x.get('count', 0) or 0), reverse=True)
            hosts = hosts[:max_hosts]

            ips = []
            for v in ip_agg.values():
                ips.append({
                    'ip': v.get('ip'),
                    'count': int(v.get('count', 0) or 0),
                    'domains': sorted(list(v.get('domains') or [])),
                })
            ips.sort(key=lambda x: int(x.get('count', 0) or 0), reverse=True)
            ips = ips[:max_ips]

            response_data = {
                'success': True,
                'available': True,
                'generated_at': now.isoformat(),
                'cached': False,
                'window': {
                    'start': start_time.isoformat(),
                    'end': now.isoformat(),
                    'hours': window_hours,
                },
                'config': {
                    'path': cfg_path,
                    'enabled': bool(cfg.get('enabled', False)),
                    'dry_run': bool(cfg.get('dry_run', True)),
                    'auto_block_enabled': bool(cfg.get('auto_block_enabled', False)),
                    'block_action': cfg.get('block_action', 'superblock'),
                    'block_ips': bool(cfg.get('block_ips', False)),
                    'min_clients': min_clients,
                    'min_subdomains': min_subdomains,
                    'min_events_per_domain': min_events,
                    'risk_score_threshold': risk_threshold,
                    'max_lines_per_scan': max_lines,
                },
                'addon_stats': addon_stats,
                'report': {
                    'domains': domains,
                    'hosts': hosts,
                    'ips': ips,
                    'counts': {
                        'domains': len(domains),
                        'hosts': len(hosts),
                        'ips': len(ips),
                    }
                },
                'analysis_error': analysis_error,
            }

            # Atualiza cache
            with ADDON_REPORT_CACHE_LOCK:
                ADDON_REPORT_CACHE['data'] = response_data
                ADDON_REPORT_CACHE['timestamp'] = time.time()

            self.send_json_response(response_data)
        except Exception as e:
            self.send_json_response({'success': False, 'error': str(e)}, 500)

    
    # --- Helpers para estatísticas de SPAM (bloqueios diretos) ---
    def _iter_spfbl_logs(self, start_time, end_time):
        """
        Itera linhas de log do SPFBL entre start_time e end_time (janela deslizante).
        Lê arquivos do dia atual e do dia anterior se necessário (.log ou .log.gz).
        """
        import gzip

        def open_file(path):
            if path.endswith('.gz'):
                return gzip.open(path, 'rt', encoding='utf-8', errors='ignore')
            return open(path, 'r', encoding='utf-8', errors='ignore')

        dates = {start_time.date(), end_time.date()}
        for day in sorted(dates):
            base = os.path.join(LOG_DIR, f"spfbl.{day.strftime('%Y-%m-%d')}.log")
            candidates = [base, base + '.gz']
            for path in candidates:
                if os.path.exists(path):
                    with open_file(path) as f:
                        for line in f:
                            yield line

    def _parse_spfbl_timestamp(self, line):
        """
        Extrai datetime de uma linha de log SPFBL.
        Formatos esperados: 2025-11-24T00:00:19.578-0300 ou sem frações.
        """
        ts_match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{4})?)", line)
        if not ts_match:
            return None
        ts_text = ts_match.group(1)
        try:
            # Tenta com micros + offset sem dois-pontos
            return datetime.strptime(ts_text, '%Y-%m-%dT%H:%M:%S.%f%z')
        except Exception:
            try:
                # Sem micros
                return datetime.strptime(ts_text, '%Y-%m-%dT%H:%M:%S%z')
            except Exception:
                return None

    def _read_last_lines(self, path, max_lines=20000, timeout=5):
        """Lê as últimas N linhas de um arquivo de forma eficiente."""
        try:
            result = subprocess.run(
                ['tail', f'-{int(max_lines)}', path],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.stdout:
                return result.stdout.splitlines()
        except Exception:
            pass

        try:
            from collections import deque
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return list(deque(f, int(max_lines)))
        except Exception:
            return []

    def _parse_addon_timestamp(self, line):
        """Extrai datetime (timezone-aware) de uma linha de log de addon."""
        if not line:
            return None
        parts = line.split(' ', 1)
        if not parts:
            return None
        ts_text = parts[0].strip()
        if not ts_text:
            return None
        try:
            ts = datetime.fromisoformat(ts_text)
            if ts.tzinfo is None:
                # Assume timezone local
                ts = ts.astimezone()
            else:
                ts = ts.astimezone()
            return ts
        except Exception:
            return None

    def _load_subdomain_campaign_addon_config(self):
        """Carrega config do addon subdomain_campaign_blocker (se existir)."""
        cfg_path = os.path.join(ADDON_PATH, 'config', 'subdomain_campaign_blocker.json')
        cfg = {}
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, 'r', encoding='utf-8') as fh:
                    cfg = json.load(fh) or {}
            except Exception:
                cfg = {}
        return cfg_path, cfg

    def _calculate_subdomain_campaign_addon_window(self, start_time, end_time, max_lines=20000):
        """
        Extrai estatísticas do addon (subdomain_campaign_blocker) em uma janela.

        - domain_blocked: quantidade de domínios-base únicos (ex: .example.com)
        - ip_blocked: quantidade de IPs únicos bloqueados pelo addon
        - host_blocked: soma de subdomínios (subdomains=) por domínio-base na janela

        Retorna também séries separadas para dry-run vs bloqueio real.
        """
        log_path = os.path.join(LOG_DIR, 'addon-subdomain-campaign.log')
        cfg_path, cfg = self._load_subdomain_campaign_addon_config()

        addon_present = os.path.isdir(ADDON_PATH)
        addon_enabled = bool(cfg.get('enabled', False))
        addon_dry_run = bool(cfg.get('dry_run', True))
        reset_at = self._load_subdomain_campaign_simulation_reset_at()
        baseline = start_time
        if reset_at and reset_at > baseline:
            baseline = reset_at

        result = {
            'available': bool(addon_present),
            'enabled': addon_enabled,
            'dry_run': addon_dry_run,
            'log_path': log_path,
            'config_path': cfg_path,
            'reset_at': reset_at.isoformat() if reset_at else None,
            'blocked': {'host_blocked': 0, 'domain_blocked': 0, 'ip_blocked': 0},
            'dry_run_events': {'host_blocked': 0, 'domain_blocked': 0, 'ip_blocked': 0},
            'effective': {'host_blocked': 0, 'domain_blocked': 0, 'ip_blocked': 0},
        }

        if not os.path.exists(log_path):
            return result

        domain_action_re = re.compile(r'\b(?P<kind>DRY_RUN|BLOCKED)\s+\[(?P<action>SUPERBLOCK|BLOCK)\]\s+(?P<token>\.[A-Za-z0-9.-]+)\b')
        ip_dry_re = re.compile(r'\bDRY_RUN\s+\[BLOCK\]\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b')
        ip_blocked_re = re.compile(r'\bBLOCKED\s+\[IP\]\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b')
        subdomains_re = re.compile(r'\bsubdomains=(\d+)\b')

        blocked_domains = {}  # base_domain -> max(subdomains)
        dry_domains = {}
        blocked_ips = set()
        dry_ips = set()

        for line in self._read_last_lines(log_path, max_lines=max_lines, timeout=5):
            ts = self._parse_addon_timestamp(line)
            if not ts or ts < baseline or ts > end_time:
                continue

            m_dom = domain_action_re.search(line)
            if m_dom:
                token = (m_dom.group('token') or '').strip()
                base = token.lstrip('.').lower()
                sub_count = 0
                sm = subdomains_re.search(line)
                if sm:
                    try:
                        sub_count = int(sm.group(1))
                    except Exception:
                        sub_count = 0
                bucket = blocked_domains if m_dom.group('kind') == 'BLOCKED' else dry_domains
                prev = bucket.get(base, 0)
                if sub_count > prev:
                    bucket[base] = sub_count
                elif base not in bucket:
                    bucket[base] = prev
                continue

            m_ip = ip_blocked_re.search(line)
            if m_ip:
                blocked_ips.add(m_ip.group('ip'))
                continue

            m_ip_dry = ip_dry_re.search(line)
            if m_ip_dry:
                dry_ips.add(m_ip_dry.group('ip'))

        blocked_counts = {
            'domain_blocked': len(blocked_domains),
            'ip_blocked': len(blocked_ips),
            'host_blocked': sum(blocked_domains.values()),
        }
        dry_counts = {
            'domain_blocked': len(dry_domains),
            'ip_blocked': len(dry_ips),
            'host_blocked': sum(dry_domains.values()),
        }

        effective = dry_counts if addon_dry_run else blocked_counts

        result['blocked'] = blocked_counts
        result['dry_run_events'] = dry_counts
        result['effective'] = effective
        return result

    def _calculate_subdomain_campaign_addon_today(self, day, max_lines=20000):
        """Calcula séries por hora (0-23) do addon para um dia específico."""
        log_path = os.path.join(LOG_DIR, 'addon-subdomain-campaign.log')
        cfg_path, cfg = self._load_subdomain_campaign_addon_config()

        addon_present = os.path.isdir(ADDON_PATH)
        addon_enabled = bool(cfg.get('enabled', False))
        addon_dry_run = bool(cfg.get('dry_run', True))
        reset_at = self._load_subdomain_campaign_simulation_reset_at()

        result = {
            'available': bool(addon_present),
            'enabled': addon_enabled,
            'dry_run': addon_dry_run,
            'log_path': log_path,
            'config_path': cfg_path,
            'reset_at': reset_at.isoformat() if reset_at else None,
            'blocked': {'host_blocked': [0] * 24, 'domain_blocked': [0] * 24, 'ip_blocked': [0] * 24},
            'dry_run_events': {'host_blocked': [0] * 24, 'domain_blocked': [0] * 24, 'ip_blocked': [0] * 24},
            'effective': {'host_blocked': [0] * 24, 'domain_blocked': [0] * 24, 'ip_blocked': [0] * 24},
        }

        if not os.path.exists(log_path):
            return result

        domain_action_re = re.compile(r'\b(?P<kind>DRY_RUN|BLOCKED)\s+\[(?P<action>SUPERBLOCK|BLOCK)\]\s+(?P<token>\.[A-Za-z0-9.-]+)\b')
        ip_dry_re = re.compile(r'\bDRY_RUN\s+\[BLOCK\]\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b')
        ip_blocked_re = re.compile(r'\bBLOCKED\s+\[IP\]\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b')
        subdomains_re = re.compile(r'\bsubdomains=(\d+)\b')

        # Para deduplicar por hora
        blocked_domains_by_hour = [dict() for _ in range(24)]  # base -> max subdomains
        dry_domains_by_hour = [dict() for _ in range(24)]
        blocked_ips_by_hour = [set() for _ in range(24)]
        dry_ips_by_hour = [set() for _ in range(24)]

        for line in self._read_last_lines(log_path, max_lines=max_lines, timeout=5):
            ts = self._parse_addon_timestamp(line)
            if not ts:
                continue
            if ts.date() != day:
                continue
            if reset_at and ts < reset_at:
                continue
            hour = ts.hour
            if hour < 0 or hour > 23:
                continue

            m_dom = domain_action_re.search(line)
            if m_dom:
                token = (m_dom.group('token') or '').strip()
                base = token.lstrip('.').lower()
                sub_count = 0
                sm = subdomains_re.search(line)
                if sm:
                    try:
                        sub_count = int(sm.group(1))
                    except Exception:
                        sub_count = 0
                bucket = blocked_domains_by_hour[hour] if m_dom.group('kind') == 'BLOCKED' else dry_domains_by_hour[hour]
                prev = bucket.get(base, 0)
                if sub_count > prev:
                    bucket[base] = sub_count
                elif base not in bucket:
                    bucket[base] = prev
                continue

            m_ip = ip_blocked_re.search(line)
            if m_ip:
                blocked_ips_by_hour[hour].add(m_ip.group('ip'))
                continue

            m_ip_dry = ip_dry_re.search(line)
            if m_ip_dry:
                dry_ips_by_hour[hour].add(m_ip_dry.group('ip'))

        blocked_series = {
            'domain_blocked': [len(blocked_domains_by_hour[h]) for h in range(24)],
            'ip_blocked': [len(blocked_ips_by_hour[h]) for h in range(24)],
            'host_blocked': [sum(blocked_domains_by_hour[h].values()) for h in range(24)],
        }
        dry_series = {
            'domain_blocked': [len(dry_domains_by_hour[h]) for h in range(24)],
            'ip_blocked': [len(dry_ips_by_hour[h]) for h in range(24)],
            'host_blocked': [sum(dry_domains_by_hour[h].values()) for h in range(24)],
        }
        effective = dry_series if addon_dry_run else blocked_series

        result['blocked'] = blocked_series
        result['dry_run_events'] = dry_series
        result['effective'] = effective
        return result

    def _calculate_spam_blocks(self, window_hours=24, by_hour=False, allowed_networks=None):
        """
        Conta bloqueios diretos do SPFBL em uma janela deslizante.
        ip_blocked: total de eventos (=> BLOCKED/BANNED)
        host_blocked: IPs que só enviaram 1 domínio na janela
        domain_blocked: domínios que usaram >1 IP na janela
        by_hour True devolve séries por hora (24 buckets relativos à janela).
        """
        from collections import defaultdict

        end_time = datetime.now().astimezone()
        start_time = end_time - timedelta(hours=window_hours)

        if allowed_networks is not None and not allowed_networks:
            result = {
                'host_blocked': 0,
                'domain_blocked': 0,
                'ip_blocked': 0,
                'success': True,
                'window_start': start_time.isoformat(),
                'window_end': end_time.isoformat()
            }
            if by_hour:
                labels = [
                    (start_time + timedelta(hours=idx)).strftime('%d/%m %Hh')
                    for idx in range(window_hours)
                ]
                result.update({
                    'hours': list(range(window_hours)),
                    'labels': labels,
                    'host_blocked': [0] * window_hours,
                    'domain_blocked': [0] * window_hours,
                    'ip_blocked': [0] * window_hours
                })
            return result

        domains_por_ip = defaultdict(set)
        ips_por_domain = defaultdict(set)
        total_blocked = 0

        # Estruturas por hora (0..23 representam a posição relativa na janela)
        hourly_stats = [defaultdict(int) for _ in range(window_hours)]
        hourly_tracking = [ {'domains_por_ip': defaultdict(set), 'ips_por_domain': defaultdict(set)} for _ in range(window_hours) ]

        spf_regex = re.compile(r"SPF '([^']+)' '([^']+)' '([^']+)' '([^']+)'")

        for line in self._iter_spfbl_logs(start_time, end_time):
            if not self._line_matches_allowed_networks(line, allowed_networks):
                continue
            if '=> BLOCKED' not in line and '=> BANNED' not in line:
                continue
            if "SPF '" not in line:
                continue

            ts = self._parse_spfbl_timestamp(line)
            if not ts or ts < start_time or ts > end_time:
                continue

            spf_match = spf_regex.search(line)
            if not spf_match:
                continue

            origin_ip, sender, domain_remetente, recipient = spf_match.groups()
            sender_domain = sender.split('@')[1] if '@' in sender else sender

            total_blocked += 1
            domains_por_ip[origin_ip].add(sender_domain)
            ips_por_domain[sender_domain].add(origin_ip)

            # Bucket horário relativo
            if by_hour:
                idx = int((ts - start_time).total_seconds() // 3600)
                if 0 <= idx < window_hours:
                    hourly_stats[idx]['ip_blocked'] += 1
                    hourly_tracking[idx]['domains_por_ip'][origin_ip].add(sender_domain)
                    hourly_tracking[idx]['ips_por_domain'][sender_domain].add(origin_ip)

        # Agregados únicos
        host_bloqueado_count = sum(1 for domains in domains_por_ip.values() if len(domains) == 1)
        domain_bloqueado_count = sum(1 for ips in ips_por_domain.values() if len(ips) > 1)

        direct_summary = {
            'host_blocked': host_bloqueado_count,
            'domain_blocked': domain_bloqueado_count,
            'ip_blocked': total_blocked,
        }

        # Addon: só expõe agregados globais em sessão "unrestricted" (admin)
        addon_summary = None
        if allowed_networks is None:
            addon_summary = self._calculate_subdomain_campaign_addon_window(start_time, end_time)
            effective = addon_summary.get('effective') or {}
            combined_summary = {
                'host_blocked': direct_summary['host_blocked'] + int(effective.get('host_blocked', 0) or 0),
                'domain_blocked': direct_summary['domain_blocked'] + int(effective.get('domain_blocked', 0) or 0),
                'ip_blocked': direct_summary['ip_blocked'] + int(effective.get('ip_blocked', 0) or 0),
            }
        else:
            combined_summary = direct_summary

        result = {
            **combined_summary,
            'direct': direct_summary,
            'addon': addon_summary,
            'success': True,
            'window_start': start_time.isoformat(),
            'window_end': end_time.isoformat()
        }

        if by_hour:
            # Calcula host/domain por bucket horário
            host_series = []
            domain_series = []
            ip_series = []
            labels = []

            for idx in range(window_hours):
                domains_pi = hourly_tracking[idx]['domains_por_ip']
                ips_pd = hourly_tracking[idx]['ips_por_domain']
                host_series.append(sum(1 for d in domains_pi.values() if len(d) == 1))
                domain_series.append(sum(1 for ips in ips_pd.values() if len(ips) > 1))
                ip_series.append(hourly_stats[idx].get('ip_blocked', 0))
                label_time = start_time + timedelta(hours=idx)
                labels.append(label_time.strftime('%d/%m %Hh'))

            result.update({
                'hours': list(range(window_hours)),
                'labels': labels,
                'host_blocked': host_series,
                'domain_blocked': domain_series,
                'ip_blocked': ip_series
            })

        return result

    def _calculate_spam_blocks_today(self, allowed_networks=None):
        """
        Calcula bloqueios diretos do SPFBL por hora do dia atual (0-23h).
        Similar ao get_today_queries, mostra as 24 horas do dia corrente.
        """
        from collections import defaultdict

        # Inicializar estruturas para 24 horas (0-23)
        hourly_stats = {}
        for hour in range(24):
            hourly_stats[hour] = {
                'ip_blocked': 0,
                'domains_por_ip': defaultdict(set),
                'ips_por_domain': defaultdict(set)
            }

        # Ler log do dia atual
        today = datetime.now()
        log_file = os.path.join(LOG_DIR, f"spfbl.{today.strftime('%Y-%m-%d')}.log")

        if not os.path.exists(log_file):
            # Se o arquivo não existe, retornar estrutura vazia
            return {
                'hours': list(range(24)),
                'labels': [f'{h}:00' for h in range(24)],
                'host_blocked': [0] * 24,
                'domain_blocked': [0] * 24,
                'ip_blocked': [0] * 24,
                'success': True
            }

        if allowed_networks is not None and not allowed_networks:
            return {
                'hours': list(range(24)),
                'labels': [f'{h}:00' for h in range(24)],
                'host_blocked': [0] * 24,
                'domain_blocked': [0] * 24,
                'ip_blocked': [0] * 24,
                'success': True
            }

        spf_regex = re.compile(r"SPF '([^']+)' '([^']+)' '([^']+)' '([^']+)'")

        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if not self._line_matches_allowed_networks(line, allowed_networks):
                        continue
                    if '=> BLOCKED' not in line and '=> BANNED' not in line:
                        continue
                    if "SPF '" not in line:
                        continue

                    # Extrair hora da linha (formato: 2025-11-26T05:52:01.123-0300)
                    match = re.search(r'T(\d{2}):', line)
                    if not match:
                        continue

                    hour = int(match.group(1))

                    # Extrair informações do SPF
                    spf_match = spf_regex.search(line)
                    if not spf_match:
                        continue

                    origin_ip, sender, domain_remetente, recipient = spf_match.groups()
                    sender_domain = sender.split('@')[1] if '@' in sender else sender

                    # Incrementar contadores
                    hourly_stats[hour]['ip_blocked'] += 1
                    hourly_stats[hour]['domains_por_ip'][origin_ip].add(sender_domain)
                    hourly_stats[hour]['ips_por_domain'][sender_domain].add(origin_ip)

        except Exception as e:
            print(f"Error reading log file: {e}")

        # Calcular séries para cada hora
        host_series = []
        domain_series = []
        ip_series = []

        for hour in range(24):
            stats = hourly_stats[hour]
            domains_pi = stats['domains_por_ip']
            ips_pd = stats['ips_por_domain']

            # Host bloqueado: IPs que só enviaram 1 domínio
            host_count = sum(1 for domains in domains_pi.values() if len(domains) == 1)
            # Domínio bloqueado: domínios que usaram >1 IP
            domain_count = sum(1 for ips in ips_pd.values() if len(ips) > 1)

            host_series.append(host_count)
            domain_series.append(domain_count)
            ip_series.append(stats['ip_blocked'])

        direct_series = {
            'host_blocked': host_series,
            'domain_blocked': domain_series,
            'ip_blocked': ip_series,
        }

        addon_series = None
        combined = direct_series
        if allowed_networks is None:
            addon_series = self._calculate_subdomain_campaign_addon_today(datetime.now().date())
            effective = addon_series.get('effective') or {}
            combined = {
                'host_blocked': [direct_series['host_blocked'][h] + int((effective.get('host_blocked') or [0]*24)[h] or 0) for h in range(24)],
                'domain_blocked': [direct_series['domain_blocked'][h] + int((effective.get('domain_blocked') or [0]*24)[h] or 0) for h in range(24)],
                'ip_blocked': [direct_series['ip_blocked'][h] + int((effective.get('ip_blocked') or [0]*24)[h] or 0) for h in range(24)],
            }

        return {
            'hours': list(range(24)),
            'labels': [f'{h}:00' for h in range(24)],
            **combined,
            'direct': direct_series,
            'addon': addon_series,
            'success': True
        }

    def handle_block_add(self):
        """Handle adding IP/domain/email to blacklist"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            token = data.get('token', '').strip()
            if not token:
                self.send_json_response({
                    'error': 'Token (IP, domínio ou email) é obrigatório'
                }, 400)
                return

            # Executar comando SPFBL block add
            result = subprocess.run(
                ['/sbin/spfbl', 'block', 'add', token],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = (result.stdout + result.stderr).strip()

            if 'ADDED' in output or result.returncode == 0:
                self.send_json_response({
                    'success': True,
                    'message': f'{token} adicionado à blacklist com sucesso',
                    'token': token
                })
            elif 'ALREADY' in output or 'EXISTS' in output:
                self.send_json_response({
                    'error': f'{token} já está na blacklist'
                }, 409)
            else:
                self.send_json_response({
                    'error': f'Erro ao adicionar à blacklist: {output}'
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro: {str(e)}'}, 500)

    def handle_block_drop(self):
        """Handle removing IP/domain/email from blacklist"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            token = data.get('token', '').strip()
            if not token:
                self.send_json_response({
                    'error': 'Token (IP, domínio ou email) é obrigatório'
                }, 400)
                return

            # Executar comando SPFBL block drop
            result = subprocess.run(
                ['/sbin/spfbl', 'block', 'drop', token],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = (result.stdout + result.stderr).strip()

            if 'DROPPED' in output or result.returncode == 0:
                self.send_json_response({
                    'success': True,
                    'message': f'{token} removido da blacklist com sucesso',
                    'token': token
                })
            elif 'NOT FOUND' in output:
                self.send_json_response({
                    'error': f'{token} não encontrado na blacklist'
                }, 404)
            else:
                self.send_json_response({
                    'error': f'Erro ao remover da blacklist: {output}'
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro: {str(e)}'}, 500)

    def handle_white_add(self):
        """Handle adding IP/domain/email to whitelist"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            token = data.get('token', '').strip()
            if not token:
                self.send_json_response({
                    'error': 'Token (IP, domínio ou email) é obrigatório'
                }, 400)
                return

            # Executar comando SPFBL white add
            result = subprocess.run(
                ['/sbin/spfbl', 'white', 'add', token],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = (result.stdout + result.stderr).strip()

            if 'ADDED' in output or result.returncode == 0:
                self.send_json_response({
                    'success': True,
                    'message': f'{token} adicionado à whitelist com sucesso',
                    'token': token
                })
            elif 'ALREADY' in output or 'EXISTS' in output:
                self.send_json_response({
                    'error': f'{token} já está na whitelist'
                }, 409)
            else:
                self.send_json_response({
                    'error': f'Erro ao adicionar à whitelist: {output}'
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro: {str(e)}'}, 500)

    def handle_white_drop(self):
        """Handle removing IP/domain/email from whitelist"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            token = data.get('token', '').strip()
            if not token:
                self.send_json_response({
                    'error': 'Token (IP, domínio ou email) é obrigatório'
                }, 400)
                return

            # Executar comando SPFBL white drop
            result = subprocess.run(
                ['/sbin/spfbl', 'white', 'drop', token],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = (result.stdout + result.stderr).strip()

            if 'DROPPED' in output or result.returncode == 0:
                self.send_json_response({
                    'success': True,
                    'message': f'{token} removido da whitelist com sucesso',
                    'token': token
                })
            elif 'NOT FOUND' in output:
                self.send_json_response({
                    'error': f'{token} não encontrado na whitelist'
                }, 404)
            else:
                self.send_json_response({
                    'error': f'Erro ao remover da whitelist: {output}'
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro: {str(e)}'}, 500)

    def _looks_like_ip_or_cidr(self, value):
        if not value:
            return False
        try:
            if '/' in value:
                ipaddress.ip_network(value, strict=False)
            else:
                ipaddress.ip_address(value)
            return True
        except Exception:
            return False

    def _block_token_variants(self, token):
        variants = set()
        if not token:
            return variants
        variants.add(token)
        stripped = token.lstrip('.')
        variants.add(stripped)
        variants.add(f'.{stripped}')
        if token.startswith('CIDR='):
            raw_cidr = token[5:]
            variants.add(raw_cidr)
            variants.add(f'CIDR={raw_cidr}')
        if self._looks_like_ip_or_cidr(stripped) and not stripped.startswith('CIDR='):
            variants.add(f'CIDR={stripped}')
        return variants

    def _detect_block_token_type(self, raw_token):
        token = (raw_token or '').strip()
        if not token:
            return 'domain', token
        if '>@' in token:
            token_type = 'pair'
        elif token.startswith('CIDR=') or self._looks_like_ip_or_cidr(token):
            token_type = 'ip'
        elif '@' in token:
            token_type = 'email'
        else:
            token_type = 'domain'

        display = token
        if display.startswith('CIDR='):
            display = display[5:]
        if display.startswith('.'):
            display = display[1:]
        return token_type, display

    def get_blocklist(self):
        """Get list of blocked IPs/domains/emails"""
        try:
            result = subprocess.run(
                ['/sbin/spfbl', 'block', 'show'],
                capture_output=True,
                text=True,
                timeout=10
            )

            blocklist = []
            output = result.stdout.strip()

            if output:
                raw_tokens = []
                for line in output.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Formato típico: CIDR=... ou .dominio ou email
                        parts = line.split()
                        if parts:
                            raw_token = parts[0]
                            raw_tokens.append(raw_token)

                known_tokens = set()
                for rt in raw_tokens:
                    known_tokens.update(self._block_token_variants(rt))

                timestamps = self.get_block_timestamps_from_logs(known_tokens=known_tokens)

                for raw_token in raw_tokens:
                    type_token, display_token = self._detect_block_token_type(raw_token)
                    variants = self._block_token_variants(raw_token)
                    ts_candidates = [timestamps.get(v) for v in variants if timestamps.get(v)]
                    timestamp = max(ts_candidates) if ts_candidates else None
                    blocklist.append({
                        'token': display_token,
                        'type': type_token,
                        'raw': raw_token,
                        'timestamp': timestamp
                    })

            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            search_term = (params.get('search') or [''])[0].strip()
            type_filter = (params.get('type') or ['all'])[0].strip().lower()
            allowed_types = {'all', 'ip', 'domain', 'email', 'pair'}
            if type_filter not in allowed_types:
                type_filter = 'all'

            if search_term:
                search_lower = search_term.lower()
                filtered_list = [
                    item for item in blocklist
                    if search_lower in item['token'].lower() or search_lower in item.get('raw', '').lower()
                ]
            else:
                filtered_list = blocklist

            if type_filter != 'all':
                filtered_list = [item for item in filtered_list if item.get('type') == type_filter]

            # Ordena por timestamp (mais recente primeiro) de forma otimizada
            # Itens sem timestamp (None or '') vão para o final
            # Ordenação em ordem decrescente: timestamps maiores (mais recentes) primeiro
            filtered_list.sort(key=lambda x: x.get('timestamp') or '', reverse=True)

            total_all = len(blocklist)
            total_items = len(filtered_list)
            page, page_size = self.get_list_pagination(default_page_size=20)
            pagination_enabled = page is not None and page_size is not None

            if total_items == 0:
                current_page = 1
                total_pages = 1
                paginated = []
                current_page_size = page_size if pagination_enabled else 0
            elif pagination_enabled:
                total_pages = max(1, math.ceil(total_items / page_size))
                current_page = min(page, total_pages)
                start = (current_page - 1) * page_size
                paginated = filtered_list[start:start + page_size]
                current_page_size = page_size
            else:
                current_page = 1
                total_pages = 1
                paginated = filtered_list
                current_page_size = total_items

            self.send_json_response({
                'success': True,
                'count': total_items,
                'total_all': total_all,
                'search': search_term,
                'type': type_filter,
                'blocklist': paginated,
                'page': current_page,
                'page_size': current_page_size,
                'total_pages': total_pages
            })

        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao listar blacklist: {str(e)}'}, 500)

    def get_block_timestamps_from_logs(self, known_tokens=None):
        """
        Extrai timestamps de bloqueios a partir de logs dos addons.
        Versão otimizada: lê logs de addons e um recorte recente dos logs principais do SPFBL.
        known_tokens: conjunto opcional de tokens/variações existentes em block show para filtrar ruído.
        """
        timestamps = {}

        def store_token(token, ts):
            if not token or not ts:
                return
            variants = self._block_token_variants(token)
            if known_tokens is not None and variants.isdisjoint(known_tokens):
                return
            for v in variants:
                prev = timestamps.get(v)
                if not prev or ts > prev:
                    timestamps[v] = ts

        # Lista apenas logs de addons (não logs principais do SPFBL para performance)
        addon_logs = [
            os.path.join(LOG_DIR, 'addon-tld.log'),
        ]

        for log_path in addon_logs:
            if not os.path.exists(log_path):
                continue

            try:
                # Lê últimas 10000 linhas
                result = subprocess.run(
                    ['tail', '-10000', log_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                for line in result.stdout.split('\n'):
                    # Formato addon-tld: "2025-11-25T20:17:01.160091 BLOCK[IP] 179.209.47.218"
                    parts = line.split()
                    if len(parts) < 3:
                        continue

                    # Primeira parte é o timestamp
                    ts = parts[0]

                    # Detecta formato e extrai token
                    token = None
                    if 'BLOCK[' in line:
                        # Formato: BLOCK[IP] token
                        if len(parts) >= 3:
                            token = parts[2]

                    if not token or not ts:
                        continue

                    store_token(token, ts)

            except Exception:
                # Falha silenciosa - timestamps são opcionais
                pass

        # Logs principais do SPFBL (somente recorte recente)
        now = datetime.now().astimezone()
        main_logs = []
        for delta in (0, 1):
            day = (now - timedelta(days=delta)).strftime('%Y-%m-%d')
            path = os.path.join(LOG_DIR, f"spfbl.{day}.log")
            if os.path.exists(path):
                main_logs.append(path)
        if not main_logs:
            candidates = sorted(glob.glob(os.path.join(LOG_DIR, 'spfbl.*.log')))
            if candidates:
                main_logs.append(candidates[-1])

        def extract_domain_from_email(value):
            if not value or '@' not in value:
                return None
            domain = value.split('@')[-1].strip().strip('>').strip()
            if not domain or ';' in domain or '.' not in domain:
                return None
            if self._looks_like_ip_or_cidr(domain):
                return None
            if re.match(r'^[A-Za-z0-9.-]{1,253}$', domain):
                return domain.lower()
            return None

        def extract_domain_from_helo(value):
            if not value:
                return None
            helo = value.strip().strip('[]')
            if not helo or ';' in helo or '.' not in helo:
                return None
            if self._looks_like_ip_or_cidr(helo):
                return None
            if re.match(r'^[A-Za-z0-9.-]{1,253}$', helo):
                return helo.lower()
            return None

        for log_path in main_logs:
            try:
                result = subprocess.run(
                    ['tail', '-20000', log_path],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for line in result.stdout.split('\n'):
                    if not re.search(r'=>\s*(BLOCKED|BANNED)\b', line):
                        continue
                    parts = line.split()
                    if not parts:
                        continue
                    ts = parts[0]

                    spf_pos = line.find(' SPF ')
                    quote_source = line[spf_pos:] if spf_pos != -1 else line
                    quoted = re.findall(r"'([^']*)'", quote_source)
                    if len(quoted) < 4:
                        continue

                    ip_value = quoted[0].strip()
                    sender_value = quoted[1].strip()
                    helo_value = quoted[2].strip()
                    recipient_value = quoted[3].strip()

                    sender_domain = extract_domain_from_helo(helo_value) or extract_domain_from_email(sender_value)
                    recipient_domain = extract_domain_from_email(recipient_value)

                    candidates = []
                    if ip_value and self._looks_like_ip_or_cidr(ip_value):
                        candidates.append(f'CIDR={ip_value}/32')
                        candidates.append(ip_value)
                    if sender_value:
                        candidates.append(sender_value)
                    if sender_domain:
                        candidates.extend([f'.{sender_domain}', sender_domain])
                    if recipient_domain:
                        candidates.extend([f'.{recipient_domain}', recipient_domain])
                    if sender_domain and recipient_domain:
                        candidates.extend([
                            f'.{sender_domain}>@{recipient_domain}',
                            f'{sender_domain}>@{recipient_domain}'
                        ])

                    for c in candidates:
                        store_token(c, ts)
            except Exception:
                pass

        return timestamps

    def get_whitelist(self):
        """Get list of whitelisted IPs/domains/emails"""
        try:
            result = subprocess.run(
                ['/sbin/spfbl', 'white', 'show'],
                capture_output=True,
                text=True,
                timeout=10
            )

            whitelist = []
            output = result.stdout.strip()

            if output:
                for line in output.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Formato típico: token ou token + data
                        parts = line.split()
                        if parts:
                            token = parts[0]
                            # Detectar tipo (IP, domínio ou email)
                            if '@' in token:
                                type_token = 'email'
                            elif '.' in token and any(c.isdigit() for c in token):
                                type_token = 'ip'
                            else:
                                type_token = 'domain'

                            whitelist.append({
                                'token': token,
                                'type': type_token,
                                'raw': line
                            })

            total_items = len(whitelist)
            page, page_size = self.get_list_pagination(default_page_size=20)
            pagination_enabled = page is not None and page_size is not None

            if total_items == 0:
                current_page = 1
                total_pages = 1
                paginated = []
                current_page_size = page_size if pagination_enabled else 0
            elif pagination_enabled:
                total_pages = max(1, math.ceil(total_items / page_size))
                current_page = min(page, total_pages)
                start = (current_page - 1) * page_size
                paginated = whitelist[start:start + page_size]
                current_page_size = page_size
            else:
                current_page = 1
                total_pages = 1
                paginated = whitelist
                current_page_size = total_items

            self.send_json_response({
                'success': True,
                'count': total_items,
                'whitelist': paginated,
                'page': current_page,
                'page_size': current_page_size,
                'total_pages': total_pages
            })

        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao listar whitelist: {str(e)}'}, 500)

    def get_users(self):
        """Get list of SPFBL users"""
        try:
            result = subprocess.run(
                ['/sbin/spfbl', 'user', 'show'],
                capture_output=True,
                text=True,
                timeout=10
            )

            users = []
            output = result.stdout.strip()

            if output:
                for line in output.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    email = None
                    name = 'N/A'
                    locale = None
                    timezone = None

                    # Formato típico documentado:
                    # admin <spfbl@example.com> en_US Etc/UTC
                    m = re.match(r'^(?P<name>.+?)\s+<(?P<email>[^>]+)>\s+(?P<locale>\S+)\s+(?P<tz>\S+)$', line)
                    if m:
                        name = m.group('name').strip()
                        email = m.group('email').strip()
                        locale = m.group('locale').strip()
                        timezone = m.group('tz').strip()
                    else:
                        # Fallback: pegar primeiro <email> se existir
                        m2 = re.search(r'<([^>]+)>', line)
                        if m2:
                            email = m2.group(1).strip()
                            name = line[:line.index('<')].strip() or 'N/A'
                        else:
                            # Último fallback: primeiro token contendo '@' é o email
                            tokens = line.split()
                            for token in tokens:
                                if '@' in token:
                                    email = token.strip('<>')
                                    break
                            if tokens:
                                name = tokens[0]

                    if not email:
                        continue

                    users.append({
                        'email': email,
                        'name': name,
                        'status': 'active',
                        'locale': locale,
                        'timezone': timezone,
                        'raw': line
                    })

            self.send_json_response({
                'success': True,
                'count': len(users),
                'users': users
            })

        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao listar usuários: {str(e)}'}, 500)

    def handle_add_user(self):
        """Handle adding a new SPFBL user"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            # Validar campos obrigatórios
            email = data.get('email', '').strip()
            name = data.get('name', '').strip()

            if not email or not name:
                self.send_json_response({
                    'error': 'Email e nome são obrigatórios'
                }, 400)
                return

            # Validar formato de email
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                self.send_json_response({
                    'error': 'Formato de email inválido'
                }, 400)
                return

            # Executar comando SPFBL user add
            result = subprocess.run(
                ['/sbin/spfbl', 'user', 'add', email, name],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = (result.stdout + result.stderr).strip()

            if 'ADDED' in output or result.returncode == 0:
                self.send_json_response({
                    'success': True,
                    'message': f'Usuário {email} adicionado com sucesso',
                    'user': {
                        'email': email,
                        'name': name
                    }
                })
            elif 'ALREADY EXISTS' in output or 'EXISTS' in output:
                self.send_json_response({
                    'error': f'Usuário {email} já existe no sistema'
                }, 409)
            else:
                self.send_json_response({
                    'error': f'Erro ao adicionar usuário: {output}'
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao adicionar usuário: {str(e)}'}, 500)

    def handle_remove_users(self):
        """Handle removing SPFBL users"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            emails = data.get('emails', [])
            if not isinstance(emails, list) or not emails:
                self.send_json_response({
                    'error': 'Lista de usuários vazia ou inválida'
                }, 400)
                return

            removed = []
            errors = []

            for email in emails:
                email_str = str(email).strip()
                if not email_str:
                    continue

                try:
                    result = subprocess.run(
                        ['/sbin/spfbl', 'user', 'drop', email_str],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    output = (result.stdout + result.stderr).strip()

                    if 'DROPPED' in output or result.returncode == 0:
                        removed.append(email_str)
                    else:
                        errors.append({
                            'email': email_str,
                            'error': output or 'Erro desconhecido'
                        })
                except subprocess.TimeoutExpired:
                    errors.append({
                        'email': email_str,
                        'error': 'Timeout ao executar comando SPFBL'
                    })
                except Exception as e:
                    errors.append({
                        'email': email_str,
                        'error': str(e)
                    })

            if removed:
                self.send_json_response({
                    'success': True,
                    'removed': removed,
                    'errors': errors,
                    'message': f'{len(removed)} usuário(s) removido(s) com sucesso'
                })
            else:
                self.send_json_response({
                    'success': False,
                    'error': 'Nenhum usuário foi removido',
                    'details': errors
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao remover usuários: {str(e)}'}, 500)

    def handle_send_totp(self):
        """Handle resending TOTP email to SPFBL users"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode('utf-8'))

            emails = data.get('emails') or []
            single_email = data.get('email')
            if single_email:
                emails.append(single_email)

            # Normalizar e validar lista
            normalized = []
            for email in emails:
                email_str = str(email).strip()
                if email_str:
                    normalized.append(email_str)

            if not normalized:
                self.send_json_response({
                    'error': 'Lista de usuários vazia ou inválida'
                }, 400)
                return

            sent = []
            errors = []

            for email_str in normalized:
                try:
                    result = subprocess.run(
                        ['/sbin/spfbl', 'user', 'send-totp', email_str],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    output = (result.stdout + result.stderr).strip()
                    upper_output = output.upper()

                    # Considerar sucesso se houver indicação clara de envio TOTP
                    if 'TOTP SENT' in upper_output or 'TOTP' in upper_output:
                        sent.append(email_str)
                    else:
                        errors.append({
                            'email': email_str,
                            'error': output or 'Erro desconhecido ao reenviar TOTP'
                        })
                except subprocess.TimeoutExpired:
                    errors.append({
                        'email': email_str,
                        'error': 'Timeout ao executar comando SPFBL'
                    })
                except Exception as e:
                    errors.append({
                        'email': email_str,
                        'error': str(e)
                    })

            if sent:
                self.send_json_response({
                    'success': True,
                    'sent': sent,
                    'errors': errors,
                    'message': f'TOTP reenviado para {len(sent)} usuário(s)'
                })
            else:
                self.send_json_response({
                    'success': False,
                    'error': 'Nenhum TOTP foi reenviado',
                    'details': errors
                }, 500)

        except json.JSONDecodeError:
            self.send_json_response({'error': 'JSON inválido'}, 400)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao reenviar TOTP: {str(e)}'}, 500)


    def get_logs(self, log_type='all'):
        """Return last lines of SPFBL log file for troubleshooting.

        log_type:
          - 'email': linhas relacionadas a consultas/envio de e-mail.
          - 'users': linhas de comandos administrativos/usuários/admin.
          - qualquer outro valor: todas as linhas.
        """
        # Verificar se está bloqueado
        if self.is_config_locked():
            self.send_json_response({
                'success': False,
                'error': 'Acesso aos logs está protegido. Remova ou renomeie o arquivo de proteção no servidor.',
                'locked': True
            }, 403)
            return

        try:
            today = datetime.utcnow().strftime('%Y-%m-%d')
            log_dir = LOG_DIR
            filename = f'spfbl.{today}.log'
            log_path = os.path.join(log_dir, filename)

            if not os.path.exists(log_path):
                self.send_json_response({
                    'success': False,
                    'error': f'Arquivo de log não encontrado: {log_path}'
                }, 404)
                return

            # Ler apenas as últimas N linhas para não sobrecarregar
            max_lines = 200
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()[-max_lines:]

            # Aplicar filtro por tipo de log
            lines = self.filter_logs_by_type(all_lines, log_type)
            lines = [self.sanitize_log_line(line) for line in lines]

            self.send_json_response({
                'success': True,
                'file': log_path,
                'type': log_type,
                'lines': [line.rstrip('\n') for line in lines]
            })

        except Exception as e:
            self.send_json_response({'error': f'Erro ao ler logs: {str(e)}'}, 500)

    def filter_logs_by_type(self, lines, log_type):
        """Filtra linhas de log por tipo de atividade."""
        if log_type not in ('email', 'users'):
            return lines

        filtered = []

        for line in lines:
            text = line.strip()
            if not text:
                continue

            upper = text.upper()

            if log_type == 'users':
                # Comandos administrativos, criação de usuários, clientes, TOTP, etc.
                if any(keyword in upper for keyword in [
                    'SERVERADM',       # Thread administrativa
                    ' ADMIN ',         # Contexto ADMIN
                    ' USER ADD ',
                    ' USER DROP ',
                    ' USER SET ',
                    ' USER SEND ',
                    ' TOTP ',
                    ' LOGIN ',
                    ' PASSWORD '
                ]):
                    filtered.append(line)
            elif log_type == 'email':
                # Atividade de consultas / SMTP / SPFBL
                if any(keyword in upper for keyword in [
                    'SERVERSPF',       # Servidor SPFBL (consultas)
                    'SERVERSMTP',      # Servidor SMTP interno
                    'SPFTCP',          # Threads de consulta SPF
                    'SPAMD/1.',        # Integração tipo spamd
                    ' QUERY ',
                    ' RESULT ',
                    ' BLOCK ',
                    ' PASS ',
                    ' SOFTFAIL ',
                    ' FAIL '
                ]):
                    filtered.append(line)

        return filtered

    def sanitize_log_line(self, line):
        """Remove/mascara informações sensíveis em linhas de log."""
        text = line
        # Mascara senhas após a palavra PASSWORD ou PASSWD
        text = re.sub(r'(PASSWORD\s+)(\S+)', r'\1******', text, flags=re.IGNORECASE)
        text = re.sub(r'(PASSWD\s+)(\S+)', r'\1******', text, flags=re.IGNORECASE)
        # Mascara possíveis códigos TOTP ou OTP numéricos de 4-10 dígitos
        text = re.sub(r'(TOTP[^\d]{0,10})(\d{4,10})', r'\1******', text, flags=re.IGNORECASE)
        text = re.sub(r'(OTP[^\d]{0,10})(\d{4,10})', r'\1******', text, flags=re.IGNORECASE)
        # Evita vazamento de hashes longos ou tokens
        text = re.sub(r'([A-Fa-f0-9]{24,})', '***MASK***', text)
        return text

    def serve_settings_page(self, status_message=None, status_type=None):
        """Render settings page with SPFBL configuration (server-side)"""
        config_file = CONF_FILE
        template_path = os.path.join(WEB_DIR, 'settings.html')

        # Verificar PRIMEIRO se a configuração está bloqueada
        is_locked = self.is_config_locked()

        # Carregar template HTML da página de configuração
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        except Exception as e:
            self.send_error(500, f'Erro ao carregar template settings.html: {str(e)}')
            return

        page = template

        # Se está bloqueado, não ler nem exibir conteúdo da configuração
        if is_locked:
            page = page.replace('[[CONFIG_CONTENT]]', '')
            page = page.replace('[[LINE_COUNT]]', '0')
            page = page.replace('[[CHAR_COUNT]]', '0')
            page = page.replace('[[STATUS_BLOCK]]', '')
            # Injetar JavaScript para mostrar o alerta
            locked_js = """<script>
document.addEventListener('DOMContentLoaded', function() {
    const configSection = document.getElementById('config');
    const protectedSection = document.getElementById('protected-section');
    if (configSection) configSection.classList.remove('active');
    if (protectedSection) protectedSection.classList.remove('hidden');
});
</script>"""
            page = page.replace('</body>', locked_js + '\n</body>')
        else:
            # Só ler e renderizar a configuração se NOT está bloqueada
            try:
                with open(config_file, 'r', encoding='utf-8', errors='replace') as f:
                    config_content = f.read()
            except Exception as e:
                config_content = ''
                if not status_message:
                    status_message = f'Erro ao ler configuração: {str(e)}'
                    status_type = 'error'

            # Definir tipo de status padrão
            if status_message and not status_type:
                status_type = 'success'

            # Contagem de linhas e caracteres
            line_count = config_content.count('\n') + 1 if config_content else 0
            char_count = len(config_content)

            # Substituir placeholders
            page = page.replace('[[CONFIG_CONTENT]]', config_content)
            page = page.replace('[[LINE_COUNT]]', str(line_count))
            page = page.replace('[[CHAR_COUNT]]', str(char_count))


        # Bloco de status (mensagem de sucesso/erro)
        if status_message:
            # Escapar caracteres básicos na mensagem
            safe_msg = (
                status_message
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
            )
            status_block = f'<div id="status-message" class="status-message {status_type}">{safe_msg}</div>'
        else:
            status_block = ''

        page = page.replace('[[STATUS_BLOCK]]', status_block)

        # Enviar resposta HTML com cabeçalhos de segurança
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        self.send_header('Content-Security-Policy', self.build_csp_policy())
        self.end_headers()
        self.wfile.write(page.encode('utf-8', errors='replace'))

    def is_config_locked(self):
        """Check if configuration is protected by lock file"""
        return os.path.exists(CONF_LOCK_FILE)

    def check_github_update(self):
        """Check for updates from GitHub CHANGELOG"""
        try:
            import urllib.request
            now_ts = time.time()
            with update_cache_lock:
                cached = update_cache.get('payload')
                checked_at = update_cache.get('checked_at', 0.0) or 0.0
                if cached and (now_ts - checked_at) < UPDATE_CACHE_SECONDS:
                    self.send_json_response(cached)
                    return

            # URLs de changelog:
            # - Por padrão usa o repositório oficial da nova dashboard.
            # - Pode ser sobrescrito por variáveis de ambiente.
            default_raw = 'https://raw.githubusercontent.com/chuvadenovembro/nova-dashboard-para-spfbl/main/CHANGELOG.md'
            default_web = 'https://github.com/chuvadenovembro/nova-dashboard-para-spfbl/blob/main/CHANGELOG.md'
            changelog_url = (os.environ.get('SPFBL_DASH_CHANGELOG_RAW_URL') or default_raw).strip()
            changelog_web_url = (os.environ.get('SPFBL_DASH_CHANGELOG_WEB_URL') or default_web).strip()

            # Fetch do GitHub
            with urllib.request.urlopen(changelog_url, timeout=5) as response:
                content = response.read().decode('utf-8')

            # Extrair versão usando regex
            import re
            match = re.search(r'^##\s+\[v(\d+\.\d+)\]', content, re.MULTILINE)
            if not match:
                self.send_json_response({'error': 'Versão não encontrada no CHANGELOG'}, 400)
                return

            latest_version = match.group(1)

            # Ler versão local
            try:
                with open(os.path.join(WEB_DIR, 'version.txt'), 'r') as f:
                    local_version = f.read().strip()
                    # Remover 'v' se existir
                    if local_version.startswith('v'):
                        local_version = local_version[1:]
            except:
                local_version = '0.00'

            # Comparar versões
            def compare_versions(v1, v2):
                parts1 = [int(x) for x in v1.split('.')]
                parts2 = [int(x) for x in v2.split('.')]
                for i in range(max(len(parts1), len(parts2))):
                    p1 = parts1[i] if i < len(parts1) else 0
                    p2 = parts2[i] if i < len(parts2) else 0
                    if p1 < p2:
                        return -1
                    if p1 > p2:
                        return 1
                return 0

            comparison = compare_versions(local_version, latest_version)

            payload = {
                'success': True,
                'local_version': local_version,
                'latest_version': latest_version,
                'update_available': comparison < 0,
                'changelog_url': changelog_web_url or changelog_url
            }
            with update_cache_lock:
                update_cache['payload'] = payload
                update_cache['checked_at'] = now_ts
            self.send_json_response(payload)
        except urllib.error.URLError as e:
            self.send_json_response({
                'success': False,
                'error': f'Erro ao conectar ao GitHub: {str(e)}'
            }, 500)
        except Exception as e:
            self.send_json_response({
                'success': False,
                'error': f'Erro ao verificar atualização: {str(e)}'
            }, 500)

    def handle_config(self):
        """Get SPFBL configuration file"""
        config_file = CONF_FILE
        is_locked = self.is_config_locked()

        try:
            # Ler arquivo preservando UTF-8
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read()

            self.send_json_response({
                'success': True,
                'content': content,
                'path': config_file,
                'locked': is_locked
            })
        except Exception as e:
            self.send_json_response({
                'error': f'Erro ao ler configuração: {str(e)}'
            }, 500)

    def handle_config_update(self):
        """Update SPFBL configuration file"""
        config_file = CONF_FILE

        # Verificar se configuração está bloqueada
        if self.is_config_locked():
            self.send_json_response({
                'error': 'Configuração protegida: arquivo spfbl.conf.lock existe. Remova o arquivo lock para editar.',
                'locked': True
            }, 403)
            return

        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            try:
                data = json.loads(body.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_json_response({'error': 'JSON inválido'}, 400)
                return

            new_content = data.get('content', '')

            if not new_content:
                self.send_json_response({'error': 'Conteúdo vazio'}, 400)
                return

            # Fazer backup antes de salvar
            backup_file = f'{config_file}.backup-{int(time.time())}'
            try:
                shutil.copy2(config_file, backup_file)
            except Exception as e:
                self.send_json_response({
                    'error': f'Erro ao fazer backup: {str(e)}'
                }, 500)
                return

            # Salvar com UTF-8 (preservando codificação)
            try:
                with open(config_file, 'w', encoding='utf-8') as f:
                    f.write(new_content)

                self.send_json_response({
                    'success': True,
                    'message': 'Configuração salva com sucesso',
                    'backup': backup_file
                })
            except Exception as e:
                # Restaurar backup se falhar
                try:
                    shutil.copy2(backup_file, config_file)
                except:
                    pass

                self.send_json_response({
                    'error': f'Erro ao salvar configuração: {str(e)}'
                }, 500)

        except Exception as e:
            self.send_json_response({
                'error': f'Erro ao processar requisição: {str(e)}'
            }, 500)

    def handle_settings_form_post(self):
        """Handle HTML form submission to update SPFBL configuration"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='replace')
            params = parse_qs(body)

            config_file = CONF_FILE
            new_content = params.get('content', [''])[0]

            if not new_content.strip():
                self.serve_settings_page(
                    status_message='O arquivo não pode estar vazio',
                    status_type='error'
                )
                return

            # Fazer backup antes de salvar
            backup_file = f'{config_file}.backup-{int(time.time())}'
            try:
                shutil.copy2(config_file, backup_file)
            except Exception as e:
                self.serve_settings_page(
                    status_message=f'Erro ao fazer backup: {str(e)}',
                    status_type='error'
                )
                return

            # Salvar novo conteúdo
            try:
                with open(config_file, 'w', encoding='utf-8') as f:
                    f.write(new_content)
            except Exception as e:
                # Restaurar backup em caso de falha
                try:
                    shutil.copy2(backup_file, config_file)
                except Exception:
                    pass

                self.serve_settings_page(
                    status_message=f'Erro ao salvar configuração: {str(e)}',
                    status_type='error'
                )
                return

            # Sucesso: recarregar página com mensagem
            self.serve_settings_page(
                status_message=f'Configuração salva com sucesso (backup em {backup_file})',
                status_type='success'
            )

        except Exception as e:
            self.serve_settings_page(
                status_message=f'Erro ao processar requisição: {str(e)}',
                status_type='error'
            )

    def get_server_memory(self):
        """Get server memory usage"""
        try:
            import psutil
            memory = psutil.virtual_memory()

            data = {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'percent': memory.percent,
                'unit': 'bytes'
            }
            self.send_json_response(data)
        except ImportError:
            # Fallback if psutil not installed - use /proc/meminfo
            try:
                with open('/proc/meminfo', 'r') as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split(':')
                        if len(parts) == 2:
                            key = parts[0].strip()
                            value = int(parts[1].split()[0]) * 1024  # Convert KB to bytes
                            meminfo[key] = value

                    total = meminfo.get('MemTotal', 0)
                    available = meminfo.get('MemAvailable', 0)
                    used = total - available
                    percent = (used / total * 100) if total > 0 else 0

                    data = {
                        'total': total,
                        'available': available,
                        'used': used,
                        'percent': percent,
                        'unit': 'bytes'
                    }
                    self.send_json_response(data)
            except Exception as e:
                self.send_json_response({'error': str(e)}, 500)
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)

    def get_uptime(self):
        """Get SPFBL service uptime"""
        try:
            result = subprocess.run(
                ['systemctl', 'show', 'spfbl', '--property=ActiveEnterTimestamp'],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except:
            return "Unknown"

    def log_message(self, format, *args):
        """Custom logging with security info"""
        # Log de acesso com informações de segurança
        client_ip = self.client_address[0]
        message = f"{client_ip} - {format%args}"

        # Log de acesso habilitado para auditoria
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}", file=sys.stderr)

def _start_subdomain_campaign_auto_runner():
    """Inicia o auto-runner do addon de campanhas por subdomínio (se habilitado)."""
    try:
        if not os.path.isdir(ADDON_PATH):
            return None

        blocker_path = os.path.join(ADDON_PATH, 'subdomain_campaign_blocker.py')
        if not os.path.isfile(blocker_path):
            return None

        # Adiciona addon ao path se necessário
        if ADDON_PATH not in sys.path:
            sys.path.insert(0, ADDON_PATH)

        from subdomain_campaign_blocker import SubdomainCampaignBlockerService

        service = SubdomainCampaignBlockerService()

        # Só inicia o auto-runner se o addon estiver enabled E auto_block_enabled
        if service.config.get('enabled') and service.config.get('auto_block_enabled'):
            service.start_auto_runner()
            print(f"   Subdomain Campaign Blocker: AUTO-RUNNER STARTED (poll: {service.config.get('poll_seconds', 60)}s)")
            return service
        else:
            enabled = service.config.get('enabled', False)
            auto_block = service.config.get('auto_block_enabled', False)
            print(f"   Subdomain Campaign Blocker: DISABLED (enabled={enabled}, auto_block={auto_block})")
            return None
    except Exception as e:
        print(f"   Subdomain Campaign Blocker: ERROR - {e}", file=sys.stderr)
        return None


if __name__ == '__main__':
    try:
        PORT = int(os.environ.get('SPFBL_DASH_PORT', '8002'))
    except (TypeError, ValueError):
        PORT = 8002

    # Servidor multi-threaded para suportar múltiplas requisições simultâneas
    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
        request_queue_size = 50

    server = ThreadedHTTPServer(('0.0.0.0', PORT), SPFBLSecureAPIHandler)
    print(f"🔒 SPFBL Secure Dashboard running on http://0.0.0.0:{PORT}")
    print(f"   Dashboard: http://0.0.0.0:{PORT}/dashboard.html")
    print(f"   Login: http://0.0.0.0:{PORT}/login")
    print(f"   API: http://0.0.0.0:{PORT}/api/stats")
    print(f"")
    print(f"   Session timeout: {SESSION_TIMEOUT}s")
    print(f"   Max login attempts: {MAX_LOGIN_ATTEMPTS}")
    print(f"   Lockout time: {LOCKOUT_TIME}s")
    print(f"   Server mode: Multi-threaded (max queue: 50)")
    print(f"   Request timeout: 30s")

    # Inicia o auto-runner do addon de campanhas por subdomínio
    subdomain_campaign_service = _start_subdomain_campaign_auto_runner()

    server.serve_forever()
