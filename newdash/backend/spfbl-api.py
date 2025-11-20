#!/usr/bin/env python3
"""
SPFBL Dashboard API - Versão Segura com Autenticação
Provides REST API endpoints and serves the dashboard frontend with authentication
"""

import subprocess
import json
import re
import os
import hmac
import hashlib
import secrets
import time
import urllib.parse
import urllib.request
import http.cookiejar
import shutil
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from http.cookies import SimpleCookie

# Configurações de Sessão (somente em memória)
SESSION_TIMEOUT = 3600  # 1 hora em segundos
MAX_LOGIN_ATTEMPTS = 5  # Máximo de tentativas de login
LOCKOUT_TIME = 300  # 5 minutos de bloqueio após exceder tentativas

# Armazenamento em memória (dicionários simples, sem chave secreta global)
sessions = {}  # {token: {'email': 'user@domain', 'created': timestamp}}
login_attempts = {}  # {ip: {'count': 0, 'locked_until': timestamp}}

class SPFBLSecureAPIHandler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin', '*'))
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
            self.serve_file('/opt/spfbl/web/login.css', 'text/css')
            return
        if path == '/logo.png':
            self.serve_file('/opt/spfbl/web/logo.png', 'image/png')
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

        # Verificar autenticação para todas as outras rotas
        if not self.is_authenticated():
            self.send_json_response({'error': 'Unauthorized', 'redirect': '/login'}, 401)
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
        elif path == '/api/server/memory':
            self.get_server_memory()
        elif path == '/api/settings/config':
            self.handle_config()
        # Serve static files / dynamic settings page
        elif path in ['/', '/dashboard', '/dashboard.html']:
            self.serve_file('/opt/spfbl/web/dashboard.html', 'text/html')
        elif path == '/settings' or path == '/settings.html':
            self.serve_settings_page()
        elif path == '/dashboard.css':
            self.serve_file('/opt/spfbl/web/dashboard.css', 'text/css')
        elif path == '/dashboard.js':
            self.serve_file('/opt/spfbl/web/dashboard.js', 'application/javascript')
        elif path == '/login.css':
            self.serve_file('/opt/spfbl/web/login.css', 'text/css')
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
        elif path == '/api/logout':
            self.handle_logout()
        elif path == '/api/clients/add':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_add_client()
        elif path == '/api/clients/remove':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_remove_clients()
        elif path == '/api/block/add':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_block_add()
        elif path == '/api/block/drop':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_block_drop()
        elif path == '/api/white/add':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_white_add()
        elif path == '/api/white/drop':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_white_drop()
        elif path == '/api/users/add':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_add_user()
        elif path == '/api/users/remove':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_remove_users()
        elif path == '/api/settings/config':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_config_update()
        elif path == '/settings' or path == '/settings.html':
            if not self.is_authenticated():
                # Para acesso HTML, redirecionar para login se não autenticado
                self.send_response(302)
                self.send_header('Location', '/login')
                self.end_headers()
                return
            self.handle_settings_form_post()
        elif path == '/api/users/send-totp':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.handle_send_totp()
        elif path == '/api/server/memory':
            if not self.is_authenticated():
                self.send_json_response({'error': 'Unauthorized'}, 401)
                return
            self.get_server_memory()
        else:
            self.send_error(404, "Not found")

    def check_user_totp_status(self, email):
        """Check if user has TOTP enabled (public endpoint)"""
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

            # DEPOIS: Verificar se usuário existe
            result = subprocess.run(
                ['/sbin/spfbl', 'user', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if email not in result.stdout:
                self.send_json_response({
                    'success': False,
                    'error': 'User not found',
                    'has_totp': False
                }, 404)
                return

            # Tentar acessar o painel antigo para verificar se tem TOTP
            base_url = os.environ.get('SPFBL_PANEL_URL', 'http://127.0.0.1:8001')
            try:
                parsed = urllib.parse.urlparse(base_url)
                if not parsed.scheme:
                    base_url = 'http://' + base_url
            except Exception:
                base_url = 'http://127.0.0.1:8001'

            email_path = '/' + urllib.parse.quote(email)

            try:
                response = urllib.request.urlopen(f"{base_url}{email_path}", timeout=3)
                html = response.read().decode('utf-8', errors='ignore')

                # Se o HTML contém o painel de controle, usuário já tem TOTP
                if "Painel de controle do SPFBL" in html or "SPFBL control panel" in html:
                    self.send_json_response({
                        'success': True,
                        'has_totp': True,
                        'message': 'User already has TOTP configured'
                    })
                else:
                    # Se não mostrou o painel, provavelmente está pedindo TOTP
                    self.send_json_response({
                        'success': True,
                        'has_totp': False,
                        'message': 'User needs to set up TOTP'
                    })
            except Exception as e:
                # Se não conseguir acessar o painel antigo, assumir que não tem TOTP
                self.send_json_response({
                    'success': True,
                    'has_totp': False,
                    'message': 'User needs to set up TOTP'
                })

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

            # Verificar reCAPTCHA se configurado
            recaptcha_secret = os.environ.get('RECAPTCHA_SECRET_KEY', '')
            if recaptcha_secret:
                if not self.verify_recaptcha(recaptcha_token, recaptcha_secret):
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
            with open('/opt/spfbl/spfbl.conf', 'r') as f:
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
            with open('/opt/spfbl/REMOTE_INTEGRATION.md', 'r', encoding='utf-8') as f:
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
            return result.get('success', False) and result.get('score', 0) > 0.5
        except Exception:
            return False

    def is_authenticated(self):
        """Verify if user is authenticated via session token"""
        cookies = SimpleCookie(self.headers.get('Cookie', ''))

        if 'session_token' not in cookies:
            return False

        token = cookies['session_token'].value

        if token not in sessions:
            return False

        session = sessions[token]

        # Verificar timeout da sessão
        if time.time() - session['created'] > SESSION_TIMEOUT:
            del sessions[token]
            return False

        return True

    def get_current_user(self):
        """Get current authenticated user info"""
        cookies = SimpleCookie(self.headers.get('Cookie', ''))
        token = cookies['session_token'].value

        if token in sessions:
            self.send_json_response({
                'email': sessions[token]['email'],
                'authenticated': True
            })
        else:
            self.send_json_response({'error': 'Not authenticated'}, 401)

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
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin', '*'))
                self.send_header('Access-Control-Allow-Credentials', 'true')

                # Cookie seguro
                cookie = SimpleCookie()
                cookie['session_token'] = token
                cookie['session_token']['httponly'] = True
                cookie['session_token']['secure'] = False  # Mudar para True em produção com HTTPS
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
        """Verify TOTP code against original SPFBL HTTP control panel.

        Fluxo:
        1. Acessa http://127.0.0.1:8001/<email>?otp=<codigo> para submeter o TOTP.
        2. Em seguida acessa http://127.0.0.1:8001/<email> com o mesmo cookie.
        3. Se o HTML de resposta tiver o título do painel de controle, considera autenticado.
        """
        base_url = os.environ.get('SPFBL_PANEL_URL', 'http://127.0.0.1:8001')

        try:
            parsed = urllib.parse.urlparse(base_url)
            if not parsed.scheme:
                base_url = 'http://' + base_url
        except Exception:
            base_url = 'http://127.0.0.1:8001'

        email_path = '/' + urllib.parse.quote(email)
        query = urllib.parse.urlencode({'otp': str(otp_code)})

        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        opener.addheaders = [
            ('User-Agent', 'spfbl-dashboard/2.0'),
        ]

        try:
            # 1) Submeter código TOTP
            url_with_otp = f"{base_url}{email_path}?{query}"
            opener.open(url_with_otp, timeout=3)

            # 2) Requisitar painel com o cookie retornado
            panel_resp = opener.open(f"{base_url}{email_path}", timeout=3)
            html = panel_resp.read().decode('utf-8', errors='ignore')
        except Exception:
            return False

        # Verificar se é o painel de controle (PT ou EN)
        if "Painel de controle do SPFBL" in html or "SPFBL control panel" in html:
            return True

        return False

    def verify_password_with_spfbl(self, email, password):
        """Verify password using the legacy SPFBL HTTP login (same endpoint usado para TOTP).

        Fluxo:
        1. POST http://127.0.0.1:8001/<email> com body password=<senha>
        2. GET a mesma URL com o cookie retornado
        3. Considera autenticado se a resposta contiver o painel de controle
        """
        base_url = os.environ.get('SPFBL_PANEL_URL', 'http://127.0.0.1:8001')

        try:
            parsed = urllib.parse.urlparse(base_url)
            if not parsed.scheme:
                base_url = 'http://' + base_url
        except Exception:
            base_url = 'http://127.0.0.1:8001'

        email_path = '/' + urllib.parse.quote(email)

        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
        opener.addheaders = [
            ('User-Agent', 'spfbl-dashboard/2.0'),
        ]

        try:
            # 1) Submeter senha via POST (como o painel legado)
            payload = urllib.parse.urlencode({'password': password}).encode('utf-8')
            opener.open(f"{base_url}{email_path}", data=payload, timeout=3)

            # 2) Requisitar painel com o cookie retornado
            panel_resp = opener.open(f"{base_url}{email_path}", timeout=3)
            html = panel_resp.read().decode('utf-8', errors='ignore')
        except Exception:
            return False

        # Verificar se é o painel de controle (PT ou EN)
        html_lower = html.lower()
        if "painel de controle do spfbl" in html_lower or "spfbl control panel" in html_lower:
            return True

        return False

    def verify_against_config(self, email, password):
        """Verify against a secure configuration file"""
        # Arquivo de senhas hash (criar separadamente)
        config_file = '/opt/spfbl/dashboard_users.conf'

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
            # Primeiro: Verificar se é o usuário padrão criado na instalação
            if email == 'spfbl@example.com' and password == 'TroqueEssaSenha123!':
                return True

            # Segundo: Procurar configuração de admin_email no spfbl.conf
            with open('/opt/spfbl/spfbl.conf', 'r') as f:
                content = f.read()

                # Verificar se este email é o admin_email configurado
                if f'admin_email={email}' in content:
                    # Extrair senha SMTP (última opção)
                    for line in content.split('\n'):
                        if line.startswith('smtp_password='):
                            stored_password = line.split('=', 1)[1].strip()
                            return password == stored_password

        except:
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

    def cleanup_old_sessions(self):
        """Remove expired sessions"""
        current_time = time.time()
        expired = [token for token, data in sessions.items()
                  if current_time - data['created'] > SESSION_TIMEOUT]

        for token in expired:
            del sessions[token]

    def sanitize_input(self, input_string):
        """Sanitize user input to prevent XSS and injection"""
        # Remove caracteres perigosos
        sanitized = re.sub(r'[<>"\';()&]', '', input_string)
        return sanitized.strip()

    def is_valid_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def serve_login_page(self):
        """Serve login page"""
        self.serve_file('/opt/spfbl/web/login.html', 'text/html')

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
            self.send_header('Content-Security-Policy',
                           "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:;")

            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404, "File not found")
        except Exception as e:
            self.send_error(500, f"Error serving file: {str(e)}")

    def send_json_response(self, data, status=200):
        """Send JSON response with security headers"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin', '*'))
        self.send_header('Access-Control-Allow-Credentials', 'true')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

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

    def get_stats(self):
        """Get SPFBL statistics"""
        try:
            clients_output = self.run_spfbl_command('client show')
            clients = clients_output.strip().split('\n') if clients_output else []

            log_file = f"/var/log/spfbl/spfbl.{datetime.now().strftime('%Y-%m-%d')}.log"
            total_queries = 0
            blocked = 0
            passed = 0
            softfail = 0
            failed = 0

            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    for line in f:
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

            stats = {
                'total_queries': total_queries,
                'clients_connected': len([c for c in clients if c.strip()]),
                'blocked': blocked,
                'passed': passed,
                'softfail': softfail,
                'failed': failed,
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

    def get_recent_queries(self):
        """Get recent queries from log"""
        try:
            log_file = f"/var/log/spfbl/spfbl.{datetime.now().strftime('%Y-%m-%d')}.log"
            queries = []

            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    lines = f.readlines()

                count = 0
                for line in reversed(lines):
                    if 'SPF' in line and '=>' in line and count < 100:
                        match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d+).*SPF.*\'(.+?)\'.*\'(.+?)\'.*\'(.+?)\'.*\'(.+?)\'.*=> (\w+)', line)
                        if match:
                            timestamp, ip, sender, helo, recipient, result = match.groups()
                            queries.append({
                                'timestamp': timestamp,
                                'ip': ip,
                                'sender': sender,
                                'helo': helo,
                                'recipient': recipient,
                                'result': result
                            })
                            count += 1

            self.send_json_response({'queries': queries})
        except Exception as e:
            self.send_json_response({'error': str(e)}, 500)

    def get_today_queries(self):
        """Get query statistics for today grouped by hour"""
        try:
            log_file = f"/var/log/spfbl/spfbl.{datetime.now().strftime('%Y-%m-%d')}.log"
            hourly_stats = {}

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

                            blocklist.append({
                                'token': token,
                                'type': type_token,
                                'raw': line
                            })

            self.send_json_response({
                'success': True,
                'count': len(blocklist),
                'blocklist': blocklist
            })

        except subprocess.TimeoutExpired:
            self.send_json_response({'error': 'Timeout ao executar comando SPFBL'}, 500)
        except Exception as e:
            self.send_json_response({'error': f'Erro ao listar blacklist: {str(e)}'}, 500)

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

            self.send_json_response({
                'success': True,
                'count': len(whitelist),
                'whitelist': whitelist
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
        try:
            today = datetime.utcnow().strftime('%Y-%m-%d')
            log_dir = '/var/log/spfbl'
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
        config_file = '/opt/spfbl/spfbl.conf'
        template_path = '/opt/spfbl/web/settings.html'

        # Ler conteúdo do arquivo de configuração
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

        # Carregar template HTML da página de configuração
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        except Exception as e:
            self.send_error(500, f'Erro ao carregar template settings.html: {str(e)}')
            return

        # Contagem de linhas e caracteres
        line_count = config_content.count('\n') + 1 if config_content else 0
        char_count = len(config_content)

        page = template
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
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
        )
        self.end_headers()
        self.wfile.write(page.encode('utf-8', errors='replace'))

    def handle_config(self):
        """Get SPFBL configuration file"""
        config_file = '/opt/spfbl/spfbl.conf'

        try:
            # Ler arquivo preservando UTF-8
            with open(config_file, 'r', encoding='utf-8') as f:
                content = f.read()

            self.send_json_response({
                'success': True,
                'content': content,
                'path': config_file
            })
        except Exception as e:
            self.send_json_response({
                'error': f'Erro ao ler configuração: {str(e)}'
            }, 500)

    def handle_config_update(self):
        """Update SPFBL configuration file"""
        config_file = '/opt/spfbl/spfbl.conf'

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

            config_file = '/opt/spfbl/spfbl.conf'
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

        # Em produção, usar logging apropriado
        # logging.info(message)
        pass

if __name__ == '__main__':
    PORT = 8002
    server = HTTPServer(('0.0.0.0', PORT), SPFBLSecureAPIHandler)
    print(f"🔒 SPFBL Secure Dashboard running on http://0.0.0.0:{PORT}")
    print(f"   Dashboard: http://0.0.0.0:{PORT}/dashboard.html")
    print(f"   Login: http://0.0.0.0:{PORT}/login")
    print(f"   API: http://0.0.0.0:{PORT}/api/stats")
    print(f"")
    print(f"   Default credentials:")
    print(f"   Email: spfbl@example.com")
    print(f"   Password: TroqueEssaSenha123!")
    print(f"")
    print(f"   Session timeout: {SESSION_TIMEOUT}s")
    print(f"   Max login attempts: {MAX_LOGIN_ATTEMPTS}")
    print(f"   Lockout time: {LOCKOUT_TIME}s")
    server.serve_forever()
