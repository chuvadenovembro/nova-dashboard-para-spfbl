# Changelog

## [v0.06] - Correção de segurança, melhorias e otimizações (2025-12-15)

### Melhorias
- Detecção mais robusta de página de login do painel legado com marcadores negativos adicionais
- Página "Listas de Bloqueio" agora exibe todos os tipos de bloqueio (IPs, domínios, hosts)
- Extração de timestamps agora inclui logs do addon subdomain-campaign
- **Otimização de performance**: Cache de 60s para lista de bloqueios
- **Otimização de performance**: Cache de 5min para timestamps de bloqueios
- **Otimização de performance**: Busca de timestamps apenas para itens filtrados (não toda a lista)
- **Otimização de performance**: Leitura reduzida de logs (5000 linhas addon, 10000 linhas SPFBL)

### Correções
- Correção crítica: Fallback perigoso na autenticação que permitia acesso sem senha correta
- Validação restritiva do HTML de resposta do painel legado (apenas marcadores positivos reconhecidos)
- API de bloqueios alterada de `block show` para `block show all` para exibir todos os bloqueios
- Correção na ordenação de bloqueios: timestamps agora são buscados para todos os itens (não apenas primeiros 200)

---

## [v0.05] - Listas, segurança e alertas

### Novo
- Filtro de blacklist por tipo (IP, domínio, email, campanha)
- Toggle persistente para ativar/desativar envio de e-mails do SPFBL (abuse/TOTP)

### Melhorias
- Página “Listas (Block/White)” redesenhada e padronizada com “Consultas”, com busca e paginação
- API/dashboard configuráveis por variáveis de ambiente, sem dados hardcoded
- Otimizações na leitura de logs/estatísticas e scoping por cliente

### Correções
- Correção da ordenação/recência dos bloqueios exibidos
- Login com TOTP compatível com painel legado
- Restrições de acesso para usuários não-admin

---

## [v0.04] - Em edição

### Novo
- Aviso de atualização da dashboard
- Proteção da configuração e logs com a criação do arquivo /opt/spfbl/spfbl.conf.lock

### Melhorias
- Melhorias no design
- Melhorias no layout responsivo

### Correções
- Modo responsivo

---

## [v0.03] - Sistema de Eventos de Fraude e Melhorias de Segurança

### Novo
- **Token de Autenticação de Fraude**: Sistema automático de geração e distribuição de tokens para autenticação de eventos de fraude entre servidor SPFBL e clientes DirectAdmin (install_spfbl.sh:162-187, 832-855)
- **Detecção de Fraude SRS**: Lógica aprimorada no cliente SPFBL que reconhece envelopes SRS encadeados e retorna `FRAUD-SRS(...)` antes de consultar o servidor central (spfbl-client-template.sh:36-176, 3791-3810)
- **Registro de Eventos de Fraude**: API e dashboard incorporam novo fluxo para armazenar, agrupar e destacar visualmente denúncias de fraude (newdash/backend/spfbl-api.py:25-210, 1299-1340; newdash/frontend/dashboard.js:448-505, dashboard.css:1014-1036)
- **Rejeição de Fraude na ACL do Exim**: DirectAdmin passa a registrar e rejeitar qualquer resultado `FRAUD-*`, evitando avanço de mensagens mesmo com indisponibilidade do servidor SPFBL (install_spfbl_directadmin_51_83_5_176.sh:13-148, 196-204)

### Melhorias

#### Instalador (install_spfbl.sh)
- Validação obrigatória de `MAIL_DOMAIN` e `SPFBL_ADMIN_EMAIL` antes de prosseguir (install_spfbl.sh:320), evitando instalações incompletas
- Detecção de IP público agora usa quedas graduais (curl → wget → dig) com fallback para IP privado quando necessário (install_spfbl.sh:356), tornando o processo mais resiliente
- Função `ensure_python2_default` não renomeia mais `/usr/bin/python`; ajusta symlink apenas quando seguro (install_spfbl.sh:444), prevenindo efeitos colaterais no sistema
- Fluxo principal reorganizado para instalar dependências antes de detectar IP público e validar entradas logo no início (install_spfbl.sh:2611), garantindo ferramentas presentes para etapas seguintes
- Instalador do DirectAdmin agora inclui `FRAUD_EVENT_ENDPOINT` e `FRAUD_EVENT_TOKEN`, instala curl automaticamente e insere novos parâmetros no cliente via sed (install_spfbl_directadmin_51_83_5_176.sh:142-147)

#### Dashboard e API (newdash/*)
- API filtra estatísticas, gráficos horários e consultas para contar apenas clientes autorizados, ignorando acessos locais (newdash/backend/spfbl-api.py:1214-1534)
- Página de consultas redesenhada com resultados em destaque, cartões responsivos, seleção por linha e painel com ações consolidadas e modernas (newdash/frontend/dashboard.html:150-228, dashboard.css:702-1051, dashboard.js:25-683)
- Navegação em dispositivos móveis convertida para topbar compacta com apenas ícones; botão de recolher discreto na base da sidebar com adaptação automática ao viewport (dashboard.css:60-210, 725-826, dashboard.js:3-187)
- Melhorias adicionais de UX: truncamento inteligente de HELO longo (dashboard.css:930), botões globais integrados ao painel de seleção e normalização de consultas para exibição consistente nos filtros

#### Cliente SPFBL (spfbl-client-template.sh)
- Inclusão de variáveis de endpoint/token para autenticação de eventos (spfbl-client-template.sh:36-176)
- Adição de utilitários: `escape_regex`, `detect_local_srs_domain`, `report_fraud_event` (spfbl-client-template.sh:3791-3810)
- Detecção de domínios locais via `/etc/virtual/` e similares com curta-circuito no comando query que retorna `FRAUD-SRS(...)` e dispara POST autenticado para o dashboard

### Correções
- Falhas na distribuição de configurações de fraude para clientes remotos resolvidas com sistema de token seguro
- Problemas de timeout em consultas resolvidos com rejeição local de fraude SRS antes de acessar o servidor central

### Notas de Implantação
- Replicar novo `install_spfbl_directadmin_*.sh` em cada servidor DirectAdmin ou reaplicar cliente usando script gerado para que o binário `/usr/local/bin/spfbl` receba heurísticas e token atualizado
- Garantir conectividade HTTP do DirectAdmin para `http://51.83.5.176:8002/api/fraud-events` (porta 8002/TCP) para registro de eventos no dashboard
- Monitorar painel "Consultas" após redistribuição; verificar se linhas destacadas com `FRAUD-SRS` aparecem; revisar firewall/rota até `51.83.5.176:9877` se continuar vendo apenas `TIMEOUT`

---

## [v0.02] - Em edição

### Novo
- Adcionado changelog

### Melhorias
- Versionamento do script
- Melhorias de segurança

### Correções
- Falha na exibição das consultas
- Falha no script para adicionar servidor directadmin remotamente
- Falha na exibição do recaptcha na tela de login (quando habilitado)

---

## [v0.01] - Versão Alpha

### Novo
- Dashboard moderna com tema claro/escuro
- Instalador automatizado para Ubuntu 22.04
- Interface completa para gerenciamento de clientes SPFBL
- Sistema de consultas com filtros avançados
- Gerenciamento de listas de controle (blacklist/whitelist)
- Painel de logs com rastreamento de atividades
- Editor de configuração com backup automático
- Autenticação com TOTP (Time-based One-Time Password)
- Suporte integrado para DirectAdmin

### Melhorias
- Otimização automática de memória JVM
- Configuração simplificada do Exim
- Interface responsiva em dispositivos móveis

### Correções
- Tratamento robusto de erros de instalação
- Validação de portas e permissões de firewall
