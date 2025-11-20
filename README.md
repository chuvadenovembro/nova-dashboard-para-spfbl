# Instalador SPFBL com Nova Dashboard + Integração com o DirectAdmin

<img width="1920" height="959" alt="scrnli_P7X6qinFeWl6Lo" src="https://github.com/user-attachments/assets/b17357e5-55e0-4a7a-a422-341c061553e1" />

<img width="1920" height="959" alt="scrnli_V9dXR71NUWLOFi" src="https://github.com/user-attachments/assets/d0aaf25c-bd05-4ef0-9e38-2e95686584e1" />

## 📋 Visão Geral

Este projeto fornece um instalador automatizado (`install_spfbl.sh`) para facilitar a implantação do **SPFBL** em servidores Ubuntu 22.04 LTS, acompanhado de uma **nova dashboard moderna** que substitui o painel clássico com funcionalidades avançadas de administração e monitoramento.

Como utilizar:

Deverá baixar o projeto em qualquer pasta de um servidor ubuntu 22

Então vai executar o script

```bash
./install_spfbl.sh
```
OBS: A pasta newdash deve estar no mesmo local do script.

Após a instalação, um arquivo txt será criado na mesma pasta onde executou o script e nele terá um comando que será executado no servidor directadmin que vai instalar o spfbl e configurar o exim para enviar as respostas para esse servidor onde foi feito a instalação do script inicial.

### Características Principais da Instalação

- ✅ Download e instalação automática do SPFBL em `/opt/spfbl`
- ✅ Configuração do Exim como "internet site" em localhost
- ✅ Abertura automática de portas no UFW/CSF: 9877 (policy), 8001 (painel antigo), 8002 (nova dashboard)
- ✅ Criação de usuário admin padrão com autenticação TOTP
- ✅ Ajuste automático de memória da JVM baseado na RAM disponível
- ✅ Integração nativa com DirectAdmin (quando aplicável)

OBS: Após ajustes não consegui mais fazer a instalação em servidores com menos de 3GB de memória ram.

**Projeto Original:** [SPFBL - GitHub](https://github.com/leonamp/SPFBL)

Para usar o painel de controle, é necessário ter MTA cliente e usuário devidamente cadastrados:

Os usuários podem ser cadastrados via painel.

Feito isso, o painel de controle pode ser acessado pela URL:

http://hostname:8002/login

Na primeira vez que o usuário entrar nesta URL, digitar o email e clicar no campo senha, o SPFBL iniciará um processo de cadastro TOTP, enviando um e-mail para o usuário com o QRcode contendo o segredo TOPT dele.

Para acessar corretamente o QRcode, é necessário baixar o aplicativo Google Authenticator, em seu celular, e ler o mesmo QRcode com este aplicativo.

O aplicativo irá gerar uma senha TOPT a cada minuto para que o usuário possa entrar com segurança na plataforma.

---

## 🎯 Recursos da Nova Dashboard

### Interface e UX
- 🌓 Tema claro/escuro com persistência de preferência
- 📱 Layout totalmente responsivo
- ⚡ Performance otimizada com SPA (Single Page Application)

### Funcionalidades Principais

**Dashboard**
- Visualização em tempo real de métricas: consultas totais, taxa de bloqueio, clientes ativos
- Monitoramento de recursos: consumo de memória JVM, uptime do servidor
- Indicadores visuais de saúde do sistema

**Gerenciamento de Consultas**
- Filtros avançados por resultado, IP de origem, remetente
- Ações rápidas: bloquear IP/remetente, adicionar à whitelist
- Histórico completo de requisições

**Gerenciamento de Servidores**
- Adicionar/remover clientes SPFBL via interface
- Suporte direto a servidores DirectAdmin/Exim
- Rótulos customizáveis e contato automático por e-mail

**Gestão de Usuários**
- Criar e remover contas SPFBL
- Reenvio de credenciais TOTP
- Controle de acesso baseado em perfis

**Listas de Controle**
- Gerenciamento de blacklist/whitelist com ações inline
- Importação/exportação de listas
- Histórico de alterações

**Logs e Auditoria**
- Painel de atividade (tentativas de envio de e-mail)
- Logs de usuários e administradores
- Rastreamento completo de alterações

**Configurações**
- Editor visual completo do arquivo `spfbl.conf`
- Backup automático antes de alterações
- Página de configurações independente da SPA para maior segurança

---

## 🔧 Integração com DirectAdmin

A instalação inclui suporte especial para servidores DirectAdmin:

- **Clientes Automáticos:** A lista de servidores autorizados (`AUTHORIZED_SERVERS` ou `AUTHORIZED_SERVERS_SIMPLE`) é aplicada como clientes SPFBL com rótulos automáticos
- **Notificações:** Suporte opcional para enviar notificações via e-mail (`DIRECTADMIN_CLIENT_EMAIL`)

### Reversão da Integração

Para remover a integração do DirectAdmin, execute:

```bash
# Fechar porta 9877 no UFW ou CSF
ufw delete allow 9877  # ou correspondente no CSF

# Remover ACL do Exim e recompilar
rm /etc/exim.acl_check_recipient.pre.conf

cd /usr/local/directadmin/custombuild
./build rewrite_confs
./build exim_conf
systemctl restart exim
```

---

## 📝 Changelog

### v0.01 - Versão Alpha

**Novo**
- ✨ Dashboard moderna com tema claro/escuro
- ✨ Instalador automatizado para Ubuntu 22.04
- ✨ Interface completa para gerenciamento de clientes SPFBL
- ✨ Sistema de consultas com filtros avançados
- ✨ Gerenciamento de listas de controle (blacklist/whitelist)
- ✨ Painel de logs com rastreamento de atividades
- ✨ Editor de configuração com backup automático
- ✨ Autenticação com TOTP (Time-based One-Time Password)
- ✨ Suporte integrado para DirectAdmin

**Melhorias**
- 🚀 Otimização automática de memória JVM
- 🚀 Configuração simplificada do Exim
- 🚀 Interface responsiva em dispositivos móveis

**Correções**
- 🐛 Tratamento robusto de erros de instalação
- 🐛 Validação de portas e permissões de firewall

---

## 🎯 Objetivo do Projeto

Fornecer uma solução **pronta para produção** de SPFBL para servidores Ubuntu 22.04, com ênfase especial em integração com **DirectAdmin**. A nova dashboard moderniza significativamente a experiência de administração comparada ao painel clássico, oferecendo:

- 🔐 Administração segura com autenticação TOTP
- 📊 Observabilidade completa do sistema
- ⚙️ Configuração centralizada e intuitiva
- 🚀 Performance otimizada em qualquer hardware

---

## 📄 Licença

Este projeto mantém a licença e conformidade com o projeto original do SPFBL. 
