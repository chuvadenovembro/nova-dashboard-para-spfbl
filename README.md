# Instalador SPFBL com Nova Dashboard + Integração com o DirectAdmin

<img width="1405" height="943" alt="scrnli_35d47X6ZINCtCo" src="https://github.com/user-attachments/assets/8da57a1e-37cc-4f31-ab38-38c54d0db7aa" />

<img width="1405" height="943" alt="scrnli_cAH95e0P9mI71P" src="https://github.com/user-attachments/assets/65666fd6-f4d1-4e50-bd61-7cb5fc9824ef" />



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

## 📄 Licença

Este projeto mantém a licença e conformidade com o projeto original do SPFBL. 
