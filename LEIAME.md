# Relatório de Manutenção 2027 — CD Embalagens

Sistema web próprio para registrar relatórios de manutenção. Substitui o Microsoft Forms com:

- **Formulário público** (`/`), com a identidade visual da CD Embalagens. Funciona no celular e no computador. Tem as mesmas perguntas do Forms "Relatório de Manutenção 2027".
- **Painel do PCM** (`/admin`), com login. Permite consultar e filtrar os relatórios, preencher o **Nº da O.S.** e exportar para o Excel.
- **Banco de dados SQLite**: um único arquivo (`data/relatorios.db`), sem instalar um servidor de banco.

## 1. Requisitos

- **Node.js 22 LTS** ou mais recente (https://nodejs.org)
- Windows Server ou Linux, com cerca de 200 MB livres

## 2. Instalação

```bash
# na pasta do sistema
npm install --omit=dev
cp .env.exemplo .env          # no Windows: copy .env.exemplo .env
npm run gerar-senha           # digite a senha do PCM e copie a linha gerada para o .env
npm start
```

Depois disso, o sistema fica disponível em `http://localhost:3000`. O painel fica em `http://localhost:3000/admin`.

Para conferir se a instalação está correta, rode `npm install` (com as dependências de desenvolvimento) e depois `npm test`. São 9 testes automáticos.

## 3. Deixar o sistema sempre ligado

**Linux (systemd)**: crie o arquivo `/etc/systemd/system/relatorio-manutencao.service`:

```ini
[Unit]
Description=Relatório de Manutenção CD
After=network.target

[Service]
WorkingDirectory=/opt/relatorio-manutencao
ExecStart=/usr/bin/node --env-file=.env server.js
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

Em seguida, ative o serviço com `sudo systemctl enable --now relatorio-manutencao`.

**Windows Server**: instale como serviço com o NSSM (https://nssm.cc):
`nssm install RelatorioManutencao "C:\Program Files\nodejs\node.exe" "--env-file=.env server.js"`
Em seguida, defina a pasta de inicialização ("Startup directory") como a pasta do sistema.

**Docker (opcional)**:
`docker build -t relatorio-manutencao .`
`docker run -d --env-file .env -p 3000:3000 -v rm-dados:/app/data relatorio-manutencao`

## 4. Publicar para pessoas de fora da empresa

Escolha **uma** das opções abaixo.

**A) Cloudflare Tunnel (recomendado: não abre portas no firewall)**
1. Instale o `cloudflared` na máquina virtual.
2. Crie um túnel apontando para `http://localhost:3000`, com um endereço como `manutencao.cdembalagens.com.br`.
3. No `.env`, ajuste `COOKIE_SEGURO=true` e `ATRAS_DE_PROXY=true`.

**B) IIS ou Nginx como proxy reverso, com HTTPS**
1. Configure o proxy para encaminhar o endereço público para `http://localhost:3000`.
2. Instale um certificado HTTPS (o Let's Encrypt é gratuito; no Windows, use o win-acme).
3. No `.env`, ajuste `COOKIE_SEGURO=true` e `ATRAS_DE_PROXY=true`.
4. Libere no firewall apenas a porta 443. A porta 3000 **não** deve ficar exposta.

> Em produção, use sempre HTTPS. Sem HTTPS, a senha do painel trafega sem proteção.

## 5. Alterar nomes e opções

Os nomes dos responsáveis, os solicitantes e os tipos de atividade ficam em `config/formulario.json`. Edite o arquivo e reinicie o sistema. Não é preciso mexer no código.

## 6. Segurança incluída

| Proteção | Como funciona |
|---|---|
| Painel com login | A senha fica guardada como hash (scrypt), nunca em texto puro. A sessão expira em 8 horas |
| Tentativas de login | Limite de 10 tentativas a cada 15 minutos por IP |
| Spam e robôs | Campo-armadilha invisível, tempo mínimo de preenchimento e limite de 20 envios a cada 15 minutos por IP |
| Validação | Todos os campos são conferidos no servidor (obrigatórios, data não futura, horímetro numérico ou "n/a") |
| Cabeçalhos de segurança | Helmet com política de conteúdo restrita (CSP), proteção contra clickjacking e HSTS quando em HTTPS |
| Banco de dados | Consultas parametrizadas (sem injeção de SQL) |
| Exportação para o Excel | Neutraliza fórmulas maliciosas nas células |
| Dados pessoais (LGPD) | Não grava IP nem dados de navegação de quem preenche |

## 7. Backup

Todos os dados ficam em `data/relatorios.db`. Inclua essa pasta na rotina de backup da TI, com cópia diária.

## 8. Estrutura

```
server.js               servidor (API, segurança, banco)
config/formulario.json  opções do formulário
public/index.html       formulário público
public/formulario.js    validação e envio
public/admin/           painel do PCM
public/estilo.css       identidade visual CD Embalagens
scripts/gerar-senha.js  gera o hash da senha do painel
teste/                  testes automáticos
```
