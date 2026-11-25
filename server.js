'use strict';
/*
 * Relatório de Manutenção — CD Embalagens
 * Servidor Node.js (Express + SQLite)
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');

// ---------------------------------------------------------------- Configuração
const PORTA = Number(process.env.PORTA || 3000);
const PASTA_DADOS = process.env.PASTA_DADOS || path.join(__dirname, 'data');
const ADMIN_USUARIO = process.env.ADMIN_USUARIO || 'pcm';
const ADMIN_SENHA_HASH = process.env.ADMIN_SENHA_HASH || '';
const COOKIE_SEGURO = String(process.env.COOKIE_SEGURO || 'false') === 'true';
const ATRAS_DE_PROXY = String(process.env.ATRAS_DE_PROXY || 'false') === 'true';
const SESSAO_HORAS = Number(process.env.SESSAO_HORAS || 8);

if (!ADMIN_SENHA_HASH) {
  console.warn('[aviso] ADMIN_SENHA_HASH não definido: o painel administrativo ficará bloqueado.');
  console.warn('        Gere com:  npm run gerar-senha');
}

const CONFIG_FORM = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'config', 'formulario.json'), 'utf8')
);

// ---------------------------------------------------------------- Banco de dados
fs.mkdirSync(PASTA_DADOS, { recursive: true });
const db = new Database(path.join(PASTA_DADOS, 'relatorios.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS respostas (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    criado_em        TEXT    NOT NULL,
    os_numero        TEXT,
    responsavel      TEXT    NOT NULL,
    solicitante      TEXT,
    data_atendimento TEXT    NOT NULL,
    horimetro        TEXT    NOT NULL,
    tipo_atividade   TEXT    NOT NULL,
    atualizado_em    TEXT,
    atualizado_por   TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_data ON respostas(data_atendimento);
`);

const sqlInserir = db.prepare(`
  INSERT INTO respostas (criado_em, responsavel, solicitante, data_atendimento,
                         horimetro, tipo_atividade)
  VALUES (@criado_em, @responsavel, @solicitante, @data_atendimento,
          @horimetro, @tipo_atividade)
`);
const sqlAtualizarOS = db.prepare(`
  UPDATE respostas SET os_numero = ?, atualizado_em = ?, atualizado_por = ? WHERE id = ?
`);

// ---------------------------------------------------------------- Validação
function texto(v, max) {
  if (v === undefined || v === null) return '';
  return String(v).replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, max);
}

function validarResposta(corpo) {
  const erros = [];
  const r = {
    responsavel: texto(corpo.responsavel, 80),
    solicitante: texto(corpo.solicitante, 80),
    data_atendimento: texto(corpo.data_atendimento, 10),
    horimetro: texto(corpo.horimetro, 20),
    tipo_atividade: texto(corpo.tipo_atividade, 80)
  };

  if (!r.responsavel) erros.push('Informe o responsável pelo atendimento.');
  if (!r.tipo_atividade) erros.push('Informe o tipo da atividade.');

  if (!/^\d{4}-\d{2}-\d{2}$/.test(r.data_atendimento)) {
    erros.push('Informe uma data de atendimento válida.');
  } else {
    const d = new Date(r.data_atendimento + 'T12:00:00Z');
    const amanha = new Date(Date.now() + 36 * 3600 * 1000);
    if (isNaN(d) || d.toISOString().slice(0, 10) !== r.data_atendimento) {
      erros.push('Informe uma data de atendimento válida.');
    } else if (d > amanha) {
      erros.push('A data do atendimento não pode ser futura.');
    } else if (d < new Date('2000-01-01T00:00:00Z')) {
      erros.push('Informe uma data de atendimento válida.');
    }
  }

  if (!r.horimetro) {
    erros.push('Informe o horímetro ou marque "Não se aplica".');
  } else if (r.horimetro.toLowerCase() === 'n/a') {
    r.horimetro = 'n/a';
  } else if (!/^[0-9][0-9.,\s]{0,19}$/.test(r.horimetro)) {
    erros.push('O horímetro deve conter apenas números.');
  }

  return { erros, r };
}

// ---------------------------------------------------------------- Senhas e sessões
function verificarSenha(senha, hashArmazenado) {
  // formato: scrypt$<salt-hex>$<hash-hex>
  const partes = String(hashArmazenado).split('$');
  if (partes.length !== 3 || partes[0] !== 'scrypt') return false;
  const salt = Buffer.from(partes[1], 'hex');
  const esperado = Buffer.from(partes[2], 'hex');
  const calculado = crypto.scryptSync(String(senha), salt, esperado.length);
  return crypto.timingSafeEqual(calculado, esperado);
}

function compararSeguro(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

const sessoes = new Map(); // token -> { usuario, expira }
const NOME_COOKIE = 'rm_sessao';

function lerCookie(req, nome) {
  const bruto = req.headers.cookie || '';
  for (const parte of bruto.split(';')) {
    const [k, ...v] = parte.trim().split('=');
    if (k === nome) return decodeURIComponent(v.join('='));
  }
  return null;
}

function definirCookie(res, valor, maxAgeSeg) {
  const atributos = [
    `${NOME_COOKIE}=${encodeURIComponent(valor)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSeg}`
  ];
  if (COOKIE_SEGURO) atributos.push('Secure');
  res.setHeader('Set-Cookie', atributos.join('; '));
}

function exigirLogin(req, res, next) {
  const token = lerCookie(req, NOME_COOKIE);
  const s = token && sessoes.get(token);
  if (!s || s.expira < Date.now()) {
    if (token) sessoes.delete(token);
    return res.status(401).json({ erro: 'Sessão expirada. Entre novamente.' });
  }
  req.usuario = s.usuario;
  next();
}

setInterval(() => {
  const agora = Date.now();
  for (const [t, s] of sessoes) if (s.expira < agora) sessoes.delete(t);
}, 15 * 60 * 1000).unref();

// ---------------------------------------------------------------- Aplicação
const app = express();
app.disable('x-powered-by');
if (ATRAS_DE_PROXY) app.set('trust proxy', 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'form-action': ["'self'"],
        'frame-ancestors': ["'self'"]
      }
    },
    strictTransportSecurity: COOKIE_SEGURO
  })
);
app.use(express.json({ limit: '20kb' }));

// Exige JSON nas chamadas que alteram dados (bloqueia envios de outros sites)
app.use('/api', (req, res, next) => {
  if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method) && !req.is('application/json')) {
    return res.status(415).json({ erro: 'Formato não suportado.' });
  }
  next();
});

const limiteEnvio = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { erro: 'Muitos envios em pouco tempo. Tente novamente em alguns minutos.' }
});
const limiteLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { erro: 'Muitas tentativas de acesso. Aguarde 15 minutos.' }
});

// ---- Público
app.get('/api/config', (req, res) => res.json(CONFIG_FORM));

app.post('/api/respostas', limiteEnvio, (req, res) => {
  const corpo = req.body || {};

  // Armadilha anti-robô: campo invisível que pessoas não preenchem,
  // e tempo mínimo de preenchimento.
  const inicio = Number(corpo._inicio || 0);
  if (texto(corpo.website, 200) || !inicio || Date.now() - inicio < 3000) {
    return res.status(201).json({ ok: true }); // resposta neutra; nada é gravado
  }

  const { erros, r } = validarResposta(corpo);
  if (erros.length) return res.status(400).json({ erro: erros.join(' '), erros });

  const info = sqlInserir.run({ ...r, criado_em: new Date().toISOString() });
  res.status(201).json({ ok: true, protocolo: info.lastInsertRowid });
});

// ---- Administração
app.post('/api/admin/login', limiteLogin, (req, res) => {
  const { usuario, senha } = req.body || {};
  const usuarioOk = compararSeguro(usuario || '', ADMIN_USUARIO);
  const senhaOk = ADMIN_SENHA_HASH ? verificarSenha(senha || '', ADMIN_SENHA_HASH) : false;
  if (!usuarioOk || !senhaOk) {
    return res.status(401).json({ erro: 'Usuário ou senha inválidos.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessoes.set(token, { usuario: ADMIN_USUARIO, expira: Date.now() + SESSAO_HORAS * 3600 * 1000 });
  definirCookie(res, token, SESSAO_HORAS * 3600);
  res.json({ ok: true, usuario: ADMIN_USUARIO });
});

app.post('/api/admin/logout', (req, res) => {
  const token = lerCookie(req, NOME_COOKIE);
  if (token) sessoes.delete(token);
  definirCookie(res, '', 0);
  res.json({ ok: true });
});

app.get('/api/admin/sessao', exigirLogin, (req, res) => res.json({ usuario: req.usuario }));

function montarFiltro(q) {
  const cond = [];
  const p = {};
  if (/^\d{4}-\d{2}-\d{2}$/.test(q.de || '')) { cond.push('data_atendimento >= @de'); p.de = q.de; }
  if (/^\d{4}-\d{2}-\d{2}$/.test(q.ate || '')) { cond.push('data_atendimento <= @ate'); p.ate = q.ate; }
  if (q.responsavel) { cond.push('responsavel = @responsavel'); p.responsavel = texto(q.responsavel, 80); }
  if (q.tipo) { cond.push('tipo_atividade = @tipo'); p.tipo = texto(q.tipo, 80); }
  if (q.os === 'pendente') cond.push("(os_numero IS NULL OR os_numero = '')");
  if (q.busca) {
    cond.push('(os_numero LIKE @busca OR responsavel LIKE @busca OR solicitante LIKE @busca OR tipo_atividade LIKE @busca)');
    p.busca = `%${texto(q.busca, 80)}%`;
  }
  return { where: cond.length ? 'WHERE ' + cond.join(' AND ') : '', params: p };
}

app.get('/api/admin/respostas', exigirLogin, (req, res) => {
  const { where, params } = montarFiltro(req.query);
  const linhas = db
    .prepare(`SELECT * FROM respostas ${where} ORDER BY data_atendimento DESC, id DESC LIMIT 5000`)
    .all(params);
  const pendentes = db
    .prepare("SELECT COUNT(*) n FROM respostas WHERE os_numero IS NULL OR os_numero = ''")
    .get().n;
  const total = db.prepare('SELECT COUNT(*) n FROM respostas').get().n;
  res.json({ linhas, total, pendentes });
});

app.patch('/api/admin/respostas/:id', exigirLogin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ erro: 'Registro inválido.' });
  const os = texto((req.body || {}).os_numero, 30);
  if (os && !/^[A-Za-z0-9./\-\s]{1,30}$/.test(os)) {
    return res.status(400).json({ erro: 'Nº da O.S. com caracteres inválidos.' });
  }
  const info = sqlAtualizarOS.run(os || null, new Date().toISOString(), req.usuario, id);
  if (!info.changes) return res.status(404).json({ erro: 'Registro não encontrado.' });
  res.json({ ok: true });
});

app.get('/api/admin/exportar.csv', exigirLogin, (req, res) => {
  const { where, params } = montarFiltro(req.query);
  const linhas = db
    .prepare(`SELECT * FROM respostas ${where} ORDER BY data_atendimento DESC, id DESC`)
    .all(params);

  // CSV no padrão do Excel em português: separador ";" e BOM UTF-8.
  const celula = (v) => {
    let s = v === null || v === undefined ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // evita injeção de fórmulas no Excel
    return '"' + s.replace(/"/g, '""') + '"';
  };
  const dataBR = (iso) => (iso && iso.length >= 10 ? iso.slice(8, 10) + '/' + iso.slice(5, 7) + '/' + iso.slice(0, 4) : '');
  const cab = ['Protocolo', 'Recebido em', 'Nº da O.S.', 'Responsável pelo atendimento', 'Solicitante',
    'Data do atendimento', 'Horímetro', 'Tipo da Atividade'];
  const corpo = linhas.map((l) => [
    l.id,
    new Date(l.criado_em).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
    l.os_numero, l.responsavel, l.solicitante, dataBR(l.data_atendimento),
    l.horimetro, l.tipo_atividade
  ].map(celula).join(';'));

  const nome = `relatorio-manutencao-${new Date().toISOString().slice(0, 10)}.csv`;
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${nome}"`);
  res.send('\uFEFF' + [cab.map(celula).join(';'), ...corpo].join('\r\n'));
});

// ---- Arquivos estáticos
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'], maxAge: '1h' }));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));

app.use((req, res) => res.status(404).send('Página não encontrada.'));
app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === 'entity.parse.failed') return res.status(400).json({ erro: 'Dados inválidos.' });
  res.status(500).json({ erro: 'Erro interno. Tente novamente.' });
});

if (require.main === module) {
  app.listen(PORTA, () => console.log(`Relatório de Manutenção em execução na porta ${PORTA}`));
}
module.exports = { app, db };
