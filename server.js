'use strict';
require('dotenv').config();

const express    = require('express');
const session    = require('express-session');
const bcrypt     = require('bcryptjs');
const mysql      = require('mysql2/promise');
const path       = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Database ──────────────────────────────────────────────────────────────────
const dbUrl  = new URL(process.env.DB_URL);
const pool   = mysql.createPool({
  host             : dbUrl.hostname,
  port             : parseInt(dbUrl.port) || 3306,
  user             : dbUrl.username,
  password         : dbUrl.password,
  database         : dbUrl.pathname.slice(1),
  waitForConnections: true,
  connectionLimit  : 10,
  queueLimit       : 0,
  timezone         : '-03:00'
});

async function initDB() {
  const conn = await pool.getConnection();
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS users (
        password_hash VARCHAR(255) NOT NULL PRIMARY KEY,
        created_at    TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS lancamentos (
        id               INT AUTO_INCREMENT PRIMARY KEY,
        UserPasswordHash VARCHAR(255)       NOT NULL,
        Tipo             ENUM('Debitar','Creditar') NOT NULL,
        MesLancamento    INT                NOT NULL,
        InicioPagamento  VARCHAR(10)        DEFAULT NULL,
        Parcelas         INT                DEFAULT 1,
        Cartao_ou_Conta  VARCHAR(100)       DEFAULT NULL,
        Grupo            VARCHAR(100)       DEFAULT NULL,
        Observacao       TEXT               DEFAULT NULL,
        ValorParcela     DECIMAL(15,2)      DEFAULT NULL,
        Valor            DECIMAL(15,2)      DEFAULT NULL,
        created_at       TIMESTAMP          DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (UserPasswordHash),
        INDEX idx_mes  (MesLancamento),
        FOREIGN KEY (UserPasswordHash) REFERENCES users(password_hash) ON UPDATE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    console.log('✔ Banco de dados inicializado');
  } finally {
    conn.release();
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
// MesLancamento = mês * 10000 + ano  (ex: abril/2026 = 42026)
function buildMesLancamento(mes, ano) {
  return parseInt(mes) * 10000 + parseInt(ano);
}

function parseMesLancamento(val) {
  const year  = val % 10000;
  const month = Math.floor(val / 10000);
  return { month, year };
}

function formatMesLabel(val) {
  const { month, year } = parseMesLancamento(val);
  return `${String(month).padStart(2, '0')}/${year}`;
}

// Converte input[type=date] YYYY-MM-DD  →  DD/MM/YYYY
function htmlDateToBR(d) {
  if (!d) return null;
  const [y, m, dd] = d.split('-');
  return `${dd}/${m}/${y}`;
}

// Converte DD/MM/YYYY  →  YYYY-MM-DD  para preencher input[type=date]
function brDateToHtml(d) {
  if (!d) return '';
  const parts = d.split('/');
  if (parts.length !== 3) return '';
  const [dd, mm, yyyy] = parts;
  return `${yyyy}-${mm}-${dd}`;
}

function formatBRL(value) {
  return Number(value || 0).toLocaleString('pt-BR', {
    style   : 'currency',
    currency: 'BRL'
  });
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret           : process.env.SESSION_SECRET,
  resave           : false,
  saveUninitialized: false,
  cookie           : {
    httpOnly: true,
    // secure: true  ← descomente se usar HTTPS
    maxAge  : 24 * 60 * 60 * 1000
  }
}));

// Disponibiliza helpers nas views
app.use((req, res, next) => {
  res.locals.formatBRL      = formatBRL;
  res.locals.formatMesLabel = formatMesLabel;
  res.locals.brDateToHtml   = brDateToHtml;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.userHash) return res.redirect('/login');
  next();
}

// ── Rotas: Auth ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.redirect(req.session.userHash ? '/dashboard' : '/login');
});

app.get('/login', (req, res) => {
  if (req.session.userHash) return res.redirect('/dashboard');
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { password } = req.body;
  if (!password || password.length > 72) {
    return res.render('login', { error: 'Senha inválida.' });
  }
  try {
    const [users] = await pool.query('SELECT password_hash FROM users');
    if (users.length === 0) return res.redirect('/register');

    let userHash = null;
    for (const u of users) {
      if (await bcrypt.compare(password, u.password_hash)) {
        userHash = u.password_hash;
        break;
      }
    }
    if (!userHash) {
      return res.render('login', { error: 'Senha incorreta.' });
    }
    req.session.userHash = userHash;
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('login', { error: 'Erro interno. Tente novamente.' });
  }
});

app.get('/register', async (req, res) => {
  try {
    const [[{ count }]] = await pool.query('SELECT COUNT(*) AS count FROM users');
    if (count > 0) return res.redirect('/login');
    res.render('register', { error: null });
  } catch (err) {
    console.error(err);
    res.redirect('/login');
  }
});

app.post('/register', async (req, res) => {
  try {
    const [[{ count }]] = await pool.query('SELECT COUNT(*) AS count FROM users');
    if (count > 0) return res.redirect('/login');

    const { password, confirmPassword } = req.body;
    if (!password || password.length < 6) {
      return res.render('register', { error: 'A senha deve ter pelo menos 6 caracteres.' });
    }
    if (password.length > 72) {
      return res.render('register', { error: 'Senha muito longa (máx. 72 caracteres).' });
    }
    if (password !== confirmPassword) {
      return res.render('register', { error: 'As senhas não coincidem.' });
    }

    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (password_hash) VALUES (?)', [hash]);
    req.session.userHash = hash;
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.render('register', { error: 'Erro ao criar usuário.' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ── Rotas: Dashboard ──────────────────────────────────────────────────────────
app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const userHash = req.session.userHash;
    const now      = new Date();

    let filterMes = req.query.mes ? parseInt(req.query.mes) : null;
    let filterAno = req.query.ano ? parseInt(req.query.ano) : null;

    // Se nenhum filtro, usa o mês atual
    if (!filterMes) filterMes = now.getMonth() + 1;
    if (!filterAno) filterAno = now.getFullYear();

    const mesLancamentoFilter = buildMesLancamento(filterMes, filterAno);

    // Transações do mês filtrado
    const [lancamentos] = await pool.query(
      `SELECT * FROM lancamentos
       WHERE UserPasswordHash = ? AND MesLancamento = ?
       ORDER BY created_at DESC`,
      [userHash, mesLancamentoFilter]
    );

    // Meses disponíveis para o filtro (todos os meses que têm lançamentos)
    const [meses] = await pool.query(
      `SELECT DISTINCT MesLancamento FROM lancamentos
       WHERE UserPasswordHash = ?
       ORDER BY MesLancamento DESC`,
      [userHash]
    );

    // Garantir que o mês atual sempre apareça no select
    const mesAtualVal = buildMesLancamento(now.getMonth() + 1, now.getFullYear());
    if (!meses.find(m => m.MesLancamento === mesAtualVal)) {
      meses.unshift({ MesLancamento: mesAtualVal });
    }

    // Totais
    let totalCreditos = 0;
    let totalDebitos  = 0;
    lancamentos.forEach(l => {
      const v = parseFloat(l.Valor) || 0;
      if (l.Tipo === 'Creditar') totalCreditos += v;
      else                       totalDebitos  += v;
    });
    const saldo = totalCreditos - totalDebitos;

    // Resumo por grupo
    const [grupos] = await pool.query(
      `SELECT Grupo, Tipo, SUM(Valor) AS total
       FROM lancamentos
       WHERE UserPasswordHash = ? AND MesLancamento = ?
       GROUP BY Grupo, Tipo
       ORDER BY total DESC`,
      [userHash, mesLancamentoFilter]
    );

    res.render('dashboard', {
      lancamentos,
      totalCreditos,
      totalDebitos,
      saldo,
      meses,
      grupos,
      filterMes,
      filterAno,
      parseMesLancamento
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Erro interno do servidor.');
  }
});

// ── Rotas: Lançamentos ────────────────────────────────────────────────────────
app.get('/lancamentos/novo', requireAuth, (req, res) => {
  const now = new Date();
  res.render('add-lancamento', {
    error      : null,
    currentMes : now.getMonth() + 1,
    currentYear: now.getFullYear()
  });
});

app.post('/lancamentos', requireAuth, async (req, res) => {
  const now = new Date();
  try {
    const {
      Tipo, mes, ano, InicioPagamento,
      Parcelas, Cartao_ou_Conta, Grupo,
      Observacao, ValorParcela, Valor
    } = req.body;

    if (!Tipo || !mes || !ano || !Valor) {
      return res.render('add-lancamento', {
        error      : 'Preencha os campos obrigatórios (Tipo, Mês, Ano, Valor).',
        currentMes : now.getMonth() + 1,
        currentYear: now.getFullYear()
      });
    }

    await pool.query(
      `INSERT INTO lancamentos
         (UserPasswordHash, Tipo, MesLancamento, InicioPagamento,
          Parcelas, Cartao_ou_Conta, Grupo, Observacao, ValorParcela, Valor)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.session.userHash,
        Tipo,
        buildMesLancamento(mes, ano),
        htmlDateToBR(InicioPagamento) || null,
        parseInt(Parcelas) || 1,
        Cartao_ou_Conta || null,
        Grupo           || null,
        Observacao      || null,
        parseFloat(ValorParcela) || null,
        parseFloat(Valor)
      ]
    );

    // Volta para o mês do lançamento criado
    res.redirect(`/dashboard?mes=${mes}&ano=${ano}`);
  } catch (err) {
    console.error(err);
    res.render('add-lancamento', {
      error      : 'Erro ao salvar lançamento.',
      currentMes : now.getMonth() + 1,
      currentYear: now.getFullYear()
    });
  }
});

app.get('/lancamentos/:id/editar', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM lancamentos WHERE id = ? AND UserPasswordHash = ?',
      [req.params.id, req.session.userHash]
    );
    if (rows.length === 0) return res.redirect('/dashboard');

    const l          = rows[0];
    const { month, year } = parseMesLancamento(l.MesLancamento);
    res.render('edit-lancamento', {
      lancamento: l,
      mes   : month,
      ano   : year,
      error : null
    });
  } catch (err) {
    console.error(err);
    res.redirect('/dashboard');
  }
});

app.post('/lancamentos/:id/editar', requireAuth, async (req, res) => {
  try {
    const {
      Tipo, mes, ano, InicioPagamento,
      Parcelas, Cartao_ou_Conta, Grupo,
      Observacao, ValorParcela, Valor
    } = req.body;

    await pool.query(
      `UPDATE lancamentos
       SET Tipo=?, MesLancamento=?, InicioPagamento=?, Parcelas=?,
           Cartao_ou_Conta=?, Grupo=?, Observacao=?, ValorParcela=?, Valor=?
       WHERE id=? AND UserPasswordHash=?`,
      [
        Tipo,
        buildMesLancamento(mes, ano),
        htmlDateToBR(InicioPagamento) || null,
        parseInt(Parcelas) || 1,
        Cartao_ou_Conta || null,
        Grupo           || null,
        Observacao      || null,
        parseFloat(ValorParcela) || null,
        parseFloat(Valor)        || null,
        req.params.id,
        req.session.userHash
      ]
    );
    res.redirect(`/dashboard?mes=${mes}&ano=${ano}`);
  } catch (err) {
    console.error(err);
    res.redirect('/dashboard');
  }
});

app.post('/lancamentos/:id/deletar', requireAuth, async (req, res) => {
  try {
    // Busca o mês antes de deletar para redirecionar corretamente
    const [rows] = await pool.query(
      'SELECT MesLancamento FROM lancamentos WHERE id = ? AND UserPasswordHash = ?',
      [req.params.id, req.session.userHash]
    );
    if (rows.length > 0) {
      const { month, year } = parseMesLancamento(rows[0].MesLancamento);
      await pool.query(
        'DELETE FROM lancamentos WHERE id = ? AND UserPasswordHash = ?',
        [req.params.id, req.session.userHash]
      );
      return res.redirect(`/dashboard?mes=${month}&ano=${year}`);
    }
    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.redirect('/dashboard');
  }
});

// ── Rotas: Configurações ──────────────────────────────────────────────────────
app.get('/configuracoes', requireAuth, (req, res) => {
  res.render('configuracoes', { error: null, success: null });
});

app.post('/configuracoes/senha', requireAuth, async (req, res) => {
  const { senhaAtual, novaSenha, confirmarSenha } = req.body;
  const userHash = req.session.userHash;

  if (!senhaAtual || !novaSenha || !confirmarSenha) {
    return res.render('configuracoes', { error: 'Preencha todos os campos.', success: null });
  }
  if (novaSenha.length < 6) {
    return res.render('configuracoes', { error: 'A nova senha deve ter pelo menos 6 caracteres.', success: null });
  }
  if (novaSenha.length > 72) {
    return res.render('configuracoes', { error: 'Senha muito longa (máx. 72 caracteres).', success: null });
  }
  if (novaSenha !== confirmarSenha) {
    return res.render('configuracoes', { error: 'As novas senhas não coincidem.', success: null });
  }

  try {
    const match = await bcrypt.compare(senhaAtual, userHash);
    if (!match) {
      return res.render('configuracoes', { error: 'Senha atual incorreta.', success: null });
    }

    const novoHash = await bcrypt.hash(novaSenha, 10);
    // UPDATE CASCADE no FK garante que os lançamentos também são atualizados
    await pool.query('UPDATE users SET password_hash = ? WHERE password_hash = ?', [novoHash, userHash]);
    req.session.userHash = novoHash;
    res.render('configuracoes', { error: null, success: 'Senha alterada com sucesso!' });
  } catch (err) {
    console.error(err);
    res.render('configuracoes', { error: 'Erro ao alterar senha.', success: null });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────
initDB()
  .then(() => {
    app.listen(PORT, () => console.log(`🚀 Servidor rodando em http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('Erro ao conectar ao banco:', err.message);
    process.exit(1);
  });
