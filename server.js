const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── SECURITY: Rate Limiting ──────────────────────────────────
const rateLimitMap = new Map();
const RATE_LIMIT = 100; // max requests per minute
const RATE_WINDOW = 60000;

function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = rateLimitMap.get(ip);
  if (!entry || now - entry.start > RATE_WINDOW) {
    rateLimitMap.set(ip, { start: now, count: 1 });
    return next();
  }
  entry.count++;
  if (entry.count > RATE_LIMIT) {
    return res.status(429).json({ error: 'Rate limit excedido. Tente novamente em 1 minuto.' });
  }
  next();
}

// Clean up rate limit map every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now - entry.start > RATE_WINDOW * 2) rateLimitMap.delete(ip);
  }
}, 300000);

// ─── SECURITY: Sanitize HTML ──────────────────────────────────
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>]/g, '').replace(/javascript:/gi, '').replace(/on\w+=/gi, '').trim();
}

function sanitizeObj(obj) {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeObj);
  const result = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') result[k] = sanitize(v);
    else if (typeof v === 'object' && v !== null) result[k] = sanitizeObj(v);
    else result[k] = v;
  }
  return result;
}

// ─── JSON FILE DATABASE ───────────────────────────────────────
const DB_PATH = path.join(__dirname, 'data.json');
const BACKUP_PATH = path.join(__dirname, 'data.backup.json');

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      return JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
    }
  } catch (e) {
    console.error('[DB] Error loading:', e.message);
  }
  return { notas: [], nextId: 1 };
}

function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf-8');
}

function backupDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      fs.copyFileSync(DB_PATH, BACKUP_PATH);
      console.log('[DB] Backup criado:', BACKUP_PATH);
    }
  } catch (e) {
    console.error('[DB] Backup error:', e.message);
  }
}

let db = loadDB();

// ─── WEBHOOK ENDPOINT ─────────────────────────────────────────
app.post('/webhook/nfe', rateLimit, (req, res) => {
  try {
    const d = req.body;
    if (!d || typeof d !== 'object') {
      return res.status(400).json({ error: 'Payload invalido' });
    }

    const raw = d.webhookPayload || d;
    const p = sanitizeObj(raw);
    const chave = (p.chaveAcesso || '').trim();

    // Validate minimum required fields
    if (!p.fornecedor && !p.cnpj && !p.numero && !chave) {
      return res.status(400).json({ error: 'Payload incompleto: fornecedor, cnpj, numero ou chaveAcesso obrigatorio' });
    }

    // Dedup
    if (chave) {
      const existing = db.notas.find(n => n.chave_acesso === chave);
      if (existing) {
        return res.json({ status: 'duplicado', id: existing.id, message: 'NFe ja registrada' });
      }
    }

    const nota = {
      id: db.nextId++,
      fornecedor: p.fornecedor || 'Nao identificado',
      cnpj: p.cnpj || '',
      numero: p.numero || '',
      serie: p.serie || '',
      chave_acesso: chave || `auto_${Date.now()}`,
      data_emissao: p.data || '',
      natureza_operacao: p.naturezaOperacao || '',
      tipo_operacao: p.tipoOperacao || '',
      valor_total: parseFloat(p.valorRaw) || 0,
      valor_produtos: parseFloat(p.valorProdutos) || 0,
      valor_icms: parseFloat(p.valorICMS) || 0,
      valor_frete: parseFloat(p.valorFrete) || 0,
      valor_desconto: parseFloat(p.valorDesconto) || 0,
      destinatario: p.destinatario || '',
      destinatario_cnpj: p.destinatarioCnpj || '',
      email_remetente: p.email || '',
      assunto_email: p.assunto || '',
      data_recebimento: p.received || new Date().toLocaleString('pt-BR'),
      tem_xml: p.temXml ? 1 : 0,
      tem_pdf: p.temPdf ? 1 : 0,
      origem: p.origem || 'n8n',
      parse_success: p.parseSuccess ? 1 : 0,
      source: p.source || '',
      protocolo: p.protocolo || '',
      total_produtos: p.totalProdutos || 0,
      link_sefaz: p.linkSefaz || '',
      info_complementares: p.informacoesComplementares || '',
      produtos: sanitizeObj(p.produtos || []),
      created_at: new Date().toISOString()
    };

    db.notas.push(nota);
    saveDB(db);

    console.log(`[NFe] #${nota.numero} ${nota.fornecedor} (ID:${nota.id}) | Total: ${db.notas.length}`);
    res.json({ status: 'ok', id: nota.id, message: 'NFe registrada com sucesso' });
  } catch (err) {
    console.error('[WEBHOOK ERROR]', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── API: LIST NOTAS (with month filter) ──────────────────────
app.get('/api/notas', (req, res) => {
  const { page = 1, limit = 50, search = '', ordem = 'desc', mes = '', tipo = '' } = req.query;
  const pg = parseInt(page);
  const lim = parseInt(limit);

  let filtered = [...db.notas];

  // Month filter (YYYY-MM)
  if (mes) {
    filtered = filtered.filter(n => (n.created_at || '').startsWith(mes));
  }

  // Type filter
  if (tipo) {
    filtered = filtered.filter(n => n.tipo_operacao === tipo);
  }

  // Search
  if (search) {
    const s = search.toLowerCase();
    filtered = filtered.filter(n =>
      (n.fornecedor || '').toLowerCase().includes(s) ||
      (n.cnpj || '').toLowerCase().includes(s) ||
      (n.numero || '').toLowerCase().includes(s) ||
      (n.chave_acesso || '').toLowerCase().includes(s) ||
      (n.destinatario || '').toLowerCase().includes(s) ||
      (n.natureza_operacao || '').toLowerCase().includes(s)
    );
  }

  filtered.sort((a, b) => {
    const da = new Date(a.created_at).getTime();
    const db2 = new Date(b.created_at).getTime();
    return ordem === 'asc' ? da - db2 : db2 - da;
  });

  const total = filtered.length;
  const pages = Math.ceil(total / lim);
  const offset = (pg - 1) * lim;
  const notas = filtered.slice(offset, offset + lim);

  // Summary for the current filter
  const summary = {
    totalValor: filtered.reduce((s, n) => s + (n.valor_total || 0), 0),
    totalICMS: filtered.reduce((s, n) => s + (n.valor_icms || 0), 0),
    totalFrete: filtered.reduce((s, n) => s + (n.valor_frete || 0), 0),
    totalDesconto: filtered.reduce((s, n) => s + (n.valor_desconto || 0), 0),
    fornecedores: new Set(filtered.filter(n => n.cnpj).map(n => n.cnpj)).size
  };

  res.json({ notas, total, page: pg, pages, summary });
});

// ─── API: AVAILABLE MONTHS ────────────────────────────────────
app.get('/api/notas/meses', (req, res) => {
  const mesMap = {};
  db.notas.forEach(n => {
    const mes = (n.created_at || '').slice(0, 7);
    if (!mes) return;
    if (!mesMap[mes]) mesMap[mes] = { mes, total: 0, valor: 0, icms: 0, frete: 0, desconto: 0, fornecedores: new Set() };
    mesMap[mes].total++;
    mesMap[mes].valor += n.valor_total || 0;
    mesMap[mes].icms += n.valor_icms || 0;
    mesMap[mes].frete += n.valor_frete || 0;
    mesMap[mes].desconto += n.valor_desconto || 0;
    if (n.cnpj) mesMap[mes].fornecedores.add(n.cnpj);
  });

  const meses = Object.values(mesMap)
    .map(m => ({ ...m, fornecedores: m.fornecedores.size }))
    .sort((a, b) => b.mes.localeCompare(a.mes));

  res.json({ meses });
});

// ─── API: PURGE ALL (must be before :id routes) ──────────────
app.delete('/api/notas/purge-all', (req, res) => {
  const confirm = req.headers['x-confirm'];
  if (confirm !== 'PURGE') {
    return res.status(400).json({ error: 'Header X-Confirm: PURGE obrigatorio' });
  }

  backupDB();

  const count = db.notas.length;
  db.notas = [];
  db.nextId = 1;
  saveDB(db);

  console.log(`[PURGE] Todas as ${count} notas removidas`);
  res.json({ purged: count, message: 'Todas as notas foram removidas. Backup salvo.' });
});

// ─── API: BULK DELETE ─────────────────────────────────────────
app.post('/api/notas/bulk-delete', (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'Array de IDs obrigatorio' });
  }
  if (ids.length > 500) {
    return res.status(400).json({ error: 'Maximo 500 notas por operacao' });
  }

  backupDB();

  const idSet = new Set(ids.map(Number));
  const before = db.notas.length;
  db.notas = db.notas.filter(n => !idSet.has(n.id));
  const deleted = before - db.notas.length;
  saveDB(db);

  console.log(`[BULK DELETE] ${deleted} notas removidas`);
  res.json({ deleted, remaining: db.notas.length });
});

// ─── API: SINGLE NOTA ─────────────────────────────────────────
app.get('/api/notas/:id', (req, res) => {
  const nota = db.notas.find(n => n.id === parseInt(req.params.id));
  if (!nota) return res.status(404).json({ error: 'Nota nao encontrada' });
  res.json(nota);
});

// ─── API: DELETE SINGLE ───────────────────────────────────────
app.delete('/api/notas/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const idx = db.notas.findIndex(n => n.id === id);
  if (idx === -1) return res.json({ deleted: false });
  const removed = db.notas.splice(idx, 1)[0];
  saveDB(db);
  console.log(`[DELETE] Nota #${removed.numero} ID:${id} removida`);
  res.json({ deleted: true, nota: { id: removed.id, numero: removed.numero, fornecedor: removed.fornecedor } });
});

// ─── API: DASHBOARD STATS ─────────────────────────────────────
app.get('/api/dashboard', (req, res) => {
  const notas = db.notas;
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  const weekAgo = new Date(now.getTime() - 7 * 86400000).toISOString();

  const stats = {
    totalNotas: notas.length,
    valorTotal: notas.reduce((s, n) => s + (n.valor_total || 0), 0),
    valorICMS: notas.reduce((s, n) => s + (n.valor_icms || 0), 0),
    valorProdutos: notas.reduce((s, n) => s + (n.valor_produtos || 0), 0),
    valorFrete: notas.reduce((s, n) => s + (n.valor_frete || 0), 0),
    valorDesconto: notas.reduce((s, n) => s + (n.valor_desconto || 0), 0),
    totalFornecedores: new Set(notas.filter(n => n.cnpj).map(n => n.cnpj)).size,
    hoje: notas.filter(n => (n.created_at || '').slice(0, 10) === today).length,
    ultimos7dias: notas.filter(n => (n.created_at || '') >= weekAgo).length,
    dbSizeWarning: notas.length > 10000,
  };

  // Top fornecedores
  const fornMap = {};
  notas.forEach(n => {
    const key = n.cnpj || n.fornecedor;
    if (!key || n.fornecedor === 'Nao identificado') return;
    if (!fornMap[key]) fornMap[key] = { fornecedor: n.fornecedor, cnpj: n.cnpj, total: 0, valor: 0 };
    fornMap[key].total++;
    fornMap[key].valor += n.valor_total || 0;
  });
  stats.topFornecedores = Object.values(fornMap).sort((a, b) => b.valor - a.valor).slice(0, 10);

  // Monthly
  const mesMap = {};
  notas.forEach(n => {
    const mes = (n.created_at || '').slice(0, 7);
    if (!mes) return;
    if (!mesMap[mes]) mesMap[mes] = { mes, total: 0, valor: 0, icms: 0 };
    mesMap[mes].total++;
    mesMap[mes].valor += n.valor_total || 0;
    mesMap[mes].icms += n.valor_icms || 0;
  });
  stats.mensal = Object.values(mesMap).sort((a, b) => a.mes.localeCompare(b.mes)).slice(-12);

  // By tipo
  const tipoMap = {};
  notas.forEach(n => {
    if (!n.tipo_operacao) return;
    if (!tipoMap[n.tipo_operacao]) tipoMap[n.tipo_operacao] = { tipo_operacao: n.tipo_operacao, total: 0, valor: 0 };
    tipoMap[n.tipo_operacao].total++;
    tipoMap[n.tipo_operacao].valor += n.valor_total || 0;
  });
  stats.porTipo = Object.values(tipoMap);

  // Recent
  stats.recentes = [...notas].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || '')).slice(0, 10);

  // By source
  const srcMap = {};
  notas.forEach(n => {
    if (!n.source) return;
    if (!srcMap[n.source]) srcMap[n.source] = { source: n.source, total: 0 };
    srcMap[n.source].total++;
  });
  stats.porFonte = Object.values(srcMap);

  res.json(stats);
});

// ─── API: EXPORT CSV ──────────────────────────────────────────
app.get('/api/export/csv', (req, res) => {
  const { mes } = req.query;
  let notas = [...db.notas];
  if (mes) notas = notas.filter(n => (n.created_at || '').startsWith(mes));
  notas.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));

  const headers = ['ID', 'Fornecedor', 'CNPJ', 'Numero', 'Serie', 'Chave Acesso', 'Data Emissao', 'Natureza Op.', 'Tipo', 'Valor Total', 'Valor Produtos', 'ICMS', 'Frete', 'Desconto', 'Destinatario', 'CNPJ Dest.', 'Protocolo', 'Recebido Em'];
  const rows = notas.map(n => [
    n.id, `"${(n.fornecedor || '').replace(/"/g, "'")}"`, n.cnpj, n.numero, n.serie, n.chave_acesso,
    n.data_emissao, `"${(n.natureza_operacao || '').replace(/"/g, "'")}"`, n.tipo_operacao,
    n.valor_total, n.valor_produtos, n.valor_icms, n.valor_frete, n.valor_desconto,
    `"${(n.destinatario || '').replace(/"/g, "'")}"`, n.destinatario_cnpj, n.protocolo, n.created_at
  ].join(';'));

  const csv = '\uFEFF' + headers.join(';') + '\n' + rows.join('\n');
  const filename = mes ? `fiscalflow_${mes}.csv` : 'fiscalflow_notas.csv';
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename=${filename}`);
  res.send(csv);
});

// ─── SPA FALLBACK ─────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── START ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  +================================================+`);
  console.log(`  |  FiscalFlow Enterprise — Dashboard NFe          |`);
  console.log(`  +================================================+`);
  console.log(`  |  App:     http://localhost:${PORT}                 |`);
  console.log(`  |  Webhook: http://localhost:${PORT}/webhook/nfe     |`);
  console.log(`  +================================================+`);
  console.log(`  ${db.notas.length} notas | Rate limit: ${RATE_LIMIT}/min\n`);
});
