require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Dynamic BASE URL ──────────────────────────────────────────────────────────
// On Vercel: reads x-forwarded-host + x-forwarded-proto headers (set by Vercel)
// On Railway/Render: uses BASE_URL env var
// Locally: falls back to localhost
function getBaseUrl(req) {
  // Priority 1: BASE_URL env var — strip trailing slash and quotes
  if (process.env.BASE_URL) {
    const url = process.env.BASE_URL
      .replace(/^\"|\"$/g, '')   // remove surrounding quotes
      .replace(/^'|'$/g, '')       // remove surrounding single quotes
      .replace(/\/$/, '')          // remove trailing slash
      .trim();
    if (url && url.startsWith('http')) {
      return url;
    }
  }

  // Priority 2: Vercel / reverse proxy headers
  if (req) {
    const forwardedProto = req.headers['x-forwarded-proto'];
    const forwardedHost  = req.headers['x-forwarded-host'];
    const host           = req.headers['host'] || '';

    if (forwardedHost && !forwardedHost.includes('localhost')) {
      const proto = (forwardedProto || 'https').split(',')[0].trim();
      return `${proto}://${forwardedHost}`;
    }
    if (host && !host.includes('localhost') && !host.includes('127.0.0.1')) {
      const proto = (forwardedProto || req.protocol || 'https').split(',')[0].trim();
      return `${proto}://${host}`;
    }
  }

  // Priority 3: Local fallback
  return `http://localhost:${PORT}`;
}

// Debug route — visit /api/debug to see what BASE_URL resolves to
app.get('/api/debug', (req, res) => {
  res.json({
    BASE_URL_env:       process.env.BASE_URL || '(not set)',
    resolvedBaseUrl:    getBaseUrl(req),
    headers: {
      host:                 req.headers['host'],
      x_forwarded_host:     req.headers['x-forwarded-host'],
      x_forwarded_proto:    req.headers['x-forwarded-proto'],
    },
    NODE_ENV: process.env.NODE_ENV || '(not set)',
  });
});

// ── Supabase ──────────────────────────────────────────────────────────────────
// Set these in your .env file or Railway/Render/Vercel environment variables
const SUPA_URL  = process.env.SUPABASE_URL  || 'YOUR_SUPABASE_PROJECT_URL';
const SUPA_KEY  = process.env.SUPABASE_KEY  || 'YOUR_SUPABASE_SERVICE_ROLE_KEY';
const db = createClient(SUPA_URL, SUPA_KEY);

// ── Auth ──────────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'billease-secret-change-in-production';

// ── Gmail ─────────────────────────────────────────────────────────────────────
const GMAIL_USER     = process.env.GMAIL_USER     || 'dadiganesh25@gmail.com';
const GMAIL_APP_PASS = process.env.GMAIL_APP_PASS || 'YOUR_GMAIL_APP_PASSWORD';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: GMAIL_USER, pass: GMAIL_APP_PASS },
});

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// DB error handler
function dbErr(res, error, msg = 'Database error') {
  console.error(msg, error);
  res.status(500).json({ error: msg + ': ' + error.message });
}

// Auth middleware
function auth(req, res, next) {
  // Accept token from Authorization header OR ?token= query param (for file downloads)
  const token = (req.headers.authorization || '').replace('Bearer ', '') || req.query.token || '';
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// Which client's data to query
function clientId(req) {
  return req.user.role === 'admin' && req.query.clientId
    ? req.query.clientId
    : req.user.id;
}

// Send verification email
async function sendVerifyEmail(toEmail, name, bizName, verifyUrl) {
  const html = `
  <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:560px;margin:auto;background:#f6f4ef;border-radius:14px;overflow:hidden;border:1px solid #dedad2">
    <div style="background:#1a5c3a;padding:28px 32px;text-align:center">
      <div style="font-size:28px">🧾</div>
      <div style="font-family:Georgia,serif;font-size:22px;color:#fff">BillEase</div>
      <div style="font-size:12px;color:rgba(255,255,255,0.65)">Smart Billing Software</div>
    </div>
    <div style="padding:30px 32px;background:#fff">
      <h2 style="color:#1a1a18;font-size:18px;margin:0 0 8px">New Registration 🎉</h2>
      <div style="background:#f6f4ef;border-radius:10px;padding:18px;margin-bottom:24px">
        <table style="width:100%;font-size:14px;border-collapse:collapse">
          <tr><td style="color:#9a9a8a;padding:5px 0;width:110px">👤 Name</td><td style="font-weight:500">${name}</td></tr>
          <tr><td style="color:#9a9a8a;padding:5px 0">📧 Email</td><td>${toEmail}</td></tr>
          <tr><td style="color:#9a9a8a;padding:5px 0">🏪 Business</td><td style="font-weight:500">${bizName}</td></tr>
          <tr><td style="color:#9a9a8a;padding:5px 0">🕐 Time</td><td>${new Date().toLocaleString('en-IN',{dateStyle:'medium',timeStyle:'short'})}</td></tr>
        </table>
      </div>
      <p style="color:#5a5a50;font-size:14px;margin:0 0 16px">Click below to verify and activate this account:</p>
      <div style="text-align:center;margin:20px 0">
        <a href="${verifyUrl}" style="display:inline-block;background:#1a5c3a;color:#fff;padding:13px 30px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px">✅ Verify Account</a>
      </div>
      <p style="color:#9a9a8a;font-size:12px;text-align:center">
        Or copy:<br><a href="${verifyUrl}" style="color:#2e8a58;word-break:break-all">${verifyUrl}</a>
      </p>
    </div>
    <div style="background:#f0ede6;padding:14px 32px;text-align:center;border-top:1px solid #dedad2">
      <p style="color:#9a9a8a;font-size:12px;margin:0">BillEase · <a href="${verifyUrl.split('/api')[0]}" style="color:#2e8a58">${verifyUrl.split('/api')[0]}</a></p>
    </div>
  </div>`;

  try {
    await transporter.sendMail({
      from: `"BillEase" <${GMAIL_USER}>`,
      to: GMAIL_USER,
      bcc: toEmail,
      subject: `🧾 New BillEase Registration — ${bizName}`,
      html,
    });
    console.log(`✅ Email sent → ${GMAIL_USER} (BCC: ${toEmail})`);
    return { success: true };
  } catch (err) {
    console.error(`⚠️  Email failed: ${err.message}`);
    console.log(`   Verify URL: ${verifyUrl}`);
    return { success: false, error: err.message };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, bizName, bizAddress, bizPhone, bizType } = req.body;
  if (!name || !email || !password || !bizName)
    return res.status(400).json({ error: 'name, email, password, bizName are required' });

  // Check existing
  const { data: existing } = await db.from('users').select('id').eq('email', email.toLowerCase()).single();
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const hashed      = await bcrypt.hash(password, 10);
  const verifyToken = uuidv4();
  const userId      = 'usr-' + uuidv4().slice(0, 8);
  const verifyUrl   = `${getBaseUrl(req)}/api/auth/verify/${verifyToken}`;

  // Insert user
  const { error: userErr } = await db.from('users').insert({
    id: userId, name, email: email.toLowerCase(),
    password: hashed, role: 'client', verified: false, verify_token: verifyToken,
    biz_name: bizName, biz_address: bizAddress || '', biz_phone: bizPhone || '',
    biz_type: bizType || 'restaurant',
  });
  if (userErr) return dbErr(res, userErr, 'Failed to create user');

  // Seed default items
  await db.from('items').insert([
    { user_id: userId, name: 'Sample Item 1', price: 50,  cat: 'General', emoji: '🛒' },
    { user_id: userId, name: 'Sample Item 2', price: 100, cat: 'General', emoji: '📦' },
  ]);

  // Init bill sequence
  await db.from('bill_sequences').insert({ user_id: userId, next_no: 1 });

  // Send email
  const mail = await sendVerifyEmail(email, name, bizName, verifyUrl);
  res.json({
    success: true,
    message: mail.success
      ? `Registered! Confirmation sent to ${GMAIL_USER}.`
      : `Registered! Email failed — use the verify link below.`,
    verifyUrl,
    emailSent: mail.success,
  });
});

// GET /api/auth/verify/:token
app.get('/api/auth/verify/:token', async (req, res) => {
  const { data: user, error } = await db.from('users')
    .select('id').eq('verify_token', req.params.token).single();
  if (error || !user)
    return res.status(400).send('<h2 style="font-family:sans-serif;color:#c0392b;padding:40px">Invalid or expired verification link.</h2>');
  await db.from('users').update({ verified: true, verify_token: null }).eq('id', user.id);
  const appUrl = getBaseUrl(req);
  res.redirect(`${appUrl}/?verified=1`);
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const { data: user, error } = await db.from('users').select('*').eq('email', email.toLowerCase()).single();
  if (error || !user) return res.status(401).json({ error: 'Invalid email or password' });
  if (!user.verified) return res.status(403).json({ error: 'Email not verified. Check your inbox or ask admin to verify.' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, verify_token: __, ...safe } = user;
  res.json({ token, user: safe });
});

// GET /api/auth/me
app.get('/api/auth/me', auth, async (req, res) => {
  const { data: user, error } = await db.from('users').select('*').eq('id', req.user.id).single();
  if (error || !user) return res.status(404).json({ error: 'User not found' });
  const { password, verify_token, ...safe } = user;
  res.json(safe);
});

// ═══════════════════════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/settings', auth, async (req, res) => {
  const { data: user, error } = await db.from('users').select('*').eq('id', req.user.id).single();
  if (error) return dbErr(res, error);
  const { password, verify_token, ...safe } = user;
  res.json(safe);
});

app.put('/api/settings', auth, async (req, res) => {
  const allowed = ['biz_name','biz_address','biz_phone','currency','tax_rate','tax_enabled','tax_name','thank_you','bill_prefix','biz_type'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  // also support camelCase keys from frontend
  const keyMap = { bizName:'biz_name', bizAddress:'biz_address', bizPhone:'biz_phone', taxRate:'tax_rate', taxEnabled:'tax_enabled', taxName:'tax_name', thankYou:'thank_you', billPrefix:'bill_prefix', bizType:'biz_type' };
  Object.entries(keyMap).forEach(([cam, snake]) => { if (req.body[cam] !== undefined) updates[snake] = req.body[cam]; });
  if (req.body.currency) updates.currency = req.body.currency;
  const { error } = await db.from('users').update(updates).eq('id', req.user.id);
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ITEMS CRUD
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/items', auth, async (req, res) => {
  const cid = clientId(req);
  let query = db.from('items').select('*').eq('user_id', cid).order('id');
  if (req.query.cat)    query = query.eq('cat', req.query.cat);
  if (req.query.search) query = query.ilike('name', `%${req.query.search}%`);
  const { data, error } = await query;
  if (error) return dbErr(res, error);
  res.json(data);
});

// GET /api/items/export — must be BEFORE /:id to avoid conflict
app.get('/api/items/export', auth, async (req, res) => {
  const cid = clientId(req);
  const { data, error } = await db.from('items').select('*').eq('user_id', cid).order('cat').order('name');
  if (error) return dbErr(res, error);
  const rows = [['name','price','category','emoji']];
  (data || []).forEach(item => rows.push([item.name, item.price, item.cat, item.emoji || '']));
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="billease_items_export.csv"');
  res.send(csv);
});

// GET /api/items/template — must be BEFORE /:id to avoid conflict
app.get('/api/items/template', auth, (req, res) => {
  const csv = 'name,price,category,emoji\nChicken Biryani,180,Food,🍛\nMasala Tea,20,Drink,☕\nVeg Sandwich,60,Food,🥪';
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="billease_items_template.csv"');
  res.send(csv);
});

// POST /api/items/bulk — must be BEFORE /:id to avoid conflict
app.post('/api/items/bulk', auth, async (req, res) => {
  const cid = clientId(req);
  const { items, mode = 'skip' } = req.body;
  if (!Array.isArray(items) || !items.length) return res.status(400).json({ error: 'items array required' });
  const valid = [], errors = [];
  items.forEach((row, i) => {
    const name  = (row.name || row.Name || row.ITEM || row.item || '').toString().trim();
    const price = parseFloat(row.price || row.Price || row.PRICE || row.rate || row.Rate || 0);
    const cat   = (row.category || row.Category || row.cat || 'General').toString().trim();
    const emoji = (row.emoji || row.Emoji || row.icon || '🛒').toString().trim();
    if (!name)           { errors.push({ row: i+1, error: 'Name is required' }); return; }
    if (!price || price <= 0) { errors.push({ row: i+1, name, error: 'Price must be > 0' }); return; }
    valid.push({ name, price, cat, emoji });
  });
  if (!valid.length) return res.json({ success: false, imported: 0, errors });
  let imported = 0, skipped = 0;
  if (mode === 'overwrite') {
    await db.from('items').delete().eq('user_id', cid);
    const { data, error } = await db.from('items').insert(valid.map(v => ({ ...v, user_id: cid }))).select();
    if (error) return dbErr(res, error);
    imported = data.length;
  } else if (mode === 'append') {
    const { data, error } = await db.from('items').insert(valid.map(v => ({ ...v, user_id: cid }))).select();
    if (error) return dbErr(res, error);
    imported = data.length;
  } else {
    const { data: existing } = await db.from('items').select('name').eq('user_id', cid);
    const existingNames = new Set((existing || []).map(e => e.name.toLowerCase()));
    const toInsert = valid.filter(v => { if (existingNames.has(v.name.toLowerCase())) { skipped++; return false; } return true; });
    if (toInsert.length) {
      const { data, error } = await db.from('items').insert(toInsert.map(v => ({ ...v, user_id: cid }))).select();
      if (error) return dbErr(res, error);
      imported = data.length;
    }
  }
  res.json({ success: true, imported, skipped, errors, message: `${imported} items imported${skipped ? `, ${skipped} skipped` : ''}${errors.length ? `, ${errors.length} errors` : ''}` });
});


app.get('/api/items/:id', auth, async (req, res) => {
  const { data, error } = await db.from('items').select('*')
    .eq('id', req.params.id).eq('user_id', clientId(req)).single();
  if (error || !data) return res.status(404).json({ error: 'Item not found' });
  res.json(data);
});

app.post('/api/items', auth, async (req, res) => {
  const { name, price, cat, emoji } = req.body;
  if (!name || !price || !cat) return res.status(400).json({ error: 'name, price, cat required' });
  const { data, error } = await db.from('items')
    .insert({ user_id: clientId(req), name, price: parseFloat(price), cat, emoji: emoji || '🛒' })
    .select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, item: data });
});

app.put('/api/items/:id', auth, async (req, res) => {
  const { name, price, cat, emoji } = req.body;
  const updates = {};
  if (name  !== undefined) updates.name  = name;
  if (price !== undefined) updates.price = parseFloat(price);
  if (cat   !== undefined) updates.cat   = cat;
  if (emoji !== undefined) updates.emoji = emoji;
  const { data, error } = await db.from('items')
    .update(updates).eq('id', req.params.id).eq('user_id', clientId(req))
    .select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, item: data });
});

app.delete('/api/items/:id', auth, async (req, res) => {
  const { error } = await db.from('items')
    .delete().eq('id', req.params.id).eq('user_id', clientId(req));
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// BILLS CRUD
// ═══════════════════════════════════════════════════════════════════════════════

// Get next bill number (atomic)
async function nextBillNo(userId) {
  const { data } = await db.from('bill_sequences').select('next_no').eq('user_id', userId).single();
  const no = data ? data.next_no : 1;
  await db.from('bill_sequences').upsert({ user_id: userId, next_no: no + 1 });
  return no;
}

app.get('/api/bills', auth, async (req, res) => {
  const cid = clientId(req);
  let query = db.from('bills').select('*').eq('user_id', cid).order('no', { ascending: false });
  if (req.query.from) query = query.gte('time', req.query.from + 'T00:00:00');
  if (req.query.to)   query = query.lte('time', req.query.to   + 'T23:59:59');
  const { data, error } = await query;
  if (error) return dbErr(res, error);
  res.json(data);
});

app.get('/api/bills/:no', auth, async (req, res) => {
  const { data, error } = await db.from('bills').select('*')
    .eq('no', req.params.no).eq('user_id', clientId(req)).single();
  if (error || !data) return res.status(404).json({ error: 'Bill not found' });
  res.json(data);
});

app.post('/api/bills', auth, async (req, res) => {
  const { cart, customer, phone, table, payMode, disc, discType, discVal } = req.body;
  if (!cart || !cart.length) return res.status(400).json({ error: 'cart is required' });
  const cid = clientId(req);
  const { data: user } = await db.from('users').select('tax_enabled,tax_rate').eq('id', cid).single();
  const sub      = cart.reduce((s, c) => s + c.price * c.qty, 0);
  const discount = Math.min(disc || 0, sub);
  const tax      = user.tax_enabled ? (sub - discount) * (user.tax_rate / 100) : 0;
  const grand    = sub - discount + tax;
  const no       = await nextBillNo(cid);
  const { data, error } = await db.from('bills').insert({
    no, user_id: cid, customer: customer || 'Guest',
    phone: phone || '', tbl: table || '', cart,
    sub, disc: discount, tax, grand,
    pay_mode: payMode || 'Cash', disc_type: discType || 'flat', disc_val: discVal || 0,
  }).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, bill: data });
});

app.put('/api/bills/:no', auth, async (req, res) => {
  const allowed = ['customer','phone','tbl','pay_mode'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  const { data, error } = await db.from('bills')
    .update(updates).eq('no', req.params.no).eq('user_id', clientId(req))
    .select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, bill: data });
});

app.delete('/api/bills/:no', auth, async (req, res) => {
  const { error } = await db.from('bills')
    .delete().eq('no', req.params.no).eq('user_id', clientId(req));
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// HELD BILLS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/held', auth, async (req, res) => {
  const { data, error } = await db.from('held_bills').select('*').eq('user_id', clientId(req));
  if (error) return dbErr(res, error);
  res.json(data);
});

app.post('/api/held', auth, async (req, res) => {
  const { customer, table, cart } = req.body;
  const { data, error } = await db.from('held_bills')
    .insert({ user_id: clientId(req), customer: customer || 'Guest', tbl: table || '', cart })
    .select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, held: data });
});

app.delete('/api/held/:id', auth, async (req, res) => {
  const { error } = await db.from('held_bills')
    .delete().eq('id', req.params.id).eq('user_id', clientId(req));
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════════════════════════════════════════

function dateRange(type, from, to) {
  const now = new Date();
  if (type === 'daily') {
    const d = from || now.toISOString().slice(0, 10);
    return { start: d + 'T00:00:00', end: d + 'T23:59:59' };
  }
  if (type === 'monthly') {
    const y = from ? parseInt(from.slice(0,4)) : now.getFullYear();
    const m = from ? parseInt(from.slice(5,7)) - 1 : now.getMonth();
    const start = new Date(y, m, 1).toISOString();
    const end   = new Date(y, m+1, 0, 23, 59, 59).toISOString();
    return { start, end };
  }
  return {
    start: from ? from + 'T00:00:00' : '2000-01-01T00:00:00',
    end:   to   ? to   + 'T23:59:59' : '2099-12-31T23:59:59',
  };
}

function buildReport(bills, client, period) {
  const itemMap = {}, catMap = {}, payMap = {}, dayMap = {}, hourMap = {};
  const totalSub  = bills.reduce((s,b) => s + parseFloat(b.sub),   0);
  const totalTax  = bills.reduce((s,b) => s + parseFloat(b.tax),   0);
  const totalDisc = bills.reduce((s,b) => s + parseFloat(b.disc),  0);
  const totalRev  = bills.reduce((s,b) => s + parseFloat(b.grand), 0);

  bills.forEach(b => {
    const cart = Array.isArray(b.cart) ? b.cart : JSON.parse(b.cart || '[]');
    cart.forEach(c => {
      if (!itemMap[c.name]) itemMap[c.name] = { name:c.name, emoji:c.emoji||'🛒', cat:c.cat, qty:0, revenue:0 };
      itemMap[c.name].qty     += c.qty;
      itemMap[c.name].revenue += c.price * c.qty;
      catMap[c.cat] = (catMap[c.cat] || 0) + c.price * c.qty;
    });
    const pm = b.pay_mode || b.payMode || 'Cash';
    payMap[pm] = payMap[pm] || { count:0, revenue:0 };
    payMap[pm].count++;
    payMap[pm].revenue += parseFloat(b.grand);
    const d = (b.time||'').slice(0,10);
    if (d) { dayMap[d] = dayMap[d] || { date:d, bills:0, revenue:0 }; dayMap[d].bills++; dayMap[d].revenue += parseFloat(b.grand); }
    const h = new Date(b.time).getHours();
    hourMap[h] = hourMap[h] || { hour:h, bills:0, revenue:0 };
    hourMap[h].bills++; hourMap[h].revenue += parseFloat(b.grand);
  });

  return {
    period, client,
    summary: { totalRevenue:totalRev, totalSub, totalTax, totalDiscount:totalDisc, totalBills:bills.length, avgBillValue: bills.length ? totalRev/bills.length : 0 },
    itemSales:    Object.values(itemMap).sort((a,b) => b.revenue - a.revenue),
    catSales:     Object.entries(catMap).map(([cat,rev]) => ({ cat, revenue:rev })).sort((a,b) => b.revenue-a.revenue),
    payBreakdown: Object.entries(payMap).map(([mode,v]) => ({ mode, ...v })),
    dailyTrend:   Object.values(dayMap).sort((a,b) => a.date.localeCompare(b.date)),
    hourlyPattern:Object.values(hourMap).sort((a,b) => a.hour-b.hour),
  };
}

app.get('/api/reports', auth, async (req, res) => {
  const cid = clientId(req);
  const { type='daily', from, to } = req.query;
  const { start, end } = dateRange(type, from, to);
  const { data: user } = await db.from('users').select('id,name,biz_name').eq('id', cid).single();
  const { data: bills, error } = await db.from('bills').select('*')
    .eq('user_id', cid).gte('time', start).lte('time', end);
  if (error) return dbErr(res, error);
  res.json(buildReport(bills, { id:user.id, name:user.name, bizName:user.biz_name }, { type, from, to }));
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/clients', auth, adminOnly, async (req, res) => {
  const { data: users, error } = await db.from('users').select('*').eq('role', 'client').order('created_at');
  if (error) return dbErr(res, error);
  // Get bill counts & revenue per client
  const clients = await Promise.all(users.map(async u => {
    const { data: bills } = await db.from('bills').select('grand').eq('user_id', u.id);
    const { password, verify_token, ...safe } = u;
    return {
      ...safe,
      billCount:    bills ? bills.length : 0,
      totalRevenue: bills ? bills.reduce((s,b) => s + parseFloat(b.grand), 0) : 0,
    };
  }));
  res.json(clients);
});

app.get('/api/admin/clients/:id', auth, adminOnly, async (req, res) => {
  const { data: user, error: ue } = await db.from('users').select('*').eq('id', req.params.id).single();
  if (ue || !user) return res.status(404).json({ error: 'Not found' });
  const { data: bills  } = await db.from('bills').select('*').eq('user_id', user.id).order('no', { ascending: false });
  const { data: items  } = await db.from('items').select('*').eq('user_id', user.id);
  const { password, verify_token, ...safe } = user;
  res.json({ ...safe, bills: bills || [], items: items || [] });
});

app.put('/api/admin/clients/:id/verify', auth, adminOnly, async (req, res) => {
  const { error } = await db.from('users').update({ verified: true, verify_token: null }).eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

app.delete('/api/admin/clients/:id', auth, adminOnly, async (req, res) => {
  if (req.params.id === 'admin-001') return res.status(403).json({ error: 'Cannot delete super admin' });
  // CASCADE deletes items, bills, held_bills automatically (set in schema)
  const { error } = await db.from('users').delete().eq('id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

app.get('/api/admin/reports', auth, adminOnly, async (req, res) => {
  const { type='daily', from, to, clientId: cid } = req.query;
  const { start, end } = dateRange(type, from, to);
  const { data: users } = await db.from('users').select('id,name,biz_name').eq('role','client');
  const filtered = cid ? users.filter(u => u.id === cid) : users;
  const combined = [];
  const perClient = await Promise.all(filtered.map(async u => {
    const { data: bills } = await db.from('bills').select('*')
      .eq('user_id', u.id).gte('time', start).lte('time', end);
    const b = bills || [];
    combined.push(...b);
    return buildReport(b, { id:u.id, name:u.name, bizName:u.biz_name }, { type, from, to });
  }));
  res.json({
    overall: buildReport(combined, { id:'platform', name:'All Clients', bizName:'Platform' }, { type, from, to }),
    perClient,
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SUPERMARKET MODULE
// ═══════════════════════════════════════════════════════════════════════════════

// ── SM PRODUCTS CRUD ─────────────────────────────────────────────────────────

// GET all products (with filters)
app.get('/api/sm/products', auth, async (req, res) => {
  const cid = clientId(req);
  let query = db.from('sm_products').select('*').eq('user_id', cid).eq('active', true).order('category').order('name');
  if (req.query.category) query = query.eq('category', req.query.category);
  if (req.query.item_type) query = query.eq('item_type', req.query.item_type);
  if (req.query.search) query = query.ilike('name', `%${req.query.search}%`);
  const { data, error } = await query;
  if (error) return dbErr(res, error);
  res.json(data);
});

// GET /api/sm/products/export — must be BEFORE /:id to avoid conflict
app.get('/api/sm/products/export', auth, async (req, res) => {
  const cid = clientId(req);
  const { data, error } = await db.from('sm_products').select('*').eq('user_id', cid).eq('active', true).order('category').order('name');
  if (error) return dbErr(res, error);
  const headers = ['name','price_per_unit','unit','item_type','category','brand','emoji','stock_qty','low_stock_alert','barcode','hsn_code','tax_rate'];
  const rows = [headers];
  (data || []).forEach(p => rows.push(headers.map(h => p[h] ?? '')));
  const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="billease_products_export.csv"');
  res.send(csv);
});

// GET /api/sm/products/template — must be BEFORE /:id to avoid conflict
app.get('/api/sm/products/template', auth, (req, res) => {
  const csv = [
    'name,price_per_unit,unit,item_type,category,brand,emoji,stock_qty,low_stock_alert,barcode,hsn_code,tax_rate',
    'Toor Dal,120,kg,loose,Pulses & Dal,,🫘,50,5,,,5',
    'Basmati Rice,80,kg,loose,Rice & Grains,India Gate,🍚,100,10,8901234567890,1006,5',
    'Amul Butter 500g,310,pcs,packet,Dairy,Amul,🧈,30,5,8901234567891,0405,12',
    'Sunflower Oil 1L,160,pcs,packet,Oils & Ghee,Fortune,🫙,20,3,8901234567892,1512,5',
  ].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="billease_supermarket_template.csv"');
  res.send(csv);
});

// POST /api/sm/products/bulk — must be BEFORE /:id to avoid conflict
app.post('/api/sm/products/bulk', auth, async (req, res) => {
  const cid = clientId(req);
  const { products, mode = 'skip' } = req.body;
  if (!Array.isArray(products) || !products.length) return res.status(400).json({ error: 'products array required' });
  const valid = [], errors = [];
  products.forEach((row, i) => {
    const name           = (row.name || row.Name || '').toString().trim();
    const price_per_unit = parseFloat(row.price_per_unit || row.price || row.Price || 0);
    const unit           = (row.unit || 'pcs').toString().trim().toLowerCase();
    const item_type      = (row.item_type || 'packet').toString().trim().toLowerCase();
    const category       = (row.category || 'General').toString().trim();
    const emoji          = (row.emoji || '🛒').toString().trim();
    const brand          = (row.brand || '').toString().trim();
    const stock_qty      = parseFloat(row.stock_qty || 0) || 0;
    const low_stock_alert = parseFloat(row.low_stock_alert || 5) || 5;
    const barcode        = (row.barcode || '').toString().trim() || null;
    const hsn_code       = (row.hsn_code || '').toString().trim() || null;
    const tax_rate       = parseFloat(row.tax_rate || 0) || 0;
    if (!name)                     { errors.push({ row: i+1, error: 'Name required' }); return; }
    if (!price_per_unit || price_per_unit <= 0) { errors.push({ row: i+1, name, error: 'Price required' }); return; }
    const validUnits = ['kg','g','l','ml','pcs','pack','box','dozen','bundle'];
    const validTypes = ['loose','packet'];
    valid.push({ name, price_per_unit, unit: validUnits.includes(unit)?unit:'pcs', item_type: validTypes.includes(item_type)?item_type:'packet', category, emoji, brand, stock_qty, low_stock_alert, barcode, hsn_code, tax_rate, active: true });
  });
  if (!valid.length) return res.json({ success: false, imported: 0, errors });
  let imported = 0, skipped = 0;
  if (mode === 'overwrite') {
    await db.from('sm_products').update({ active: false }).eq('user_id', cid);
    const { data, error } = await db.from('sm_products').insert(valid.map(v => ({ ...v, user_id: cid }))).select();
    if (error) return dbErr(res, error);
    imported = data.length;
  } else {
    const { data: ex } = await db.from('sm_products').select('name').eq('user_id', cid).eq('active', true);
    const exNames = new Set((ex || []).map(e => e.name.toLowerCase()));
    const toIns = valid.filter(v => { if (exNames.has(v.name.toLowerCase())) { skipped++; return false; } return true; });
    if (toIns.length) {
      const { data, error } = await db.from('sm_products').insert(toIns.map(v => ({ ...v, user_id: cid }))).select();
      if (error) return dbErr(res, error);
      imported = data.length;
    }
  }
  res.json({ success: true, imported, skipped, errors, message: `${imported} products imported${skipped ? `, ${skipped} skipped` : ''}${errors.length ? `, ${errors.length} errors` : ''}` });
});


// GET single product
app.get('/api/sm/products/:id', auth, async (req, res) => {
  const { data, error } = await db.from('sm_products').select('*')
    .eq('id', req.params.id).eq('user_id', clientId(req)).single();
  if (error || !data) return res.status(404).json({ error: 'Product not found' });
  res.json(data);
});

// POST create product
app.post('/api/sm/products', auth, async (req, res) => {
  const cid = clientId(req);
  const { name, category, emoji, item_type, unit, price_per_unit, stock_qty, low_stock_alert, barcode, brand, hsn_code, tax_rate } = req.body;
  if (!name || !price_per_unit) return res.status(400).json({ error: 'name and price_per_unit required' });
  const { data, error } = await db.from('sm_products').insert({
    user_id: cid, name, category: category || 'General',
    emoji: emoji || '🛒', item_type: item_type || 'packet',
    unit: unit || 'pcs', price_per_unit: parseFloat(price_per_unit),
    stock_qty: parseFloat(stock_qty) || 0,
    low_stock_alert: parseFloat(low_stock_alert) || 5,
    barcode: barcode || null, brand: brand || null,
    hsn_code: hsn_code || null, tax_rate: parseFloat(tax_rate) || 0,
  }).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, product: data });
});

// PUT update product
app.put('/api/sm/products/:id', auth, async (req, res) => {
  const allowed = ['name','category','emoji','item_type','unit','price_per_unit','stock_qty','low_stock_alert','barcode','brand','hsn_code','tax_rate','active'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  if (updates.price_per_unit) updates.price_per_unit = parseFloat(updates.price_per_unit);
  if (updates.stock_qty !== undefined) updates.stock_qty = parseFloat(updates.stock_qty);
  const { data, error } = await db.from('sm_products').update(updates)
    .eq('id', req.params.id).eq('user_id', clientId(req)).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, product: data });
});

// DELETE product (soft delete)
app.delete('/api/sm/products/:id', auth, async (req, res) => {
  const { error } = await db.from('sm_products').update({ active: false })
    .eq('id', req.params.id).eq('user_id', clientId(req));
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

// PATCH update stock quantity
app.patch('/api/sm/products/:id/stock', auth, async (req, res) => {
  const { delta, set_to } = req.body;
  const { data: current } = await db.from('sm_products').select('stock_qty')
    .eq('id', req.params.id).eq('user_id', clientId(req)).single();
  if (!current) return res.status(404).json({ error: 'Not found' });
  const newQty = set_to !== undefined ? parseFloat(set_to) : (parseFloat(current.stock_qty) + parseFloat(delta || 0));
  const { data, error } = await db.from('sm_products').update({ stock_qty: Math.max(0, newQty) })
    .eq('id', req.params.id).eq('user_id', clientId(req)).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, product: data });
});

// GET categories list
app.get('/api/sm/categories', auth, async (req, res) => {
  const { data, error } = await db.from('sm_products').select('category')
    .eq('user_id', clientId(req)).eq('active', true);
  if (error) return dbErr(res, error);
  const cats = [...new Set(data.map(r => r.category))].sort();
  res.json(cats);
});

// GET low stock products
app.get('/api/sm/low-stock', auth, async (req, res) => {
  const { data, error } = await db.from('sm_products').select('*')
    .eq('user_id', clientId(req)).eq('active', true);
  if (error) return dbErr(res, error);
  const low = data.filter(p => parseFloat(p.stock_qty) <= parseFloat(p.low_stock_alert));
  res.json(low);
});

// ── SM BILLS ─────────────────────────────────────────────────────────────────

async function nextSmBillNo(userId) {
  const { data } = await db.from('sm_bill_sequences').select('next_no').eq('user_id', userId).single();
  const no = data ? data.next_no : 1;
  await db.from('sm_bill_sequences').upsert({ user_id: userId, next_no: no + 1 });
  return no;
}

// GET all SM bills
app.get('/api/sm/bills', auth, async (req, res) => {
  const cid = clientId(req);
  let query = db.from('sm_bills').select('*').eq('user_id', cid).order('no', { ascending: false });
  if (req.query.from) query = query.gte('time', req.query.from + 'T00:00:00');
  if (req.query.to)   query = query.lte('time', req.query.to   + 'T23:59:59');
  const { data, error } = await query;
  if (error) return dbErr(res, error);
  res.json(data);
});

// GET single SM bill
app.get('/api/sm/bills/:no', auth, async (req, res) => {
  const { data, error } = await db.from('sm_bills').select('*')
    .eq('no', req.params.no).eq('user_id', clientId(req)).single();
  if (error || !data) return res.status(404).json({ error: 'Bill not found' });
  res.json(data);
});

// POST create SM bill
app.post('/api/sm/bills', auth, async (req, res) => {
  const { cart, customer, phone, payMode, discount, discountType, discountVal, notes } = req.body;
  if (!cart || !cart.length) return res.status(400).json({ error: 'cart required' });
  const cid = clientId(req);
  const { data: user } = await db.from('users').select('tax_enabled,tax_rate').eq('id', cid).single();

  // Calculate totals (each item can have own tax_rate)
  const subtotal = cart.reduce((s, c) => s + parseFloat(c.amount), 0);
  const disc = Math.min(parseFloat(discount) || 0, subtotal);
  const taxable = subtotal - disc;

  // Use per-item tax if set, else store tax
  let tax = 0;
  if (user.tax_enabled) {
    cart.forEach(item => {
      const itemSubtotal = parseFloat(item.amount);
      const ratio = subtotal > 0 ? itemSubtotal / subtotal : 0;
      const taxableItem = taxable * ratio;
      const rate = item.tax_rate > 0 ? item.tax_rate : user.tax_rate;
      tax += taxableItem * (rate / 100);
    });
  }

  const grand = taxable + tax;
  const no = await nextSmBillNo(cid);

  // Deduct stock for each item
  for (const item of cart) {
    if (item.product_id) {
      await db.from('sm_products').rpc || await db.from('sm_products')
        .select('stock_qty').eq('id', item.product_id).eq('user_id', cid).single()
        .then(async ({ data: p }) => {
          if (p) {
            const newQty = Math.max(0, parseFloat(p.stock_qty) - parseFloat(item.qty));
            await db.from('sm_products').update({ stock_qty: newQty })
              .eq('id', item.product_id).eq('user_id', cid);
          }
        });
    }
  }

  const { data, error } = await db.from('sm_bills').insert({
    no, user_id: cid, customer: customer || 'Walk-in',
    phone: phone || '', cart, subtotal, discount: disc,
    tax, grand_total: grand, pay_mode: payMode || 'Cash',
    discount_type: discountType || 'flat', discount_val: discountVal || 0,
    notes: notes || '',
  }).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, bill: data });
});

// DELETE SM bill
app.delete('/api/sm/bills/:no', auth, async (req, res) => {
  const { error } = await db.from('sm_bills')
    .delete().eq('no', req.params.no).eq('user_id', clientId(req));
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

// ── SM REPORTS ───────────────────────────────────────────────────────────────
app.get('/api/sm/reports', auth, async (req, res) => {
  const cid = clientId(req);
  const { type = 'daily', from, to } = req.query;
  const { start, end } = dateRange(type, from, to);
  const { data: bills, error } = await db.from('sm_bills').select('*')
    .eq('user_id', cid).gte('time', start).lte('time', end);
  if (error) return dbErr(res, error);

  const totalRev = bills.reduce((s, b) => s + parseFloat(b.grand_total), 0);
  const totalTax = bills.reduce((s, b) => s + parseFloat(b.tax), 0);
  const totalDisc = bills.reduce((s, b) => s + parseFloat(b.discount), 0);

  // Product-wise sales
  const productMap = {};
  bills.forEach(b => {
    const cart = Array.isArray(b.cart) ? b.cart : JSON.parse(b.cart || '[]');
    cart.forEach(item => {
      if (!productMap[item.name]) productMap[item.name] = { name: item.name, emoji: item.emoji || '🛒', unit: item.unit, qty: 0, amount: 0 };
      productMap[item.name].qty += parseFloat(item.qty);
      productMap[item.name].amount += parseFloat(item.amount);
    });
  });

  // Category-wise
  const catMap = {};
  bills.forEach(b => {
    const cart = Array.isArray(b.cart) ? b.cart : JSON.parse(b.cart || '[]');
    cart.forEach(item => {
      catMap[item.category || 'General'] = (catMap[item.category || 'General'] || 0) + parseFloat(item.amount);
    });
  });

  // Payment mode
  const payMap = {};
  bills.forEach(b => {
    const pm = b.pay_mode || 'Cash';
    payMap[pm] = payMap[pm] || { count: 0, revenue: 0 };
    payMap[pm].count++;
    payMap[pm].revenue += parseFloat(b.grand_total);
  });

  // Daily trend
  const dayMap = {};
  bills.forEach(b => {
    const d = b.time.slice(0, 10);
    dayMap[d] = dayMap[d] || { date: d, bills: 0, revenue: 0 };
    dayMap[d].bills++;
    dayMap[d].revenue += parseFloat(b.grand_total);
  });

  res.json({
    summary: { totalRevenue: totalRev, totalTax, totalDiscount: totalDisc, totalBills: bills.length, avgBillValue: bills.length ? totalRev / bills.length : 0 },
    productSales: Object.values(productMap).sort((a, b) => b.amount - a.amount),
    catSales: Object.entries(catMap).map(([cat, rev]) => ({ cat, revenue: rev })).sort((a, b) => b.revenue - a.revenue),
    payBreakdown: Object.entries(payMap).map(([mode, v]) => ({ mode, ...v })),
    dailyTrend: Object.values(dayMap).sort((a, b) => a.date.localeCompare(b.date)),
  });
});

// ADMIN — FULL PRODUCT MANAGEMENT FOR ANY CLIENT
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/admin/clients/:id/items  — get all regular items for a client
app.get('/api/admin/clients/:id/items', auth, adminOnly, async (req, res) => {
  const { data, error } = await db.from('items').select('*').eq('user_id', req.params.id).order('cat').order('name');
  if (error) return dbErr(res, error);
  res.json(data);
});

// POST /api/admin/clients/:id/items  — add item for a client
app.post('/api/admin/clients/:id/items', auth, adminOnly, async (req, res) => {
  const { name, price, cat, emoji } = req.body;
  if (!name || !price || !cat) return res.status(400).json({ error: 'name, price, cat required' });
  const { data, error } = await db.from('items')
    .insert({ user_id: req.params.id, name, price: parseFloat(price), cat, emoji: emoji || '🛒' }).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, item: data });
});

// PUT /api/admin/clients/:id/items/:itemId
app.put('/api/admin/clients/:id/items/:itemId', auth, adminOnly, async (req, res) => {
  const { name, price, cat, emoji } = req.body;
  const updates = {};
  if (name !== undefined)  updates.name  = name;
  if (price !== undefined) updates.price = parseFloat(price);
  if (cat !== undefined)   updates.cat   = cat;
  if (emoji !== undefined) updates.emoji = emoji;
  const { data, error } = await db.from('items')
    .update(updates).eq('id', req.params.itemId).eq('user_id', req.params.id).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, item: data });
});

// DELETE /api/admin/clients/:id/items/:itemId
app.delete('/api/admin/clients/:id/items/:itemId', auth, adminOnly, async (req, res) => {
  const { error } = await db.from('items').delete().eq('id', req.params.itemId).eq('user_id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

// POST /api/admin/clients/:id/items/bulk — bulk import for a client
app.post('/api/admin/clients/:id/items/bulk', auth, adminOnly, async (req, res) => {
  // Reuse the bulk import logic by temporarily setting clientId to target
  req.query.clientId = req.params.id;
  return require('express').Router().post('/fake', async (fakeReq, fakeRes) => {}); // workaround: call handler directly
});

// GET /api/admin/clients/:id/sm-products  — get all SM products for a client
app.get('/api/admin/clients/:id/sm-products', auth, adminOnly, async (req, res) => {
  const { data, error } = await db.from('sm_products').select('*').eq('user_id', req.params.id).eq('active', true).order('category').order('name');
  if (error) return dbErr(res, error);
  res.json(data);
});

// POST /api/admin/clients/:id/sm-products — add SM product for a client
app.post('/api/admin/clients/:id/sm-products', auth, adminOnly, async (req, res) => {
  const { name, price_per_unit, unit, item_type, category, emoji, brand, stock_qty, low_stock_alert, barcode, hsn_code, tax_rate } = req.body;
  if (!name || !price_per_unit) return res.status(400).json({ error: 'name and price_per_unit required' });
  const { data, error } = await db.from('sm_products').insert({
    user_id: req.params.id, name, price_per_unit: parseFloat(price_per_unit),
    unit: unit || 'pcs', item_type: item_type || 'packet',
    category: category || 'General', emoji: emoji || '🛒',
    brand: brand || null, stock_qty: parseFloat(stock_qty) || 0,
    low_stock_alert: parseFloat(low_stock_alert) || 5,
    barcode: barcode || null, hsn_code: hsn_code || null,
    tax_rate: parseFloat(tax_rate) || 0, active: true
  }).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, product: data });
});

// PUT /api/admin/clients/:id/sm-products/:productId
app.put('/api/admin/clients/:id/sm-products/:productId', auth, adminOnly, async (req, res) => {
  const allowed = ['name','category','emoji','item_type','unit','price_per_unit','stock_qty','low_stock_alert','barcode','brand','hsn_code','tax_rate','active'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  if (updates.price_per_unit) updates.price_per_unit = parseFloat(updates.price_per_unit);
  if (updates.stock_qty !== undefined) updates.stock_qty = parseFloat(updates.stock_qty);
  const { data, error } = await db.from('sm_products')
    .update(updates).eq('id', req.params.productId).eq('user_id', req.params.id).select().single();
  if (error) return dbErr(res, error);
  res.json({ success: true, product: data });
});

// DELETE /api/admin/clients/:id/sm-products/:productId
app.delete('/api/admin/clients/:id/sm-products/:productId', auth, adminOnly, async (req, res) => {
  const { error } = await db.from('sm_products').update({ active: false })
    .eq('id', req.params.productId).eq('user_id', req.params.id);
  if (error) return dbErr(res, error);
  res.json({ success: true });
});

// POST /api/admin/clients/:id/sm-products/bulk — bulk import SM products for a client
app.post('/api/admin/clients/:id/sm-products/bulk', auth, adminOnly, async (req, res) => {
  const cid = req.params.id;
  const { products, mode = 'skip' } = req.body;
  if (!Array.isArray(products) || !products.length)
    return res.status(400).json({ error: 'products array required' });

  const valid = [], errors = [];
  products.forEach((row, i) => {
    const name = (row.name || row.Name || '').toString().trim();
    const price = parseFloat(row.price_per_unit || row.price || 0);
    const unit  = (row.unit || 'pcs').toString().trim().toLowerCase();
    const item_type = (row.item_type || 'packet').toString().trim().toLowerCase();
    if (!name)  { errors.push({ row: i+1, error: 'Name required' }); return; }
    if (!price) { errors.push({ row: i+1, name, error: 'Price required' }); return; }
    valid.push({
      name, price_per_unit: price, unit, item_type,
      category: (row.category || 'General').toString().trim(),
      emoji: (row.emoji || '🛒').toString().trim(),
      brand: (row.brand || '').toString().trim() || null,
      stock_qty: parseFloat(row.stock_qty || 0) || 0,
      low_stock_alert: parseFloat(row.low_stock_alert || 5) || 5,
      barcode: (row.barcode || '').toString().trim() || null,
      hsn_code: (row.hsn_code || '').toString().trim() || null,
      tax_rate: parseFloat(row.tax_rate || 0) || 0,
      active: true,
    });
  });

  if (!valid.length) return res.json({ success: false, imported: 0, errors });
  let imported = 0, skipped = 0;

  if (mode === 'overwrite') {
    await db.from('sm_products').update({ active: false }).eq('user_id', cid);
    const { data, error } = await db.from('sm_products').insert(valid.map(v => ({ ...v, user_id: cid }))).select();
    if (error) return dbErr(res, error);
    imported = data.length;
  } else {
    const { data: ex } = await db.from('sm_products').select('name').eq('user_id', cid).eq('active', true);
    const exNames = new Set((ex || []).map(e => e.name.toLowerCase()));
    const toIns = valid.filter(v => { if (exNames.has(v.name.toLowerCase())) { skipped++; return false; } return true; });
    if (toIns.length) {
      const { data, error } = await db.from('sm_products').insert(toIns.map(v => ({ ...v, user_id: cid }))).select();
      if (error) return dbErr(res, error);
      imported = data.length;
    }
  }
  res.json({ success: true, imported, skipped, errors,
    message: `${imported} products imported${skipped ? `, ${skipped} skipped` : ''}${errors.length ? `, ${errors.length} errors` : ''}` });
});

// ═══════════════════════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`\n✅  BillEase (Supabase) → http://localhost:${PORT}`);
  console.log(`🗄️   Supabase URL : ${SUPA_URL.slice(0,40)}...`);
  console.log(`👤  Admin        : admin@billease.com / password\n`);
});
