const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcrypt');
const pool    = require('./db');
const path    = require('path');
const app     = express();

app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: 'secret123',
  resave: false,
  saveUninitialized: false,
}));

// ── Middleware ──────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.user)
    return res.status(401).json({ error: 'Не авторизован' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Нет доступа' });
  next();
}

// ── AUTH ────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { login, password, full_name, phone, email } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users
        (login,password,full_name,phone,email)
       VALUES ($1,$2,$3,$4,$5)`,
      [login, hashed, full_name, phone, email]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'Логин или email занят' });
  }
});

app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  const r = await pool.query(
    'SELECT * FROM users WHERE login=$1', [login]);
  const user = r.rows[0];
  if (!user) return res.status(401)
    .json({ error: 'Неверный логин или пароль' });

  let valid = false;
  if (user.role === 'admin') {
    valid = password === user.password; // админ без хэша
  } else {
    valid = await bcrypt.compare(password, user.password);
  }
  if (!valid) return res.status(401)
    .json({ error: 'Неверный логин или пароль' });

  req.session.user = {
    id: user.id, login: user.login, role: user.role };
  res.json({ ok: true, role: user.role });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user)
    return res.status(401).json({ error: 'Нет' });
  res.json(req.session.user);
});

// ── APPLICATIONS (CRUD) ─────────────────────
// Создать заявку
app.post('/api/applications', requireAuth,
  async (req, res) => {
  const { title, date_field, extra_field } = req.body;
  await pool.query(
    `INSERT INTO applications
      (user_id,title,date_field,extra_field)
     VALUES ($1,$2,$3,$4)`,
    [req.session.user.id, title, date_field, extra_field]);
  res.json({ ok: true });
});

// Мои заявки
app.get('/api/applications/my', requireAuth,
  async (req, res) => {
  const r = await pool.query(
    `SELECT * FROM applications
     WHERE user_id=$1
     ORDER BY created_at DESC`,
    [req.session.user.id]);
  res.json(r.rows);
});

// Все заявки (админ)
app.get('/api/applications/all', requireAdmin, async (req, res) => {
  const r = await pool.query(`
    SELECT a.*, u.full_name, u.email,
      COALESCE(
        (SELECT review_text FROM reviews
         WHERE application_id = a.id
         ORDER BY created_at DESC LIMIT 1),
        ''
      ) AS review_text
    FROM applications a
    JOIN users u ON a.user_id = u.id
    ORDER BY a.created_at DESC
  `);
  res.json(r.rows);
});

// Изменить статус (админ)
app.put('/api/applications/:id/status', requireAdmin,
  async (req, res) => {
  const { status } = req.body;
  await pool.query(
    'UPDATE applications SET status=$1 WHERE id=$2',
    [status, req.params.id]);
  res.json({ ok: true });
});

// Удалить заявку
app.delete('/api/applications/:id', requireAuth,
  async (req, res) => {
  await pool.query(
    'DELETE FROM applications WHERE id=$1',
    [req.params.id]);
  res.json({ ok: true });
});

// ── REVIEWS ────────────────────────────────
app.post('/api/reviews', requireAuth,
  async (req, res) => {
  const { application_id, review_text } = req.body;
  await pool.query(
    `INSERT INTO reviews
      (application_id,user_id,review_text)
     VALUES ($1,$2,$3)`,
    [application_id, req.session.user.id, review_text]);
  res.json({ ok: true });
});

// ── СТРАНИЦЫ ───────────────────────────────
const page = f => (req, res) =>
  res.sendFile(path.join(__dirname, 'public', f));

app.get('/',          page('index.html'));
app.get('/register',  page('register.html'));
app.get('/dashboard', page('dashboard.html'));
app.get('/apply',     page('apply.html'));
app.get('/admin',     page('admin.html'));

app.listen(3000, () =>
  console.log('http://localhost:3000'));