/**
 * 云监控调度平台 - 信息报送系统
 * 后端服务：Node.js + Express
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const REPORTS_FILE = path.join(DATA_DIR, 'reports.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

// 确保数据目录存在
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
// 工具函数
// ─────────────────────────────────────────────
function loadJSON(file, defaultVal) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {}
  return defaultVal;
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}
function hash(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}
function genToken() {
  return crypto.randomBytes(32).toString('hex');
}
function today() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
}

// ─────────────────────────────────────────────
// 初始化默认用户数据
// ─────────────────────────────────────────────
function initUsers() {
  if (fs.existsSync(USERS_FILE)) return;
  const users = [
    // 轮值值班长（尊远投资）
    { id: 'u001', username: 'chouzw',   password: hash('zytz2026'), name: '丑子文', role: 'admin', company: '尊远投资',          phone: '' },
    { id: 'u002', username: 'lixr',     password: hash('zytz2026'), name: '李晓锐', role: 'admin', company: '尊远投资',          phone: '15141120968' },
    { id: 'u003', username: 'fanjw',    password: hash('zytz2026'), name: '范家玮', role: 'duty',  company: '尊远投资',          phone: '' },
    { id: 'u004', username: 'yinyf',    password: hash('zytz2026'), name: '尹宜凡', role: 'duty',  company: '尊远投资',          phone: '' },
    // 信息报送员
    { id: 'u101', username: 'huanpeng', password: hash('hp2026'),   name: '门闻',   role: 'reporter', company: '中山希尔顿欢朋酒店', phone: '' },
    { id: 'u102', username: 'haizun',   password: hash('hz2026'),   name: '贺恕',   role: 'reporter', company: '海尊酒店',           phone: '' },
    { id: 'u103', username: 'zhixuan',  password: hash('zx2026'),   name: '李颖',   role: 'reporter', company: '智选假日酒店',       phone: '' },
    { id: 'u104', username: 'yaduo',    password: hash('yd2026'),   name: '于秀丽', role: 'reporter', company: '亚朵酒店',           phone: '' },
    { id: 'u105', username: 'jiancai',  password: hash('jc2026'),   name: '傅建华', role: 'reporter', company: '尊远建材',           phone: '' },
    { id: 'u106', username: 'sifangda', password: hash('sfd2026'),  name: '张君',   role: 'reporter', company: '辽宁思方达',         phone: '' },
    { id: 'u107', username: 'jlsfd',   password: hash('sfd2026'),  name: '（待定）', role: 'reporter', company: '吉林思方达',         phone: '' },
  ];
  saveJSON(USERS_FILE, users);
}
initUsers();

// ─────────────────────────────────────────────
// Session 管理
// ─────────────────────────────────────────────
function getSessions() { return loadJSON(SESSIONS_FILE, {}); }
function saveSessions(s) { saveJSON(SESSIONS_FILE, s); }

function authenticate(req, res, next) {
  const token = req.headers['x-token'];
  const sessions = getSessions();
  const uid = sessions[token];
  if (!uid) return res.status(401).json({ error: '请先登录' });
  const users = loadJSON(USERS_FILE, []);
  const user = users.find(u => u.id === uid);
  if (!user) return res.status(401).json({ error: '用户不存在' });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin' && req.user.role !== 'duty') {
    return res.status(403).json({ error: '无权限，仅值班长/管理员可操作' });
  }
  next();
}

// ─────────────────────────────────────────────
// API 路由
// ─────────────────────────────────────────────

// 登录
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.json({ ok: false, msg: '请输入账号和密码' });
  const users = loadJSON(USERS_FILE, []);
  const user = users.find(u => u.username === username && u.password === hash(password));
  if (!user) return res.json({ ok: false, msg: '账号或密码错误' });
  const token = genToken();
  const sessions = getSessions();
  sessions[token] = user.id;
  saveSessions(sessions);
  res.json({ ok: true, token, user: { id: user.id, name: user.name, role: user.role, company: user.company } });
});

// 登出
app.post('/api/logout', authenticate, (req, res) => {
  const token = req.headers['x-token'];
  const sessions = getSessions();
  delete sessions[token];
  saveSessions(sessions);
  res.json({ ok: true });
});

// 获取当前用户信息
app.get('/api/me', authenticate, (req, res) => {
  const { password, ...safeUser } = req.user;
  res.json({ ok: true, user: safeUser });
});

// 修改密码
app.post('/api/change-password', authenticate, (req, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return res.json({ ok: false, msg: '参数不完整' });
  const users = loadJSON(USERS_FILE, []);
  const idx = users.findIndex(u => u.id === req.user.id);
  if (users[idx].password !== hash(oldPassword)) return res.json({ ok: false, msg: '原密码错误' });
  users[idx].password = hash(newPassword);
  saveJSON(USERS_FILE, users);
  res.json({ ok: true, msg: '密码修改成功' });
});

// ─────────────────────────────────────────────
// 日报相关
// ─────────────────────────────────────────────

// 提交/更新报送信息
app.post('/api/report', authenticate, (req, res) => {
  const { date, data } = req.body;
  const reportDate = date || today();
  const reports = loadJSON(REPORTS_FILE, {});
  if (!reports[reportDate]) reports[reportDate] = {};
  const company = req.user.company;
  reports[reportDate][company] = {
    ...data,
    company,
    reporter: req.user.name,
    reporterPhone: req.user.phone,
    reporterId: req.user.id,
    submittedAt: new Date().toISOString(),
  };
  saveJSON(REPORTS_FILE, reports);
  res.json({ ok: true, msg: '报送成功' });
});

// 获取本公司今日报送（报送员只能看自己公司）
app.get('/api/report/mine', authenticate, (req, res) => {
  const date = req.query.date || today();
  const reports = loadJSON(REPORTS_FILE, {});
  const myReport = reports[date]?.[req.user.company] || null;
  res.json({ ok: true, date, report: myReport });
});

// 获取所有公司今日报送（仅管理员/值班长）
app.get('/api/report/all', authenticate, requireAdmin, (req, res) => {
  const date = req.query.date || today();
  const reports = loadJSON(REPORTS_FILE, {});
  const dayReports = reports[date] || {};
  // 获取所有子公司列表
  const users = loadJSON(USERS_FILE, []);
  const companies = [...new Set(users.filter(u => u.role === 'reporter').map(u => u.company))];
  res.json({ ok: true, date, reports: dayReports, companies });
});

// 获取历史日期列表（管理员用）
app.get('/api/report/dates', authenticate, requireAdmin, (req, res) => {
  const reports = loadJSON(REPORTS_FILE, {});
  const dates = Object.keys(reports).sort().reverse();
  res.json({ ok: true, dates });
});

// 管理员：获取用户列表
app.get('/api/users', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '无权限' });
  const users = loadJSON(USERS_FILE, []).map(u => {
    const { password, ...safe } = u;
    return safe;
  });
  res.json({ ok: true, users });
});

// 管理员：重置用户密码
app.post('/api/users/reset-password', authenticate, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '无权限' });
  const { userId, newPassword } = req.body;
  const users = loadJSON(USERS_FILE, []);
  const idx = users.findIndex(u => u.id === userId);
  if (idx < 0) return res.json({ ok: false, msg: '用户不存在' });
  users[idx].password = hash(newPassword);
  saveJSON(USERS_FILE, users);
  res.json({ ok: true, msg: '密码重置成功' });
});

// 启动服务
app.listen(PORT, '0.0.0.0', () => {
  console.log(`云监控调度平台服务已启动：http://localhost:${PORT}`);
  console.log(`局域网访问：http://<本机IP>:${PORT}`);
});
