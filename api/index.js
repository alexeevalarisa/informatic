const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'it-platform-secret-key-2024';

// Создаём папку для данных
const DATA_DIR = process.env.RENDER ? '/tmp' : path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'database.sqlite');

// Подключаем SQLite
const db = new sqlite3.Database(DB_PATH);

// Создаём таблицы
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    name TEXT,
    lastName TEXT,
    firstName TEXT,
    classId TEXT,
    createdAt TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS classes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    createdAt TEXT,
    createdBy TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS lessons (
    id TEXT PRIMARY KEY,
    classId TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    content TEXT,
    createdAt TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS lesson_files (
    id TEXT PRIMARY KEY,
    lessonId TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT,
    size INTEGER,
    data TEXT,
    uploadedAt TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    lessonId TEXT NOT NULL,
    studentId TEXT NOT NULL,
    text TEXT,
    fileName TEXT,
    fileType TEXT,
    fileSize INTEGER,
    fileData TEXT,
    grade INTEGER,
    feedback TEXT,
    submittedAt TEXT,
    gradedAt TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS notes (
    id TEXT PRIMARY KEY,
    classId TEXT,
    studentId TEXT,
    content TEXT NOT NULL,
    createdAt TEXT,
    createdBy TEXT
  )`);
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Multer
const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ===== AUTH =====
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Требуется авторизация' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Неверный токен' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Доступ запрещён' });
  next();
}

// ===== HELPERS =====
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

// ===== AUTH ROUTES =====
app.post('/api/auth/setup', async (req, res) => {
  const { username, password } = req.body;
  const existing = await dbGet('SELECT * FROM users WHERE role = ?', ['admin']);
  if (existing) return res.status(400).json({ error: 'Администратор уже создан' });

  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();
  const now = new Date().toISOString();
  await dbRun('INSERT INTO users (id, username, password, role, name, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
    [id, username, hashed, 'admin', 'Администратор', now]);

  const token = jwt.sign({ id, role: 'admin', username }, JWT_SECRET);
  res.json({ token, user: { id, username, role: 'admin', name: 'Администратор' } });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
  if (!user) return res.status(400).json({ error: 'Неверный логин или пароль' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Неверный логин или пароль' });

  const token = jwt.sign({ id: user.id, role: user.role, username: user.username }, JWT_SECRET);
  res.json({
    token,
    user: { id: user.id, username: user.username, role: user.role, name: user.name, classId: user.classId }
  });
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const user = await dbGet('SELECT id, username, role, name, classId FROM users WHERE id = ?', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json(user);
});

// ===== CLASSES =====
app.post('/api/classes', authMiddleware, adminOnly, async (req, res) => {
  const { name, description } = req.body;
  const id = uuidv4();
  const now = new Date().toISOString();
  await dbRun('INSERT INTO classes (id, name, description, createdAt, createdBy) VALUES (?, ?, ?, ?, ?)',
    [id, name, description || '', now, req.user.id]);
  res.json({ id, name, description: description || '', createdAt: now, createdBy: req.user.id });
});

app.get('/api/classes', authMiddleware, adminOnly, async (req, res) => {
  const classes = await dbAll('SELECT * FROM classes ORDER BY createdAt DESC');
  res.json(classes);
});

app.get('/api/classes/:id', authMiddleware, async (req, res) => {
  const cls = await dbGet('SELECT * FROM classes WHERE id = ?', [req.params.id]);
  if (!cls) return res.status(404).json({ error: 'Класс не найден' });
  if (req.user.role === 'student' && req.user.classId !== cls.id) return res.status(403).json({ error: 'Доступ запрещён' });

  const students = await dbAll('SELECT id, username, name, lastName, firstName, classId FROM users WHERE role = ? AND classId = ?', ['student', cls.id]);
  const lessons = await dbAll('SELECT * FROM lessons WHERE classId = ? ORDER BY createdAt DESC', [cls.id]);
  res.json({ ...cls, students, lessons });
});

app.delete('/api/classes/:id', authMiddleware, adminOnly, async (req, res) => {
  await dbRun('DELETE FROM notes WHERE classId = ?', [req.params.id]);
  const students = await dbAll('SELECT id FROM users WHERE classId = ?', [req.params.id]);
  for (const s of students) {
    await dbRun('DELETE FROM submissions WHERE studentId = ?', [s.id]);
    await dbRun('DELETE FROM notes WHERE studentId = ?', [s.id]);
  }
  await dbRun('DELETE FROM users WHERE classId = ?', [req.params.id]);
  const lessons = await dbAll('SELECT id FROM lessons WHERE classId = ?', [req.params.id]);
  for (const l of lessons) {
    await dbRun('DELETE FROM lesson_files WHERE lessonId = ?', [l.id]);
    await dbRun('DELETE FROM submissions WHERE lessonId = ?', [l.id]);
  }
  await dbRun('DELETE FROM lessons WHERE classId = ?', [req.params.id]);
  await dbRun('DELETE FROM classes WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ===== STUDENTS =====
app.post('/api/classes/:id/students', authMiddleware, adminOnly, async (req, res) => {
  const { lastName, firstName, username, password } = req.body;
  const classId = req.params.id;

  const cls = await dbGet('SELECT * FROM classes WHERE id = ?', [classId]);
  if (!cls) return res.status(404).json({ error: 'Класс не найден' });

  const existing = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
  if (existing) return res.status(400).json({ error: 'Логин уже занят' });

  const hashed = await bcrypt.hash(password, 10);
  const id = uuidv4();
  const now = new Date().toISOString();
  await dbRun('INSERT INTO users (id, username, password, role, name, lastName, firstName, classId, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [id, username, hashed, 'student', `${lastName} ${firstName}`, lastName, firstName, classId, now]);

  res.json({ id, username, name: `${lastName} ${firstName}`, lastName, firstName, classId, createdAt: now });
});

app.get('/api/classes/:id/students', authMiddleware, async (req, res) => {
  if (req.user.role === 'student' && req.user.classId !== req.params.id) return res.status(403).json({ error: 'Доступ запрещён' });
  const students = await dbAll('SELECT id, username, name, lastName, firstName, classId FROM users WHERE role = ? AND classId = ?', ['student', req.params.id]);
  res.json(students);
});

app.delete('/api/students/:id', authMiddleware, adminOnly, async (req, res) => {
  await dbRun('DELETE FROM submissions WHERE studentId = ?', [req.params.id]);
  await dbRun('DELETE FROM notes WHERE studentId = ?', [req.params.id]);
  await dbRun('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ===== NOTES =====
app.post('/api/notes', authMiddleware, adminOnly, async (req, res) => {
  const { classId, studentId, content } = req.body;
  const id = uuidv4();
  const now = new Date().toISOString();
  await dbRun('INSERT INTO notes (id, classId, studentId, content, createdAt, createdBy) VALUES (?, ?, ?, ?, ?, ?)',
    [id, classId || null, studentId || null, content, now, req.user.id]);
  res.json({ id, classId: classId || null, studentId: studentId || null, content, createdAt: now });
});

app.get('/api/notes', authMiddleware, adminOnly, async (req, res) => {
  const { classId, studentId } = req.query;
  let sql = 'SELECT * FROM notes WHERE 1=1';
  const params = [];
  if (classId) { sql += ' AND classId = ?'; params.push(classId); }
  if (studentId) { sql += ' AND studentId = ?'; params.push(studentId); }
  sql += ' ORDER BY createdAt DESC';
  const notes = await dbAll(sql, params);
  res.json(notes);
});

app.delete('/api/notes/:id', authMiddleware, adminOnly, async (req, res) => {
  await dbRun('DELETE FROM notes WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ===== LESSONS =====
app.post('/api/lessons', authMiddleware, adminOnly, async (req, res) => {
  const { classId, title, description, content } = req.body;
  const id = uuidv4();
  const now = new Date().toISOString();
  await dbRun('INSERT INTO lessons (id, classId, title, description, content, createdAt) VALUES (?, ?, ?, ?, ?, ?)',
    [id, classId, title, description || '', content || '', now]);
  res.json({ id, classId, title, description: description || '', content: content || '', createdAt: now });
});

app.get('/api/classes/:id/lessons', authMiddleware, async (req, res) => {
  if (req.user.role === 'student' && req.user.classId !== req.params.id) return res.status(403).json({ error: 'Доступ запрещён' });
  const lessons = await dbAll('SELECT * FROM lessons WHERE classId = ? ORDER BY createdAt DESC', [req.params.id]);
  res.json(lessons);
});

app.get('/api/lessons/:id', authMiddleware, async (req, res) => {
  const lesson = await dbGet('SELECT * FROM lessons WHERE id = ?', [req.params.id]);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
  if (req.user.role === 'student' && req.user.classId !== lesson.classId) return res.status(403).json({ error: 'Доступ запрещён' });

  const files = await dbAll('SELECT id, name, type, size, uploadedAt FROM lesson_files WHERE lessonId = ?', [req.params.id]);
  res.json({ ...lesson, files });
});

app.put('/api/lessons/:id', authMiddleware, adminOnly, async (req, res) => {
  const { title, description, content } = req.body;
  const lesson = await dbGet('SELECT * FROM lessons WHERE id = ?', [req.params.id]);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
  await dbRun('UPDATE lessons SET title = ?, description = ?, content = ? WHERE id = ?',
    [title || lesson.title, description !== undefined ? description : lesson.description, content !== undefined ? content : lesson.content, req.params.id]);
  const updated = await dbGet('SELECT * FROM lessons WHERE id = ?', [req.params.id]);
  const files = await dbAll('SELECT id, name, type, size, uploadedAt FROM lesson_files WHERE lessonId = ?', [req.params.id]);
  res.json({ ...updated, files });
});

app.delete('/api/lessons/:id', authMiddleware, adminOnly, async (req, res) => {
  await dbRun('DELETE FROM lesson_files WHERE lessonId = ?', [req.params.id]);
  await dbRun('DELETE FROM submissions WHERE lessonId = ?', [req.params.id]);
  await dbRun('DELETE FROM lessons WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ===== FILES =====
app.post('/api/lessons/:id/files', authMiddleware, adminOnly, upload.single('file'), async (req, res) => {
  const lesson = await dbGet('SELECT * FROM lessons WHERE id = ?', [req.params.id]);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
  if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });

  const id = uuidv4();
  const now = new Date().toISOString();
  await dbRun('INSERT INTO lesson_files (id, lessonId, name, type, size, data, uploadedAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [id, req.params.id, req.file.originalname, req.file.mimetype, req.file.size, req.file.buffer.toString('base64'), now]);
  res.json({ id, name: req.file.originalname, type: req.file.mimetype, size: req.file.size, uploadedAt: now });
});

app.get('/api/files/:lessonId/:fileId', authMiddleware, async (req, res) => {
  const lesson = await dbGet('SELECT * FROM lessons WHERE id = ?', [req.params.lessonId]);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
  if (req.user.role === 'student' && req.user.classId !== lesson.classId) return res.status(403).json({ error: 'Доступ запрещён' });

  const file = await dbGet('SELECT * FROM lesson_files WHERE id = ? AND lessonId = ?', [req.params.fileId, req.params.lessonId]);
  if (!file) return res.status(404).json({ error: 'Файл не найден' });

  const buffer = Buffer.from(file.data, 'base64');
  res.setHeader('Content-Type', file.type);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
  res.send(buffer);
});

app.delete('/api/lessons/:lessonId/files/:fileId', authMiddleware, adminOnly, async (req, res) => {
  await dbRun('DELETE FROM lesson_files WHERE id = ? AND lessonId = ?', [req.params.fileId, req.params.lessonId]);
  res.json({ success: true });
});

// ===== SUBMISSIONS =====
app.post('/api/lessons/:id/submissions', authMiddleware, upload.single('file'), async (req, res) => {
  const lesson = await dbGet('SELECT * FROM lessons WHERE id = ?', [req.params.id]);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Только ученики могут отправлять ответы' });
  if (req.user.classId !== lesson.classId) return res.status(403).json({ error: 'Доступ запрещён' });

  await dbRun('DELETE FROM submissions WHERE lessonId = ? AND studentId = ?', [req.params.id, req.user.id]);

  const id = uuidv4();
  const now = new Date().toISOString();
  const file = req.file ? {
    name: req.file.originalname,
    type: req.file.mimetype,
    size: req.file.size,
    data: req.file.buffer.toString('base64')
  } : null;

  await dbRun('INSERT INTO submissions (id, lessonId, studentId, text, fileName, fileType, fileSize, fileData, grade, feedback, submittedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    [id, req.params.id, req.user.id, req.body.text || '', file ? file.name : null, file ? file.type : null, file ? file.size : null, file ? file.data : null, null, null, now]);

  res.json({ id, lessonId: req.params.id, studentId: req.user.id, text: req.body.text || '', file, grade: null, feedback: '', submittedAt: now });
});

app.get('/api/lessons/:id/submissions', authMiddleware, adminOnly, async (req, res) => {
  const submissions = await dbAll('SELECT * FROM submissions WHERE lessonId = ? ORDER BY submittedAt DESC', [req.params.id]);
  const result = [];
  for (const s of submissions) {
    const student = await dbGet('SELECT name, username FROM users WHERE id = ?', [s.studentId]);
    result.push({
      ...s,
      studentName: student ? student.name : 'Неизвестно',
      studentUsername: student ? student.username : '',
      file: s.fileName ? { name: s.fileName, type: s.fileType, size: s.fileSize } : null
    });
  }
  res.json(result);
});

app.get('/api/my-submissions', authMiddleware, async (req, res) => {
  if (req.user.role !== 'student') return res.status(403).json({ error: 'Доступ запрещён' });
  const submissions = await dbAll('SELECT * FROM submissions WHERE studentId = ? ORDER BY submittedAt DESC', [req.user.id]);
  res.json(submissions.map(s => ({
    ...s,
    file: s.fileName ? { name: s.fileName, type: s.fileType, size: s.fileSize } : null
  })));
});

app.put('/api/submissions/:id/grade', authMiddleware, adminOnly, async (req, res) => {
  const { grade, feedback } = req.body;
  const now = new Date().toISOString();
  await dbRun('UPDATE submissions SET grade = ?, feedback = ?, gradedAt = ? WHERE id = ?',
    [grade, feedback || '', now, req.params.id]);
  const sub = await dbGet('SELECT * FROM submissions WHERE id = ?', [req.params.id]);
  res.json({ ...sub, file: sub.fileName ? { name: sub.fileName, type: sub.fileType, size: sub.fileSize } : null });
});

app.get('/api/submissions/:id/file', authMiddleware, async (req, res) => {
  const sub = await dbGet('SELECT * FROM submissions WHERE id = ?', [req.params.id]);
  if (!sub) return res.status(404).json({ error: 'Ответ не найден' });
  if (req.user.role === 'student' && req.user.id !== sub.studentId) return res.status(403).json({ error: 'Доступ запрещён' });
  if (!sub.fileData) return res.status(404).json({ error: 'Файл не найден' });

  const buffer = Buffer.from(sub.fileData, 'base64');
  res.setHeader('Content-Type', sub.fileType);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(sub.fileName)}"`);
  res.send(buffer);
});

// ===== EXPORT =====
app.get('/api/classes/:id/export', authMiddleware, adminOnly, async (req, res) => {
  const cls = await dbGet('SELECT * FROM classes WHERE id = ?', [req.params.id]);
  if (!cls) return res.status(404).json({ error: 'Класс не найден' });
  const students = await dbAll('SELECT lastName, firstName, username FROM users WHERE role = ? AND classId = ?', ['student', req.params.id]);
  res.json({ className: cls.name, students: students.map(s => ({ Фамилия: s.lastName, Имя: s.firstName, Логин: s.username, Пароль: '********' })) });
});

// ===== STATS =====
app.get('/api/stats', authMiddleware, adminOnly, async (req, res) => {
  const classes = await dbGet('SELECT COUNT(*) as c FROM classes');
  const students = await dbGet('SELECT COUNT(*) as c FROM users WHERE role = ?', ['student']);
  const lessons = await dbGet('SELECT COUNT(*) as c FROM lessons');
  const submissions = await dbGet('SELECT COUNT(*) as c FROM submissions');
  res.json({
    totalClasses: classes.c,
    totalStudents: students.c,
    totalLessons: lessons.c,
    totalSubmissions: submissions.c
  });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Catch-all для SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
