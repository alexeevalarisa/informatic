const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'it-platform-secret-key-2024';

// In-memory хранилище (для демо; для продакшена используйте MongoDB/PostgreSQL)
let db = {
  users: [],
  classes: [],
  lessons: [],
  submissions: [],
  notes: [],
  files: []
};

// Загрузка данных из файла (если есть)
const DB_FILE = '/tmp/db.json';
if (fs.existsSync(DB_FILE)) {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    console.log('Could not load DB file');
  }
}

function saveDB() {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
  } catch (e) {
    console.log('Could not save DB');
  }
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Multer для загрузки файлов
const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ===== AUTH MIDDLEWARE =====
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
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }
  next();
}

// ===== AUTH ROUTES =====

// Регистрация админа (первый запуск)
app.post('/api/auth/setup', async (req, res) => {
  const { username, password } = req.body;

  const existingAdmin = db.users.find(u => u.role === 'admin');
  if (existingAdmin) {
    return res.status(400).json({ error: 'Администратор уже создан' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const admin = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    role: 'admin',
    name: 'Администратор',
    createdAt: new Date().toISOString()
  };

  db.users.push(admin);
  saveDB();

  const token = jwt.sign({ id: admin.id, role: admin.role, username: admin.username }, JWT_SECRET);
  res.json({ token, user: { id: admin.id, username: admin.username, role: admin.role, name: admin.name } });
});

// Логин
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'Неверный логин или пароль' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Неверный логин или пароль' });

  const token = jwt.sign({ id: user.id, role: user.role, username: user.username }, JWT_SECRET);
  res.json({ 
    token, 
    user: { 
      id: user.id, 
      username: user.username, 
      role: user.role, 
      name: user.name,
      classId: user.classId || null
    } 
  });
});

// Проверка токена
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

  res.json({ 
    id: user.id, 
    username: user.username, 
    role: user.role, 
    name: user.name,
    classId: user.classId || null
  });
});

// ===== CLASSES ROUTES =====

// Создать класс
app.post('/api/classes', authMiddleware, adminOnly, (req, res) => {
  const { name, description } = req.body;

  const newClass = {
    id: uuidv4(),
    name,
    description: description || '',
    createdAt: new Date().toISOString(),
    createdBy: req.user.id
  };

  db.classes.push(newClass);
  saveDB();
  res.json(newClass);
});

// Получить все классы
app.get('/api/classes', authMiddleware, adminOnly, (req, res) => {
  res.json(db.classes);
});

// Получить один класс
app.get('/api/classes/:id', authMiddleware, (req, res) => {
  const cls = db.classes.find(c => c.id === req.params.id);
  if (!cls) return res.status(404).json({ error: 'Класс не найден' });

  // Ученик может видеть только свой класс
  if (req.user.role === 'student' && req.user.classId !== cls.id) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }

  const students = db.users.filter(u => u.role === 'student' && u.classId === cls.id);
  const lessons = db.lessons.filter(l => l.classId === cls.id);

  res.json({ ...cls, students, lessons });
});

// Удалить класс
app.delete('/api/classes/:id', authMiddleware, adminOnly, (req, res) => {
  db.classes = db.classes.filter(c => c.id !== req.params.id);
  db.users = db.users.filter(u => !(u.role === 'student' && u.classId === req.params.id));
  db.lessons = db.lessons.filter(l => l.classId !== req.params.id);
  db.notes = db.notes.filter(n => n.classId !== req.params.id);
  saveDB();
  res.json({ success: true });
});

// ===== STUDENTS ROUTES =====

// Добавить ученика в класс
app.post('/api/classes/:id/students', authMiddleware, adminOnly, async (req, res) => {
  const { lastName, firstName, username, password } = req.body;
  const classId = req.params.id;

  const cls = db.classes.find(c => c.id === classId);
  if (!cls) return res.status(404).json({ error: 'Класс не найден' });

  const existing = db.users.find(u => u.username === username);
  if (existing) return res.status(400).json({ error: 'Логин уже занят' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const student = {
    id: uuidv4(),
    username,
    password: hashedPassword,
    role: 'student',
    name: `${lastName} ${firstName}`,
    lastName,
    firstName,
    classId,
    createdAt: new Date().toISOString()
  };

  db.users.push(student);
  saveDB();
  res.json({ 
    id: student.id, 
    username: student.username, 
    name: student.name,
    lastName: student.lastName,
    firstName: student.firstName,
    classId: student.classId,
    createdAt: student.createdAt
  });
});

// Получить учеников класса
app.get('/api/classes/:id/students', authMiddleware, (req, res) => {
  const classId = req.params.id;

  if (req.user.role === 'student' && req.user.classId !== classId) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }

  const students = db.users
    .filter(u => u.role === 'student' && u.classId === classId)
    .map(u => ({ id: u.id, username: u.username, name: u.name, lastName: u.lastName, firstName: u.firstName, classId: u.classId }));

  res.json(students);
});

// Удалить ученика
app.delete('/api/students/:id', authMiddleware, adminOnly, (req, res) => {
  db.users = db.users.filter(u => u.id !== req.params.id);
  db.submissions = db.submissions.filter(s => s.studentId !== req.params.id);
  db.notes = db.notes.filter(n => n.studentId !== req.params.id);
  saveDB();
  res.json({ success: true });
});

// ===== NOTES ROUTES =====

// Создать заметку
app.post('/api/notes', authMiddleware, adminOnly, (req, res) => {
  const { classId, studentId, content } = req.body;

  const note = {
    id: uuidv4(),
    classId: classId || null,
    studentId: studentId || null,
    content,
    createdAt: new Date().toISOString(),
    createdBy: req.user.id
  };

  db.notes.push(note);
  saveDB();
  res.json(note);
});

// Получить заметки (только админ)
app.get('/api/notes', authMiddleware, adminOnly, (req, res) => {
  const { classId, studentId } = req.query;
  let notes = db.notes;

  if (classId) notes = notes.filter(n => n.classId === classId);
  if (studentId) notes = notes.filter(n => n.studentId === studentId);

  res.json(notes);
});

// Удалить заметку
app.delete('/api/notes/:id', authMiddleware, adminOnly, (req, res) => {
  db.notes = db.notes.filter(n => n.id !== req.params.id);
  saveDB();
  res.json({ success: true });
});

// ===== LESSONS ROUTES =====

// Создать урок
app.post('/api/lessons', authMiddleware, adminOnly, (req, res) => {
  const { classId, title, description, content } = req.body;

  const lesson = {
    id: uuidv4(),
    classId,
    title,
    description: description || '',
    content: content || '',
    files: [],
    createdAt: new Date().toISOString()
  };

  db.lessons.push(lesson);
  saveDB();
  res.json(lesson);
});

// Получить уроки класса
app.get('/api/classes/:id/lessons', authMiddleware, (req, res) => {
  const classId = req.params.id;

  if (req.user.role === 'student' && req.user.classId !== classId) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }

  const lessons = db.lessons.filter(l => l.classId === classId);
  res.json(lessons);
});

// Получить один урок
app.get('/api/lessons/:id', authMiddleware, (req, res) => {
  const lesson = db.lessons.find(l => l.id === req.params.id);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

  if (req.user.role === 'student' && req.user.classId !== lesson.classId) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }

  res.json(lesson);
});

// Обновить урок
app.put('/api/lessons/:id', authMiddleware, adminOnly, (req, res) => {
  const lesson = db.lessons.find(l => l.id === req.params.id);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

  const { title, description, content } = req.body;
  if (title) lesson.title = title;
  if (description !== undefined) lesson.description = description;
  if (content !== undefined) lesson.content = content;

  saveDB();
  res.json(lesson);
});

// Удалить урок
app.delete('/api/lessons/:id', authMiddleware, adminOnly, (req, res) => {
  db.lessons = db.lessons.filter(l => l.id !== req.params.id);
  db.submissions = db.submissions.filter(s => s.lessonId !== req.params.id);
  saveDB();
  res.json({ success: true });
});

// ===== FILES ROUTES =====

// Загрузить файл к уроку
app.post('/api/lessons/:id/files', authMiddleware, adminOnly, upload.single('file'), (req, res) => {
  const lesson = db.lessons.find(l => l.id === req.params.id);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

  if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });

  const fileData = {
    id: uuidv4(),
    name: req.file.originalname,
    type: req.file.mimetype,
    size: req.file.size,
    data: req.file.buffer.toString('base64'),
    uploadedAt: new Date().toISOString()
  };

  lesson.files.push(fileData);
  saveDB();
  res.json(fileData);
});

// Скачать файл
app.get('/api/files/:lessonId/:fileId', authMiddleware, (req, res) => {
  const lesson = db.lessons.find(l => l.id === req.params.lessonId);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

  if (req.user.role === 'student' && req.user.classId !== lesson.classId) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }

  const file = lesson.files.find(f => f.id === req.params.fileId);
  if (!file) return res.status(404).json({ error: 'Файл не найден' });

  const buffer = Buffer.from(file.data, 'base64');
  res.setHeader('Content-Type', file.type);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
  res.send(buffer);
});

// Удалить файл
app.delete('/api/lessons/:lessonId/files/:fileId', authMiddleware, adminOnly, (req, res) => {
  const lesson = db.lessons.find(l => l.id === req.params.lessonId);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

  lesson.files = lesson.files.filter(f => f.id !== req.params.fileId);
  saveDB();
  res.json({ success: true });
});

// ===== SUBMISSIONS ROUTES =====

// Ученик загружает ответ
app.post('/api/lessons/:id/submissions', authMiddleware, upload.single('file'), (req, res) => {
  const lesson = db.lessons.find(l => l.id === req.params.id);
  if (!lesson) return res.status(404).json({ error: 'Урок не найден' });

  if (req.user.role !== 'student') {
    return res.status(403).json({ error: 'Только ученики могут отправлять ответы' });
  }

  if (req.user.classId !== lesson.classId) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }

  // Удаляем предыдущую отправку этого ученика
  db.submissions = db.submissions.filter(s => !(s.lessonId === req.params.id && s.studentId === req.user.id));

  const submission = {
    id: uuidv4(),
    lessonId: req.params.id,
    studentId: req.user.id,
    text: req.body.text || '',
    file: req.file ? {
      name: req.file.originalname,
      type: req.file.mimetype,
      size: req.file.size,
      data: req.file.buffer.toString('base64')
    } : null,
    grade: null,
    feedback: '',
    submittedAt: new Date().toISOString()
  };

  db.submissions.push(submission);
  saveDB();
  res.json(submission);
});

// Получить ответы на урок (админ)
app.get('/api/lessons/:id/submissions', authMiddleware, adminOnly, (req, res) => {
  const submissions = db.submissions.filter(s => s.lessonId === req.params.id);

  // Добавляем информацию об учениках
  const result = submissions.map(s => {
    const student = db.users.find(u => u.id === s.studentId);
    return {
      ...s,
      studentName: student ? student.name : 'Неизвестно',
      studentUsername: student ? student.username : ''
    };
  });

  res.json(result);
});

// Получить свои ответы (ученик)
app.get('/api/my-submissions', authMiddleware, (req, res) => {
  if (req.user.role !== 'student') {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }

  const submissions = db.submissions.filter(s => s.studentId === req.user.id);
  res.json(submissions);
});

// Оценить ответ
app.put('/api/submissions/:id/grade', authMiddleware, adminOnly, (req, res) => {
  const { grade, feedback } = req.body;

  const submission = db.submissions.find(s => s.id === req.params.id);
  if (!submission) return res.status(404).json({ error: 'Ответ не найден' });

  submission.grade = grade;
  submission.feedback = feedback || '';
  submission.gradedAt = new Date().toISOString();

  saveDB();
  res.json(submission);
});

// Скачать файл ответа
app.get('/api/submissions/:id/file', authMiddleware, (req, res) => {
  const submission = db.submissions.find(s => s.id === req.params.id);
  if (!submission) return res.status(404).json({ error: 'Ответ не найден' });

  if (req.user.role === 'student' && req.user.id !== submission.studentId) {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }

  if (!submission.file) return res.status(404).json({ error: 'Файл не найден' });

  const buffer = Buffer.from(submission.file.data, 'base64');
  res.setHeader('Content-Type', submission.file.type);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(submission.file.name)}"`);
  res.send(buffer);
});

// ===== EXPORT ROUTES =====

// Экспорт логинов и паролей класса
app.get('/api/classes/:id/export', authMiddleware, adminOnly, (req, res) => {
  const cls = db.classes.find(c => c.id === req.params.id);
  if (!cls) return res.status(404).json({ error: 'Класс не найден' });

  const students = db.users.filter(u => u.role === 'student' && u.classId === req.params.id);

  const data = students.map(s => ({
    Фамилия: s.lastName,
    Имя: s.firstName,
    Логин: s.username,
    Пароль: '********' // Пароли хешированы, показываем звёздочки
  }));

  res.json({ className: cls.name, students: data });
});

// ===== STATS =====
app.get('/api/stats', authMiddleware, adminOnly, (req, res) => {
  res.json({
    totalClasses: db.classes.length,
    totalStudents: db.users.filter(u => u.role === 'student').length,
    totalLessons: db.lessons.length,
    totalSubmissions: db.submissions.length
  });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Start server
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;
