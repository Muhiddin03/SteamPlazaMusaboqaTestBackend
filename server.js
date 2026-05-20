require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── DATABASE CONNECTION ───────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ─── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// ─── DATABASE INIT (Jadvallar yaratish) ───────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id VARCHAR(50) PRIMARY KEY,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS tests (
        id SERIAL PRIMARY KEY,
        class_id VARCHAR(50) REFERENCES classes(id) ON DELETE CASCADE,
        question TEXT NOT NULL,
        correct_answer TEXT NOT NULL,
        options JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS results (
        id SERIAL PRIMARY KEY,
        class_id VARCHAR(50) REFERENCES classes(id) ON DELETE CASCADE,
        team_name VARCHAR(100) NOT NULL,
        student_name VARCHAR(100) NOT NULL,
        score INTEGER NOT NULL,
        total INTEGER NOT NULL,
        time_taken VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('✅ Database tables ready');
  } finally {
    client.release();
  }
}

// ─── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Steam Plaza API ishlayapti!' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSES (SINFLAR) API
// ═══════════════════════════════════════════════════════════════════════════════

// Barcha sinflarni olish
app.get('/api/classes', async (req, res) => {
  try {
    const result = await pool.query('SELECT id FROM classes ORDER BY id');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Yangi sinf qo'shish
app.post('/api/classes', async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'Sinf nomi kerak' });
  try {
    await pool.query('INSERT INTO classes (id) VALUES ($1)', [id]);
    res.json({ success: true, id });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Bu sinf allaqachon mavjud' });
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Sinf o'chirish
app.delete('/api/classes/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM classes WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS (SAVOLLAR) API
// ═══════════════════════════════════════════════════════════════════════════════

// Bazadagi barcha testlarni olish (Yangi qo'shilgan qism 🛠️)
app.get('/api/tests', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tests ORDER BY class_id ASC, id ASC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Sinf savollarini olish
app.get('/api/classes/:id/tests', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tests WHERE class_id = $1 ORDER BY id',
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Bir sinf guruhining barcha testlarini olish (Parallel tizim uchun)
app.get('/api/grade/:grade/tests', async (req, res) => {
  try {
    const fullClassId = req.params.grade; 
    const gradeDigit = fullClassId.split('-')[0]; 
    const parallelPattern = gradeDigit + '-%'; 

    const result = await pool.query(
      `SELECT id, class_id, question, correct_answer, options 
       FROM tests 
       WHERE class_id = $1 
          OR (class_id LIKE $2 AND SPLIT_PART(class_id, '-', 1) = $3)`,
      [fullClassId, parallelPattern, gradeDigit]
    );
    
    const shuffledTests = result.rows.sort(() => Math.random() - 0.5);
    res.json(shuffledTests);
  } catch (err) {
    console.error("❌ /api/grade/:grade/tests ichida xatolik:", err);
    res.status(500).json({ error: 'Server ichki xatosi: ' + err.message });
  }
});

// Yangi savol qo'shish
app.post('/api/classes/:id/tests', async (req, res) => {
  const { question, correct_answer, wrong1, wrong2, targetClasses } = req.body;
  if (!question || !correct_answer) return res.status(400).json({ error: 'Savol va to\'g\'ri javob kerak' });
  
  const options = JSON.stringify([correct_answer, wrong1 || '', wrong2 || '']);
  const classesToInsert = targetClasses && targetClasses.length > 0 ? targetClasses : [req.params.id];
  
  try {
    const insertedRows = [];
    for (const cId of classesToInsert) {
      const result = await pool.query(
        'INSERT INTO tests (class_id, question, correct_answer, options) VALUES ($1, $2, $3, $4) RETURNING *',
        [cId, question, correct_answer, options]
      );
      insertedRows.push(result.rows[0]);
    }
    res.json(insertedRows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Mavjud savolni tahrirlash/yangilash (Yangi qo'shilgan qism 🛠️)
app.put('/api/tests/:id', async (req, res) => {
  const { id } = req.params;
  const { class_id, question, correct_answer, wrong1, wrong2 } = req.body;
  
  if (!class_id || !question || !correct_answer) {
    return res.status(400).json({ error: "Sinf, savol va to'g'ri javob majburiy!" });
  }

  const options = JSON.stringify([correct_answer, wrong1 || '', wrong2 || '']);

  try {
    const result = await pool.query(
      `UPDATE tests 
       SET class_id = $1, question = $2, correct_answer = $3, options = $4 
       WHERE id = $5 RETURNING *`,
      [class_id, question, correct_answer, options, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Savol topilmadi" });
    }

    res.json({ success: true, test: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Savol o'chirish
app.delete('/api/tests/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM tests WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// RESULTS (NATIJALAR) API
// ═══════════════════════════════════════════════════════════════════════════════

// Barcha natijalarni olish
app.get('/api/results', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM results ORDER BY score DESC, created_at DESC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Sinf natijalari
app.get('/api/classes/:id/results', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM results WHERE class_id = $1 ORDER BY score DESC, created_at DESC',
      [req.params.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Natija saqlash
app.post('/api/results', async (req, res) => {
  const { class_id, team_name, student_name, score, total, time_taken } = req.body;
  if (!class_id || !team_name || !student_name) return res.status(400).json({ error: "Ma'lumot yetarli emas" });
  
  try {
    const result = await pool.query(
      'INSERT INTO results (class_id, team_name, student_name, score, total, time_taken) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [class_id, team_name, student_name, score, total, time_taken]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Natija o'chirish
app.delete('/api/results/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM results WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SETTINGS API
// ═══════════════════════════════════════════════════════════════════════════════

// Barchasini o'chirish
app.delete('/api/clear-all', async (req, res) => {
  try {
    await pool.query('DELETE FROM results');
    await pool.query('DELETE FROM tests');
    await pool.query('DELETE FROM classes');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// ─── START SERVER ──────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server ${PORT}-portda ishlamoqda`);
  });
}).catch(err => {
  console.error('❌ Database ulanishda xatolik:', err);
  process.exit(1);
});
