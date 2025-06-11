require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'frontend')));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_here';

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '12345678',
  database: process.env.DB_NAME || 'gov_feedback'
};

async function getDBConnection() {
  return await mysql.createConnection(dbConfig);
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ success: false, message: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
    req.user = user;
    next();
  });
}

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

// Register route (citizens only)
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const role = 'citizen';

  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: 'Name, email, and password are required' });
  }

  let connection;
  try {
    connection = await getDBConnection();
    const [existingUser] = await connection.execute('SELECT id FROM users WHERE email = ?', [email]);

    if (existingUser.length > 0) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await connection.execute(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, role]
    );

    res.json({ success: true, message: 'User registered successfully as citizen' });
  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Login route (citizen and admin)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }

  let connection;
  try {
    connection = await getDBConnection();
    const [users] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    const user = users[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

    const redirectPath = user.role === 'admin' ? '/admin-dashboard.html' : '/citizen.html';

    res.json({ success: true, token, role: user.role, redirect: redirectPath });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// POST /feedback - citizen submits feedback
app.post('/feedback', authenticateToken, authorizeRoles('citizen'), async (req, res) => {
  const { subject, message, priority } = req.body;
  const validPriorities = ['low', 'medium', 'high'];

  if (!subject || !message) {
    return res.status(400).json({ success: false, message: 'Subject and message are required' });
  }

  // Case insensitive priority check
  if (priority && !validPriorities.includes(priority.toLowerCase())) {
    return res.status(400).json({ success: false, message: 'Invalid priority value' });
  }

  let connection;
  try {
    connection = await getDBConnection();
    await connection.execute(
      'INSERT INTO feedback (user_id, subject, message, priority) VALUES (?, ?, ?, ?)',
      [req.user.id, subject, message, priority ? priority.toLowerCase() : 'medium']
    );

    res.json({ success: true, message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Feedback Submission Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// GET /feedback - admin sees all feedback with upvote counts
app.get('/feedback', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  let connection;
  try {
    connection = await getDBConnection();
    const [feedbacks] = await connection.execute(
      `SELECT f.*, u.name AS user_name, 
        (SELECT COUNT(*) FROM upvotes up WHERE up.feedback_id = f.id) AS upvotes_count
       FROM feedback f
       JOIN users u ON f.user_id = u.id
       ORDER BY f.id DESC`
    );

    res.json({ success: true, feedbacks });
  } catch (error) {
    console.error('Get Feedback Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// GET /my-feedback - citizen sees own feedback
app.get('/my-feedback', authenticateToken, authorizeRoles('citizen'), async (req, res) => {
  let connection;
  try {
    connection = await getDBConnection();
    const [feedbacks] = await connection.execute(
      'SELECT * FROM feedback WHERE user_id = ? ORDER BY id DESC',
      [req.user.id]
    );

    res.json({ success: true, feedbacks });
  } catch (error) {
    console.error('Get My Feedback Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// GET /public-feedback - citizen sees all feedback with upvotes count
app.get('/public-feedback', authenticateToken, authorizeRoles('citizen'), async (req, res) => {
  let connection;
  try {
    connection = await getDBConnection();
    const [feedbacks] = await connection.execute(
      `SELECT f.*, u.name AS user_name,
        (SELECT COUNT(*) FROM upvotes up WHERE up.feedback_id = f.id) AS upvotes_count
       FROM feedback f
       JOIN users u ON f.user_id = u.id
       ORDER BY f.id DESC`
    );
    res.json({ success: true, feedbacks });
  } catch (error) {
    console.error('Public Feedback Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// DELETE /feedback/:id - admin deletes feedback
app.delete('/feedback/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  const feedbackId = req.params.id;
  let connection;
  try {
    connection = await getDBConnection();
    await connection.execute('DELETE FROM feedback WHERE id = ?', [feedbackId]);
    res.json({ success: true, message: 'Feedback deleted successfully' });
  } catch (error) {
    console.error('Delete Feedback Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// PUT /feedback/:id - admin edits a feedback
app.put('/feedback/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  const feedbackId = req.params.id;
  const { subject, message, priority } = req.body;
  const validPriorities = ['low', 'medium', 'high'];

  if (!subject || !message || !priority) {
    return res.status(400).json({ success: false, message: 'Subject, message, and priority are required' });
  }

  if (!validPriorities.includes(priority.toLowerCase())) {
    return res.status(400).json({ success: false, message: 'Invalid priority value' });
  }

  let connection;
  try {
    connection = await getDBConnection();
    await connection.execute(
      'UPDATE feedback SET subject = ?, message = ?, priority = ? WHERE id = ?',
      [subject, message, priority.toLowerCase(), feedbackId]
    );
    res.json({ success: true, message: 'Feedback updated successfully' });
  } catch (error) {
    console.error('Update Feedback Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// POST /upvote - citizen upvotes a feedback
app.post('/upvote', authenticateToken, authorizeRoles('citizen'), async (req, res) => {
  const { feedbackId } = req.body;
  if (!feedbackId) {
    return res.status(400).json({ success: false, message: 'Feedback ID is required' });
  }

  let connection;
  try {
    connection = await getDBConnection();
    // Check if already upvoted
    const [existing] = await connection.execute(
      'SELECT * FROM upvotes WHERE user_id = ? AND feedback_id = ?',
      [req.user.id, feedbackId]
    );

    if (existing.length > 0) {
      return res.status(400).json({ success: false, message: 'You already upvoted this feedback' });
    }

    await connection.execute(
      'INSERT INTO upvotes (user_id, feedback_id) VALUES (?, ?)',
      [req.user.id, feedbackId]
    );

    res.json({ success: true, message: 'Upvoted successfully' });
  } catch (error) {
    console.error('Upvote Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// POST /notices - admin posts a notice
app.post('/notices', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  const { title, content } = req.body;

  if (!title || !content) {
    return res.status(400).json({ success: false, message: 'Title and content are required' });
  }

  let connection;
  try {
    connection = await getDBConnection();
    await connection.execute('INSERT INTO notices (title, content) VALUES (?, ?)', [title, content]);

    res.json({ success: true, message: 'Notice posted successfully' });
  } catch (error) {
    console.error('Post Notice Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// GET /notices - citizen gets notices
app.get('/notices', authenticateToken, authorizeRoles('citizen'), async (req, res) => {
  let connection;
  try {
    connection = await getDBConnection();
    const [notices] = await connection.execute('SELECT * FROM notices ORDER BY id DESC');

    res.json({ success: true, notices });
  } catch (error) {
    console.error('Get Notices Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// POST /request-password-reset - citizen/admin requests password reset email token
app.post('/request-password-reset', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required' });
  }

  let connection;
  try {
    connection = await getDBConnection();
    const [users] = await connection.execute('SELECT id FROM users WHERE email = ?', [email]);

    if (users.length === 0) {
      return res.status(400).json({ success: false, message: 'Email not found' });
    }

    const user = users[0];
    // Generate a token and expiry
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour expiry

    await connection.execute(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
      [resetToken, resetTokenExpires, user.id]
    );

    // TODO: Send resetToken by email to the user here (Email service integration)

    res.json({ success: true, message: 'Password reset token generated and (supposedly) sent to email' });
  } catch (error) {
    console.error('Request Password Reset Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// POST /reset-password - reset password with token
app.post('/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword) {
    return res.status(400).json({ success: false, message: 'Email, token and new password are required' });
  }

  let connection;
  try {
    connection = await getDBConnection();
    const [users] = await connection.execute(
      'SELECT id, reset_token, reset_token_expires FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid email' });
    }

    const user = users[0];

    if (!user.reset_token || user.reset_token !== token) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });
    }

    if (new Date() > new Date(user.reset_token_expires)) {
      return res.status(400).json({ success: false, message: 'Reset token expired' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await connection.execute(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
      [hashedPassword, user.id]
    );

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset Password Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// POST /logout - client can call to clear token (server doesn't hold session)
app.post('/logout', authenticateToken, (req, res) => {
  // Since JWT is stateless, logout is client-side. We just confirm here.
  res.json({ success: true, message: 'Logged out successfully (token should be discarded client-side)' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
app.post('/api/chatbot', (req, res) => {
  const message = req.body.message.toLowerCase();

  let reply = "Sorry, I don't understand. Please ask about a government service like 'citizenship', 'passport', or 'marriage registration'.";

  if (message.includes('citizenship')) {
    reply = `To apply for a citizenship certificate:
- Visit your local ward office
- Bring a birth certificate, parent’s citizenship copies, and a recommendation letter
- Fill out the citizenship application form`;
  } else if (message.includes('passport')) {
    reply = `To renew/apply for a passport:
- Visit https://nepalpassport.gov.np
- Book an appointment online
- Bring citizenship and old passport (if any)
- Visit your District Administration Office for biometric submission`;
  } else if (message.includes('marriage')) {
    reply = `To register a marriage:
- Both parties must be present at the Ward Office
- Submit citizenship copies, photos, and marriage recommendation form
- Pay the applicable fee`;
  } else if (message.includes('land')) {
    reply = `For land registration/transfer:
- Visit the Land Revenue Office
- Submit land ownership documents, citizenship, and a transfer request
- Pay registration and tax fees`;
  } else if (message.includes('birth')) {
    reply = `To get a birth certificate:
- Go to your local Ward Office within 35 days of birth
- Bring hospital birth report and parent's citizenship
- Fill out the birth registration form`;

  }

  res.json({ reply });
});
