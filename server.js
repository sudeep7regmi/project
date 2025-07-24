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

app.use(cors());
app.use(express.static(path.join(__dirname, 'frontend')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_here';

const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '12345678',
  database: process.env.DB_NAME || 'gov_feedback',
};

async function getDBConnection() {
  return await mysql.createConnection(dbConfig);
}


// Middleware to verify JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token)
    return res.status(401).json({ success: false, message: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err)
      return res.status(403).json({ success: false, message: 'Invalid token' });

    req.user = user;
    next();
  });
}

function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ success: false, message: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

// ========== Routes ==========

// Register new citizen
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const role = 'citizen'; 

  if (!name || !email || !password)
    return res
      .status(400)
      .json({ success: false, message: 'Name, email, and password are required' });

  let connection;
  try {
    connection = await getDBConnection();

    const [existingUser] = await connection.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (existingUser.length > 0)
      return res.status(400).json({ success: false, message: 'Email already registered' });

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

// Login route (citizen/admin)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res
      .status(400)
      .json({ success: false, message: 'Email and password are required' });

  let connection;
  try {
    connection = await getDBConnection();

    const [users] = await connection.execute('SELECT * FROM users WHERE email = ?', [
      email,
    ]);

    if (users.length === 0)
      return res.status(400).json({ success: false, message: 'Invalid credentials' });

    const user = users[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch)
      return res.status(400).json({ success: false, message: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: '1h',
    });

    const redirectPath = user.role === 'admin' ? '/admin.html' : '/citizen.html';

    res.json({ success: true, token, role: user.role, redirect: redirectPath });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Citizen submits feedback (with priority fix)
app.post('/feedback', authenticateToken, authorizeRoles('citizen'), async (req, res) => {
  const { subject, message, priority } = req.body;
  const validPriorities = ['low', 'medium', 'high'];

  if (!subject || !message || !priority)
    return res.status(400).json({
      success: false,
      message: 'Subject, message, and priority are required'
    });

  if (!validPriorities.includes(priority.toLowerCase()))
    return res.status(400).json({ success: false, message: 'Priority must be low, medium, or high' });

  let connection;
  try {
    connection = await getDBConnection();

    await connection.execute(
      'INSERT INTO feedback (user_id, subject, message, priority) VALUES (?, ?, ?, ?)',
      [req.user.id, subject, message, priority.toLowerCase()]
    );

    res.json({ success: true, message: 'Feedback submitted successfully' });
  } catch (error) {
    console.error('Feedback Submission Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Admin views all feedback with upvotes count
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

// Citizen views own feedback
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

// Citizen views all public feedback with upvote info
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

    // Add whether current user has upvoted each feedback
    const feedbacksWithUpvoteInfo = await Promise.all(
      feedbacks.map(async (fb) => {
        const [upvoted] = await connection.execute(
          'SELECT * FROM upvotes WHERE user_id = ? AND feedback_id = ?',
          [req.user.id, fb.id]
        );
        return {
          ...fb,
          hasUpvoted: upvoted.length > 0,
          upvotes: fb.upvotes_count || 0,
        };
      })
    );

    res.json({ success: true, feedbacks: feedbacksWithUpvoteInfo });
  } catch (error) {
    console.error('Public Feedback Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Admin deletes feedback
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

// Admin updates feedback
app.put('/feedback/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  const feedbackId = req.params.id;
  const { subject, message, priority } = req.body;
  const validPriorities = ['low', 'medium', 'high'];

  if (!subject || !message || !priority)
    return res.status(400).json({
      success: false,
      message: 'Subject, message, and priority are required',
    });

  if (!validPriorities.includes(priority.toLowerCase()))
    return res.status(400).json({ success: false, message: 'Priority must be low, medium, or high' });

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

// Citizen upvotes feedback
app.post('/upvote', authenticateToken, authorizeRoles('citizen'), async (req, res) => {
  const { feedbackId } = req.body;
  if (!feedbackId)
    return res
      .status(400)
      .json({ success: false, message: 'Feedback ID is required' });

  let connection;
  try {
    connection = await getDBConnection();

    // Check if already upvoted
    const [existing] = await connection.execute(
      'SELECT * FROM upvotes WHERE user_id = ? AND feedback_id = ?',
      [req.user.id, feedbackId]
    );

    if (existing.length > 0)
      return res
        .status(400)
        .json({ success: false, message: 'You already upvoted this feedback' });

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

// Admin posts notice
app.post('/notices', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  const { title, content } = req.body;

  if (!title || !content)
    return res
      .status(400)
      .json({ success: false, message: 'Title and content are required' });

  let connection;
  try {
    connection = await getDBConnection();

    await connection.execute('INSERT INTO notices (title, content) VALUES (?, ?)', [
      title,
      content,
    ]);

    res.json({ success: true, message: 'Notice posted successfully' });
  } catch (error) {
    console.error('Post Notice Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Citizen gets notices
app.get('/notices', authenticateToken, authorizeRoles('admin','citizen'), async (req, res) => {
  let connection;
  try {
    connection = await getDBConnection();

    const [notices] = await connection.execute(
      'SELECT * FROM notices ORDER BY id DESC'
    );

    res.json({ success: true, notices });
  } catch (error) {
    console.error('Get Notices Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Admin updates notice
app.put('/notices/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  const noticeId = req.params.id;
  const { title, content } = req.body;

  if (!title || !content)
    return res
      .status(400)
      .json({ success: false, message: 'Title and content are required' });

  let connection;
  try {
    connection = await getDBConnection();

    await connection.execute(
      'UPDATE notices SET title = ?, content = ? WHERE id = ?',
      [title, content, noticeId]
    );

    res.json({ success: true, message: 'Notice updated successfully' });
  } catch (error) {
    console.error('Update Notice Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Admin deletes notice
app.delete('/notices/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
  const noticeId = req.params.id;
  let connection;
  try {
    connection = await getDBConnection();

    await connection.execute('DELETE FROM notices WHERE id = ?', [noticeId]);

    res.json({ success: true, message: 'Notice deleted successfully' });
  } catch (error) {
    console.error('Delete Notice Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Request password reset token
app.post('/request-password-reset', async (req, res) => {
  const { email } = req.body;
  if (!email)
    return res.status(400).json({ success: false, message: 'Email is required' });

  let connection;
  try {
    connection = await getDBConnection();

    const [users] = await connection.execute('SELECT id FROM users WHERE email = ?', [
      email,
    ]);

    if (users.length === 0)
      return res.status(400).json({ success: false, message: 'Email not found' });

    const user = users[0];
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour expiry

    await connection.execute(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
      [resetToken, resetTokenExpires, user.id]
    );

    // TODO: Implement email sending of resetToken to user.email

    res.json({
      success: true,
      message: 'Password reset token generated and (supposedly) sent to email',
    });
  } catch (error) {
    console.error('Request Password Reset Error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  } finally {
    if (connection) await connection.end();
  }
});

// Reset password using token
app.post('/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  if (!email || !token || !newPassword)
    return res
      .status(400)
      .json({ success: false, message: 'Email, token, and new password are required' });

  let connection;
  try {
    connection = await getDBConnection();

    const [users] = await connection.execute(
      'SELECT id, reset_token, reset_token_expires FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0)
      return res.status(400).json({ success: false, message: 'Invalid email' });

    const user = users[0];

    if (!user.reset_token || user.reset_token !== token)
      return res.status(400).json({ success: false, message: 'Invalid or expired reset token' });

    if (new Date() > new Date(user.reset_token_expires))
      return res.status(400).json({ success: false, message: 'Reset token expired' });

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

// Logout route (stateless)
app.post('/logout', authenticateToken, (req, res) => {
  res.json({ success: true, message: 'Logged out successfully (discard token client-side)' });
});

// AI Chatbot endpoint
app.post('/api/chatbot', authenticateToken, async (req, res) => {
  try {
    const message = (req.body.message || '').toLowerCase();

    // Predefined responses for common government queries
    const predefinedResponses = {
      'citizenship': {
        reply: `Citizenship Certificate Process:
1. Visit your local ward office with:
   - Birth certificate
   - Parent's citizenship copies
   - Recommendation letter
   - Passport photos (2 copies)
2. Fill application form
3. Pay NPR 500-1000 fee
4. Processing time: 15-30 days`,
        keywords: ['citizenship', 'nagarikta']
      },
      'passport': {
        reply: `Passport Application:
1. Visit https://nepalpassport.gov.np
2. Create account & fill application
3. Book appointment
4. Documents needed:
   - Citizenship certificate
   - Old passport (if renewing)
5. Processing time: 7-15 days`,
        keywords: ['passport', 'राहदानी']
      },
      'tax': {
        reply: `Tax Payment:
1. Online: https://ird.gov.np
2. Required:
   - PAN number
   - Tax details
3. Deadline: July 15 each year`,
        keywords: ['tax', 'कर']
      },
      'complaint': {
        reply: `To file a complaint:
1. Online: https://complaint.gov.np
2. In-person:
   - Visit concerned department
   - Fill complaint form
   - Get tracking number
3. Follow up using tracking number`,
        keywords: ['complaint', 'शिकायत']
      }
      
    };

    // Check predefined responses first
    for (const [key, response] of Object.entries(predefinedResponses)) {
      if (response.keywords.some(kw => message.includes(kw))) {
        return res.json({ 
          reply: response.reply,
          source: 'predefined'
        });
      }
    }

    // Fallback to AI if no predefined response
    /*if (!gpt4all) {
      throw new Error('AI model not ready');
    }

    const prompt = `As a government assistant, answer concisely in bullet points if needed:
    
    Question: ${message}
    
    If unsure, direct to https://gov.np`;

    const aiResponse = await gpt4all.prompt(prompt);
    
    res.json({
      reply: aiResponse.trim(),
      source: 'ai'
    });*/

  } catch (error) {
    console.error('Chatbot Error:', error);
    res.json({
      reply: "I can't answer right now. Please visit https://gov.np for help.",
      source: 'error'
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
