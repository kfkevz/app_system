const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const sgMail = require('@sendgrid/mail');
const PDFDocument = require('pdfkit');
const app = express();
const port = 5000;

app.use(express.json());
app.use(express.static('/app'));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  next();
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.get('/', (req, res) => {
  res.sendFile(path.join('/app', 'index.html'));
});

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'utf8'); // 32 bytes
const IV_LENGTH = 16;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

pool.connect((err) => {
  if (err) {
    console.error('Failed to connect to PostgreSQL:', err.message);
    process.exit(1);
  }
  console.log('Successfully connected to PostgreSQL');
});

async function initializeDatabase() {
  try {
    await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sensitive_data (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        data_type VARCHAR(100) NOT NULL,
        encrypted_data TEXT NOT NULL
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reminders (
        user_id INTEGER PRIMARY KEY REFERENCES users(id),
        last_sent TIMESTAMP,
        last_response VARCHAR(10),
        follow_up_count INTEGER DEFAULT 0,
        next_notification TIMESTAMP,
        recipient_email VARCHAR(255)
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        contact_email VARCHAR(255) NOT NULL,
        is_emergency_contact BOOLEAN DEFAULT FALSE
      )
    `);

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Failed to initialize database:', error);
    process.exit(1);
  }
}

initializeDatabase();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const [iv, encryptedText] = text.split(':').map(str => Buffer.from(str, 'hex'));
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

async function sendScheduledReminders() {
  try {
    const now = new Date();
    const result = await pool.query(`
      SELECT r.user_id, r.last_sent, r.last_response, r.follow_up_count, r.next_notification, r.recipient_email, u.email
      FROM reminders r
      JOIN users u ON r.user_id = u.id
      WHERE r.next_notification <= $1 OR r.next_notification IS NULL
    `, [now]);

    for (const reminder of result.rows) {
      const lastSent = reminder.last_sent ? new Date(reminder.last_sent) : null;
      const followUpCount = reminder.follow_up_count || 0;
      let nextNotification;

      if (followUpCount === 0) {
        // Weekly notification
        const msg = {
          to: reminder.email,
          from: 'no-reply@yourdomain.com',
          subject: 'Weekly Data Update Request',
          text: `Do you want to edit or add data to your vault? Reply "Yes" or "No".`,
          html: `<p>Do you want to edit or add data to your vault?</p><p>Reply <strong>Yes</strong> or <strong>No</strong>.</p>`,
        };
        await sgMail.send(msg);
        console.log('Weekly reminder sent to:', reminder.email);
        nextNotification = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 1 week
        await pool.query(
          'UPDATE reminders SET last_sent = $1, follow_up_count = 0, next_notification = $2 WHERE user_id = $3',
          [now, nextNotification, reminder.user_id]
        );
      } else if (followUpCount === 1) {
        // 2-day follow-up
        const msg = {
          to: reminder.email,
          from: 'no-reply@yourdomain.com',
          subject: 'Follow-up: Data Update Request',
          text: `You haven't responded to our last request. Do you want to edit Diseño de software? Reply "Yes" or "No".`,
          html: `<p>You haven't responded to our last request.</p><p>Do you want to edit or add data? Reply <strong>Yes</strong> or <strong>No</strong>.</p>`,
        };
        await sgMail.send(msg);
        console.log('Follow-up reminder sent to:', reminder.email);
        nextNotification = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000); // 2 days
        await pool.query(
          'UPDATE reminders SET last_sent = $1, follow_up_count = 2, next_notification = $2 WHERE user_id = $3',
          [now, nextNotification, reminder.user_id]
        );
      } else if (followUpCount >= 2) {
        // Compile and send PDF to recipient
        const dataResult = await pool.query('SELECT id, data_type, encrypted_data FROM sensitive_data WHERE user_id = $1', [reminder.user_id]);
        const data = dataResult.rows.map(row => ({
          id: row.id,
          data_type: row.data_type,
          decrypted_data: decrypt(row.encrypted_data),
        }));

        const doc = new PDFDocument();
        let buffers = [];
        doc.on('data', buffers.push.bind(buffers));
        doc.on('end', async () => {
          const pdfData = Buffer.concat(buffers);
          const msg = {
            to: reminder.recipient_email,
            from: 'no-reply@yourdomain.com',
            subject: 'Sensitive Data Report',
            text: `Attached is the sensitive data report for user ${reminder.email}.`,
            html: `<p>Attached is the sensitive data report for user ${reminder.email}.</p>`,
            attachments: [
              {
                content: pdfData.toString('base64'),
                filename: 'sensitive_data_report.pdf',
                type: 'application/pdf',
                disposition: 'attachment',
              },
            ],
          };
          await sgMail.send(msg);
          console.log('PDF report sent to:', reminder.recipient_email);
        });

        doc.fontSize(16).text('Sensitive Data Report', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12);
        data.forEach(item => {
          const [username, password] = item.decrypted_data.split(':');
          doc.text(`ID: ${item.id}`);
          doc.text(`Data Type: ${item.data_type}`);
          doc.text(`Username: ${username}`);
          doc.text(`Password: ${password || 'N/A'}`);
          doc.moveDown();
        });
        doc.end();

        nextNotification = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // Reset to 1 week
        await pool.query(
          'UPDATE reminders SET last_sent = $1, follow_up_count = 0, last_response = NULL, next_notification = $2 WHERE user_id = $3',
          [now, nextNotification, reminder.user_id]
        );
      }
    }
  } catch (error) {
    console.error('Error sending scheduled reminders:', error);
  }
}

setInterval(sendScheduledReminders, 60 * 60 * 1000); // Check every hour
sendScheduledReminders();

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0 || !(await bcrypt.compare(password, result.rows[0].password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: result.rows[0].id, email: result.rows[0].email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, id: result.rows[0].id });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/sensitive-data', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, data_type, encrypted_data FROM sensitive_data WHERE user_id = $1', [req.user.id]);
    const data = result.rows.map(row => ({
      id: row.id,
      data_type: row.data_type,
      decrypted_data: decrypt(row.encrypted_data),
    }));
    res.json(data);
  } catch (error) {
    console.error('Error fetching sensitive data:', error);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});

app.post('/api/sensitive-data', authenticateToken, async (req, res) => {
  const { dataType, data } = req.body;
  try {
    const encryptedData = encrypt(data);
    await pool.query(
      'INSERT INTO sensitive_data (user_id, data_type, encrypted_data) VALUES ($1, $2, $3)',
      [req.user.id, dataType, encryptedData]
    );
    // Reset notification timer
    const now = new Date();
    const nextNotification = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      'UPDATE reminders SET last_sent = $1, follow_up_count = 0, last_response = NULL, next_notification = $2 WHERE user_id = $3',
      [now, nextNotification, req.user.id]
    );
    res.json({ message: 'Data saved successfully' });
  } catch (error) {
    console.error('Error saving sensitive data:', error);
    res.status(500).json({ error: 'Failed to save data' });
  }
});

app.put('/api/sensitive-data/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { dataType, data } = req.body;
  try {
    const encryptedData = encrypt(data);
    await pool.query(
      'UPDATE sensitive_data SET data_type = $1, encrypted_data = $2 WHERE id = $3 AND user_id = $4',
      [dataType, encryptedData, id, req.user.id]
    );
    // Reset notification timer
    const now = new Date();
    const nextNotification = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      'UPDATE reminders SET last_sent = $1, follow_up_count = 0, last_response = NULL, next_notification = $2 WHERE user_id = $3',
      [now, nextNotification, req.user.id]
    );
    res.json({ message: 'Data updated successfully' });
  } catch (error) {
    console.error('Error updating sensitive data:', error);
    res.status(500).json({ error: 'Failed to update data' });
  }
});

app.delete('/api/sensitive-data/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM sensitive_data WHERE id = $1 AND user_id = $2', [id, req.user.id]);
    res.json({ message: 'Data deleted successfully' });
  } catch (error) {
    console.error('Error deleting sensitive data:', error);
    res.status(500).json({ error: 'Failed to delete data' });
  }
});

app.post('/api/reminder-reply', async (req, res) => {
  const { email, response } = req.body;
  try {
    const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const userId = userResult.rows[0].id;
    const now = new Date();
    let nextNotification;
    let msg;

    if (response.toLowerCase() === 'yes') {
      const loginLink = 'http://localhost:8080/'; // Updated to point to frontend
      msg = {
        to: email,
        from: 'no-reply@yourdomain.com',
        subject: 'Login to Update Your Data',
        text: `Click here to login and update your data: ${loginLink}`,
        html: `<p>Click here to login and update your data:</p><p><a href="${loginLink}">${loginLink}</a></p>`,
      };
      nextNotification = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 1 week
    } else if (response.toLowerCase() === 'no') {
      msg = {
        to: email,
        from: 'no-reply@yourdomain.com',
        subject: 'Reminder Acknowledged',
        text: `Thank you for your response. We will check again in a week.`,
        html: `<p>Thank you for your response. We will check again in a week.</p>`,
      };
      nextNotification = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 1 week
    } else {
      return res.status(400).json({ error: 'Invalid response. Please reply with "Yes" or "No".' });
    }

    await sgMail.send(msg);
    console.log(`Response (${response}) processed for:`, email);
    await pool.query(
      'UPDATE reminders SET last_response = $1, last_sent = $2, follow_up_count = 0, next_notification = $3 WHERE user_id = $4',
      [response.toLowerCase(), now, nextNotification, userId]
    );
    res.json({ message: 'Response processed successfully' });
  } catch (error) {
    console.error('Error processing reminder reply:', error);
    res.status(500).json({ error: 'Failed to process response' });
  }
});

// Placeholder for SendGrid Inbound Parse webhook
app.post('/api/email-webhook', async (req, res) => {
  try {
    const { from, text } = req.body; // Adjust based on SendGrid webhook payload
    const response = text.trim().toLowerCase();
    if (['yes', 'no'].includes(response)) {
      await fetch('/api/reminder-reply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: from, response })
      });
    }
    res.status(200).send();
  } catch (error) {
    console.error('Error processing email webhook:', error);
    res.status(500).send();
  }
});

app.get('/api/reminders', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM reminders WHERE user_id = $1', [req.user.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching reminders:', error);
    res.status(500).json({ error: 'Failed to fetch reminders' });
  }
});

app.post('/api/reminders', authenticateToken, async (req, res) => {
  const { lastResponse, followUpCount, recipientEmail } = req.body;
  try {
    await pool.query(
      'INSERT INTO reminders (user_id, last_response, follow_up_count, recipient_email) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO UPDATE SET last_response = $2, follow_up_count = $3, recipient_email = $4',
      [req.user.id, lastResponse, followUpCount, recipientEmail]
    );
    res.json({ message: 'Reminder saved successfully' });
  } catch (error) {
    console.error('Error saving reminder:', error);
    res.status(500).json({ error: 'Failed to save reminder' });
  }
});

app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM contacts WHERE user_id = $1', [req.user.id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching contacts:', error);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

app.post('/api/contacts', authenticateToken, async (req, res) => {
  const { contactEmail, isEmergencyContact } = req.body;
  try {
    await pool.query(
      'INSERT INTO contacts (user_id, contact_email, is_emergency_contact) VALUES ($1, $2, $3)',
      [req.user.id, contactEmail, isEmergencyContact]
    );
    res.json({ message: 'Contact saved successfully' });
  } catch (error) {
    console.error('Error saving contact:', error);
    res.status(500).json({ error: 'Failed to save contact' });
  }
});

app.listen(port, () => {
  console.log(`Backend running on port ${port}`);
});