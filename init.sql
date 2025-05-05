CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS sensitive_data (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  data_type VARCHAR(100) NOT NULL,
  encrypted_data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reminders (
  user_id INTEGER PRIMARY KEY REFERENCES users(id),
  last_sent TIMESTAMP,
  last_response VARCHAR(10),
  follow_up_count INTEGER DEFAULT 0,
  next_notification TIMESTAMP,
  recipient_email VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS contacts (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  contact_email VARCHAR(255) NOT NULL,
  is_emergency_contact BOOLEAN DEFAULT FALSE
);

-- Insert test user (password: root123)
INSERT INTO users (email, password_hash)
VALUES ('test@example.com', '$2a$10$Q8yZ2b3Xz5vY7kW9mPqN.u6J5kT2x9L8rH4jG7vM3nK6pF8qR2tW')
ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash;

-- Insert kfa user (password: root123)
INSERT INTO users (email, password_hash)
VALUES ('kfa@gmail.com', '$2a$10$Q8yZ2b3Xz5vY7kW9mPqN.u6J5kT2x9L8rH4jG7vM3nK6pF8qR2tW')
ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash;

-- Insert reminders for users
INSERT INTO reminders (user_id, recipient_email)
SELECT id, 'recipient@example.com' FROM users WHERE email = 'test@example.com'
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO reminders (user_id, recipient_email)
SELECT id, 'recipient@example.com' FROM users WHERE email = 'kfa@gmail.com'
ON CONFLICT (user_id) DO NOTHING;