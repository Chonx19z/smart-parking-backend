require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(cors({
  origin: '*', // Allow all origins for testing
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors());
app.use(express.json());

// Log all requests for debugging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('PostgreSQL connection failed:', err.stack);
  } else {
    console.log('PostgreSQL connected successfully at:', res.rows[0].now);
    initializeDatabase();
  }
});

// Initialize database with tables and test users
async function initializeDatabase() {
  try {
    // Create users table if not exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        phone_number VARCHAR(15) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100),
        role VARCHAR(10) NOT NULL DEFAULT 'USER',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Create parking_slots table if not exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS parking_slots (
        id SERIAL PRIMARY KEY,
        slot_number VARCHAR(10) UNIQUE NOT NULL,
        status VARCHAR(20) DEFAULT 'AVAILABLE',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Check if admin user exists
    const adminExists = await pool.query(
      'SELECT * FROM users WHERE phone_number = $1',
      ['0969871077']
    );
    
    // Add admin user if not exists
    if (adminExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('191046', 10);
      await pool.query(
        'INSERT INTO users (phone_number, password, name, email, role) VALUES ($1, $2, $3, $4, $5)',
        ['0969871077', hashedPassword, 'Admin User', 'admin@smartparking.com', 'ADMIN']
      );
      console.log('Admin user created');
    }
    
    // Check if test user exists
    const userExists = await pool.query(
      'SELECT * FROM users WHERE phone_number = $1',
      ['0123456789']
    );
    
    // Add test user if not exists
    if (userExists.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('123456', 10);
      await pool.query(
        'INSERT INTO users (phone_number, password, name, email, role) VALUES ($1, $2, $3, $4, $5)',
        ['0123456789', hashedPassword, 'Test User', 'user@smartparking.com', 'USER']
      );
      console.log('Test user created');
    }
    
    // Check if parking slots exist
    const slotsExist = await pool.query('SELECT COUNT(*) FROM parking_slots');
    
    // Add parking slots if none exist
    if (parseInt(slotsExist.rows[0].count) === 0) {
      const slots = [
        'A1', 'A2', 'A3', 'A4',
        'B1', 'B2', 'B3', 'B4',
        'C1', 'C2', 'C3', 'C4',
        'D1', 'D2', 'D3', 'D4'
      ];
      
      for (const slot of slots) {
        await pool.query(
          'INSERT INTO parking_slots (slot_number, status) VALUES ($1, $2)',
          [slot, 'AVAILABLE']
        );
      }
      console.log('Parking slots created');
    }
    
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Authentication middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'smartparking2024secretkey123456');
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

// Routes
// Health check
app.get('/api/health', (req, res) => {
  pool.query('SELECT NOW()', (err, dbRes) => {
    if (err) {
      return res.json({ 
        status: 'warning', 
        message: 'Server is running but database connection failed', 
        error: err.message,
        timestamp: new Date()
      });
    }
    
    res.json({ 
      status: 'ok', 
      message: 'Server is running with PostgreSQL database', 
      timestamp: new Date(),
      dbTime: dbRes.rows[0].now
    });
  });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('Login attempt received');
    
    const { phoneNumber, password } = req.body;
    
    // Validate input
    if (!phoneNumber || !password) {
      return res.status(400).json({
        success: false,
        message: 'Phone number and password are required'
      });
    }
    
    // Find user
    const userResult = await pool.query(
      'SELECT * FROM users WHERE phone_number = $1 AND is_active = true',
      [phoneNumber]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid phone number or password'
      });
    }
    
    const user = userResult.rows[0];
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid phone number or password'
      });
    }

    // Generate token
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET || 'smartparking2024secretkey123456',
      { expiresIn: '24h' }
    );

    console.log(`Login successful for: ${phoneNumber}`);

    // Send response
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        phoneNumber: user.phone_number,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
});

// Get user profile
app.get('/api/auth/profile', verifyToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [req.user.id]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const user = userResult.rows[0];

    res.json({
      success: true,
      user: {
        id: user.id,
        phoneNumber: user.phone_number,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching profile'
    });
  }
});

// Get parking slots
app.get('/api/parking/status', async (req, res) => {
  try {
    const slotsResult = await pool.query('SELECT * FROM parking_slots ORDER BY slot_number');
    
    res.json({
      success: true,
      slots: slotsResult.rows.map(slot => ({
        slotNumber: slot.slot_number,
        status: slot.status
      })),
      timestamp: Date.now()
    });
  } catch (error) {
    console.error('Error getting parking status:', error);
    res.status(500).json({
      success: false,
      message: 'Error getting parking status'
    });
  }
});

// Database connection test endpoint
app.get('/api/db-test', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      success: true,
      message: 'PostgreSQL connection successful',
      timestamp: result.rows[0].now,
      dbConfig: {
        host: process.env.DB_HOST || 'Using connection string',
        database: process.env.DB_NAME || 'Using connection string',
        port: process.env.DB_PORT || 'Using connection string'
      }
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({
      success: false,
      message: 'Database connection failed',
      error: error.message
    });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment variables:`);
  console.log(`DATABASE_URL: ${process.env.DATABASE_URL ? 'Set (hidden)' : 'Not set'}`);
  console.log(`JWT_SECRET: ${process.env.JWT_SECRET ? 'Set (hidden)' : 'Not set (using default)'}`);
  console.log(`Test users will be created automatically if they don't exist:`);
  console.log(`- Admin: Phone 0969871077, Password 191046`);
  console.log(`- User: Phone 0123456789, Password 123456`);
});