const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// JWT Secret - should be in environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// MongoDB connection
const mongoURI = process.env.MONGODB_URI || 'mongodb+srv://nandaaustin534:nanda123@cluster0.ccbeqak.mongodb.net/employeeDB?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

// User Schema
const UserSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  password: { 
    type: String, 
    required: true,
    minlength: 6
  },
  employeeId: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  role: { 
    type: String, 
    enum: ['admin', 'employee'], 
    default: 'employee' 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  isActive: {
    type: Boolean,
    default: true
  }
});

// Log Schema (updated to reference user)
const LogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  username: {
    type: String,
    required: true
  },
  action: {
    type: String,
    enum: ['checkin', 'checkout'],
    required: true
  },
  timestamp: { 
    type: Date, 
    default: () => {
      const now = new Date();
      const jakartaTime = new Date(now.getTime() + (7 * 60 * 60 * 1000));
      return jakartaTime;
    }
  },
});

const User = mongoose.model('User', UserSchema);
const Log = mongoose.model('Log', LogSchema);

// CORS configuration
const allowedOrigins = [
  'http://localhost:5500',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5501',
  'https://rainbow-lokum-fc45f3.netlify.app',
  'https://bucolic-naiad-8de588.netlify.app',
  'nandacobacoba.netlify.app',
  'nandamasihnyoba.netlify.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin) || origin.endsWith('.netlify.app')) {
      return callback(null, true);
    }
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.use(bodyParser.json());

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Initialize default admin user
async function initializeDefaultUsers() {
  try {
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await User.create({
        username: 'admin',
        password: hashedPassword,
        employeeId: 'ADMIN001',
        role: 'admin'
      });
      console.log('Default admin user created');
    }

    const employeeExists = await User.findOne({ username: 'employee1' });
    if (!employeeExists) {
      const hashedPassword = await bcrypt.hash('emp123', 10);
      await User.create({
        username: 'employee1',
        password: hashedPassword,
        employeeId: 'EMP001',
        role: 'employee'
      });
      console.log('Default employee user created');
    }
  } catch (error) {
    console.error('Error initializing default users:', error);
  }
}

// Initialize default users when server starts
initializeDefaultUsers();

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Employee Check-in API with Authentication is running!', 
    timestamp: new Date().toISOString(),
    timezone: 'Asia/Jakarta'
  });
});

// Register endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password, employeeId, role = 'employee' } = req.body;

    // Validation
    if (!username || !password || !employeeId) {
      return res.status(400).json({ 
        error: 'Username, password, and employee ID are required' 
      });
    }

    if (username.length < 3) {
      return res.status(400).json({ 
        error: 'Username must be at least 3 characters long' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        error: 'Password must be at least 6 characters long' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { employeeId }] 
    });

    if (existingUser) {
      return res.status(400).json({ 
        error: 'Username or Employee ID already exists' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      password: hashedPassword,
      employeeId,
      role: role === 'admin' ? 'admin' : 'employee'
    });

    await user.save();

    res.status(201).json({ 
      success: true, 
      message: 'User registered successfully',
      user: {
        id: user._id,
        username: user.username,
        employeeId: user.employeeId,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'Internal server error during registration' 
    });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({ 
        error: 'Username and password are required' 
      });
    }

    // Find user
    const user = await User.findOne({ username, isActive: true });
    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid username or password' 
      });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ 
        error: 'Invalid username or password' 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username, 
        role: user.role,
        employeeId: user.employeeId
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        employeeId: user.employeeId,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Internal server error during login' 
    });
  }
});

// Verify token endpoint
app.get('/verify', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.userId,
      username: req.user.username,
      employeeId: req.user.employeeId,
      role: req.user.role
    }
  });
});

// Log attendance (protected)
app.post('/log', authenticateToken, async (req, res) => {
  try {
    const { action } = req.body;
    
    if (action !== 'checkin' && action !== 'checkout') {
      return res.status(400).json({ 
        error: 'Action must be either "checkin" or "checkout"' 
      });
    }

    const log = new Log({ 
      userId: req.user.userId,
      username: req.user.username,
      action 
    });
    
    const savedLog = await log.save();
    console.log('Log saved successfully:', savedLog);
    
    res.json({ 
      success: true, 
      data: {
        id: savedLog._id,
        username: savedLog.username,
        action: savedLog.action,
        timestamp: savedLog.timestamp
      }
    });
    
  } catch (error) {
    console.error('Error saving log:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error', 
      details: error.message 
    });
  }
});

// Get logs (protected)
app.get('/logs', authenticateToken, async (req, res) => {
  try {
    let query = {};
    
    // If not admin, only show user's own logs
    if (req.user.role !== 'admin') {
      query.userId = req.user.userId;
    }

    const logs = await Log.find(query)
      .sort({ timestamp: -1 })
      .limit(100);
    
    console.log('Found logs:', logs.length);
    
    // Format timestamps for Jakarta timezone
    const formattedLogs = logs.map(log => ({
      id: log._id,
      username: log.username,
      action: log.action,
      timestamp: log.timestamp,
      formattedTime: log.timestamp.toLocaleString('id-ID', {
        timeZone: 'Asia/Jakarta',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      })
    }));
    
    res.json(formattedLogs);
    
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ 
      error: 'Internal server error', 
      details: error.message 
    });
  }
});

// Get all users (admin only)
app.get('/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ 
        error: 'Admin access required' 
      });
    }

    const users = await User.find({ isActive: true })
      .select('-password')
      .sort({ createdAt: -1 });

    res.json(users);
    
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ 
      error: 'Internal server error' 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: err.message 
  });
});

// Handle 404
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await mongoose.connection.close();
  process.exit(0);
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});