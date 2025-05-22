const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
// Use Railway's PORT environment variable or fallback to 3000
const port = process.env.PORT || 3000;

// MongoDB connection string - should be moved to environment variable
const mongoURI = process.env.MONGODB_URI || 'mongodb+srv://nandaaustin534:nanda123@cluster0.ccbeqak.mongodb.net/employeeDB?retryWrites=true&w=majority&appName=Cluster0';

mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Add connection event listeners
mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('Disconnected from MongoDB Atlas');
});

const LogSchema = new mongoose.Schema({
  name: String,
  action: String, // "checkin" or "checkout"
  timestamp: { 
    type: Date, 
    default: () => {
      // Create Jakarta time (WIB - UTC+7)
      const now = new Date();
      const jakartaTime = new Date(now.getTime() + (7 * 60 * 60 * 1000));
      return jakartaTime;
    }
  },
});

const Log = mongoose.model('Log', LogSchema);

// Fixed CORS configuration
const allowedOrigins = [
  'http://localhost:5500',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
  'http://127.0.0.1:5501',
  'https://rainbow-lokum-fc45f3.netlify.app', // Your new Netlify URL
  'https://bucolic-naiad-8de588.netlify.app', // Your old Netlify URL
  'nandacobacoba.netlify.app',
  'nandamasihnyoba.netlify.app'
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    // Check if origin is in allowed list or is a netlify.app subdomain
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

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Employee Check-in API is running!', 
    timestamp: new Date().toISOString(),
    timezone: 'Asia/Jakarta'
  });
});

app.post('/log', async (req, res) => {
  try {
    console.log('Received POST /log request:', req.body);
    const { name, action } = req.body;
    
    // Enhanced validation
    if (!name || !name.trim()) {
      console.log('Empty or missing name');
      return res.status(400).json({ error: 'Name is required and cannot be empty' });
    }
    
    if (action !== 'checkin' && action !== 'checkout') {
      console.log('Invalid action:', action);
      return res.status(400).json({ error: 'Action must be either "checkin" or "checkout"' });
    }

    const log = new Log({ 
      name: name.trim(), // Trim whitespace
      action 
    });
    
    const savedLog = await log.save();
    console.log('Log saved successfully:', savedLog);
    res.json({ 
      success: true, 
      data: savedLog 
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

app.get('/logs', async (req, res) => {
  try {
    console.log('Received GET /logs request');
    const logs = await Log.find().sort({ timestamp: -1 }).limit(100);
    console.log('Found logs:', logs.length);
    
    // Format timestamps on server side for Jakarta timezone
    const formattedLogs = logs.map(log => ({
      ...log.toObject(),
      formattedTime: log.timestamp.toLocaleString('id-ID', {
        timeZone: 'Asia/Jakarta',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }),
      // Keep original timestamp for compatibility
      timestamp: log.timestamp
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