const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
// Use Railway's PORT environment variable or fallback to 3000
const port = process.env.PORT || 3000;

// MongoDB connection string
const mongoURI = 'mongodb+srv://nandaaustin534:nanda123@cluster0.ccbeqak.mongodb.net/employeeDB?retryWrites=true&w=majority&appName=Cluster0';

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
      // Create Jakarta time (UTC+7)
      const now = new Date();
      const jakartaTime = new Date(now.getTime() + (7 * 60 * 60 * 1000));
      return jakartaTime;
    }
  },
});

const Log = mongoose.model('Log', LogSchema);

// CORS configuration for production
app.use(cors({
  origin: [
    'http://localhost:5500', // Live Server
    'http://localhost:3000', // Local development
    'http://127.0.0.1:5500', // Alternative localhost
    'https://*.netlify.app', // All Netlify apps
    // Add your specific Netlify URL here once you know it
  ],
  credentials: true
}));

app.use(bodyParser.json());

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ message: 'Employee Check-in API is running!' });
});

app.post('/log', async (req, res) => {
  try {
    console.log('Received POST /log request:', req.body);
    const { name, action } = req.body;
    
    if (!name || (action !== 'checkin' && action !== 'checkout')) {
      console.log('Invalid name or action');
      return res.status(400).json({ error: 'Invalid data' });
    }

    const log = new Log({ name, action });
    const savedLog = await log.save();
    console.log('Log saved successfully:', savedLog);
    res.json({ success: true });
  } catch (error) {
    console.error('Error saving log:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

app.get('/logs', async (req, res) => {
  try {
    console.log('Received GET /logs request');
    const logs = await Log.find().sort({ timestamp: -1 });
    console.log('Found logs:', logs.length);
    res.json(logs);
  } catch (error) {
    console.error('Error fetching logs:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// ONLY ONE app.listen() call at the end
app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on port ${port}`);
});