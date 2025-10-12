import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { connectDB } from './db/connectDB.js';

// import routes
import healthCheckRoute from './routes/healthCheck.route.js';

// Load environment variables from .env file
dotenv.config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));
app.use(express.static('public'));

// routes
app.use('/api/v1', healthCheckRoute);



// Connect to MongoDB
connectDB().then(() => {  
  // Start the server
  app.listen(PORT, () => {
    console.log(`✅ Server is running on http://localhost:${PORT}`);
  });
}).catch((err) => {
  console.error('❌ Failed to connect to MongoDB', err);
});   