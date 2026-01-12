const express = require('express');
const cors = require('cors');
require('dotenv').config();
const db = require('./config/postgresdb');

// เรียกใช้ Route
const authRoutes = require('./routes/authRoutes'); 

const app = express();

app.use(cors());
app.use(express.json());

// ใช้งาน Route
app.use('/api/auth', authRoutes); // ลิ้งค์จะเป็น /api/auth/register

app.get('/', (req, res) => {
  res.send('MIIOT Backend is running!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});