const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateToken, authorizeAdmin } = require('../middleware/authMiddleware');

// Public Routes (ไม่ต้องมี Token)
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/logout', authController.logout);

// Protected Routes (ต้องมี Token)
// 1. สำหรับ User ทุกคน (001, 002, 003...)
router.get('/me', authenticateToken, (req, res) => {
  res.json({ message: 'Auth Success', user: req.user });
});

// 2. สำหรับ Admin เท่านั้น (001, 002, 004)
router.get('/admin-dashboard', authenticateToken, authorizeAdmin, (req, res) => {
  res.json({ message: 'Welcome Admin! This is restricted area.' });
});

module.exports = router;