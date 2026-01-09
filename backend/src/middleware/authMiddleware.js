const jwt = require('jsonwebtoken');

// 1. เช็คว่ามี Token ไหม
exports.authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  // ใช้ secret เดียวกับตอน Login (AccessToken) และแก้ Typo ใน ' ' ออก
  jwt.verify(token, process.env.JWT_SECRET || 'secret_key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// 2. เช็คว่าเป็น Admin ไหม
exports.authorizeAdmin = (req, res, next) => {
  // อ้างอิงจากตาราง adm_membergroup:
  // 001 = System Admin
  // 002 = Super User
  // 004 = Admin Customer
  // 005 = Supervisor
  const adminRoles = ['001', '002', '004', '005']; 

  if (!adminRoles.includes(req.user.role)) {
    return res.status(403).json({ 
      message: `Access Denied: สิทธิ์ของคุณคือ ${req.user.role} แต่ระบบต้องการ Admin` 
    });
  }
  next();
};