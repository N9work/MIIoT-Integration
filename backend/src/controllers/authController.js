const pool = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ==========================================
// 1. REGISTER 
// ==========================================
exports.register = async (req, res) => {
  const body = req.body;

  try {
    // 1. Validation
    if (!body.memberemail || !body.memberpassword) {
      return res.status(400).json({ message: 'กรุณาระบุอีเมลและรหัสผ่าน' });
    }

    // 2. Check Duplicate Email
    const checkEmail = await pool.query('SELECT 1 FROM adm_member WHERE memberemail = $1', [body.memberemail]);
    if (checkEmail.rows.length > 0) {
      return res.status(400).json({ message: 'อีเมลนี้มีผู้ใช้งานแล้ว' });
    }

    // 3. Generate ID (00000001)
    const lastMember = await pool.query('SELECT memberid FROM adm_member ORDER BY memberid DESC LIMIT 1');
    let newId = '00000001';
    if (lastMember.rows.length > 0) {
      const lastIdStr = lastMember.rows[0].memberid;
      const lastIdNum = parseInt(lastIdStr, 10);
      if (!isNaN(lastIdNum)) {
        newId = (lastIdNum + 1).toString().padStart(8, '0');
      }
    }

    // 4. Hash Password
    const hashedPassword = await bcrypt.hash(body.memberpassword, 10);

    // 5. Filter Fields (Whitelist)
    const allowedFields = [
      'memberemail', 'memberfirstnameeng', 'memberlastnameeng',
      'memberfirstnameth', 'memberlastnameth', 'memberphone',
      'customer_id', 'membergroupid'
    ];
    const filteredBody = {};
    allowedFields.forEach(key => {
      if (body[key] !== undefined) filteredBody[key] = body[key];
    });

    // 6. Prepare Final Data
    const finalData = {
      ...filteredBody,
      memberid: newId,
      memberpassword: hashedPassword,
      // Default: ถ้าไม่ส่งมา ให้เป็น '003' (User) ตามตาราง adm_membergroup
      membergroupid: body.membergroupid || '003',
      memberphone: (body.memberphone && body.memberphone.trim() !== '') ? body.memberphone.trim() : null,
      isactive: true,
      createdby: 'SYSTEM',
      createddatetime: new Date()
    };

    // 7. Dynamic SQL
    const columns = Object.keys(finalData).join(', ');
    const placeholders = Object.keys(finalData).map((_, i) => `$${i + 1}`).join(', ');
    const values = Object.values(finalData);

    const sql = `INSERT INTO adm_member (${columns}) VALUES (${placeholders}) RETURNING memberid, memberemail`;
    const result = await pool.query(sql, values);

    res.status(201).json({
      message: 'สมัครสมาชิกสำเร็จ',
      user: result.rows[0]
    });

  } catch (err) {
    console.error('Register Error:', err.message);
    res.status(500).json({ message: 'Server Error', error: err.message });
  }
};

// ==========================================
// 2. LOGIN 
// ==========================================
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Find User
    const user = await pool.query('SELECT * FROM adm_member WHERE memberemail = $1', [email]);
    if (user.rows.length === 0) return res.status(401).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });

    // 2. Check Password
    const validPassword = await bcrypt.compare(password, user.rows[0].memberpassword);
    if (!validPassword) return res.status(401).json({ message: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });

    // 3. Generate Tokens
    const accessToken = jwt.sign(
      { id: user.rows[0].memberid, role: user.rows[0].membergroupid },
      process.env.JWT_SECRET || 'secret_key',
      { expiresIn: '1h' }
    );
    const refreshToken = jwt.sign(
      { id: user.rows[0].memberid },
      process.env.JWT_REFRESH_SECRET || 'refresh_secret_key',
      { expiresIn: '7d' }
    );

    // 4. Save Login History
    await pool.query(
      `INSERT INTO adm_login (member_id, token, ip_address, created_at) VALUES ($1, $2, $3, NOW())`,
      [user.rows[0].memberid, refreshToken, req.ip]
    );

    // 5. Response
    res.json({
      message: 'เข้าสู่ระบบสำเร็จ',
      accessToken,
      refreshToken,
      user: {
        id: user.rows[0].memberid,
        name_en: user.rows[0].memberfirstnameeng,
        name_th: user.rows[0].memberfirstnameth,
        email: user.rows[0].memberemail,
        group: user.rows[0].membergroupid
      }
    });

  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).send('Server Error');
  }
};

// ==========================================
// 3. REFRESH TOKEN ขอ Access Token ใหม่
// ==========================================
exports.refreshToken = async (req, res) => {
  const { token } = req.body;

  if (!token) return res.sendStatus(401);

  try {
    const tokenInDb = await pool.query('SELECT * FROM adm_login WHERE token = $1', [token]);
    if (tokenInDb.rows.length === 0) {
      return res.status(403).json({ message: 'Token นี้ถูกยกเลิกหรือไม่มีอยู่ในระบบ' });
    }

    jwt.verify(token, process.env.JWT_REFRESH_SECRET || 'refresh_secret_key', (err, user) => {
      if (err) return res.status(403).json({ message: 'Token หมดอายุหรือระบุตัวตนไม่ได้' });

      pool.query('SELECT membergroupid FROM adm_member WHERE memberid = $1', [user.id])
        .then(result => {
          const currentRole = result.rows[0]?.membergroupid || '003';
          
          const newAccessToken = jwt.sign(
            { id: user.id, role: currentRole },
            process.env.JWT_SECRET || 'secret_key', 
            { expiresIn: '1h' }
          );

          res.json({ accessToken: newAccessToken });
        })
        .catch(dbErr => {
          console.error(dbErr);
          res.sendStatus(500);
        });
    });

  } catch (err) {
    console.error('Refresh Token Error:', err.message);
    res.sendStatus(500);
  }
};

// ==========================================
// 4. LOGOUT
// ==========================================
exports.logout = async (req, res) => {
  const { token } = req.body;

  if (!token) return res.status(400).json({ message: 'กรุณาระบุ Refresh Token ที่ต้องการ Logout' });

  try {
    await pool.query('DELETE FROM adm_login WHERE token = $1', [token]);
    res.json({ message: 'ออกจากระบบเรียบร้อย (Token ถูกทำลายแล้ว)' });
  } catch (err) {
    console.error('Logout Error:', err.message);
    res.status(500).send('Server Error');
  }
};