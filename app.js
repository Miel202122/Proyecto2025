/* ========================= app.js =========================
 * Honey Management Platform – Express Server (v.29-May-2025)
 * – Serves static assets (CSS, images, JS)
 * – EJS view engine
 * – Business API endpoints + image upload via multer
 * – MySQL connection via ./database/db
 * ======================================================== */

/* ---------- 1. Dependencies ---------- */
const express       = require('express');
const path          = require('path');
const nodemailer    = require('nodemailer');
const bcrypt        = require('bcryptjs');
const multer        = require('multer');
const cookieParser  = require('cookie-parser');
const jwt           = require('jsonwebtoken');
const db            = require('./database/db');       // MySQL connection
const { isAuthenticated, authorizeByRole } = require('./middleware/auth');

const app  = express();

/* Make currentUser available in every template */
app.use((req,res,next)=>{ res.locals.currentUser = req.user || null; next();});
const PORT = process.env.PORT || 3000;

/* ---------- 2. Global Middleware ---------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());
// ---------- Static assets BEFORE auth middleware ----------
app.use(express.static(path.join(__dirname, 'public')));
app.use('/img', express.static(path.join(__dirname, 'public', 'uploads', 'img')));
app.use('/styles', express.static(path.join(__dirname, 'public', 'styles')));
app.use('/js', express.static(path.join(__dirname, 'public', 'js')));

app.use(isAuthenticated);
app.use(authorizeByRole);

// Mantiene res.locals.currentUser siempre actualizado
app.use((req, res, next) => {
  if (req.user) res.locals.currentUser = req.user;
  next();
});

/* ---------- 3. Static File Serving ---------- */
app.use(express.static(path.join(__dirname, 'public')));
app.use('/img',     express.static(path.join(__dirname, 'public', 'uploads', 'img')));
app.use('/styles',  express.static(path.join(__dirname, 'public', 'styles')));

/* ---------- 4. View Engine Setup ---------- */
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'vistas'));

/* ===========================================================
 *                    View Routes (EJS Pages)
 * ========================================================== */
/* =====================  RUTAS PÚBLICAS  ===================== */
app.get('/',          (_, res) => res.render('Login'));
app.get('/registro',  (_, res) => res.render('Register'));
app.get('/Pass',      (_, res) => res.render('Pass'));
app.get('/registroN', (_, res) => res.render('RegisterN'));

/* =====================  RUTAS PRIVADAS  ===================== */
app.get('/main',            isAuthenticated, authorizeByRole, (_, res) => res.render('Main'));
app.get('/Main', (req,res)=> res.redirect('/main'));


app.get('/VUser',           isAuthenticated, authorizeByRole, (_, res) => res.render('UserV'));
app.get('/User',            isAuthenticated, authorizeByRole, (_, res) => res.render('User'));

app.get('/Apiarie',         isAuthenticated, authorizeByRole, (_, res) => res.render('Apiarie'));
app.get('/VApiarie',        isAuthenticated, authorizeByRole, (_, res) => res.render('VApiarie'));

app.get('/Harvest',         isAuthenticated, authorizeByRole, (_, res) => res.render('Harvest'));
app.get('/VHarvest',        isAuthenticated, authorizeByRole, (_, res) => res.render('VHarvest'));

app.get('/QualityH',        isAuthenticated, authorizeByRole, (_, res) => res.render('QualityH'));

app.get('/agregarProducto', isAuthenticated, authorizeByRole, (_, res) => res.render('agregarProducto'));
app.get('/VProducto',       isAuthenticated, authorizeByRole, (_, res) => res.render('VProductos'));

app.get('/Standar',         isAuthenticated, authorizeByRole, (_, res) => res.render('Estandares'));
app.get('/VStandar',        isAuthenticated, authorizeByRole, (_, res) => res.render('VEstandares'));

app.get('/Alerts',          isAuthenticated, authorizeByRole, (_, res) => res.render('Alerts'));
app.get('/Reports',         isAuthenticated, authorizeByRole, (_, res) => res.render('Reportes'));

/* ===========================================================
 *                      Business API
 * ========================================================== */

/* -- Password Update -- */
app.post('/actualizar_contrasena', (req, res) => {
  const { username, email, cellphone, newPassword } = req.body;
  if (!username || !email || !cellphone || !newPassword) {
    return res.status(400).json({ success: false, message: 'Datos incompletos.' });
  }
  const sqlSelect = `
    SELECT id FROM user
     WHERE name = ? AND mail = ? AND cellphone = ?
  `;
  db.query(sqlSelect, [username, email, cellphone], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Error de servidor.' });
    if (!rows.length) return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });

    const userId = rows[0].id;
    bcrypt.hash(newPassword, 10).then(hash => {
      db.query('UPDATE user SET password = ? WHERE id = ?', [hash, userId], updateErr => {
        if (updateErr) return res.status(500).json({ success: false, message: 'No se pudo actualizar la contraseña.' });
        res.json({ success: true, message: 'Contraseña actualizada exitosamente.' });
      });
    }).catch(() => res.status(500).json({ success: false, message: 'Error de servidor.' }));
  });
});

/* ---------- AUTENTICACIÓN ---------- */
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Faltan credenciales.' });
  }

  const sql = 'SELECT id, name, mail, password, role FROM user WHERE name = ? OR mail = ?';
  db.query(sql, [username, username], (err, results) => {
    if (err)     return res.status(500).json({ success: false, message: 'Error de servidor.' });
    if (!results.length) {
      return res.status(401).json({ success: false, message: 'Usuario no encontrado.' });
    }

    const user = results[0];
    const ok = user.password.startsWith('$2') ?
               bcrypt.compareSync(password, user.password) :
               password === user.password;

    if (!ok) return res.status(401).json({ success: false, message: 'Contraseña incorrecta.' });

    const role  = (user.role || 'user').trim().toLowerCase();
    const token = jwt.sign({ id: user.id, role }, process.env.JWT_SECRET || 'supersecretkey', { expiresIn: '2h' });

    // Cookie http-only, misma ruta siempre
    res.cookie('token', token, { httpOnly:true, sameSite:'lax', path:'/' });
    res.json({ success: true, message: 'Inicio de sesión exitoso.' });
  });
});

/* ---------- Logout ---------- */
app.get('/logout', (req, res) => {
  res.clearCookie('token', { path:'/' });   // elimina cookie del token
  res.redirect('/');
});


/* -- User Management (CRUD) -- */
// Create user
app.post('/registrar_usuario', async (req, res) => {
  const { name, mail, password, cellphone, role } = req.body;
  if (!name || !mail || !password || !role) {
    return res.json({ success: false, message: 'Faltan campos requeridos.' });
  }
  const hash = bcrypt.hash(password, 10);
  const sql = 'INSERT INTO user (name, mail, password, cellphone, role) VALUES (?,?,?,?,?)';
  db.query(sql, [name, mail, hash, cellphone, role], err => {
    if (err) return res.json({ success: false, message: 'Error al registrar usuario.' });
    res.json({ success: true, message: 'Registro exitoso.' });
  });
});
// Read users (optional name filter)
app.get('/usuarios', (req, res) => {
  const filtro = req.query.nombre;
  let sql = 'SELECT * FROM user';
  const params = [];
  if (filtro) {
    sql += ' WHERE name LIKE ?';
    params.push(`%${filtro}%`);
  }
  db.query(sql, params, (err, result) => {
    if (err) return res.json({ success: false, message: 'Error al obtener usuarios.' });
    res.json({ success: true, data: result });
  });
});
// Delete user
app.delete('/usuarios/:id', (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, message: 'ID inválido.' });
  }
  db.query('DELETE FROM user WHERE id = ?', [id], (err, result) => {
    if (err) {
      console.error('Error deleting user:', err);
      return res.status(500).json({ success: false, message: 'Error de servidor.' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
    }
    res.json({ success: true, message: 'Usuario eliminado exitosamente.' });
  });
});
// Update user
app.put('/usuarios/:id', (req, res) => {
  const { id } = req.params;
  const { name, mail, cellphone, role, status } = req.body;
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, message: 'ID inválido.' });
  }
  if (!name || !mail || !cellphone || !role || typeof status === 'undefined') {
    return res.status(400).json({ success: false, message: 'Datos incompletos.' });
  }
  const sql = `
    UPDATE user
       SET name = ?, mail = ?, cellphone = ?, role = ?, status = ?
     WHERE id = ?
  `;
  db.query(sql, [name, mail, cellphone, role, status, id], (err, result) => {
    if (err) {
      console.error('Error updating user:', err);
      return res.status(500).json({ success: false, message: 'Error de servidor.' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado.' });
    }
    res.json({ success: true, message: 'Usuario actualizado exitosamente.' });
  });
});

/* -- Apiaries Management (CRUD) -- */
// Create apiary
app.post('/registrar_apiario', (req, res) => {
  const { name, ubication, adress, latitude, length, id_user } = req.body;
  const sql = `
    INSERT INTO apiarie
      (name, ubication, adress, latitude, length, registration_date, id_user)
    VALUES (?, ?, ?, ?, ?, NOW(), ?)
  `;
  db.query(sql, [name, ubication, adress, latitude, length, id_user], err => {
    if (err) return res.json({ success: false, message: 'Error al registrar apiario.' });
    res.json({ success: true, message: 'Apiario registrado exitosamente.' });
  });
});
// Read apiaries with optional ubication filter
app.get('/apiarios', (req, res) => {
  const { ubication } = req.query;
  let sql = 'SELECT * FROM apiarie';
  const params = [];
  if (ubication) {
    sql += ' WHERE ubication LIKE ?';
    params.push(`%${ubication}%`);
  }
  db.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Error al obtener apiarios.' });
    res.json({ success: true, data: rows });
  });
});
// Delete apiary (handles foreign‑key constraints)
app.delete('/apiarios/:id', (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, message: 'ID inválido.' });
  }
  db.query('DELETE FROM apiarie WHERE id = ?', [id], (err, result) => {
    if (err) {
      console.error('Error deleting apiary:', err);
      // FK constraint error
      if (err.code === 'ER_ROW_IS_REFERENCED_2' || err.errno === 1451) {
        return res.status(409).json({
          success: false,
          message: 'No se puede eliminar el apiario con datos relacionados.'
        });
      }
      return res.status(500).json({ success: false, message: 'Error de servidor.' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Apiario no encontrado.' });
    }
    res.json({ success: true, message: `Apiario ID ${id} eliminado exitosamente.` });
  });
});
// Update apiary
app.put('/apiarios/:id', (req, res) => {
  const { id } = req.params;
  const { name, ubication, adress, latitude, length } = req.body;
  const sql = `
    UPDATE apiarie
       SET name = ?, ubication = ?, adress = ?, latitude = ?, length = ?
     WHERE id = ?
  `;
  db.query(sql, [name, ubication, adress, latitude, length, id], err => {
    if (err) return res.json({ success: false, message: 'Error al actualizar apiario.' });
    res.json({ success: true, message: 'Apiario actualizado exitosamente.' });
  });
});

/* -- Product Management (CRUD + file upload) -- */
// Multer setup for image uploads
const storage = multer.diskStorage({
  destination: './public/uploads/',
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 10000000 },  // 10MB limit
  fileFilter: (req, file, cb) => {
    const types = /jpeg|jpg|png|gif/;
    const okMime = types.test(file.mimetype);
    const okExt  = types.test(path.extname(file.originalname).toLowerCase());
    cb(okMime && okExt ? null : new Error('Solo se permiten imágenes'), okMime && okExt);
  }
});
// Create product with image
app.post(
  '/agregar-producto',
  upload.single('imagen'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'No se subió ninguna imagen.' });
    }
    const { nombre, descripcion, precio, id_apiarie } = req.body;
    const imagen = req.file.filename;
    const sql = `
      INSERT INTO products (nombre, descripcion, precio, imagen, id_apiarie)
      VALUES (?, ?, ?, ?, ?)
    `;
    db.query(sql, [nombre, descripcion, precio, imagen, id_apiarie], err => {
      if (err) {
        console.error('Error adding product:', err);
        return res.status(500).json({ success: false, message: 'Error al agregar producto.' });
      }
      res.json({ success: true, message: 'Producto agregado exitosamente.' });
    });
  }
);
// Read all products
app.get('/api/productos', (req, res) => {
  db.query('SELECT * FROM products', (err, results) => {
    if (err) return res.status(500).json({ success: false, message: 'Error en la base de datos.' });
    res.json({ data: results });
  });
});
// Update product
app.put('/api/productos/:id', (req, res) => {
  const { nombre, descripcion, precio, id_apiarie } = req.body;
  const sql = `
    UPDATE products
       SET nombre = ?, descripcion = ?, precio = ?, id_apiarie = ?
     WHERE id = ?
  `;
  db.query(
    sql,
    [nombre, descripcion, precio, id_apiarie, req.params.id],
    err => {
      if (err) return res.status(500).json({ success: false, message: 'Error al actualizar producto.' });
      res.json({ success: true, message: 'Producto actualizado exitosamente.' });
    }
  );
});
// Delete product
app.delete('/api/productos/:id', (req, res) => {
  db.query('DELETE FROM products WHERE id = ?', [req.params.id], err => {
    if (err) return res.status(500).json({ success: false, message: 'Error al eliminar producto.' });
    res.json({ success: true, message: 'Producto eliminado exitosamente.' });
  });
});

/* -- Harvest Management (CRUD) -- */
// Create harvest
app.post('/agregar-cosecha', (req, res) => {
  const { harvest_date, volume_kg, flowering_type, Temperature, humidity, id_apiarie } = req.body;
  if (!harvest_date || volume_kg == null || !flowering_type || Temperature == null || humidity == null || !id_apiarie) {
    return res.json({ success: false, message: 'Faltan campos requeridos.' });
  }
  const sql = `
    INSERT INTO harvest (harvest_date, volume_kg, flowering_type, Temperature, humidity, id_apiarie)
    VALUES (?, ?, ?, ?, ?, ?)
  `;
  db.query(sql, [harvest_date, volume_kg, flowering_type, Temperature, humidity, id_apiarie], err => {
    if (err) return res.json({ success: false, message: 'Error al registrar cosecha.' });
    res.json({ success: true, message: 'Cosecha registrada exitosamente.' });
  });
});
// Read harvests (optional filter by apiary)
app.get('/cosechas', (req, res) => {
  const { id_apiario } = req.query;
  let sql = 'SELECT * FROM harvest';
  const params = [];
  if (id_apiario) {
    sql += ' WHERE id_apiario = ?';
    params.push(id_apiario);
  }
  db.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Error al obtener cosechas.' });
    res.json({ success: true, data: rows });
  });
});
// Delete harvest
app.delete('/cosechas/:id', (req, res) => {
  db.query('DELETE FROM harvest WHERE id = ?', [req.params.id], (err, result) => {
    if (err) {
      console.error('Error deleting harvest:', err);
      return res.status(500).json({ success: false, message: 'Error al eliminar cosecha.' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Cosecha no encontrada.' });
    }
    res.json({ success: true, message: 'Cosecha eliminada exitosamente.' });
  });
});
// Update harvest
app.put('/cosechas/:id', (req, res) => {
  const { harvest_date, volume_kg, flowering_type, Temperature, humidity } = req.body;
  const sql = `
    UPDATE harvest
       SET harvest_date = ?, volume_kg = ?, flowering_type = ?, Temperature = ?, humidity = ?
     WHERE id = ?
  `;
  db.query(sql, [harvest_date, volume_kg, flowering_type, Temperature, humidity, req.params.id], (err, result) => {
    if (err) {
      console.error('Error updating harvest:', err);
      return res.status(500).json({ success: false, message: 'Error al actualizar cosecha.' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Cosecha no encontrada.' });
    }
    res.json({ success: true, message: 'Cosecha actualizada exitosamente.' });
  });
});

/* -- Honey Quality Management (CRUD + Chart Data) -- */
// Create quality record
app.post('/agregar-calidad', (req, res) => {
  const { analysis_date, humidity, acidity, HMF, diastase, result, id_harvest } = req.body;
  if (!analysis_date || humidity == null || acidity == null || HMF == null || diastase == null || !result || !id_harvest) {
    return res.json({ success: false, message: 'Faltan campos requeridos.' });
  }
  const sql = `
    INSERT INTO honey_quality (analysis_date, humidity, acidity, HMF, diastase, result, id_harvest)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;
  db.query(sql, [analysis_date, humidity, acidity, HMF, diastase, result, id_harvest], err => {
    if (err) return res.json({ success: false, message: 'Error al guardar análisis.' });
    res.json({ success: true, message: 'Análisis registrado exitosamente.' });
  });
});
// Update quality record
app.put('/editar-calidad/:id', (req, res) => {
  const { analysis_date, humidity, acidity, HMF, diastase, result, id_harvest } = req.body;
  const sql = `
    UPDATE honey_quality
       SET analysis_date = ?, humidity = ?, acidity = ?, HMF = ?, diastase = ?, result = ?, id_harvest = ?
     WHERE id = ?
  `;
  db.query(sql, [analysis_date, humidity, acidity, HMF, diastase, result, id_harvest, req.params.id], err => {
    if (err) return res.status(500).json({ success: false, message: 'Error al actualizar análisis.' });
    res.json({ success: true, message: 'Análisis actualizado exitosamente.' });
  });
});
// Delete quality record
app.delete('/eliminar-calidad/:id', (req, res) => {
  db.query('DELETE FROM honey_quality WHERE id = ?', [req.params.id], err => {
    if (err) return res.status(500).json({ success: false, message: 'Error al eliminar análisis.' });
    res.json({ success: true, message: 'Análisis eliminado exitosamente.' });
  });
});
// Fetch quality records sorted
app.get('/calidades', (_, res) => {
  const sql = 'SELECT * FROM honey_quality ORDER BY analysis_date DESC';
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Error al obtener análisis.' });
    res.json({ success: true, data: rows });
  });
});
// Chart data for humidity/acidity/HMF/diastase over time
app.get('/api/honey_quality_chart', (_, res) => {
  const sql = `
    SELECT DATE_FORMAT(analysis_date,'%Y-%m-%d') AS label,
           humidity, acidity, HMF AS hmf, diastase
      FROM honey_quality
     WHERE humidity IS NOT NULL
       AND acidity IS NOT NULL
       AND HMF IS NOT NULL
       AND diastase IS NOT NULL
     ORDER BY analysis_date
  `;
  db.query(sql, (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, message: 'Error al obtener datos para gráfico.' });
    }
    res.json({
      labels:   rows.map(r => r.label),
      datasets: {
        humidity: rows.map(r => r.humidity),
        acidity:  rows.map(r => r.acidity),
        hmf:      rows.map(r => r.hmf),
        diastase: rows.map(r => r.diastase)
      }
    });
  });
});

/* -- Quality Standards (CRUD) -- */
// Create standard
app.post('/registrar_estandar', (req, res) => {
  const {
    name,
    max_moisture, max_acidity, max_HMF, max_diastase,
    min_moisture, min_acidity, min_HMF, min_diastase
  } = req.body;
  // Quick server‑side validation
  if (
    !name ||
    [max_moisture, max_acidity, max_HMF, max_diastase,
     min_moisture, min_acidity, min_HMF, min_diastase].some(v => v === undefined)
  ) {
    return res.json({ success: false, message: 'Faltan campos requeridos.' });
  }
  const sql = `
    INSERT INTO quality_standards
      (name, max_moisture, max_acidity, max_HMF, max_diastase,
       min_moisture, min_acidity, min_HMF, min_diastase)
    VALUES (?,?,?,?,?,?,?,?,?)
  `;
  db.query(sql, [
    name,
    max_moisture, max_acidity, max_HMF, max_diastase,
    min_moisture, min_acidity, min_HMF, min_diastase
  ], err => {
    if (err) {
      console.error('Error registering standard:', err);
      return res.json({ success: false, message: 'Error al registrar estándar.' });
    }
    res.json({ success: true, message: 'Estándar registrado exitosamente.' });
  });
});
// Read standards
app.get('/standards', (_, res) => {
  db.query('SELECT * FROM quality_standards ORDER BY id DESC', (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Error al obtener estándares.' });
    res.json({ success: true, data: rows });
  });
});
// Update standard
app.put('/actualizar_estandar/:id', (req, res) => {
  const { id } = req.params;
  const {
    name, max_moisture, min_moisture,
    max_acidity,  min_acidity,
    max_HMF,      min_HMF,
    max_diastase, min_diastase
  } = req.body;
  const sql = `
    UPDATE quality_standards
       SET name=?, max_moisture=?, min_moisture=?,
           max_acidity=?, min_acidity=?,
           max_HMF=?, min_HMF=?,
           max_diastase=?, min_diastase=?
     WHERE id=?
  `;
  db.query(sql, [
    name, max_moisture, min_moisture,
    max_acidity, min_acidity,
    max_HMF, min_HMF,
    max_diastase, min_diastase,
    id
  ], err => {
    if (err) return res.json({ success: false, message: 'Error al actualizar estándar.' });
    res.json({ success: true, message: 'Estándar actualizado exitosamente.' });
  });
});
// Delete standard
app.delete('/eliminar_estandar/:id', (req, res) => {
  db.query('DELETE FROM quality_standards WHERE id=?', [req.params.id], err => {
    if (err) return res.json({ success: false, message: 'Error al eliminar estándar.' });
    res.json({ success: true, message: 'Estándar eliminado exitosamente.' });
  });
});

/* -- Quality Alerts (CRUD) -- */
// Create alert
app.post('/alertas-calidad', (req, res) => {
  const { message, alert_date, id_quality_standards, id_honey_quality } = req.body;
  if (!message || !alert_date || !id_quality_standards || !id_honey_quality) {
    return res.status(400).json({ success: false, message: 'Datos incompletos.' });
  }
  const sql = `
    INSERT INTO quality_alerts (message, alert_date, id_quality_standards, id_honey_quality)
    VALUES (?, ?, ?, ?)
  `;
  db.query(sql, [message, alert_date, id_quality_standards, id_honey_quality], err => {
    if (err) {
      console.error('Error registering alert:', err);
      return res.status(500).json({ success: false, message: 'Error al registrar alerta.' });
    }
    res.json({ success: true, message: 'Alerta registrada exitosamente.' });
  });
});
// Read alerts
app.get('/alertas-calidad', (req, res) => {
  db.query('SELECT * FROM quality_alerts ORDER BY alert_date DESC', (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Error al obtener alertas.' });
    res.json({ success: true, data: rows });
  });
});
// Delete alert
app.delete('/alertas-calidad/:id', (req, res) => {
  const { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ success: false, message: 'ID inválido.' });
  }
  db.query('DELETE FROM quality_alerts WHERE id = ?', [id], (err, result) => {
    if (err) {
      console.error('Error deleting alert:', err);
      return res.status(500).json({ success: false, message: 'Error al eliminar alerta.' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Alerta no encontrada.' });
    }
    res.json({ success: true, message: 'Alerta eliminada exitosamente.' });
  });
});

/* -- Harvest Reports (CRUD) -- */
// List reports
app.get('/harvest_reports', (req, res) => {
  const sql = `
    SELECT id, description, recommendations, alerts,
           moisture_diff, acidity_diff, HMF_diff, diastase_diff,
           id_harvest
      FROM harvest_reports
     ORDER BY id DESC
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: 'Error al obtener informes.' });
    res.json({ data: rows });
  });
});
// Create report
app.post('/harvest_reports', (req, res) => {
  const {
    id_harvest, description, recommendations, alerts,
    moisture_diff, acidity_diff, HMF_diff, diastase_diff
  } = req.body;
  const sql = `
    INSERT INTO harvest_reports
      (description, recommendations, alerts,
       moisture_diff, acidity_diff, HMF_diff, diastase_diff,
       id_harvest)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `;
  db.query(sql, [
    description, recommendations, alerts,
    moisture_diff, acidity_diff, HMF_diff, diastase_diff,
    id_harvest
  ], err => {
    if (err) return res.status(500).json({ success: false, message: 'Error al guardar informe.' });
    res.json({ success: true, message: 'Informe guardado exitosamente.' });
  });
});
// Delete report
app.delete('/harvest_reports/:id', (req, res) => {
  db.query('DELETE FROM harvest_reports WHERE id = ?', [req.params.id], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: 'Error al eliminar informe.' });
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Informe no encontrado.' });
    }
    res.json({ success: true, message: 'Informe eliminado exitosamente.' });
  });
});

/* ===========================================================
 *                  Start HTTP Server
 * =========================================================== */
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);
