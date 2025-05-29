// middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

// Rutas que no requieren sesión
const PUBLIC_ROUTES = [
  '/', '/registro', '/Pass', '/registroN',
  '/login', '/actualizar_contrasena', '/registrar_usuario'
, '/logout'];

// Qué rutas puede ver cada rol
const ROLE_ALLOWED_PATHS = {
  admin: null,          // acceso total
  apiario: [
    '/main', '/Apiarie', '/VApiarie',
    '/Harvest', '/VHarvest', '/QualityH',
    '/Reports', '/Alerts'
  , '/VProducto', '/agregarProducto'],
  user: [
    '/main', '/VProducto', '/VProductos', '/VProducto'
  ]
};

/* ---------- Helpers ---------- */
// Coincidencia exacta o prefijo (para rutas como /VApiarie/123)
function matchPath(allowedList, current) {
  return allowedList.some(p => current === p || current.startsWith(p + '/'));
}

/* ---------- Middlewares ---------- */
function isAuthenticated(req, res, next) {
  // 1) Rutas públicas: pasar directo
  if (PUBLIC_ROUTES.includes(req.path)) return next();

  // 2) Leer token de cookie o header
  const token = req.cookies?.token ||
                (req.headers.authorization && req.headers.authorization.split(' ')[1]);

  if (!token) return res.redirect('/');          // sin sesión

  // 3) Verificar JWT
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.redirect('/');           // token inválido / expirado
    req.user = decoded;                          // payload disponible en req
    res.locals.currentUser = decoded;            // …y en todas las vistas EJS
    next();
  });
}

function authorizeByRole(req, res, next) {
  // Si por alguna razón no hay usuario (no debería ocurrir) => continuar
  if (!req.user) return next();

  const role = (req.user.role || 'user').toLowerCase();
  if (role === 'admin') return next();
  // Permitir siempre las rutas de API (prefijo /api) para usuarios autenticados
  if (req.path.startsWith('/api')) return next();           // admin: acceso total

  const allowed = ROLE_ALLOWED_PATHS[role] || [];
  if (matchPath(allowed, req.path)) return next();

  return res.redirect('/main?unauthorized=1');    // 403 para rutas no permitidas
}

module.exports = { isAuthenticated, authorizeByRole };
