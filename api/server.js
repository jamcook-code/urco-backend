const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const XLSX = require('xlsx');

const app = express();

// Configuración de CORS para permitir Netlify, GitHub Pages y localhost
const corsOptions = {
  origin: [
    'http://localhost:3000', // Para desarrollo local
    'https://jamcook-code.github.io', // Origen base de GitHub Pages
    'https://jamcook-code.github.io/urco-frontend/', // URL completa de GitHub Pages
    'https://promapurco.netlify.app/' // URL de Netlify
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

app.use(express.json());

// Conectar a MongoDB
mongoose.connect('mongodb+srv://jamcook17_db_user:NuevaPass123@cluster0.9pnomnh.mongodb.net/?appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Conectado a MongoDB'))
  .catch(err => console.error('Error de conexión a MongoDB:', err));
// Modelo de Usuario
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role: String,
  points: { type: Number, default: 0 },
  address: String,
  phone: String,
  key: String, // Clave para aliados (no para user)
  storeName: String,
});
const User = mongoose.model('User', userSchema);

// Modelo de Historial de Puntos
const pointsHistorySchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  type: String, // 'ingreso' o 'egreso'
  points: Number,
  description: String,
  performedBy: String,
  storeName: String,
  date: { type: Date, default: Date.now },
});
const PointsHistory = mongoose.model('PointsHistory', pointsHistorySchema);

// Modelo de Valores de Reciclaje
const recyclingValueSchema = new mongoose.Schema({
  material: String,
  value: Number, // Puntos por kg
  description: String,
});
const RecyclingValue = mongoose.model('RecyclingValue', recyclingValueSchema);

// Modelo de Claves de Registro
const registrationKeySchema = new mongoose.Schema({
  role: String,
  key: String,
});
const RegistrationKey = mongoose.model('RegistrationKey', registrationKeySchema);

// Middleware de autenticación
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Acceso denegado' });
  try {
    const verified = jwt.verify(token, 'secretkey');
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Token inválido' });
  }
};

// Rutas
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ _id: user._id, role: user.role }, 'secretkey');
  res.json({ token, user: { username: user.username, email: user.email, role: user.role, points: user.points, address: user.address, phone: user.phone, key: user.key, storeName: user.storeName } });
});

app.post('/api/users/register', async (req, res) => {
  const { username, email, password, role, registrationKey, address, phone } = req.body;
  console.log('Intentando registrar:', { username, email, role });
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword, role, address, phone });
  try {
         await user.save();
         console.log('Usuario guardado:', user);
         res.json({ message: 'Usuario registrado' });
       } catch (error) {
         console.error('Error al guardar usuario:', error);
         res.status(500).json({ message: 'Error al registrar' });
       }
  if (role !== 'user') {
    let keyValid = false;
    if (role === 'admin') {
      // Clave por defecto para admin: '1234'
      const keyDoc = await RegistrationKey.findOne({ role });
      if (keyDoc) {
        keyValid = keyDoc.key === registrationKey;
      } else {
        keyValid = registrationKey === '1234';  // Por defecto
      }
    } else {
      const keyDoc = await RegistrationKey.findOne({ role });
      keyValid = keyDoc && keyDoc.key === registrationKey;
    }
    if (!keyValid) {
      return res.status(400).json({ message: 'Clave de registro inválida' });
    }
  }
  await user.save();
  res.json({ message: 'Usuario registrado' });
});

app.put('/api/users/update-profile', auth, async (req, res) => {
  const { email, address, phone, password, key, storeName } = req.body;
  const user = await User.findById(req.user._id);
  if (email) user.email = email;
  if (address !== undefined) user.address = address;
  if (phone !== undefined) user.phone = phone;
  if (password) user.password = await bcrypt.hash(password, 10);
  if (key !== undefined) user.key = key;
  if (storeName !== undefined) user.storeName = storeName;
  await user.save();
  res.json({ message: 'Perfil actualizado' });
});

app.post('/api/users/add-points', auth, async (req, res) => {
  if (req.user.role !== 'gestor' && req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  const { username, points, description } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
  user.points += parseInt(points);
  await user.save();
  const performedBy = await User.findById(req.user._id);
  const history = new PointsHistory({ userId: user._id, type: 'ingreso', points, description, performedBy: performedBy.username, storeName: performedBy.storeName });
  await history.save();
  res.json({ message: 'Puntos agregados' });
});

app.post('/api/users/deduct-points', auth, async (req, res) => {
  if (req.user.role !== 'aliado' && req.user.role !== 'user') return res.status(403).json({ message: 'Acceso denegado' });
  const { username, points, description, password } = req.body; // Cambiar 'key' por 'password'
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
  // Para aliados, verificar clave; para 'user', verificar contraseña de login
  if (req.user.role === 'aliado') {
    if (!req.body.key || user.key !== req.body.key) return res.status(400).json({ message: 'Clave incorrecta' });
  } else if (req.user.role === 'user' && req.user._id.toString() !== user._id.toString()) {
    return res.status(403).json({ message: 'No puedes descontar puntos de otros' });
  } else if (req.user.role === 'user') {
    // Verificar contraseña de login para 'user'
    if (!(await bcrypt.compare(password, user.password))) return res.status(400).json({ message: 'Contraseña incorrecta' });
  }
  user.points -= parseInt(points);
  await user.save();
  const performedBy = await User.findById(req.user._id);
  const history = new PointsHistory({ userId: user._id, type: 'egreso', points, description, performedBy: performedBy.username, storeName: performedBy.storeName });
  await history.save();
  res.json({ message: 'Puntos descontados' });
});

app.get('/api/users/points-history', auth, async (req, res) => {
  const history = await PointsHistory.find({ userId: req.user._id });
  res.json(history);
});

app.get('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'gestor' && req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  const users = await User.find({}, 'username email address phone role points');
  res.json(users);
});

app.delete('/api/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: 'Usuario eliminado' });
});

app.get('/api/recycling-values', async (req, res) => {
  const values = await RecyclingValue.find();
  res.json(values);
});

app.post('/api/recycling-values', auth, async (req, res) => {
  if (req.user.role !== 'gestor' && req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  const { material, value, description } = req.body;
  const recyclingValue = new RecyclingValue({ material, value, description });
  await recyclingValue.save();
  res.json({ message: 'Valor agregado' });
});

app.put('/api/recycling-values/:id', auth, async (req, res) => {
  if (req.user.role !== 'gestor' && req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  const { material, value, description } = req.body;
  await RecyclingValue.findByIdAndUpdate(req.params.id, { material, value, description });
  res.json({ message: 'Valor actualizado' });
});

app.delete('/api/recycling-values/:id', auth, async (req, res) => {
  if (req.user.role !== 'gestor' && req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  await RecyclingValue.findByIdAndDelete(req.params.id);
  res.json({ message: 'Valor eliminado' });
});

app.get('/api/admin/registration-keys', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  const keys = await RegistrationKey.find();
  res.json(keys);
});

app.put('/api/admin/registration-keys', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  const { role, key } = req.body;
  await RegistrationKey.findOneAndUpdate({ role }, { key }, { upsert: true });
  res.json({ message: 'Clave actualizada' });
});

// Ruta raíz para Vercel
app.get('/', (req, res) => res.send('Servidor corriendo'));

// Exportar para Vercel (reemplaza app.listen)
module.exports = app;