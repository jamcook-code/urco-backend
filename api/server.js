const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const auth = require('../middleware/auth');

const app = express();

// Configuración de CORS para permitir Netlify, GitHub Pages y localhost
const corsOptions = {
  origin: [
    'http://localhost:3000', // Para desarrollo local
    'https://jamcook-code.github.io/urco-frontend/', // URL de GitHub Pages
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

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => console.log('Conectado a MongoDB'))
.catch(err => console.error('Error de conexión a MongoDB:', err));

// Modelos
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  points: { type: Number, default: 0 },
  key: { type: String }, // Opcional para 'user'
  address: { type: String },
  phone: { type: String },
  storeName: { type: String },
});

const recyclingValueSchema = new mongoose.Schema({
  material: { type: String, required: true },
  value: { type: Number, required: true },
  description: String,
});

const pointsHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['ingreso', 'egreso'] },
  points: { type: Number, required: true },
  description: String,
  performedBy: { type: String },
  storeName: { type: String },
  date: { type: Date, default: Date.now },
});

const profileHistorySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  oldData: { type: Object },
  newData: { type: Object },
  date: { type: Date, default: Date.now },
});

const registrationKeySchema = new mongoose.Schema({
  role: { type: String, required: true, unique: true },
  key: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);
const RecyclingValue = mongoose.model('RecyclingValue', recyclingValueSchema);
const PointsHistory = mongoose.model('PointsHistory', pointsHistorySchema);
const ProfileHistory = mongoose.model('ProfileHistory', profileHistorySchema);
const RegistrationKey = mongoose.model('RegistrationKey', registrationKeySchema);

// Inicializar claves por defecto
async function initKeys() {
  const roles = ['aliado', 'gestor', 'admin'];
  for (const role of roles) {
    const existing = await RegistrationKey.findOne({ role });
    if (!existing) {
      await new RegistrationKey({ role, key: `clave_${role}_default` }).save();
      console.log(`Clave creada para ${role}: clave_${role}_default`);
    }
  }
}
initKeys();

// Rutas
app.get('/', (req, res) => {
  res.redirect('/api/');
});

app.get('/api/', (req, res) => {
  res.json({ message: 'Backend URCO funcionando en Vercel!' });
});

// Usuarios
app.post('/api/users/register', async (req, res) => {
  const { username, email, password, role, registrationKey } = req.body;
  if (role !== 'user') {
    const keyDoc = await RegistrationKey.findOne({ role });
    if (!keyDoc || keyDoc.key !== registrationKey) {
      return res.status(400).json({ message: 'Clave de registro incorrecta' });
    }
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword, role: role || 'user' });
  try {
    await user.save();
    res.status(201).json({ message: 'Usuario registrado' });
  } catch (err) {
    res.status(400).json({ message: 'Error al registrar usuario', error: err.message });
  }
});

app.post('/api/users/login', async (req, res) => {
  console.log('POST /api/users/login recibido');
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token, user });
});

app.put('/api/users/update-profile', auth, async (req, res) => {
  const { email, address, phone, key, storeName, password } = req.body;
  const user = await User.findById(req.user._id);
  const oldData = { email: user.email, address: user.address, phone: user.phone, key: user.key, storeName: user.storeName };
  user.email = email || user.email;
  user.address = address || user.address;
  user.phone = phone || user.phone;
  user.key = key || user.key;
  user.storeName = storeName || user.storeName;
  if (password) {
    user.password = await bcrypt.hash(password, 10);
  }
  await user.save();
  const history = new ProfileHistory({ userId: user._id, oldData, newData: { email, address, phone, key, storeName } });
  await history.save();
  res.json(user);
});

app.get('/api/users/points-history', auth, async (req, res) => {
  const history = await PointsHistory.find({ userId: req.user._id });
  res.json(history);
});

app.post('/api/users/add-points', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'gestor') return res.status(403).json({ message: 'Acceso denegado' });
  const { username, points, description } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
  user.points += parseInt(points);
  await user.save();
  const performedBy = await User.findById(req.user._id);
  const history = new PointsHistory({ userId: user._id, type: 'ingreso', points, description: description || 'Asignado por gestor/admin', performedBy: performedBy.username, storeName: performedBy.storeName });
  await history.save();
  res.json({ message: 'Puntos agregados' });
});

app.post('/api/users/deduct-points', auth, async (req, res) => {
  if (req.user.role !== 'aliado' && req.user.role !== 'user') return res.status(403).json({ message: 'Acceso denegado' });
  const { username, points, description } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
  // Para aliados, key es requerido; para 'user', opcional (si es el mismo usuario)
  if (req.user.role === 'aliado' && (!req.body.key || user.key !== req.body.key)) return res.status(400).json({ message: 'Clave incorrecta' });
  if (req.user.role === 'user' && req.user._id.toString() !== user._id.toString()) return res.status(403).json({ message: 'No puedes descontar puntos de otros' });
  user.points -= parseInt(points);
  await user.save();
  const performedBy = await User.findById(req.user._id);
  const history = new PointsHistory({ userId: user._id, type: 'egreso', points, description, performedBy: performedBy.username, storeName: performedBy.storeName });
  await history.save();
  res.json({ message: 'Puntos descontados' });
});

app.get('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'gestor') return res.status(403).json({ message: 'Acceso denegado' });
  const users = await User.find();
  res.json(users);
});

app.delete('/api/users/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: 'Usuario eliminado' });
});

// Valores de reciclaje
app.get('/api/recycling-values', auth, async (req, res) => {
  const values = await RecyclingValue.find();
  res.json(values);
});

app.post('/api/recycling-values', auth, async (req, res) => {
  console.log('Rol del usuario:', req.user.role);
  if (req.user.role !== 'admin' && req.user.role !== 'gestor') return res.status(403).json({ message: 'Acceso denegado' });
  const { material, value, description } = req.body;
  const newValue = new RecyclingValue({ material, value, description });
  try {
    await newValue.save();
    res.status(201).json(newValue);
  } catch (err) {
    res.status(400).json({ message: 'Error al agregar valor', error: err.message });
  }
});

app.delete('/api/recycling-values/:id', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'gestor') return res.status(403).json({ message: 'Acceso denegado' });
  await RecyclingValue.findByIdAndDelete(req.params.id);
  res.json({ message: 'Valor eliminado' });
});

// Admin: gestionar claves de registro
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

module.exports = app;