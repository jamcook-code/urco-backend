const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const auth = require('../middleware/auth');

const app = express();

// CORS
const corsOptions = {
  origin: ['https://peaceful-crostata-5451a0.netlify.app', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', 'https://peaceful-crostata-5451a0.netlify.app');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

app.use(express.json());

// MongoDB
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
  key: { type: String }, // Clave para aliados
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
  date: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const RecyclingValue = mongoose.model('RecyclingValue', recyclingValueSchema);
const PointsHistory = mongoose.model('PointsHistory', pointsHistorySchema);
const registrationKeySchema = new mongoose.Schema({
  role: { type: String, required: true, unique: true }, // 'aliado', 'gestor', 'admin'
  key: { type: String, required: true },
});

const RegistrationKey = mongoose.model('RegistrationKey', registrationKeySchema);

// Inicializa claves por defecto (ejecuta una vez)
async function initKeys() {
  const roles = ['aliado', 'gestor', 'admin'];
  for (const role of roles) {
    const existing = await RegistrationKey.findOne({ role });
    if (!existing) {
      await new RegistrationKey({ role, key: `clave_${role}_default` }).save();
    }
  }
}
initKeys();

// Rutas nuevas para admin
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

// Modifica registro para validar clave
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
// Rutas
app.get('/', (req, res) => {
  res.redirect('/api/');
});

app.get('/api/', (req, res) => {
  res.json({ message: 'Backend URCO funcionando en Vercel!' });
});

// Usuarios
app.post('/api/users/register', async (req, res) => {
  const { username, email, password, key } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword, key, role: 'user' });
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
  const { username, email, key } = req.body;
  const user = await User.findByIdAndUpdate(req.user._id, { username, email, key }, { new: true });
  res.json(user);
});

app.get('/api/users/points-history', auth, async (req, res) => {
  const history = await PointsHistory.find({ userId: req.user._id });
  res.json(history);
});

app.post('/api/users/add-points', auth, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'gestor') return res.status(403).json({ message: 'Acceso denegado' });
  const { email, points } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: 'Usuario no encontrado' });
  user.points += parseInt(points);
  await user.save();
  const history = new PointsHistory({ userId: user._id, type: 'ingreso', points, description: 'Asignado por gestor' });
  await history.save();
  res.json({ message: 'Puntos agregados' });
});

app.post('/api/users/deduct-points', auth, async (req, res) => {
  if (req.user.role !== 'aliado') return res.status(403).json({ message: 'Acceso denegado' });
  const { email, points, description, key } = req.body;
  const user = await User.findOne({ email });
  if (!user || user.key !== key) return res.status(400).json({ message: 'Usuario o clave incorrecta' });
  user.points -= parseInt(points);
  await user.save();
  const history = new PointsHistory({ userId: user._id, type: 'egreso', points, description });
  await history.save();
  res.json({ message: 'Puntos descontados' });
});

app.get('/api/users', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
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
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  const { material, value, description } = req.body;
  const newValue = new RecyclingValue({ material, value, description });
  try {
    await newValue.save();
    res.status(201).json(newValue);
  } catch (err) {
    res.status(400).json({ message: 'Error al agregar valor', error: err.message });
  }
});

module.exports = app;