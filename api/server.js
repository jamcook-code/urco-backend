const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Conectado a MongoDB'))
.catch(err => console.error('Error de conexión a MongoDB:', err));

// Modelos
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' }, // Ej. 'admin' o 'user'
});

const recyclingValueSchema = new mongoose.Schema({
  material: { type: String, required: true },
  value: { type: Number, required: true }, // Valor por kg o unidad
  description: String,
});

const User = mongoose.model('User', userSchema);
const RecyclingValue = mongoose.model('RecyclingValue', recyclingValueSchema);

// Middleware de autenticación
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Acceso denegado' });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Token inválido' });
  }
};

// Rutas con prefijo /api
// Ruta raíz (para verificar que funciona)
app.get('/api/', (req, res) => {
  res.json({ message: 'Backend URCO funcionando en Vercel!' });
});

// Usuarios
app.post('/api/users/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, email, password: hashedPassword });
  try {
    await user.save();
    res.status(201).json({ message: 'Usuario registrado' });
  } catch (err) {
    res.status(400).json({ message: 'Error al registrar usuario', error: err.message });
  }
});

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET);
  res.json({ token });
});

// Valores de reciclaje (protegido)
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

// Exportar app para Vercel (no usar app.listen())
module.exports = app;