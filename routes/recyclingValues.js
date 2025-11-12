const express = require('express');
const RecyclingValue = require('../models/RecyclingValue');
const auth = require('../middleware/auth');

const router = express.Router();

// Obtener valores (público o protegido según necesidad)
router.get('/', async (req, res) => {
  try {
    const values = await RecyclingValue.find();
    const result = {};
    values.forEach(v => result[v.material] = { points: v.points, money: v.money });
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Guardar valores (solo administradores)
router.post('/', auth, async (req, res) => {
  if (req.user.role !== 'Administrador') return res.status(403).json({ message: 'Acceso denegado' });
  try {
    for (const [material, data] of Object.entries(req.body)) {
      await RecyclingValue.findOneAndUpdate(
        { material },
        { points: data.points, money: data.money },
        { upsert: true, new: true }
      );
    }
    res.json({ message: 'Valores actualizados' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;