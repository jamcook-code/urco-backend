const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Conectar a MongoDB
mongoose.connect(process.env.MONGO_URI, {

}).then(() => console.log('Conectado a MongoDB')).catch(err => console.error(err));

// Rutas
app.use('/users', require('./routes/users'));
app.use('/recycling-values', require('./routes/recyclingValues'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));