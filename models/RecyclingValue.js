const mongoose = require('mongoose');

const recyclingValueSchema = new mongoose.Schema({
  material: { type: String, required: true, unique: true },
  points: { type: Number, required: true },
  money: { type: Number, required: true },
}, { timestamps: true });

module.exports = mongoose.model('RecyclingValue', recyclingValueSchema);