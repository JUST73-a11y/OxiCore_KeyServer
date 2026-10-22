const mongoose = require('mongoose');

const KeySchema = new mongoose.Schema({
  keyCode: { type: String, unique: true, required: true, index: true },
  plan: { type: String, enum: ['1h', '2h', 'daily', 'weekly', 'custom'], default: 'daily' },
  durationSeconds: { type: Number, required: true },
  maxDevices: { type: Number, default: 1 },
  status: { type: String, enum: ['active', 'revoked', 'expired'], default: 'active' },
  note: { type: String, default: '' },
  activatedAt: { type: Date, default: null },
  expiresAt: { type: Date, default: null },
  devices: [{
    deviceId: String,
    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
  }],
}, { timestamps: true });

const AdminSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
});

module.exports = {
  Key: mongoose.model('Key', KeySchema),
  Admin: mongoose.model('Admin', AdminSchema),
};
