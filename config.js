// ENV ustun — Railway/Render da Environment Variables qoyiladi
module.exports = {
  PORT: process.env.PORT || 3000,
  MONGO_URI: process.env.MONGO_URI || 'mongodb+srv://USER:PASS@cluster0.uvqemnt.mongodb.net/oxikey?retryWrites=true&w=majority',
  API_SECRET: process.env.API_SECRET || 'oxicore_secret_change_me_2026',
  SESSION_SECRET: process.env.SESSION_SECRET || 'oxicore_session_change_me_2026',
  ADMIN_USER: process.env.ADMIN_USER || 'admin',
  ADMIN_PASS: process.env.ADMIN_PASS || 'admin123',
  TIMEZONE_OFFSET_MIN: parseInt(process.env.TIMEZONE_OFFSET_MIN || '300', 10),
};
