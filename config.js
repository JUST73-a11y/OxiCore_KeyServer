module.exports = {
  PORT: process.env.PORT || 3000,
  MONGO_URI: process.env.MONGO_URI || 'mongodb+srv://JustAli:Justali0113JustAli2006@cluster0.uvqemnt.mongodb.net/oxikey?retryWrites=true&w=majority',
  API_SECRET: process.env.API_SECRET || 'oxicore_secret_my_super_key_2026',
  SESSION_SECRET: process.env.SESSION_SECRET || 'oxicore_session_secret_2026',
  ADMIN_USER: process.env.ADMIN_USER || 'admin',
  ADMIN_PASS: process.env.ADMIN_PASS || 'admin12345',
  TIMEZONE_OFFSET_MIN: parseInt(process.env.TIMEZONE_OFFSET_MIN || '300', 10),
};
