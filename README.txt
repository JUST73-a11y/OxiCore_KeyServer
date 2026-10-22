OxiCore Key Server — Node.js + MongoDB
======================================

TALAB:
- Node.js 18+
- MongoDB (local yoki Atlas)

O'RNATISH:
1) config.js ni tahrirla:
   MONGO_URI   — mongodb://127.0.0.1:27017/oxikey  yoki Atlas URI
   API_SECRET  — uzun random (apk da ham shu)
   ADMIN_USER / ADMIN_PASS

2) Terminal:
   cd OxiCore_KeyServer
   npm install
   npm start

3) Admin panel:
   http://IP:3000/admin/login
   (default config dagi login/parol)

4) API (apk ishlatadi):
   POST http://IP:3000/api/activate
   POST http://IP:3000/api/validate
   body JSON:
   {
     "key": "ABCD-EFGH-IJKL-MNOP",
     "device_id": "android_id",
     "secret": "API_SECRET"
   }

IMKONIYATLAR:
- plan: 1h, 2h, daily, weekly, custom (sekund)
- max devices
- extend / revoke / reset-from-now
- bir nechta key birdan generatsiya

APK:
Server ishlagach IP/domain + API_SECRET ni yoz —
LoginActivity ni shu API ga ulab apk beraman.
