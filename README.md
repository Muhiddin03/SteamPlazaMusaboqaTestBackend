# 🎓 Steam Plaza — Onlayn test tizimi (v2)

Railway (Node.js + PostgreSQL) backend va Vercel frontend. Onlayn test, qoidabuzarliklarni nazorat qilish va admin paneli bor.

```
steam-plaza/
├── backend/            ← Railway (Node.js + Express + PostgreSQL)
│   ├── server.js
│   ├── package.json / package-lock.json
│   └── .env.example    ← kerakli o'zgaruvchilar ro'yxati
└── frontend/           ← Vercel (statik sayt)
    ├── index.html      ← o'quvchi sahifasi (test)
    ├── admin.html      ← admin panel
    ├── config.js       ← ⚠️ backend manzili shu yerda
    ├── common.js, script.js, admin.js, style.css
    └── vercel.json     ← xavfsizlik sarlavhalari (CSP va h.k.)
```

---

## 🔐 Xavfsizlik (v2 da nima o'zgardi)

| Muammo (eski) | Hozir |
|---|---|
| Parol `1234` brauzer kodida yozilgan edi | Parol faqat serverda, **bcrypt** bilan shifrlangan holda saqlanadi |
| Backend hech kimni tekshirmasdi (`curl` bilan bazani o'chirish mumkin edi) | Barcha admin amallari **JWT token** talab qiladi (8 soat amal qiladi) |
| Parolni cheksiz taxmin qilish mumkin edi | 5 marta xato → hisob 15 daqiqaga bloklanadi, IP bo'yicha ham cheklov bor |
| XSS: o'quvchi ismi orqali admin brauzerida kod ishlatish mumkin edi | Barcha matnlar xavfsiz (`textContent`) chiqariladi, qat'iy CSP sarlavhasi bor |
| Har qanday sayt API'ga murojaat qila olardi | CORS faqat `ALLOWED_ORIGINS` dagi saytga ruxsat beradi |
| To'g'ri javoblar o'quvchiga yuborilardi, ball brauzerda hisoblanardi | To'g'ri javob **hech qachon** o'quvchiga yuborilmaydi, ball serverda hisoblanadi |
| — | Bazani tozalash uchun parolni qayta kiritish kerak |
| — | Parol o'zgartirilganda boshqa qurilmalardagi barcha sessiyalar yopiladi |

## 👁️ Test nazorati (proctoring)

O'quvchi test yechayotganda tizim quyidagilarni kuzatadi va admin paneliga yozadi:

**Qoidabuzarlik** (sanaladi; limitga yetsa test avtomatik to'xtatiladi):
- Ilovadan yoki brauzerdan chiqish, boshqa ilovaga o'tish (ChatGPT, Google, galereya...)
- Ekran ustida boshqa oyna yoki ilova ochish (Android'dagi suzuvchi oynalar, 3 soniyadan uzoq)
- To'liq ekran rejimidan chiqish
- Ekranni bo'lish (split-screen)
- Saytni boshqa varaqda (tab) ochish
- Kamera o'chirilishi (kamera yoqilgan bo'lsa)

**Ogohlantirish** (faqat yoziladi): nusxalash yoki joylashtirishga urinish, Ctrl+C/V/P, PrintScreen, DevTools, internet uzilishi, sahifani qayta yuklash, **juda tez javob** (savolni o'qishga ham ulgurmay javob berish).

**Qo'shimcha himoya:**
- Har bir savolga vaqt beriladi (standart 45 soniya). Vaqt serverda hisoblanadi, shuning uchun uni aldab bo'lmaydi
- Savollar ham, javob variantlari ham har bir o'quvchi uchun tasodifiy tartibda chiqadi. Ixtiyoriy ravishda har o'quvchiga bazadan N ta tasodifiy savol berish mumkin
- Ekranda o'quvchining ismi yozilgan suv belgisi turadi (skrinshot tarqatilsa, kimniki ekani ko'rinadi)
- Matnni belgilash va nusxalash bloklangan
- Bitta o'quvchi testni faqat bir marta topshiradi (admin natijani o'chirsa, qayta topshira oladi)
- **Kamera nazorati** (ixtiyoriy): old kameradan har 20 soniyada va har qoidabuzarlikda surat olinadi, admin ularni ko'radi

Admin panelidagi **Natijalar** bo'limi har 10 soniyada yangilanadi. Unda kim hozir yechayotgani, har bir o'quvchining xavf darajasi (Toza / Shubhali / Yuqori xavf), vaqt ko'rsatilgan nazorat jurnali, har bir savolga ketgan vaqt va kamera suratlari ko'rinadi. Admin testni istalgan payt to'xtata oladi.

> ⚠️ **Halol cheklov:** hech bir veb-sayt o'quvchi qo'lidagi **kitob** yoki **ikkinchi telefonni** aniq ko'ra olmaydi. Bunga qarshi eng samarali vositalar: qisqa vaqt (30–45 soniya), tasodifiy savollar, **kamera nazorati** va javob vaqtlari tahlili. Hammasi bir joyda ishlatilsa, ko'chirish ancha qiyinlashadi.

---

## 🚀 O'rnatish / yangilash

### 1️⃣ Railway (backend) o'zgaruvchilari

Railway → backend servisi → **Variables** bo'limiga quyidagilarni qo'shing. **Kodni push qilishdan OLDIN qo'shing**, aks holda server ishga tushmaydi:

| O'zgaruvchi | Qiymat |
|---|---|
| `DATABASE_URL` | allaqachon bor (Postgres ulangan) |
| `JWT_SECRET` | tasodifiy uzun satr, pastga qarang |
| `ADMIN_USERNAME` | `admin` (yoki o'zingiz xohlagan login) |
| `ADMIN_PASSWORD` | kuchli parol: kamida 10 belgi, harf va raqam |
| `ALLOWED_ORIGINS` | Vercel sayt manzili, masalan `https://steam-plaza.vercel.app` |
| `NODE_ENV` | `production` |

`JWT_SECRET` yaratish:
```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

> Eski ma'lumotlar (sinflar, savollar, natijalar) **saqlanadi**. Eski natijalar "Eski natija" belgisi bilan ko'rinadi.

### 2️⃣ Frontend sozlamasi

`frontend/config.js` fayliga Railway manzilini yozing:
```js
API_URL: 'https://sizning-backend.up.railway.app'
```
Agar backend `*.up.railway.app` emas, o'z domeningizda bo'lsa, `frontend/vercel.json` dagi `connect-src` qismiga ham o'sha domenni yozing.

### 3️⃣ Vercel

Vercel loyihasida **Root Directory = `frontend`** bo'lishi kerak (`vercel.json` shu papkada). GitHub'ga push qilingach, Vercel o'zi yangilanadi.

### 4️⃣ Tekshirish
- `https://backend-manzil/` → `{"status":"ok",...}`
- `https://sayt/admin.html` → `ADMIN_USERNAME` / `ADMIN_PASSWORD` bilan kiring
- **Sozlamalar** bo'limida parolni darhol o'zingiz biladigan boshqa parolga almashtiring

### 🔑 Parolni unutsangiz
Railway'da `ADMIN_RESET_PASSWORD=true` va yangi `ADMIN_PASSWORD` ni o'rnating, qayta deploy qiling, tizimga kiring, keyin `ADMIN_RESET_PASSWORD` ni **o'chirib qo'ying**.

---

## 🆘 Muammolar

| Muammo | Yechim |
|---|---|
| "Serverga ulanib bo'lmadi" | `config.js` dagi URL noto'g'ri, yoki `ALLOWED_ORIGINS` Vercel manziliga mos emas |
| Railway logs: `JWT_SECRET ...` | `JWT_SECRET` qo'shilmagan yoki 32 belgidan qisqa |
| Railway logs: `ADMIN_PASSWORD yaroqsiz` | Parol juda oddiy yoki qisqa |
| "Siz bu testni allaqachon boshlagansiz" | Admin → Natijalar → o'quvchini tanlang → "O'chirish (qayta topshirish)" |
| Kamera ishlamaydi | Sayt `https://` da bo'lishi kerak, brauzerda kameraga ruxsat bering |
| iPhone'da to'liq ekran yo'q | Safari buni qo'llab-quvvatlamaydi, lekin ilovadan chiqish baribir aniqlanadi |
