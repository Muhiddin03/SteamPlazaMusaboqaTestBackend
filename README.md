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
- **Kamera nazorati** (standart: yoqilgan; admin **Kuzatuv** bo'limidagi tugma bilan istalgan paytda yoqadi/o'chiradi — yangi boshlanadigan testlarga qo'llanadi)
  - Admin barcha faol o'quvchilarning kamera kadrlarini har 4 soniyada ko'radi; o'quvchini bossa — katta oynada **har soniyada** (kadrlar faqat server xotirasida)
  - Bazaga faqat **dalil suratlari** saqlanadi: test boshida bitta va har bir qoida buzilgan paytda (aynan o'sha holat — masalan bosh burilgan kadr)
- **Sun'iy intellekt bilan yuz kuzatuvi** (telefonning o'zida, MediaPipe; video hech qayerga yuborilmaydi):
  - Yuz kameradan chiqsa — 4 s da **ogohlantirish**, 12 s davom etsa **qoidabuzarlik**
  - Kamerada boshqa odam — 2 s da ogohlantirish, 5 s da **qoidabuzarlik**
  - Boshni yon tomonga burish, pastga qarash (kitob/telefon) — 4 s da **ogohlantirish**, 10 s davom etsa **qoidabuzarlik**
  - Ortiqcha harakat — 4 s da ogohlantirish
  - Qog'oz rejimi yoqilsa — o'quvchi rozilik oynasida bu haqda alohida yozuv chiqadi
  - O'quvchi ekranida chiqqan **har bir** ogohlantirish o'qituvchiga ham boradi — aynan o'sha paytdagi surat bilan; admin har bir o'quvchida "nima — necha marta" xulosasini va har bir hodisaning suratini ko'radi
  - Kameraga ruxsat berilmasa (ayniqsa kompyuterda) — o'quvchi oynasida qanday ruxsat berish ko'rsatmasi va "Qayta urinish" tugmasi chiqadi
  - Qoralama (✏️) ochiq paytda bosh holati tekshirilmaydi
  - Ovozli signal admin panelning istalgan bo'limida ishlaydi ("Sinash" tugmasi bilan tekshiring)
  - O'quvchi ekranida darhol qizil ogohlantirish chiqadi; adminda kartochka qizaradi, ovozli signal va bildirishnoma keladi
  - Boshida ~2.5 soniya o'quvchining odatiy holati o'rganiladi (kalibrovka), keyin shunga nisbatan o'lchanadi

**Matematika testlari:** admin **Kuzatuv** yoki **Sozlamalar**da "Qog'ozda ishlash" ni yoqsa — pastga qarash va yozish harakati xavf hisoblanmaydi, yuz 12 soniyagacha ko'rinmasa kechiriladi. Bundan tashqari test ekranida har doim **✏️ Qoralama** bor — o'quvchi barmoq bilan misol ishlaydi (har savolda tozalanadi).

**Natijalar va PDF:**
- Natijalarni belgilab (yoki filtrdagi hammasini) **birdan o'chirish** — admin paroli bilan tasdiqlanadi
- **O'quvchiga PDF** — o'quvchiga yuborish uchun shaffof varaqa: ball, foiz, baho (5 balli), har bir savol bo'yicha javobi va to'g'ri javob, nazorat qaydlari
- **To'liq hisobot PDF** — admin uchun: yuqoridagilar + xavf darajasi, qurilma, kamera suratlari
- Bir nechta o'quvchi tanlansa — bitta PDF: boshida reyting jadvali, keyin har bir o'quvchi alohida sahifada
- **PDF** (reyting jadvali) va **TOP-3** — sinflar kesimida

**O'quvchi oqimi:** sinf → ism familiya → taqiqlar haqida ogohlantirish oynasi → kamera roziligi → test. Javob bitta bosishda yuboriladi, savol va variantlar telefon ekraniga to'liq sig'adi.

> 💡 **Tezlik:** har bir so'rov ~300 ms oladi, chunki Railway serveri uzoqda joylashgan. Railway → backend → Settings → **Region** ni `EU West (Amsterdam)` ga o'zgartirsangiz, O'zbekistondan javob ~2–3 barobar tezlashadi (Postgres'ni ham shu regionga ko'chiring).

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
