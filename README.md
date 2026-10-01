🔐 NPVT Decryptor Bot

ربات تلگرامی رمزگشای کانفیگ — فرمت‌های قفل اپلیکیشن‌های تونل را باز می‌کند و خروجی را به‌صورت لینک‌های استاندارد آماده ایمپورت (vless:// / vmess:// / trojan:// / ss:// / ssh://) تحویل می‌دهد.

    ⚠️ Disclaimer: این ابزار برای رمزگشایی کانفیگ‌هایی است که خودتان ساخته‌اید یا رمز آن‌ها به‌صورت عمومی منتشر شده است. مسئولیت نحوه استفاده با کاربر است.

⚡ نصب سریع (Quick Start)

🐳 Docker — همه در یک خط:

git clone https://github.com/arash7898666/bot.git && cd bot && docker build -t npvtbot . && docker run -d --name npvtbot -e BOT_TOKEN="توکن_ربات" -e ADMIN_IDS="آیدی_ادمین" -v $(pwd)/data:/app/data --restart unless-stopped npvtbot

☁️ Render — بدون سرور:Fork این ریپو → در Render یک Web Service بساز → متغیرهای BOT_TOKEN و ADMIN_IDS را اضافه کن → تمام. 🎉
📖 راهنمای کامل نصب (VPS سه روش + Render + systemd)
📋 فرمت‌های پشتیبانی‌شده
🟢 NPV Tunnel (کامل)
فرمت	نوع قفل	نیاز به رمز
.npvt	رمزنگاری whitebox چندلایه	❌
.npvs v1 — Passphrase	PBKDF2 + ChaCha20-Poly1305	✅ رمز
.npvs v1 — AppKey	whitebox AES	❌
.npvs v5 (Gen2) — Passphrase	PBKDF2 + HKDF + رکوردهای رمز	✅ رمز (Key)
.npvs v5 (Gen2) — Anyone with the app	whitebox AES نسل ۲	❌
.npvs v5 (Gen2) — Keep open (NPVO1)	بدون قفل	❌
.npvs v5 (Gen2) — Specific people (E2E)	رمزنگاری گیرنده‌محور	🔒 طبق طراحی، بدون کلید گیرنده باز نمی‌شود
کانتینر NPVT1 / NPVTSUB1	مرجع‌های قدیمی	❌
🟢 سایر اپلیکیشن‌ها
فرمت	اپلیکیشن
.ehi	HTTP Injector
.hat	HA Tunnel Plus
.happ	Happ
.slip	SlipNet
.nm	NetMod
.dark	DarkTunnel
🟢 عمومی

    فایل‌های ZIP (تو در تو تا ۳ لایه)
    JSON (شامل v2rayJson توکار و napsternetV profiles)
    Base64 / Hex
    لینک‌های خام: vless://, vmess://, trojan://, ss://, ssr://, hysteria2://, tuic://

🤖 نحوه استفاده

    ربات را استارت کنید: /start
    فایل کانفیگ را به‌صورت فایل بفرستید (نه متن) — فرمت خودکار تشخیص داده می‌شود
    اگر فایل رمز داشته باشد، ربات رمز (Key/Passphrase) می‌پرسد → تایپ کنید و بفرستید
    لینک‌های استخراج‌شده را در هر کلاینتی (v2rayNG، Hiddify، NapsternetV و...) ایمپورت کنید

دستورات ربات
دستور	سطح دسترسی	توضیح
/start	همه	شروع و راهنما
/formats	همه	لیست فرمت‌ها
/version	همه	نسخه ربات
/channel	همه	وضعیت جوین اجباری
/setchannel @name	ادمین	تنظیم جوین اجباری (off برای غیرفعال)
/stats	ادمین	آمار کاربران و پردازش‌ها
/broadcast متن	ادمین	ارسال پیام همگانی
🚀 راه‌اندازی
متغیرهای محیطی
متغیر	الزامی	توضیح
BOT_TOKEN	✅	توکن ربات از @BotFather
ADMIN_IDS	اختیاری	آیدی عددی ادمین‌ها با کاما: 123,456
FORCE_CHANNEL	اختیاری	کانال جوین اجباری (یا با /setchannel داخل ربات)
DEBUG	اختیاری	1 = لاگ تشخیصی بیشتر
PORT	اختیاری	پورت health-check (پیش‌فرض 8080)
🐳 نصب روی VPS
روش ۱ — Docker (پیشنهادی)

# نصب داکر (اگر ندارید)curl -fsSL https://get.docker.com | sh# دریافت و بیلدgit clone https://github.com/arash7898666/bot.gitcd botdocker build -t npvtbot .# اجراdocker run -d --name npvtbot \  -e BOT_TOKEN="123456:ABC-DEF..." \  -e ADMIN_IDS="123456789" \  -v $(pwd)/data:/app/data \  --restart unless-stopped \  npvtbot

مدیریت:

docker logs -f npvtbot                      # لاگ زندهdocker restart npvtbot                      # ری‌استارتdocker stop npvtbot && docker rm npvtbot    # حذف

روش ۲ — مستقیم با Go

# Go 1.22+ لازم استgit clone https://github.com/arash7898666/bot.git && cd botgo mod tidygo build -o npvtbot .BOT_TOKEN="123456:ABC-DEF..." ADMIN_IDS="123456789" ./npvtbot

روش ۳ — systemd (اجرای دائمی)

sudo nano /etc/systemd/system/npvtbot.service

محتوا:

[Unit]Description=NPVT Decryptor BotAfter=network.target[Service]WorkingDirectory=/opt/botExecStart=/opt/bot/npvtbotEnvironment=BOT_TOKEN=123456:ABC-DEF...Environment=ADMIN_IDS=123456789Restart=alwaysRestartSec=5[Install]WantedBy=multi-user.target

فعال‌سازی:

sudo mkdir -p /opt/bot# باینری npvtbot و فایل‌های پروژه را در /opt/bot بگذاریدsudo systemctl daemon-reloadsudo systemctl enable --now npvtbotsudo journalctl -u npvtbot -f   # لاگ زنده

☁️ نصب روی Render

    این ریپو را Fork کنید
    در Render Dashboard → New → Web Service
    ریپو را وصل کنید — Runtime: Docker
    در بخش Environment این متغیرها را اضافه کنید:
        BOT_TOKEN = توکن ربات
        ADMIN_IDS = آیدی ادمین
    Create Web Service — دیپلوی خودکار شروع می‌شود

⚠️ نکات مهم Render:

    فقط یک سرویس با یک توکن اجرا کنید — اجرای دوتایی خطای Conflict: terminated by other getUpdates می‌دهد
    پلن Free خواب می‌رود؛ برای ربات فعال پلن پولی بهتر است
    کش جداول بعد از هر دیپلوی پاک می‌شود و خودکار دوباره دانلود می‌شود (بی‌ضرر)

🔄 جداول رمزنگاری (White-Box)

برای بازکردن قفل‌های «بدون رمز»، ربات به جداول white-box نیاز دارد (نسل ۱ و ۲). در اولین اجرا خودکار از Pantegnos دانلود و در npvs_cache_*.bin کش می‌شوند.

اگر سرور اینترنت خروجی ندارد: فایل‌ها را دستی از مسیر internal/modules/impl/assets/npvs/ ریپوی Pantegnos بردارید و کنار باینری در پوشه npvs/ بگذارید.

سلامت جداول در لاگ استارتاپ نمایش داده می‌شود:

🧪 WB SelfTest: 2/2 KDK درست✅ جداول Gen2 White-Box آماده شد (749568 بایت)

🛡️ نکات امنیتی

    توکن ربات هرگز commit نشود — همیشه از متغیر محیطی بخوانید. اگر لو رفت، در BotFather با /revoke توکن جدید بگیرید
    فایل‌های bot_settings.json و bot_stats.json حاوی اطلاعات کاربران‌اند — عمومی نکنید
    ربات را فقط در یک مکان اجرا کنید (VPS یا Render)

🛠️ تکنولوژی

Go 1.22 • Telegram Bot API • ChaCha20-Poly1305 • PBKDF2 • HKDF • Argon2id • White-box AES (Gen1/Gen2) • XXTEA • MsgPack
🙏 منابع

    فرمت NPVS: بازمهندسی‌شده از Pantegnos
    go-telegram-bot-api • golang.org/x/crypto • vmihailenco/msgpack

📄 License

MIT
