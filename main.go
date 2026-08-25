package main

import (
    "archive/zip"
    "bytes"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "os"
    "path/filepath"
    "runtime/debug"
    "strings"
    "sync"
    "time"

    tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const botVersion = "7.0-LIGHT-OPT"

const (
    msgLimit   = 3900
    maxChunks  = 3
    procTimeout = 120 * time.Second
)

var (
    bot        *tgbotapi.BotAPI
    adminIDs   = map[int64]bool{}
    httpClient = &http.Client{Timeout: 90 * time.Second}
)

// ═══════════════════ تنظیمات و آمار ═══════════════════

type BotSettings struct {
    ForceChannel string `json:"force_channel"`
}

type BotStats struct {
    Users     map[int64]string `json:"users"`
    Processed int              `json:"processed"`
}

var (
    settings   = BotSettings{}
    stats      = BotStats{Users: map[int64]string{}}
    settingsMu sync.Mutex
    statsMu    sync.Mutex
    statsDirty bool
)

const settingsFile = "bot_settings.json"
const statsFile = "bot_stats.json"

func loadState() {
    if b, err := os.ReadFile(settingsFile); err == nil {
        _ = json.Unmarshal(b, &settings)
    } else if ch := os.Getenv("FORCE_CHANNEL"); ch != "" {
        if !strings.HasPrefix(ch, "@") {
            ch = "@" + ch
        }
        settings.ForceChannel = ch
    }
    if b, err := os.ReadFile(statsFile); err == nil {
        _ = json.Unmarshal(b, &stats)
        if stats.Users == nil {
            stats.Users = map[int64]string{}
        }
    }
}

func saveSettings() {
    settingsMu.Lock()
    defer settingsMu.Unlock()
    b, _ := json.Marshal(settings)
    _ = os.WriteFile(settingsFile, b, 0644)
}

func persistStats() {
    b, _ := json.Marshal(stats)
    _ = os.WriteFile(statsFile, b, 0644)
    statsDirty = false
}

func startStatsFlusher() {
    go func() {
        for range time.Tick(30 * time.Second) {
            statsMu.Lock()
            if statsDirty {
                persistStats()
            }
            statsMu.Unlock()
        }
    }()
}

func trackUser(from *tgbotapi.User) {
    if from == nil {
        return
    }
    statsMu.Lock()
    defer statsMu.Unlock()
    name := from.FirstName
    if from.UserName != "" {
        name = "@" + from.UserName
    }
    if old, ok := stats.Users[from.ID]; !ok || old != name {
        stats.Users[from.ID] = name
        statsDirty = true
    }
}

func incrementProcessed() {
    statsMu.Lock()
    stats.Processed++
    statsDirty = true
    statsMu.Unlock()
}

func channelStatus() string {
    settingsMu.Lock()
    defer settingsMu.Unlock()
    if settings.ForceChannel == "" {
        return "غیرفعال"
    }
    return settings.ForceChannel
}

// ═══════════════════ کش عضویت کانال (۵ دقیقه، فقط مثبت) ═══════════════════

type memberCacheEntry struct {
    until time.Time
}

var memberCache = struct {
    sync.Mutex
    m map[int64]memberCacheEntry
}{m: map[int64]memberCacheEntry{}}

const memberCacheTTL = 5 * time.Minute

func isMemberOf(userID int64, channel string) bool {
    if channel == "" {
        return true
    }
    memberCache.Lock()
    e, hit := memberCache.m[userID]
    memberCache.Unlock()
    if hit && time.Now().Before(e.until) {
        return true
    }

    member, err := bot.GetChatMember(tgbotapi.GetChatMemberConfig{
        ChatConfigWithUser: tgbotapi.ChatConfigWithUser{
            SuperGroupUsername: channel,
            UserID:             userID,
        },
    })
    if err != nil {
        log.Printf("⚠️ بررسی عضویت ناموفق (%s): %v — احتمالاً ربات ادمین کانال نیست", channel, err)
        return false
    }
    switch member.Status {
    case "creator", "administrator", "member":
        memberCache.Lock()
        memberCache.m[userID] = memberCacheEntry{until: time.Now().Add(memberCacheTTL)}
        memberCache.Unlock()
        return true
    }
    return false
}

// ═══════════════════ قفل هر-کاربر ═══════════════════

var userLocks sync.Map

func tryAcquireUser(chatID int64) bool {
    actual, _ := userLocks.LoadOrStore(chatID, make(chan struct{}, 1))
    ch := actual.(chan struct{})
    select {
    case ch <- struct{}{}:
        return true
    default:
        return false
    }
}

func releaseUser(chatID int64) {
    if v, ok := userLocks.Load(chatID); ok {
        select {
        case <-v.(chan struct{}):
        default:
        }
    }
}

// ═══════════════════ منوی دستورات (☰) ═══════════════════

func setBotCommands() {
    publicCmds := []tgbotapi.BotCommand{
        {Command: "start", Description: "🚀 شروع و راهنمای ربات"},
        {Command: "help", Description: "📖 راهنمای استفاده"},
        {Command: "formats", Description: "📋 فرمت‌های پشتیبانی‌شده"},
        {Command: "version", Description: "🤖 نمایش نسخه ربات"},
        {Command: "channel", Description: "📢 وضعیت جوین اجباری"},
    }
    if _, err := bot.Request(tgbotapi.NewSetMyCommands(publicCmds...)); err != nil {
        log.Printf("⚠️ ثبت منوی عمومی ناموفق: %v", err)
        return
    }

    adminCmds := append(append([]tgbotapi.BotCommand{}, publicCmds...),
        tgbotapi.BotCommand{Command: "setchannel", Description: "⚙️ تنظیم کانال اجباری"},
        tgbotapi.BotCommand{Command: "stats", Description: "📊 آمار ربات"},
        tgbotapi.BotCommand{Command: "broadcast", Description: "📣 ارسال پیام همگانی"},
    )
    cmdsJSON, _ := json.Marshal(adminCmds)
    for id := range adminIDs {
        params := tgbotapi.Params{}
        params["commands"] = string(cmdsJSON)
        params["scope"] = fmt.Sprintf(`{"type":"chat","chat_id":%d}`, id)
        if _, err := bot.MakeRequest("setMyCommands", params); err != nil {
            log.Printf("⚠️ ثبت منوی ادمین برای %d ناموفق: %v", id, err)
        }
    }
}

// ═══════════════════ اصلی ═══════════════════

func main() {
    token := os.Getenv("BOT_TOKEN")
    if token == "" {
        log.Fatal("❌ BOT_TOKEN تنظیم نشده. توکن را از @BotFather بگیرید.")
    }

    for _, s := range strings.Split(os.Getenv("ADMIN_IDS"), ",") {
        var id int64
        if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &id); err == nil && id != 0 {
            adminIDs[id] = true
        }
    }

    loadState()
    startStatsFlusher()
    startBundleReaper()

    var err error
    bot, err = tgbotapi.NewBotAPI(token)
    if err != nil {
        log.Fatalf("❌ اتصال به Bot API ناموفق: %v", err)
    }
    bot.Debug = os.Getenv("DEBUG") == "1"
    go setBotCommands()
    log.Printf("✅ ربات @%s روشن شد — نسخه %s — کانال اجباری: %s",
        bot.Self.UserName, botVersion, channelStatus())

    u := tgbotapi.NewUpdate(0)
    u.Timeout = 60
    u.AllowedUpdates = []string{"message"}

    for update := range bot.GetUpdatesChan(u) {
        if update.Message == nil {
            continue
        }
        go safeHandle(update.Message)
    }
}

func safeHandle(msg *tgbotapi.Message) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("💥 panic: %v\n%s", r, debug.Stack())
        }
    }()
    handleMessage(msg)
}

type procOut struct {
    res     *processResult
    err     error
    needPwd bool
}

func handleMessage(msg *tgbotapi.Message) {
    chatID := msg.Chat.ID
    userID := int64(0)
    if msg.From != nil {
        userID = msg.From.ID
    }
    admin := adminIDs[userID]

    trackUser(msg.From)

    // ─── جوین اجباری (ادمین رد می‌شود) ───
    settingsMu.Lock()
    forceCh := settings.ForceChannel
    settingsMu.Unlock()
    if forceCh != "" && !admin {
        if !isMemberOf(userID, forceCh) {
            sendJoinPrompt(chatID, forceCh)
            return
        }
    }

    // ─── دستورات ───
    if msg.IsCommand() {
        switch msg.Command() {
        case "start", "help":
            sendHTML(chatID, helpText())
        case "formats":
            sendHTML(chatID, formatsText())
        case "version":
            reply(chatID, "🤖 نسخه ربات: "+botVersion)
        case "channel":
            reply(chatID, "📢 وضعیت جوین اجباری: "+channelStatus())
        case "setchannel":
            if !admin {
                reply(chatID, "⛔ این دستور فقط برای ادمین است.")
                return
            }
            handleSetChannel(msg, chatID)
        case "stats":
            if !admin {
                reply(chatID, "⛔ این دستور فقط برای ادمین است.")
                return
            }
            reply(chatID, statsText())
        case "broadcast":
            if !admin {
                reply(chatID, "⛔ این دستور فقط برای ادمین است.")
                return
            }
            handleBroadcast(msg, chatID)
        default:
            reply(chatID, "❓ دستور ناشناخته. /help را بزنید.")
        }
        return
    }

    // ─── بررسی باندل رمزدار در انتظار ───
    if strings.TrimSpace(msg.Text) != "" {
        if bd, found, expired := takePendingBundle(chatID); found || expired {
            if expired {
                reply(chatID, "⏰ مهلت ارسال رمز به پایان رسید.\n\n🔑 فایل را دوباره بفرستید و این‌بار سریع‌تر رمز را ارسال کنید.")
                return
            }
            sendAction(chatID, tgbotapi.ChatTyping)
            bres, berr := trySlipnetBundleDecrypt(bd, strings.TrimSpace(msg.Text))
            if berr != nil {
                reply(chatID, "❌ "+berr.Error()+"\n\n🔑 رمز اشتباه بود. فایل را دوباره بفرستید و رمز صحیح را ارسال کنید.")
            } else {
                sendBundleResult(chatID, bres)
            }
            return
        }
    }

    // ─── قفل هر-کاربر ───
    if !tryAcquireUser(chatID) {
        reply(chatID, "⏳ درخواست قبلی شما هنوز در حال پردازش است. لطفاً منتظر بمانید.")
        return
    }
    defer releaseUser(chatID)

    var data []byte
    var name string
    var fileExt string
    var progMsgID int

    switch {
    case msg.Document != nil:
        if msg.Document.FileSize > 19*1024*1024 {
            reply(chatID, "❌ فایل بزرگ‌تر از ۱۹ مگابایت است؛ ربات‌های تلگرام اجازهٔ دانلود ندارند.")
            return
        }
        pm := tgbotapi.NewMessage(chatID, "⏳ در حال دانلود و رمزگشایی...")
        if sent, err := bot.Send(pm); err == nil {
            progMsgID = sent.MessageID
        }
        d, err := downloadFile(msg.Document.FileID)
        if err != nil {
            deleteProgress(chatID, progMsgID)
            reply(chatID, "❌ دانلود فایل ناموفق بود:\n"+err.Error())
            return
        }
        data = d
        fileExt = strings.ToLower(filepath.Ext(msg.Document.FileName))
        name = strings.TrimSuffix(msg.Document.FileName, filepath.Ext(msg.Document.FileName))
        if name == "" {
            name = "config"
        }

    case strings.TrimSpace(msg.Text) != "":
        if len(msg.Entities) > 0 {
            var extra []string
            txt := strings.TrimSpace(msg.Text)
            for _, e := range msg.Entities {
                if e.Type == "text_link" && e.URL != "" {
                    extra = append(extra, e.URL)
                }
            }
            if len(extra) > 0 {
                txt += "\n" + strings.Join(extra, "\n")
            }
            data = []byte(txt)
        } else {
            data = []byte(msg.Text)
        }
        name = "npvt"

    case strings.TrimSpace(msg.Caption) != "":
        data = []byte(msg.Caption)
        name = "npvt"

    default:
        reply(chatID, "📎 فایل را بفرستید یا محتوایش را متن کنید. راهنما: /help")
        return
    }

    incrementProcessed()
    sendAction(chatID, tgbotapi.ChatTyping)

    // ─── پردازش با سقف زمان ───
    done := make(chan procOut, 1)
    go func() {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("💥 panic در پردازش: %v\n%s", r, debug.Stack())
                done <- procOut{err: fmt.Errorf("خطای داخلی در پردازش")}
            }
        }()
        r, e, np := processRouted(data, fileExt, chatID)
        done <- procOut{res: r, err: e, needPwd: np}
    }()

    var out procOut
    select {
    case out = <-done:
    case <-time.After(procTimeout):
        deleteProgress(chatID, progMsgID)
        reply(chatID, "⏱️ پردازش این فایل بیش از حد طول کشید و متوقف شد.\n\n💡 فایل سبک‌تری بفرستید یا بعداً دوباره تلاش کنید.\n\n🤖 "+botVersion)
        return
    }

    deleteProgress(chatID, progMsgID)

    if out.needPwd {
        reply(chatID, "🔐 این فایل SlipNet یک باندل رمزدار است!\n\n🔑 لطفاً رمز (Password) فایل را همین حالا به‌صورت یک پیام بفرستید:")
        return
    }
    if out.err != nil {
        reply(chatID, "❌ "+out.err.Error()+"\n\n🤖 "+botVersion)
        return
    }

    res := out.res
    if res == nil || (len(res.URIs) == 0 && len(res.Raw) == 0) {
        if res != nil && len(res.Errors) > 0 {
            reply(chatID, "⚠️ کانفیگی استخراج نشد:\n"+strings.Join(res.Errors, "\n")+"\n\n🤖 "+botVersion)
        } else {
            reply(chatID, "⚠️ در این ورودی کانفیگی پیدا نشد.\n\n🤖 "+botVersion)
        }
        return
    }

    var lines []string
    for i, u := range res.URIs {
        if i > 0 {
            lines = append(lines, "")
        }
        lines = append(lines, u)
    }
    for _, r := range res.Raw {
        lines = append(lines, "", "─────── RAW ───────", r)
    }
    content := strings.Join(lines, "\n")

    summary := fmt.Sprintf("✅ %d کانفیگ استخراج شد", len(res.URIs))
    if len(res.Raw) > 0 {
        summary += fmt.Sprintf(" • %d بلوک خام", len(res.Raw))
    }
    if len(res.URIs) == 0 && len(res.Raw) > 0 {
        summary += "\nℹ️ این کانفیگ از نوع SSH/Tunnel است و لینک V2ray ندارد — داده کامل در RAW."
    }
    if len(res.Errors) > 0 {
        summary += fmt.Sprintf("\n⚠️ %d بلوک نادیده", len(res.Errors))
    }
    summary += "\n🤖 نسخه " + botVersion

    kb := buildCopyKeyboard(res.URIs)

    switch {
    case len(content) <= msgLimit:
        if kb != nil {
            m := tgbotapi.NewMessage(chatID, summary+"\n\n"+content)
            m.DisableWebPagePreview = true
            m.ReplyMarkup = kb
            if _, err := bot.Send(m); err != nil {
                reply(chatID, summary+"\n\n"+content)
            }
        } else {
            reply(chatID, summary+"\n\n"+content)
        }
    case len(content) <= maxChunks*msgLimit:
        reply(chatID, summary)
        replyLines(chatID, lines)
    default:
        reply(chatID, summary)
        sendAction(chatID, tgbotapi.ChatUploadDocument)
        if err := sendDocument(chatID, name+"_configs.txt", []byte(content)); err != nil {
            reply(chatID, "❌ ارسال فایل ناموفق بود: "+err.Error())
        }
    }
}

func deleteProgress(chatID int64, msgID int) {
    if msgID == 0 {
        return
    }
    _, _ = bot.Request(tgbotapi.NewDeleteMessage(chatID, msgID))
}

// دکمه «📋 کپی» فقط برای ۱ تا ۲ کانفیگ کوتاه
func buildCopyKeyboard(uris []string) *tgbotapi.InlineKeyboardMarkup {
    if len(uris) == 0 || len(uris) > 2 {
        return nil
    }
    for _, u := range uris {
        if len(u) > 250 {
            return nil
        }
    }
    var rows [][]tgbotapi.InlineKeyboardButton
    for _, u := range uris {
        rows = append(rows, tgbotapi.NewInlineKeyboardRow(
            tgbotapi.NewInlineKeyboardButtonSwitch("📋 کپی کانفیگ", u),
        ))
    }
    kb := tgbotapi.NewInlineKeyboardMarkup(rows...)
    return &kb
}

// ═══════════════════ جوین اجباری ═══════════════════

func sendJoinPrompt(chatID int64, channel string) {
    link := "https://t.me/" + strings.TrimPrefix(channel, "@")
    keyboard := tgbotapi.NewInlineKeyboardMarkup(
        tgbotapi.NewInlineKeyboardRow(
            tgbotapi.NewInlineKeyboardButtonURL("📢 عضویت در کانال", link),
        ),
    )
    m := tgbotapi.NewMessage(chatID, fmt.Sprintf(
        "🔒 برای استفاده از ربات ابتدا در کانال عضو شوید:\n\n%s\n\n"+
            "بعد از عضویت، دوباره پیام یا فایل خود را بفرستید. 👇", channel))
    m.ReplyMarkup = keyboard
    m.DisableWebPagePreview = true
    if _, err := bot.Send(m); err != nil {
        log.Printf("خطا در ارسال پیام عضویت: %v", err)
    }
}

func handleSetChannel(msg *tgbotapi.Message, chatID int64) {
    parts := strings.Fields(msg.Text)
    if len(parts) < 2 || strings.EqualFold(parts[1], "off") {
        settingsMu.Lock()
        settings.ForceChannel = ""
        settingsMu.Unlock()
        saveSettings()
        reply(chatID, "✅ جوین اجباری غیرفعال شد.")
        return
    }
    ch := parts[1]
    if !strings.HasPrefix(ch, "@") {
        ch = "@" + ch
    }
    settingsMu.Lock()
    settings.ForceChannel = ch
    settingsMu.Unlock()
    saveSettings()
    reply(chatID, "✅ جوین اجباری فعال شد روی "+ch+
        "\n\n⚠️ مهم: حتماً ربات را در این کانال «ادمین» کنید،"+
        " وگرنه نمی‌تواند عضویت کاربران را بررسی کند.")
}

func statsText() string {
    statsMu.Lock()
    users := len(stats.Users)
    processed := stats.Processed
    statsMu.Unlock()
    return fmt.Sprintf("📊 آمار ربات:\n\n👥 کاربران: %d\n"+
        "📦 پردازش‌ها: %d\n"+
        "📢 کانال اجباری: %s\n"+
        "🤖 نسخه: %s", users, processed, channelStatus(), botVersion)
}

func handleBroadcast(msg *tgbotapi.Message, chatID int64) {
    parts := strings.Fields(msg.Text)
    if len(parts) < 2 {
        reply(chatID, "استفاده: /broadcast متن پیام")
        return
    }
    text := strings.Join(parts[1:], " ")

    statsMu.Lock()
    ids := make([]int64, 0, len(stats.Users))
    for id := range stats.Users {
        ids = append(ids, id)
    }
    statsMu.Unlock()

    reply(chatID, fmt.Sprintf("⏳ در حال ارسال به %d کاربر...", len(ids)))
    sent := 0
    for _, id := range ids {
        m := tgbotapi.NewMessage(id, "📢 "+text)
        m.DisableWebPagePreview = true
        if _, err := bot.Send(m); err == nil {
            sent++
        }
        time.Sleep(50 * time.Millisecond)
    }
    reply(chatID, fmt.Sprintf("✅ پیام به %d کاربر از %d ارسال شد.", sent, len(ids)))
}

// ═══════════════════ ابزارهای تلگرام ═══════════════════

func reply(chatID int64, text string) {
    if r := []rune(text); len(r) > 4090 {
        text = string(r[:4080]) + "\n…"
    }
    m := tgbotapi.NewMessage(chatID, text)
    m.DisableWebPagePreview = true
    if _, err := bot.Send(m); err != nil {
        log.Printf("خطا در ارسال پیام: %v", err)
    }
}

func sendHTML(chatID int64, html string) {
    m := tgbotapi.NewMessage(chatID, html)
    m.ParseMode = "HTML"
    m.DisableWebPagePreview = true
    if _, err := bot.Send(m); err != nil {
        m2 := tgbotapi.NewMessage(chatID, html)
        m2.DisableWebPagePreview = true
        bot.Send(m2)
    }
}

func sendAction(chatID int64, action string) {
    _, _ = bot.Request(tgbotapi.NewChatAction(chatID, action))
}

func sendDocument(chatID int64, name string, data []byte) error {
    doc := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{Name: name, Bytes: data})
    _, err := bot.Send(doc)
    return err
}

func downloadFile(fileID string) ([]byte, error) {
    f, err := bot.GetFile(tgbotapi.FileConfig{FileID: fileID})
    if err != nil {
        return nil, err
    }
    resp, err := httpClient.Get(f.Link(bot.Token))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("HTTP %d هنگام دانلود", resp.StatusCode)
    }
    return io.ReadAll(resp.Body)
}

func replyLines(chatID int64, lines []string) {
    var cur []string
    size := 0
    flush := func() {
        if len(cur) > 0 {
            reply(chatID, strings.Join(cur, "\n"))
            cur, size = nil, 0
        }
    }
    for _, l := range lines {
        for rr := []rune(l); len(rr) > msgLimit; rr = []rune(l) {
            flush()
            reply(chatID, string(rr[:msgLimit]))
            l = string(rr[msgLimit:])
        }
        if size+len(l)+1 > msgLimit {
            flush()
        }
        cur = append(cur, l)
        size += len(l) + 1
    }
    flush()
}

func helpText() string {
    return `🔐 <b>ربات رمزگشای کانفیگ</b> — نسخه <code>` + botVersion + `</code>

📤 فایل کانفیگ را بفرستید — فرمت خودکار تشخیص داده می‌شود.

/formats → لیست کامل فرمت‌ها
/version → نسخه ربات
/channel → وضعیت کانال`
}

func formatsText() string {
    return `📋 <b>فرمت‌های ورودی پشتیبانی‌شده:</b>

<code>.npvt</code> — NapsternetV
<code>.ehi</code> — HTTP Injector
<code>.hat</code> — HA Tunnel Plus
<code>.happ</code> — Happ (+ لینک happ://)
<code>.slip</code> — SlipNet (+ باندل رمزدار)
<code>.nm</code> — NetMod
<code>.dark</code> — DarkTunnel

📥 همچنین: JSON مستقیم، base64، ZIP حاوی JSON و لینک‌های خام
<code>vless / vmess / trojan / ss / hy2 / tuic</code>

💡 کانفیگ‌های SSH/Tunnel فاقد لینک V2ray هستند و داده کاملشان در RAW نمایش داده می‌شود.`
}

// ═══════════════════ موتور پردازش یونیورسال ═══════════════════

type processResult struct {
    URIs   []string
    Raw    []string
    Errors []string
}

func processInput(data []byte) (*processResult, error) {
    if len(data) > 50*1024*1024 {
        return nil, fmt.Errorf("ورودی بیش از حد بزرگ است")
    }
    return processUniversal(data, 0)
}

func processUniversal(data []byte, depth int) (*processResult, error) {
    if len(data) > 4 && data[0] == 'P' && data[1] == 'K' && depth < 3 {
        return processZIP(data, depth)
    }

    text := strings.TrimSpace(string(data))
    if text == "" {
        return nil, fmt.Errorf("محتوای ورودی خالی است")
    }

    if text[0] == '{' || text[0] == '[' {
        res := &processResult{}
        consumeJSONBlob([]byte(text), res)
        return res, nil
    }

    npvtRes := tryNPVT(text)
    if npvtRes != nil && (len(npvtRes.URIs) > 0 || len(npvtRes.Raw) > 0) {
        return npvtRes, nil
    }

    if b, ok := decodeB64Loose(text); ok {
        inner := strings.TrimSpace(string(b))
        if inner != "" && (inner[0] == '{' || inner[0] == '[') {
            res := &processResult{}
            consumeJSONBlob(b, res)
            if len(res.URIs) > 0 || len(res.Raw) > 0 {
                return res, nil
            }
        }
        if uris := scanPlainURIs(b); len(uris) > 0 {
            return &processResult{URIs: uris}, nil
        }
    }

    if uris := scanPlainURIs([]byte(text)); len(uris) > 0 {
        return &processResult{URIs: uris}, nil
    }

    if npvtRes != nil && len(npvtRes.Errors) > 0 {
        return nil, fmt.Errorf("رمزگشایی ناموفق:\n%s", strings.Join(npvtRes.Errors, "\n"))
    }
    return nil, fmt.Errorf("هیچ فرمت شناخته‌شده‌ای در ورودی پیدا نشد")
}

const zipTotalLimit = 100 << 20

func processZIP(data []byte, depth int) (*processResult, error) {
    zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
    if err != nil {
        return nil, fmt.Errorf("فایل ZIP نامعتبر است: %v", err)
    }
    res := &processResult{}
    var total int64
    for _, f := range zr.File {
        if f.FileInfo().IsDir() {
            continue
        }
        rc, err := f.Open()
        if err != nil {
            continue
        }
        content, _ := io.ReadAll(io.LimitReader(rc, 20<<20))
        rc.Close()

        total += int64(len(content))
        if total > zipTotalLimit {
            res.Errors = append(res.Errors, "حجم کل محتویات ZIP بیش از حد مجاز است")
            break
        }

        if len(content) > 4 && content[0] == 'P' && content[1] == 'K' && depth < 3 {
            if sub, err := processZIP(content, depth+1); err == nil {
                res.URIs = append(res.URIs, sub.URIs...)
                res.Raw = append(res.Raw, sub.Raw...)
                res.Errors = append(res.Errors, sub.Errors...)
            }
            continue
        }

        inner := strings.TrimSpace(string(content))
        if inner == "" {
            continue
        }
        if inner[0] == '{' || inner[0] == '[' {
            consumeJSONBlob(content, res)
            continue
        }
        if uris := scanPlainURIs(content); len(uris) > 0 {
            res.URIs = append(res.URIs, uris...)
            continue
        }
        if sub, err := processUniversal(content, depth+1); err == nil {
            res.URIs = append(res.URIs, sub.URIs...)
            res.Raw = append(res.Raw, sub.Raw...)
        }
    }
    return res, nil
}

// ═══════════════════ مسیر NPVT ═══════════════════

func tryNPVT(text string) *processResult {
    res := &processResult{}

    tokens := strings.Split(text, ",")
    if len(tokens) <= 1 {
        tokens = strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' })
    }

    decoded := 0
    for i, tok := range tokens {
        tok = strings.TrimSpace(tok)
        if tok == "" {
            continue
        }
        b, err := decodeOne(tok)
        if err != nil {
            continue
        }
        decoded++
        if len(b) < 16 {
            res.Errors = append(res.Errors, fmt.Sprintf("بلوک %d: کوتاه‌تر از ۱۶ بایت.", i+1))
            continue
        }
        pt, derr := decrypt(b)
        if derr != nil {
            res.Errors = append(res.Errors, fmt.Sprintf("بلوک %d: %v", i+1, derr))
            continue
        }
        if !isMostlyPrintable(pt) {
            preview := make([]byte, 0, 80)
            for j, bb := range pt {
                if j >= 80 {
                    break
                }
                if bb >= 0x20 && bb < 0x7F {
                    preview = append(preview, bb)
                } else {
                    preview = append(preview, '.')
                }
            }
            res.Errors = append(res.Errors, fmt.Sprintf("بلوک %d: خروجی نامعتبر — %s", i+1, string(preview)))
            continue
        }
        consumeJSONBlob(pt, res)
    }

    if decoded == 0 {
        return nil
    }
    res.URIs = dedupe(res.URIs)
    res.Raw = dedupe(res.Raw)
    return res
}

// ═══════════════════ مصرف JSON ═══════════════════

func consumeJSONBlob(pt []byte, res *processResult) {
    pt = trimNonPrintable(pt)
    if len(pt) == 0 {
        return
    }

    var root any
    if err := json.Unmarshal(pt, &root); err == nil {
        if isNoiseJSON(root) {
            res.Errors = append(res.Errors, "یک بلوک متادیتای قفل (بدون کانفیگ) نادیده گرفته شد")
            return
        }
        var uris []string
        walkJSON(root, &uris)
        if len(uris) > 0 {
            res.URIs = append(res.URIs, uris...)
            return
        }
        if s := strings.TrimSpace(string(pt)); s != "" {
            res.Raw = append(res.Raw, s)
        }
        return
    }

    objs := splitJSONObjects(pt)
    if len(objs) > 1 {
        foundAny := false
        for _, obj := range objs {
            var r any
            if json.Unmarshal(obj, &r) != nil {
                continue
            }
            if isNoiseJSON(r) {
                continue
            }
            var uris []string
            walkJSON(r, &uris)
            if len(uris) > 0 {
                res.URIs = append(res.URIs, uris...)
                foundAny = true
            }
        }
        if foundAny {
            return
        }
    }

    if uris := scanPlainURIs(pt); len(uris) > 0 {
        res.URIs = append(res.URIs, uris...)
        return
    }

    if s := strings.TrimSpace(string(pt)); s != "" {
        res.Raw = append(res.Raw, s)
    }
}

func isNoiseJSON(root any) bool {
    m, ok := root.(map[string]any)
    if !ok {
        return false
    }
    if _, hasLock := m["isLocked"]; !hasLock {
        return false
    }
    _, hasServer := m["server"]
    _, hasProfile := m["v2rayProfile"]
    _, hasOutbounds := m["outbounds"]
    _, hasCfg := m["configType"]
    return !hasServer && !hasProfile && !hasOutbounds && !hasCfg
}

func dedupe(in []string) []string {
    seen := make(map[string]struct{}, len(in))
    out := make([]string, 0, len(in))
    for _, s := range in {
        if _, ok := seen[s]; ok {
            continue
        }
        seen[s] = struct{}{}
        out = append(out, s)
    }
    return out
}

func isMostlyPrintable(b []byte) bool {
    if len(b) == 0 {
        return false
    }
    bad := 0
    for _, c := range b {
        if c == 0 {
            bad += 3
        } else if c < 0x09 || (c > 0x0D && c < 0x20) {
            bad++
        }
    }
    return bad < len(b)/4
}

func decodeOne(text string) ([]byte, error) {
    for c := '0'; c <= '9'; c++ {
        text = strings.ReplaceAll(text, "NPVT"+string(c), "")
    }
    text = strings.Join(strings.Fields(text), "")
    if text == "" {
        return nil, fmt.Errorf("توکن خالی")
    }

    isHex := len(text)%2 == 0
    if isHex {
        for _, c := range text {
            if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
                isHex = false
                break
            }
        }
    }
    if isHex {
        if b, err := hex.DecodeString(text); err == nil {
            return b, nil
        }
    }

    padded := text
    if m := len(padded) % 4; m != 0 {
        padded += strings.Repeat("=", 4-m)
    }
    if b, err := base64.StdEncoding.DecodeString(padded); err == nil {
        return b, nil
    }
    if b, err := base64.URLEncoding.DecodeString(padded); err == nil {
        return b, nil
    }

    return nil, fmt.Errorf("قالب توکن شناسایی نشد: %.32s…", text)
}

func decodeB64Loose(text string) ([]byte, bool) {
    text = strings.Join(strings.Fields(text), "")
    if text == "" || len(text) < 8 {
        return nil, false
    }
    padded := text
    if m := len(padded) % 4; m != 0 {
        padded += strings.Repeat("=", 4-m)
    }
    if b, err := base64.StdEncoding.DecodeString(padded); err == nil {
        return b, true
    }
    if b, err := base64.URLEncoding.DecodeString(padded); err == nil {
        return b, true
    }
    if b, err := base64.RawStdEncoding.DecodeString(text); err == nil {
        return b, true
    }
    return nil, false
}

func trimNonPrintable(b []byte) []byte {
    start := 0
    for start < len(b) && (b[start] < 0x20 || b[start] == 0x00) && b[start] != '\n' && b[start] != '\r' && b[start] != '\t' {
        start++
    }
    end := len(b)
    for end > start && (b[end-1] < 0x20 || b[end-1] == 0x00) && b[end-1] != '\n' && b[end-1] != '\r' && b[end-1] != '\t' {
        end--
    }
    return b[start:end]
}

func splitJSONObjects(data []byte) [][]byte {
    var objects [][]byte
    depth := 0
    start := -1
    inString := false
    escaped := false
    for i, b := range data {
        if escaped {
            escaped = false
            continue
        }
        if b == '\\' {
            escaped = true
            continue
        }
        if b == '"' {
            inString = !inString
            continue
        }
        if inString {
            continue
        }
        switch b {
        case '{':
            if depth == 0 {
                start = i
            }
            depth++
        case '}':
            depth--
            if depth == 0 && start >= 0 {
                objects = append(objects, data[start:i+1])
                start = -1
            }
        }
    }
    return objects
}

var uriSchemes = []string{
    "vless://", "vmess://", "trojan://", "ss://", "ssr://",
    "hysteria2://", "hy2://", "hysteria://", "tuic://",
    "socks://", "socks5://",
}

func scanPlainURIs(pt []byte) []string {
    s := string(pt)
    if !strings.Contains(s, "://") {
        return nil
    }
    var uris []string
    for _, f := range strings.Fields(s) {
        f = strings.TrimRight(f, ",;")
        for _, sc := range uriSchemes {
            if strings.HasPrefix(f, sc) {
                uris = append(uris, f)
                break
            }
        }
    }
    return uris
}

// ═══════════════════ رمزنگاری NPVT ═══════════════════

const nr = 2

var shiftOrder = [16]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}

func shiftRowsLike(b [16]byte) [16]byte {
    var out [16]byte
    for i := 0; i < 16; i++ {
        out[i] = b[shiftOrder[i]]
    }
    return out
}

func coreTransform(block [16]byte) [16]byte {
    buf := block

    iB := nr - 1
    for i10 := 0; i10 < iB; i10++ {
        buf = shiftRowsLike(buf)

        for i11 := 0; i11 < 4; i11++ {
            i13 := i11 * 4
            i14, i15, i16 := i13+1, i13+2, i13+3

            iC := tyBoxes[i13][buf[i13]]
            iC2 := tyBoxes[i14][buf[i14]]
            iC3 := tyBoxes[i15][buf[i15]]
            iC4 := tyBoxes[i16][buf[i16]]

            for i17 := 0; i17 < 4; i17++ {
                i18 := (i11 * 24) + (i17 * 6)
                i19 := i17 * 8
                i20 := uint(28 - i19)
                i22 := uint(24 - i19)

                n1 := (iC >> i20) & 15
                n2 := (iC2 >> i20) & 15
                n3 := (iC3 >> i20) & 15
                n4 := (iC4 >> i20) & 15
                b10 := xorTable[i18][n1][n2]
                b11 := xorTable[i18+1][n3][n4]

                m1 := (iC >> i22) & 15
                m2 := (iC2 >> i22) & 15
                m3 := (iC3 >> i22) & 15
                m4 := (iC4 >> i22) & 15
                lo := xorTable[i18+5][xorTable[i18+2][m1][m2]][xorTable[i18+3][m3][m4]]
                hi := xorTable[i18+4][b10][b11]

                buf[i13+i17] = lo | (hi << 4)
            }

            iC5 := mbl[i13][buf[i13]]
            iC6 := mbl[i14][buf[i14]]
            iC7 := mbl[i15][buf[i15]]
            iC8 := mbl[i16][buf[i16]]

            for i27 := 0; i27 < 4; i27++ {
                i28 := (i11 * 24) + (i27 * 6)
                i29 := i27 * 8
                i30 := uint(28 - i29)
                i31 := uint(24 - i29)

                n1 := (iC5 >> i30) & 15
                n2 := (iC6 >> i30) & 15
                n3 := (iC7 >> i30) & 15
                n4 := (iC8 >> i30) & 15
                a1 := xorTable[i28][n1][n2]
                a2 := xorTable[i28+1][n3][n4]
                hi := xorTable[i28+4][a1][a2]

                m1 := (iC5 >> i31) & 15
                m2 := (iC6 >> i31) & 15
                m3 := (iC7 >> i31) & 15
                m4 := (iC8 >> i31) & 15
                b1 := xorTable[i28+2][m1][m2]
                b2 := xorTable[i28+3][m3][m4]
                lo := xorTable[i28+5][b1][b2]

                buf[i13+i27] = (hi << 4) | lo
            }
        }
    }

    buf = shiftRowsLike(buf)
    for i := 0; i < 16; i++ {
        buf[i] = tboxesLast[i][buf[i]]
    }

    return buf
}

func ctrCrypt(nonce [16]byte, data []byte) []byte {
    counter := nonce
    out := make([]byte, len(data))
    var keystream [16]byte
    for i := 0; i < len(data); i++ {
        if i%16 == 0 {
            keystream = coreTransform(counter)
            ctrIncrement(&counter)
        }
        out[i] = keystream[i%16] ^ data[i]
    }
    return out
}

func decrypt(ciphertextWithNonce []byte) ([]byte, error) {
    if len(ciphertextWithNonce) < 16 {
        return nil, fmt.Errorf("ciphertext must be at least 16 bytes")
    }
    var nonce [16]byte
    copy(nonce[:], ciphertextWithNonce[:16])
    ct := ciphertextWithNonce[16:]
    return ctrCrypt(nonce, ct), nil
}

func ctrIncrement(counter *[16]byte) {
    i := 15
    for i > -1 {
        counter[i]++
        if counter[i] != 0 {
            break
        }
        i--
    }
}

// ═══════════════════ پیمایش JSON ═══════════════════

func walkJSON(v any, uris *[]string) {
    switch x := v.(type) {
    case map[string]any:
        if raw, ok := x["v2rayJson"]; ok {
            switch c := raw.(type) {
            case string:
                if c != "" {
                    if u, err := extractURIsFromConfig([]byte(c)); err == nil {
                        *uris = append(*uris, u...)
                    }
                }
            case map[string]any:
                b, _ := json.Marshal(c)
                if u, err := extractURIsFromConfig(b); err == nil {
                    *uris = append(*uris, u...)
                }
            }
        }
        if raw, ok := x["v2rRawJson"]; ok {
            switch c := raw.(type) {
            case string:
                if c != "" {
                    if u, err := extractURIsFromConfig([]byte(c)); err == nil {
                        *uris = append(*uris, u...)
                    }
                }
            case map[string]any:
                b, _ := json.Marshal(c)
                if u, err := extractURIsFromConfig(b); err == nil {
                    *uris = append(*uris, u...)
                }
            }
        }
        if _, ok := x["outbounds"]; ok {
            b, _ := json.Marshal(x)
            if u, err := extractURIsFromConfig(b); err == nil {
                *uris = append(*uris, u...)
            }
        }
        if _, ok := x["v2rayProfile"]; ok {
            b, _ := json.Marshal(x)
            if u, err := extractFromV2rayProfile(b); err == nil {
                *uris = append(*uris, u...)
            }
        }
        for _, v := range x {
            walkJSON(v, uris)
        }
    case []any:
        for _, v := range x {
            walkJSON(v, uris)
        }
    }
}

// ═══════════════════ struct ها ═══════════════════

type tlsSettingsT struct {
    ServerName    string   `json:"serverName"`
    AllowInsecure bool     `json:"allowInsecure"`
    Alpn          []string `json:"alpn"`
    Fingerprint   string   `json:"fingerprint"`
}

type realitySettingsT struct {
    ServerName  string `json:"serverName"`
    Fingerprint string `json:"fingerprint"`
    PublicKey   string `json:"publicKey"`
    ShortId     string `json:"shortId"`
    SpiderX     string `json:"spiderX"`
}

type wsSettingsT struct {
    Path    string            `json:"path"`
    Host    string            `json:"host"`
    Headers map[string]string `json:"headers"`
}

type grpcSettingsT struct {
    ServiceName string `json:"serviceName"`
    MultiMode   bool   `json:"multiMode"`
}

type kcpSettingsT struct {
    Header struct {
        Type string `json:"type"`
    } `json:"header"`
    Seed string `json:"seed"`
}

type quicSettingsT struct {
    Security string `json:"security"`
    Key      string `json:"key"`
    Header   struct {
        Type string `json:"type"`
    } `json:"header"`
}

type httpUpgradeSettingsT struct {
    Path string `json:"path"`
    Host string `json:"host"`
}

type streamSettingsT struct {
    Network             string                `json:"network"`
    Security            string                `json:"security"`
    TLSSettings         *tlsSettingsT         `json:"tlsSettings"`
    RealitySettings     *realitySettingsT     `json:"realitySettings"`
    WSSettings          *wsSettingsT          `json:"wsSettings"`
    GRPCSettings        *grpcSettingsT        `json:"grpcSettings"`
    KCPSettings         *kcpSettingsT         `json:"kcpSettings"`
    QUICSettings        *quicSettingsT        `json:"quicSettings"`
    HTTPUpgradeSettings *httpUpgradeSettingsT `json:"httpupgradeSettings"`
}

type vnextUserT struct {
    Id         string `json:"id"`
    Encryption string `json:"encryption"`
    Flow       string `json:"flow"`
    Security   string `json:"security"`
    AlterId    int    `json:"alterId"`
}

type vnextEntryT struct {
    Address string       `json:"address"`
    Port    int          `json:"port"`
    Users   []vnextUserT `json:"users"`
}

type vnextSettingsT struct {
    Vnext []vnextEntryT `json:"vnext"`
}

type serverEntryT struct {
    Address  string `json:"address"`
    Port     int    `json:"port"`
    Password string `json:"password"`
    Method   string `json:"method"`
    Flow     string `json:"flow"`
}

type serversSettingsT struct {
    Servers []serverEntryT `json:"servers"`
}

type napsternetProfile struct {
    ConfigType int    `json:"configType"`
    Remarks    string `json:"remarks"`
    Server     string `json:"server"`
    ServerPort any    `json:"serverPort"`
    Password   string `json:"password"`
    Method     string `json:"method"`
    V2rayJson  string `json:"v2rayJson"`
}

func getPortString(p any) string {
    if p == nil {
        return ""
    }
    switch v := p.(type) {
    case string:
        return v
    case float64:
        return fmt.Sprintf("%.0f", v)
    case int:
        return fmt.Sprintf("%d", v)
    case int64:
        return fmt.Sprintf("%d", v)
    default:
        return fmt.Sprintf("%v", v)
    }
}

func formatHost(addr string) string {
    if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
        return "[" + addr + "]"
    }
    return addr
}

func escapeUserInfo(s string) string {
    return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func cleanRemarks(s string) string {
    s = strings.ReplaceAll(s, "#", "")
    s = strings.ReplaceAll(s, "\n", " ")
    s = strings.ReplaceAll(s, "\r", "")
    s = strings.TrimSpace(s)
    s = strings.ReplaceAll(s, " ", "_")
    s = strings.ReplaceAll(s, "|", "-")
    return s
}

func formatQuery(q url.Values) string {
    s := q.Encode()
    s = strings.ReplaceAll(s, "%2F", "/")
    s = strings.ReplaceAll(s, "%40", "@")
    s = strings.ReplaceAll(s, "%3A", ":")
    s = strings.ReplaceAll(s, "%2C", ",")
    return s
}

func buildStreamQuery(ss *streamSettingsT) url.Values {
    q := url.Values{}
    network := ss.Network
    if network == "" {
        network = "tcp"
    }
    q.Set("type", network)

    security := ss.Security
    if security == "" {
        security = "none"
    }
    q.Set("security", security)

    switch network {
    case "ws":
        if ss.WSSettings != nil {
            if ss.WSSettings.Path != "" {
                q.Set("path", ss.WSSettings.Path)
            }
            if ss.WSSettings.Host != "" {
                q.Set("host", ss.WSSettings.Host)
            } else if h, ok := ss.WSSettings.Headers["Host"]; ok && h != "" {
                q.Set("host", h)
            } else if h, ok := ss.WSSettings.Headers["host"]; ok && h != "" {
                q.Set("host", h)
            }
        }
    case "grpc":
        if ss.GRPCSettings != nil {
            if ss.GRPCSettings.ServiceName != "" {
                q.Set("serviceName", ss.GRPCSettings.ServiceName)
            }
            if ss.GRPCSettings.MultiMode {
                q.Set("mode", "multi")
            } else {
                q.Set("mode", "gun")
            }
        }
    case "kcp":
        if ss.KCPSettings != nil {
            if ss.KCPSettings.Header.Type != "" {
                q.Set("headerType", ss.KCPSettings.Header.Type)
            }
            if ss.KCPSettings.Seed != "" {
                q.Set("seed", ss.KCPSettings.Seed)
            }
        }
    case "quic":
        if ss.QUICSettings != nil {
            if ss.QUICSettings.Security != "" {
                q.Set("quicSecurity", ss.QUICSettings.Security)
            }
            if ss.QUICSettings.Key != "" {
                q.Set("key", ss.QUICSettings.Key)
            }
            if ss.QUICSettings.Header.Type != "" {
                q.Set("headerType", ss.QUICSettings.Header.Type)
            }
        }
    case "httpupgrade":
        if ss.HTTPUpgradeSettings != nil {
            if ss.HTTPUpgradeSettings.Path != "" {
                q.Set("path", ss.HTTPUpgradeSettings.Path)
            }
            if ss.HTTPUpgradeSettings.Host != "" {
                q.Set("host", ss.HTTPUpgradeSettings.Host)
            }
        }
    }

    switch security {
    case "tls":
        if ss.TLSSettings != nil {
            if ss.TLSSettings.ServerName != "" {
                q.Set("sni", ss.TLSSettings.ServerName)
            }
            if ss.TLSSettings.Fingerprint != "" {
                q.Set("fp", ss.TLSSettings.Fingerprint)
            }
            if len(ss.TLSSettings.Alpn) > 0 {
                q.Set("alpn", strings.Join(ss.TLSSettings.Alpn, ","))
            }
            if ss.TLSSettings.AllowInsecure {
                q.Set("allowInsecure", "1")
            }
        }
    case "reality":
        if ss.RealitySettings != nil {
            if ss.RealitySettings.ServerName != "" {
                q.Set("sni", ss.RealitySettings.ServerName)
            }
            if ss.RealitySettings.Fingerprint != "" {
                q.Set("fp", ss.RealitySettings.Fingerprint)
            }
            if ss.RealitySettings.PublicKey != "" {
                q.Set("pbk", ss.RealitySettings.PublicKey)
            }
            if ss.RealitySettings.ShortId != "" {
                q.Set("sid", ss.RealitySettings.ShortId)
            }
            if ss.RealitySettings.SpiderX != "" {
                q.Set("spx", ss.RealitySettings.SpiderX)
            }
        }
    }
    return q
}

func vlessURI(vs vnextSettingsT, ss *streamSettingsT, remarks string) (string, error) {
    if len(vs.Vnext) == 0 || len(vs.Vnext[0].Users) == 0 {
        return "", fmt.Errorf("vless: missing vnext/user")
    }
    v := vs.Vnext[0]
    u := v.Users[0]

    q := buildStreamQuery(ss)
    enc := u.Encryption
    if enc == "" {
        enc = "none"
    }
    q.Set("encryption", enc)
    if u.Flow != "" {
        q.Set("flow", u.Flow)
    }

    return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
        u.Id, formatHost(v.Address), v.Port, formatQuery(q), cleanRemarks(remarks)), nil
}

func vmessURI(vs vnextSettingsT, ss *streamSettingsT, remarks string) (string, error) {
    if len(vs.Vnext) == 0 || len(vs.Vnext[0].Users) == 0 {
        return "", fmt.Errorf("vmess: missing vnext/user")
    }
    v := vs.Vnext[0]
    u := v.Users[0]

    network := ss.Network
    if network == "" {
        network = "tcp"
    }

    tlsFlag := ""
    if ss.Security == "tls" || ss.Security == "reality" {
        tlsFlag = "tls"
    }

    host, path := "", ""
    switch network {
    case "ws":
        if ss.WSSettings != nil {
            path = ss.WSSettings.Path
            if ss.WSSettings.Host != "" {
                host = ss.WSSettings.Host
            } else if h, ok := ss.WSSettings.Headers["Host"]; ok {
                host = h
            } else if h, ok := ss.WSSettings.Headers["host"]; ok {
                host = h
            }
        }
    case "grpc":
        if ss.GRPCSettings != nil {
            path = ss.GRPCSettings.ServiceName
        }
    case "httpupgrade":
        if ss.HTTPUpgradeSettings != nil {
            path = ss.HTTPUpgradeSettings.Path
            host = ss.HTTPUpgradeSettings.Host
        }
    }

    sni, fp, alpn := "", "", ""
    if ss.TLSSettings != nil {
        sni = ss.TLSSettings.ServerName
        fp = ss.TLSSettings.Fingerprint
        if len(ss.TLSSettings.Alpn) > 0 {
            alpn = strings.Join(ss.TLSSettings.Alpn, ",")
        }
    }

    scy := u.Security
    if scy == "" {
        scy = "auto"
    }

    obj := map[string]string{
        "v":    "2",
        "ps":   cleanRemarks(remarks),
        "add":  v.Address,
        "port": fmt.Sprintf("%d", v.Port),
        "id":   u.Id,
        "aid":  fmt.Sprintf("%d", u.AlterId),
        "scy":  scy,
        "net":  network,
        "type": "none",
        "host": host,
        "path": path,
        "tls":  tlsFlag,
        "sni":  sni,
        "fp":   fp,
        "alpn": alpn,
    }
    b, err := json.Marshal(obj)
    if err != nil {
        return "", err
    }
    return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
}

func trojanURI(ts serversSettingsT, ss *streamSettingsT, remarks string) (string, error) {
    if len(ts.Servers) == 0 {
        return "", fmt.Errorf("trojan: missing server")
    }
    s := ts.Servers[0]
    q := buildStreamQuery(ss)
    if s.Flow != "" {
        q.Set("flow", s.Flow)
    }
    return fmt.Sprintf("trojan://%s@%s:%d?%s#%s",
        escapeUserInfo(s.Password), formatHost(s.Address), s.Port, formatQuery(q), cleanRemarks(remarks)), nil
}

func shadowsocksURI(ts serversSettingsT, remarks string) (string, error) {
    if len(ts.Servers) == 0 {
        return "", fmt.Errorf("shadowsocks: missing server")
    }
    s := ts.Servers[0]
    userInfo := base64.RawURLEncoding.EncodeToString([]byte(s.Method + ":" + s.Password))
    return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, formatHost(s.Address), s.Port, cleanRemarks(remarks)), nil
}

func outboundToURI(protocol string, settingsRaw, streamRaw json.RawMessage, remarks string) (string, error) {
    var ss streamSettingsT
    if len(streamRaw) > 0 {
        _ = json.Unmarshal(streamRaw, &ss)
    }

    switch strings.ToLower(protocol) {
    case "vless":
        var vs vnextSettingsT
        if err := json.Unmarshal(settingsRaw, &vs); err != nil {
            return "", err
        }
        return vlessURI(vs, &ss, remarks)
    case "vmess":
        var vs vnextSettingsT
        if err := json.Unmarshal(settingsRaw, &vs); err != nil {
            return "", err
        }
        return vmessURI(vs, &ss, remarks)
    case "trojan":
        var ts serversSettingsT
        if err := json.Unmarshal(settingsRaw, &ts); err != nil {
            return "", err
        }
        return trojanURI(ts, &ss, remarks)
    case "shadowsocks":
        var ts serversSettingsT
        if err := json.Unmarshal(settingsRaw, &ts); err != nil {
            return "", err
        }
        return shadowsocksURI(ts, remarks)
    case "hysteria2", "hy2":
        var h struct {
            Servers []struct {
                Address  string `json:"address"`
                Port     int    `json:"port"`
                Password string `json:"password"`
                Auth     string `json:"auth"`
            } `json:"servers"`
        }
        if err := json.Unmarshal(settingsRaw, &h); err == nil && len(h.Servers) > 0 {
            srv := h.Servers[0]
            auth := srv.Password
            if auth == "" {
                auth = srv.Auth
            }
            q := buildStreamQuery(&ss)
            return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s", escapeUserInfo(auth), formatHost(srv.Address), srv.Port, formatQuery(q), cleanRemarks(remarks)), nil
        }
        return "", fmt.Errorf("invalid hysteria2 config")
    case "tuic":
        var t struct {
            Servers []struct {
                Address  string `json:"address"`
                Port     int    `json:"port"`
                UUID     string `json:"uuid"`
                Password string `json:"password"`
            } `json:"servers"`
        }
        if err := json.Unmarshal(settingsRaw, &t); err == nil && len(t.Servers) > 0 {
            srv := t.Servers[0]
            pass := srv.UUID
            if pass == "" {
                pass = srv.Password
            }
            q := buildStreamQuery(&ss)
            return fmt.Sprintf("tuic://%s:%s@%s:%d?%s#%s", escapeUserInfo(pass), escapeUserInfo(srv.Password), formatHost(srv.Address), srv.Port, formatQuery(q), cleanRemarks(remarks)), nil
        }
        return "", fmt.Errorf("invalid tuic config")
    default:
        return "", fmt.Errorf("unsupported protocol: %s", protocol)
    }
}

func extractURIsFromConfig(pt []byte) ([]string, error) {
    var cfg struct {
        Remarks   string            `json:"remarks"`
        Outbounds []json.RawMessage `json:"outbounds"`
    }
    if err := json.Unmarshal(pt, &cfg); err != nil {
        return nil, err
    }

    var uris []string
    for _, obRaw := range cfg.Outbounds {
        var hdr struct {
            Tag            string          `json:"tag"`
            Protocol       string          `json:"protocol"`
            Settings       json.RawMessage `json:"settings"`
            StreamSettings json.RawMessage `json:"streamSettings"`
        }
        if err := json.Unmarshal(obRaw, &hdr); err != nil {
            continue
        }
        switch strings.ToLower(hdr.Protocol) {
        case "freedom", "blackhole", "dns", "":
            continue
        }

        remarks := cfg.Remarks
        if remarks == "" {
            remarks = hdr.Tag
        }
        if remarks == "" {
            remarks = hdr.Protocol
        }
        uri, err := outboundToURI(hdr.Protocol, hdr.Settings, hdr.StreamSettings, remarks)
        if err != nil {
            continue
        }
        uris = append(uris, uri)
    }
    return uris, nil
}

func extractFromV2rayProfile(b []byte) ([]string, error) {
    var p napsternetProfile
    if err := json.Unmarshal(b, &p); err != nil || p.Server == "" {
        var wrapper struct {
            V2rayProfile napsternetProfile `json:"v2rayProfile"`
        }
        if err2 := json.Unmarshal(b, &wrapper); err2 == nil && wrapper.V2rayProfile.Server != "" {
            p = wrapper.V2rayProfile
        } else if err != nil {
            return nil, err
        }
    }

    if p.V2rayJson != "" {
        if u, err := extractURIsFromConfig([]byte(p.V2rayJson)); err == nil && len(u) > 0 {
            return u, nil
        }
    }

    var uris []string
    remarks := cleanRemarks(p.Remarks)
    portStr := getPortString(p.ServerPort)

    if p.Server != "" {
        if (p.ConfigType == 3 || p.Method != "") && p.Password != "" {
            userInfo := base64.RawURLEncoding.EncodeToString([]byte(p.Method + ":" + p.Password))
            uri := fmt.Sprintf("ss://%s@%s:%s#%s", userInfo, formatHost(p.Server), portStr, remarks)
            uris = append(uris, uri)
        } else if p.ConfigType == 4 || (p.Password != "" && p.Method == "") {
            uri := fmt.Sprintf("trojan://%s@%s:%s#%s", escapeUserInfo(p.Password), formatHost(p.Server), portStr, remarks)
            uris = append(uris, uri)
        }
    }

    return uris, nil
}
