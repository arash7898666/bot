package main

import (
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
    "time"

    tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const (
    msgLimit  = 3900
    maxChunks = 3
)

var (
    bot        *tgbotapi.BotAPI
    adminIDs   = map[int64]bool{}
    httpClient = &http.Client{Timeout: 90 * time.Second}
)

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

    var err error
    bot, err = tgbotapi.NewBotAPI(token)
    if err != nil {
        log.Fatalf("❌ اتصال به Bot API ناموفق: %v", err)
    }
    bot.Debug = os.Getenv("DEBUG") == "1"
    log.Printf("✅ ربات @%s روشن شد", bot.Self.UserName)

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

func handleMessage(msg *tgbotapi.Message) {
    chatID := msg.Chat.ID

    if len(adminIDs) > 0 && (msg.From == nil || !adminIDs[msg.From.ID]) {
        reply(chatID, "⛔ شما اجازهٔ استفاده از این ربات را ندارید.")
        return
    }

    if msg.IsCommand() {
        switch msg.Command() {
        case "start", "help":
            sendHTML(chatID, helpText())
        default:
            reply(chatID, "❓ دستور ناشناخته. /help را بزنید.")
        }
        return
    }

    var data []byte
    var name string

    switch {
    case msg.Document != nil:
        if msg.Document.FileSize > 19*1024*1024 {
            reply(chatID, "❌ فایل بزرگ‌تر از ۱۹ مگابایت است؛ ربات‌های تلگرام اجازهٔ دانلود ندارند.")
            return
        }
        sendAction(chatID, tgbotapi.ChatUploadDocument)
        d, err := downloadFile(msg.Document.FileID)
        if err != nil {
            reply(chatID, "❌ دانلود فایل ناموفق بود:\n"+err.Error())
            return
        }
        data = d
        name = strings.TrimSuffix(msg.Document.FileName, filepath.Ext(msg.Document.FileName))
        if name == "" {
            name = "npvt"
        }

    case strings.TrimSpace(msg.Text) != "":
        data = []byte(msg.Text)
        name = "npvt"

    case strings.TrimSpace(msg.Caption) != "":
        data = []byte(msg.Caption)
        name = "npvt"

    default:
        reply(chatID, "📎 فایل .npvt را بفرستید یا محتوایش را متن کنید. راهنما: /help")
        return
    }

    sendAction(chatID, tgbotapi.ChatTyping)

    res, err := processInput(data)
    if err != nil {
        reply(chatID, "❌ "+err.Error())
        return
    }

    if len(res.URIs) == 0 && len(res.Raw) == 0 {
        if len(res.Errors) > 0 {
            reply(chatID, "⚠️ هیچ کانفیگی استخراج نشد:\n"+strings.Join(res.Errors, "\n"))
        } else {
            reply(chatID, "⚠️ در این ورودی کانفیگی پیدا نشد.")
        }
        return
    }

    var lines []string
    lines = append(lines, res.URIs...)
    for _, r := range res.Raw {
        lines = append(lines, "", "─────── RAW ───────", r)
    }
    content := strings.Join(lines, "\n")

    summary := fmt.Sprintf("✅ %d کانفیگ استخراج شد", len(res.URIs))
    if len(res.Raw) > 0 {
        summary += fmt.Sprintf(" • %d بلوک خام", len(res.Raw))
    }
    if len(res.Errors) > 0 {
        summary += fmt.Sprintf("\n⚠️ %d بلوک ناموفق", len(res.Errors))
    }

    switch {
    case len(content) <= msgLimit:
        reply(chatID, summary+"\n\n"+content)
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
    return `🔐 <b>ربات رمزگشای NPVT</b>

فایل‌های <code>.npvt</code> اپلیکیشن NapsternetV را رمزگشایی کرده و کانفیگ‌های V2ray را استخراج می‌کنم.

📤 <b>نحوه استفاده:</b>
• فایل <code>.npvt</code> را بفرستید
• یا محتوای فایل را به‌صورت متن پیام کنید

✨ <b>خروجی:</b> لینک‌های <code>vless://</code> <code>vmess://</code> <code>trojan://</code> <code>ss://</code> — قابل ایمپورت در v2rayNG / Hiddify / NapsternetV و مشابه آنها.

⚙️ کانفیگ‌های غیر V2ray (مثل SSH) به‌صورت JSON خام برگردانده می‌شوند.`
}

type processResult struct {
    URIs   []string
    Raw    []string
    Errors []string
}

func processInput(data []byte) (*processResult, error) {
    if len(data) > 50*1024*1024 {
        return nil, fmt.Errorf("ورودی بیش از حد بزرگ است")
    }

    blobs, decodeErrs, err := loadBlobs(data)
    if err != nil {
        return nil, err
    }

    res := &processResult{Errors: decodeErrs}

    for i, blob := range blobs {
        if len(blob) < 16 {
            res.Errors = append(res.Errors, fmt.Sprintf("بلوک %d: کوتاه‌تر از ۱۶ بایت (بدون nonce) است.", i+1))
            continue
        }
        pt, derr := decrypt(blob)
        if derr != nil {
            res.Errors = append(res.Errors, fmt.Sprintf("بلوک %d: %v", i+1, derr))
            continue
        }
        uris := processBlob(pt)
        if len(uris) == 0 {
            if !isMostlyPrintable(pt) {
                res.Errors = append(res.Errors, fmt.Sprintf("بلوک %d: خروجی رمزگشایی نامعتبر بود.", i+1))
                continue
            }
            var pretty bytes.Buffer
            if jerr := json.Indent(&pretty, pt, "", "  "); jerr == nil && pretty.Len() > 0 {
                res.Raw = append(res.Raw, pretty.String())
            } else if s := strings.TrimSpace(string(pt)); s != "" {
                res.Raw = append(res.Raw, s)
            }
            continue
        }
        res.URIs = append(res.URIs, uris...)
    }

    res.URIs = dedupe(res.URIs)
    res.Raw = dedupe(res.Raw)
    return res, nil
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

func loadBlobs(raw []byte) ([][]byte, []string, error) {
    text := strings.TrimSpace(string(raw))
    if text == "" {
        return nil, nil, fmt.Errorf("محتوای ورودی خالی است")
    }

    blobs, errs := decodeTokens(strings.Split(text, ","))

    if len(blobs) == 0 && strings.ContainsAny(text, "\n\r") {
        lines := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' })
        if b2, e2 := decodeTokens(lines); len(b2) > 0 {
            blobs, errs = b2, append(errs, e2...)
        }
    }

    if len(blobs) == 0 {
        if len(errs) > 0 {
            return nil, errs, fmt.Errorf("هیچ توکنی قابل رمزگشایی نبود:\n%s", strings.Join(errs, "\n"))
        }
        return nil, errs, fmt.Errorf("دادهٔ قابل پردازشی پیدا نشد")
    }
    return blobs, errs, nil
}

func decodeTokens(tokens []string) ([][]byte, []string) {
    var blobs [][]byte
    var errs []string
    for i, tok := range tokens {
        tok = strings.TrimSpace(tok)
        if tok == "" {
            continue
        }
        b, err := decodeOne(tok)
        if err != nil {
            errs = append(errs, fmt.Sprintf("توکن %d: %v", i+1, err))
            continue
        }
        blobs = append(blobs, b)
    }
    return blobs, errs
}

func decodeOne(text string) ([]byte, error) {
    text = strings.ReplaceAll(text, "NPVT1", "")
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

    return nil, fmt.Errorf("قالب توکن شناسایی نشد (hex/base64): %.32s…", text)
}

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

func processBlob(pt []byte) []string {
    var root any
    if err := json.Unmarshal(pt, &root); err == nil {
        var uris []string
        walkJSON(root, &uris)
        if len(uris) > 0 {
            return uris
        }
    }
    if sub, err := extractURIsFromConfig(pt); err == nil && len(sub) > 0 {
        return sub
    }
    return scanPlainURIs(pt)
}

var uriSchemes = []string{"vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://", "tuic://"}

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

func walkJSON(v any, uris *[]string) {
    switch x := v.(type) {
    case map[string]any:
        if raw, ok := x["v2rayJson"]; ok {
            switch c := raw.(type) {
            case string:
                if u, err := extractURIsFromConfig([]byte(c)); err == nil {
                    *uris = append(*uris, u...)
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
        for _, v := range x {
            walkJSON(v, uris)
        }
    case []any:
        for _, v := range x {
            walkJSON(v, uris)
        }
    }
}

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

func escapeUserInfo(s string) string {
    return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
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
            if h, ok := ss.WSSettings.Headers["Host"]; ok && h != "" {
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
        u.Id, v.Address, v.Port, q.Encode(), url.PathEscape(remarks)), nil
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
            if h, ok := ss.WSSettings.Headers["Host"]; ok {
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
        "ps":   remarks,
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
        escapeUserInfo(s.Password), s.Address, s.Port, q.Encode(), url.PathEscape(remarks)), nil
}

func shadowsocksURI(ts serversSettingsT, remarks string) (string, error) {
    if len(ts.Servers) == 0 {
        return "", fmt.Errorf("shadowsocks: missing server")
    }
    s := ts.Servers[0]
    userInfo := base64.RawURLEncoding.EncodeToString([]byte(s.Method + ":" + s.Password))
    return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, s.Address, s.Port, url.PathEscape(remarks)), nil
}

func outboundToURI(protocol string, settingsRaw, streamRaw json.RawMessage, remarks string) (string, error) {
    var ss streamSettingsT
    if len(streamRaw) > 0 {
        if err := json.Unmarshal(streamRaw, &ss); err != nil {
            return "", err
        }
    }

    switch protocol {
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
        switch hdr.Protocol {
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
