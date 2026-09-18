package main

import (
    "bytes"
    "compress/flate"
    "compress/gzip"
    "compress/zlib"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
    "github.com/vmihailenco/msgpack/v5"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/pbkdf2"
)

const npvsWrapSize = 60
const npvsEngine = "NPVS Engine v5"

// بالاترین نسخه envelope که پذیرفته می‌شود
const npvsMaxVersion = 5

// ═══════════════════ رمزهای در انتظار ═══════════════════

type pendingPassEntry struct {
    kind    string
    data    []byte
    created time.Time
}

var pendingPass sync.Map

const pendingPassTTL = 10 * time.Minute

func setPendingPass(chatID int64, kind string, data []byte) {
    pendingPass.Store(chatID, pendingPassEntry{kind: kind, data: data, created: time.Now()})
}

func takePendingPass(chatID int64) (string, []byte, bool, bool) {
    v, ok := pendingPass.LoadAndDelete(chatID)
    if !ok {
        return "", nil, false, false
    }
    e, ok := v.(pendingPassEntry)
    if !ok {
        return "", nil, false, false
    }
    if time.Since(e.created) > pendingPassTTL {
        return "", nil, false, true
    }
    return e.kind, e.data, true, false
}

func startPassReaper() {
    go func() {
        for range time.Tick(5 * time.Minute) {
            pendingPass.Range(func(k, v any) bool {
                if e, ok := v.(pendingPassEntry); ok && time.Since(e.created) > pendingPassTTL {
                    pendingPass.Delete(k)
                }
                return true
            })
        }
    }()
}

// ═══════════════════ Sentinel (npvs1:...) ═══════════════════

const npvSentinelPrefix = "npvs1:"
const npvSentinelAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"

func decodeSentinelToken(tok string) ([]byte, bool) {
    if dec, err := base64.StdEncoding.DecodeString(tok); err == nil {
        return dec, true
    }
    if dec, err := base64.URLEncoding.DecodeString(tok); err == nil {
        return dec, true
    }
    if m := len(tok) % 4; m != 0 {
        if dec, err := base64.URLEncoding.DecodeString(tok + strings.Repeat("=", 4-m)); err == nil {
            return dec, true
        }
    }
    return nil, false
}

func decodeNpvSentinels(s string) string {
    var sb strings.Builder
    for {
        i := strings.Index(s, npvSentinelPrefix)
        if i < 0 {
            sb.WriteString(s)
            return sb.String()
        }
        sb.WriteString(s[:i])
        s = s[i+len(npvSentinelPrefix):]
        j := 0
        for j < len(s) && strings.IndexByte(npvSentinelAlphabet, s[j]) >= 0 {
            j++
        }
        tok := s[:j]
        s = s[j:]
        if dec, ok := decodeSentinelToken(tok); ok {
            sb.Write(dec)
        } else {
            sb.WriteString(npvSentinelPrefix)
            sb.WriteString(tok)
        }
    }
}

// ═══════════════════ Regex ═══════════════════

var (
    reProtocol   = regexp.MustCompile(`(?:\\*)"protocol(?:\\*)"\s*:\s*(?:\\*)"(trojan|vless|vmess|shadowsocks)(?:\\*)"`)
    reAddress    = regexp.MustCompile(`(?:\\*)"address(?:\\*)"\s*:\s*(?:\\*)"([^"\\]+)(?:\\*)"`)
    reServer     = regexp.MustCompile(`(?:\\*)"server(?:\\*)"\s*:\s*(?:\\*)"([^"\\]+)(?:\\*)"`)
    reServerPort = regexp.MustCompile(`(?:\\*)"serverPort(?:\\*)"\s*:\s*(?:\\*)"?([^"\\,}\]]+)(?:\\*)"?`)
    rePort       = regexp.MustCompile(`(?:\\*)"port(?:\\*)"\s*:\s*(?:\\*)"?(\d+)(?:\\*)"?`)
    rePassword   = regexp.MustCompile(`(?:\\*)"password(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reMethod     = regexp.MustCompile(`(?:\\*)"method(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reNetwork    = regexp.MustCompile(`(?:\\*)"network(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reWSSHost    = regexp.MustCompile(`(?:\\*)"host(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reWSPath     = regexp.MustCompile(`(?:\\*)"path(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reSecurity   = regexp.MustCompile(`(?:\\*)"security(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reSNI        = regexp.MustCompile(`(?:\\*)"serverName(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reFinger     = regexp.MustCompile(`(?:\\*)"fingerprint(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reRemarks    = regexp.MustCompile(`(?:\\*)"remarks(?:\\*)"\s*:\s*(?:\\*)"([^"\\]*)(?:\\*)"`)
    reUUID       = regexp.MustCompile(`(?:\\*)"id(?:\\*)"\s*:\s*(?:\\*)"([^"\\]+)(?:\\*)"`)
)

func firstGroup(re *regexp.Regexp, s string) string {
    m := re.FindStringSubmatch(s)
    if len(m) >= 2 {
        return m[1]
    }
    return ""
}

func splitHostPort(s string) (string, string) {
    if i := strings.LastIndex(s, ":"); i > 0 {
        host, port := s[:i], s[i+1:]
        if port != "" && strings.Trim(port, "0123456789") == "" {
            return host, port
        }
    }
    return s, ""
}

func normalizeAddr(addr, port string) (string, string) {
    if port == "" && strings.Contains(addr, ":") {
        return splitHostPort(addr)
    }
    return addr, port
}

// 🔒 پیام دیباگ فقط وقتی DEBUG=1 فعال است
func debugModeEnabled() bool {
    return os.Getenv("DEBUG") == "1"
}

func debugPreview(s string, n int) string {
    if len(s) > n {
        s = s[:n]
    }
    s = strings.ReplaceAll(s, "\\", "⇧")
    s = strings.ReplaceAll(s, "\n", "⏎")
    s = strings.ReplaceAll(s, "\r", "⏎")
    s = strings.ReplaceAll(s, "\t", "→")
    return s
}

func npvsDebugInfo(pt []byte) string {
    var sb strings.Builder
    sb.WriteString("🔧 " + npvsEngine + " — دیباگ (DEBUG فعال)\n")
    lower := strings.ToLower(string(pt))
    sb.WriteString(fmt.Sprintf("📊 حجم: %d بایت\n", len(pt)))
    fmt.Fprintf(&sb, "   protocol=%d trojan=%d vless=%d vmess=%d\n",
        strings.Count(lower, "protocol"), strings.Count(lower, "trojan"),
        strings.Count(lower, "vless"), strings.Count(lower, "vmess"))
    fmt.Fprintf(&sb, "   server=%d password=%d npvs1=%d\n",
        strings.Count(lower, "server"), strings.Count(lower, "password"),
        strings.Count(lower, "npvs1:"))
    sb.WriteString("📝 ۴۰۰ کاراکتر اول:\n")
    sb.WriteString(debugPreview(string(pt), 400))
    return sb.String()
}

func npvsNoLinkMessage() string {
    return "🔧 " + npvsEngine + "\n⚠️ متن رمزگشایی شد ولی کانفیگ قابل شناسایی نبود.\n💡 اگر فایل معتبر است با سازنده چک کنید."
}

// ═══════════════════ استخراج ═══════════════════

func uriKey(u string) string {
    i := strings.Index(u, "://")
    if i < 0 {
        return u
    }
    rest := u[i+3:]
    if j := strings.IndexAny(rest, "?#"); j >= 0 {
        rest = rest[:j]
    }
    return rest
}

func dedupeByURI(in []string) []string {
    seen := map[string]struct{}{}
    out := make([]string, 0, len(in))
    for _, u := range in {
        k := uriKey(u)
        if _, ok := seen[k]; ok {
            continue
        }
        seen[k] = struct{}{}
        out = append(out, u)
    }
    return out
}

func regexExtractFromText(text string) []string {
    uris := extractByProtocol(text)
    profileUris := extractByProfile(text)

    for _, pu := range profileUris {
        dup := false
        for _, u := range uris {
            if uriKey(u) == uriKey(pu) {
                dup = true
                break
            }
        }
        if !dup {
            uris = append(uris, pu)
        }
    }
    return dedupeByURI(uris)
}

func extractByProtocol(text string) []string {
    var uris []string
    protoIdxs := reProtocol.FindAllStringSubmatchIndex(text, -1)
    for _, pm := range protoIdxs {
        proto := text[pm[2]:pm[3]]
        windowEnd := pm[1] + 3000
        if windowEnd > len(text) {
            windowEnd = len(text)
        }
        window := text[pm[1]:windowEnd]
        switch proto {
        case "trojan":
            if uri := buildTrojanFromRegex(window, text); uri != "" {
                uris = append(uris, uri)
            }
        case "vless":
            if uri := buildVlessFromRegex(window, text); uri != "" {
                uris = append(uris, uri)
            }
        case "vmess":
            if uri := buildVMessFromRegex(window, text); uri != "" {
                uris = append(uris, uri)
            }
        case "shadowsocks":
            if uri := buildSSFromRegex(window, text); uri != "" {
                uris = append(uris, uri)
            }
        }
    }
    return uris
}

func extractByProfile(text string) []string {
    var uris []string
    serverIdxs := reServer.FindAllStringSubmatchIndex(text, -1)
    for _, sm := range serverIdxs {
        server := text[sm[2]:sm[3]]
        winEnd := sm[1] + 2500
        if winEnd > len(text) {
            winEnd = len(text)
        }
        window := text[sm[1]:winEnd]

        port := firstGroup(reServerPort, window)
        if port == "" {
            port = firstGroup(rePort, window)
        }
        pwd := firstGroup(rePassword, window)
        if pwd == "" {
            continue
        }
        method := firstGroup(reMethod, window)
        remarks := firstGroup(reRemarks, window)

        server, port = normalizeAddr(server, port)
        if port == "" {
            port = "443"
        }

        if method != "" {
            userInfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + pwd))
            uris = append(uris, fmt.Sprintf("ss://%s@%s:%s#%s",
                userInfo, formatHost(server), port, cleanRemarks(remarks)))
        } else {
            uris = append(uris, fmt.Sprintf("trojan://%s@%s:%s#%s",
                url.QueryEscape(pwd), formatHost(server), port, cleanRemarks(remarks)))
        }
    }
    return uris
}

// ═══════════════════ ساخت لینک‌ها ═══════════════════

func buildTrojanFromRegex(window, fullText string) string {
    addr := firstGroup(reAddress, window)
    port := firstGroup(rePort, window)
    pass := firstGroup(rePassword, window)
    if addr == "" {
        return ""
    }
    addr, port = normalizeAddr(addr, port)
    if port == "" {
        port = "443"
    }

    q := url.Values{}
    netw := firstGroup(reNetwork, window)
    if netw != "" {
        q.Set("type", netw)
    }
    sec := firstGroup(reSecurity, window)
    if sec != "" {
        q.Set("security", sec)
    }
    if netw == "ws" {
        if h := firstGroup(reWSSHost, window); h != "" {
            q.Set("host", h)
        }
        if p := firstGroup(reWSPath, window); p != "" {
            q.Set("path", p)
        }
    }
    if sec == "tls" {
        if sni := firstGroup(reSNI, window); sni != "" {
            q.Set("sni", sni)
        }
        if fp := firstGroup(reFinger, window); fp != "" {
            q.Set("fp", fp)
        }
    }

    remarks := firstGroup(reRemarks, window)
    if remarks == "" {
        remarks = firstGroup(reRemarks, fullText)
    }

    return fmt.Sprintf("trojan://%s@%s:%s?%s#%s",
        url.QueryEscape(pass), formatHost(addr), port, formatQuery(q), cleanRemarks(remarks))
}

func buildVlessFromRegex(window, fullText string) string {
    addr := firstGroup(reAddress, window)
    port := firstGroup(rePort, window)
    uuid := firstGroup(reUUID, window)
    if addr == "" || uuid == "" {
        return ""
    }
    addr, port = normalizeAddr(addr, port)
    if port == "" {
        port = "443"
    }

    q := url.Values{}
    q.Set("encryption", "none")
    netw := firstGroup(reNetwork, window)
    if netw != "" {
        q.Set("type", netw)
    }
    sec := firstGroup(reSecurity, window)
    if sec != "" {
        q.Set("security", sec)
    }
    if netw == "ws" {
        if h := firstGroup(reWSSHost, window); h != "" {
            q.Set("host", h)
        }
        if p := firstGroup(reWSPath, window); p != "" {
            q.Set("path", p)
        }
    }
    if sec == "tls" {
        if sni := firstGroup(reSNI, window); sni != "" {
            q.Set("sni", sni)
        }
    }

    remarks := firstGroup(reRemarks, window)
    if remarks == "" {
        remarks = firstGroup(reRemarks, fullText)
    }

    return fmt.Sprintf("vless://%s@%s:%s?%s#%s",
        uuid, formatHost(addr), port, formatQuery(q), cleanRemarks(remarks))
}

func buildVMessFromRegex(window, fullText string) string {
    addr := firstGroup(reAddress, window)
    port := firstGroup(rePort, window)
    uuid := firstGroup(reUUID, window)
    if addr == "" || uuid == "" {
        return ""
    }
    addr, port = normalizeAddr(addr, port)
    if port == "" {
        port = "443"
    }

    netw := firstGroup(reNetwork, window)
    if netw == "" {
        netw = "tcp"
    }
    tlsFlag := ""
    if sec := firstGroup(reSecurity, window); sec == "tls" || sec == "reality" {
        tlsFlag = "tls"
    }
    host, path := "", ""
    if netw == "ws" {
        host = firstGroup(reWSSHost, window)
        path = firstGroup(reWSPath, window)
    }

    remarks := firstGroup(reRemarks, window)
    if remarks == "" {
        remarks = firstGroup(reRemarks, fullText)
    }

    obj := map[string]string{
        "v": "2", "ps": cleanRemarks(remarks), "add": addr, "port": port,
        "id": uuid, "aid": "0", "scy": "auto", "net": netw, "type": "none",
        "host": host, "path": path, "tls": tlsFlag,
    }
    b, err := json.Marshal(obj)
    if err != nil {
        return ""
    }
    return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func buildSSFromRegex(window, fullText string) string {
    addr := firstGroup(reAddress, window)
    port := firstGroup(rePort, window)
    pass := firstGroup(rePassword, window)
    method := firstGroup(reMethod, window)
    if addr == "" || pass == "" {
        return ""
    }
    addr, port = normalizeAddr(addr, port)
    if port == "" {
        port = "443"
    }
    if method == "" {
        method = "aes-256-gcm"
    }

    userInfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + pass))
    remarks := firstGroup(reRemarks, window)
    if remarks == "" {
        remarks = firstGroup(reRemarks, fullText)
    }

    return fmt.Sprintf("ss://%s@%s:%s#%s",
        userInfo, formatHost(addr), port, cleanRemarks(remarks))
}

// ═══════════════════ ساختارهای NPVS ═══════════════════

type npvsPassphraseWrap struct {
    Iters int    `json:"iters"`
    Kdf   string `json:"kdf"`
    Salt  string `json:"salt"`
    Wrap  string `json:"wrap"`
}

type npvsAppKeyWrap struct {
    Kdf   string `json:"kdf"`
    KeyID int    `json:"keyId"`
    Salt  string `json:"salt"`
    Wrap  string `json:"wrap"`
}

type npvsHeader struct {
    V          int                 `json:"v"`
    ConfigID   string              `json:"configId"`
    Passphrase *npvsPassphraseWrap `json:"passphrase"`
    AppKey     *npvsAppKeyWrap     `json:"appKey"`
    Policy     struct {
        DisplayMessage      string  `json:"displayMessage"`
        CustomServerMessage string  `json:"customServerMessage"`
        ExpiresAt           *string `json:"expiresAt"`
    } `json:"policy"`
    Recipients []json.RawMessage `json:"recipients"`
}

type npvsEnvelope struct {
    headerRaw []byte
    hdr       npvsHeader
    nonce     []byte
    body      []byte
}

// ═══════════════════ 🐞 دیباگ نسخه ۲ ═══════════════════

// خطای پارسر که دیباگ را با خودش حمل می‌کند
// و در پیام «❌» تلگرام خودکار نمایش داده می‌شود
type npvsParseError struct {
    msg   string
    debug string
}

func (e *npvsParseError) Error() string { return e.msg + "\n\n" + e.debug }

func npvsDebugDump(b []byte) string {
    ver, hdrLen := -1, -1
    if len(b) >= 9 {
        ver = int(b[4])
        hdrLen = int(binary.BigEndian.Uint32(b[5:9]))
    }
    var sb strings.Builder
    sb.WriteString("🐞 NPVS DEBUG v2\n━━━━━━━━━━━━━━\n")
    fmt.Fprintf(&sb, "size=%d ver=%d hdrLen=%d\n", len(b), ver, hdrLen)

    if hdrLen > 2 && 9+hdrLen <= len(b) {
        hdr := b[9 : 9+hdrLen]
        pr := 0
        for _, c := range hdr {
            if c >= 0x20 && c < 0x7f {
                pr++
            }
        }
        // ~37% = رندوم (رمزشده) / خیلی بیشتر = انکودینگ ساختاری (msgpack و ...)
        fmt.Fprintf(&sb, "header printable=%d/%d (%.0f%%)\n",
            pr, len(hdr), 100*float64(pr)/float64(len(hdr)))

        // آیا بعد از هدر، nonce+bodyLen+body+sig دقیقاً جا می‌شود؟
        off := 9 + hdrLen
        if off+16 <= len(b) {
            bodyLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
            exact := off+16+bodyLen+64 == len(b)
            fmt.Fprintf(&sb, "bodyLen@%d=%d exactFit=%v\n", off, bodyLen, exact)
        }
        if 9+96 <= len(b) {
            sb.WriteString("head96:\n" + hex.EncodeToString(b[9:9+96]) + "\n")
        }
        s := 9 + hdrLen - 16
        if s < 0 {
            s = 0
        }
        e := 9 + hdrLen + 48
        if e > len(b) {
            e = len(b)
        }
        sb.WriteString("boundary:\n" + hex.EncodeToString(b[s:e]) + "\n")
    }
    t := 80
    if t > len(b) {
        t = len(b)
    }
    sb.WriteString("tail80:\n" + hex.EncodeToString(b[len(b)-t:]) + "\n")
    return sb.String()
}

func npvsHexdump(b []byte, width int) string {
    var sb strings.Builder
    for i := 0; i < len(b); i += width {
        end := i + width
        if end > len(b) {
            end = len(b)
        }
        fmt.Fprintf(&sb, "%06x %s\n", i, hex.EncodeToString(b[i:end]))
    }
    return sb.String()
}

// 🐞 دامپ کامل فایل به‌صورت فایل متنی → برای آنالیز آفلاین
func sendNPVSDebugDump(chatID int64, data []byte) {
    doc := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{
        Name:  "npvs_v5_dump.txt",
        Bytes: []byte(npvsHexdump(data, 32)),
    })
    if _, err := bot.Send(doc); err != nil {
        log.Printf("[NPVS] send dump failed: %v", err)
    }
}

// ═══════════════════ 🆕 ابزارهای decompress / انکودینگ هدر ═══════════════════

func npvsTryDecompress(b []byte) ([]byte, bool) {
    if len(b) < 2 {
        return nil, false
    }
    limit := int64(8 << 20) // سقف ۸ مگابایت خروجی

    if r, err := zlib.NewReader(bytes.NewReader(b)); err == nil {
        if out, err := io.ReadAll(io.LimitReader(r, limit)); err == nil && len(out) > 0 {
            return out, true
        }
    }
    if r, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
        if out, err := io.ReadAll(io.LimitReader(r, limit)); err == nil && len(out) > 0 {
            return out, true
        }
    }
    fr := flate.NewReader(bytes.NewReader(b))
    if out, err := io.ReadAll(io.LimitReader(fr, limit)); err == nil && len(out) > 0 {
        return out, true
    }
    return nil, false
}

// از خامِ هدر، JSON قابل پارس بیرون می‌کشد:
// خام → msgpack → پیشوندها → decompress → base64
func npvsHeaderJSON(raw []byte) ([]byte, bool) {
    if json.Valid(raw) {
        return raw, true
    }

    // 🆕 msgpack مستقیم
    var m map[string]any
    if err := msgpack.Unmarshal(raw, &m); err == nil && len(m) > 0 {
        if jb, jerr := json.Marshal(m); jerr == nil {
            return jb, true
        }
    }
    // 🆕 یک بایت فلگ + msgpack
    if len(raw) > 1 {
        var m2 map[string]any
        if err := msgpack.Unmarshal(raw[1:], &m2); err == nil && len(m2) > 0 {
            if jb, jerr := json.Marshal(m2); jerr == nil {
                return jb, true
            }
        }
    }

    // 🆕 حذف پیشوند احتمالی و JSON
    for _, off := range []int{1, 2, 4, 8} {
        if len(raw) > off && raw[off] == '{' && json.Valid(raw[off:]) {
            return raw[off:], true
        }
    }

    // decompress (خام / با پیشوند ۱ و ۲ بایتی)
    cands := [][]byte{raw}
    if len(raw) > 1 {
        cands = append(cands, raw[1:])
    }
    if len(raw) > 2 {
        cands = append(cands, raw[2:])
    }
    for _, c := range cands {
        if dec, ok := npvsTryDecompress(c); ok && json.Valid(dec) {
            return dec, true
        }
    }

    // base64
    s := strings.TrimSpace(strings.Join(strings.Fields(string(raw)), ""))
    if len(s) > 8 {
        padded := s
        if m3 := len(padded) % 4; m3 != 0 {
            padded += strings.Repeat("=", 4-m3)
        }
        if dec, err := base64.StdEncoding.DecodeString(padded); err == nil && json.Valid(dec) {
            return dec, true
        }
        if dec, err := base64.URLEncoding.DecodeString(padded); err == nil && json.Valid(dec) {
            return dec, true
        }
    }
    return nil, false
}

// اگر متنِ رمزگشایی‌شده فشرده بود، بازش می‌کند
func npvsPlaintext(pt []byte) []byte {
    if isMostlyPrintable(pt) {
        return pt
    }
    if dec, ok := npvsTryDecompress(pt); ok && isMostlyPrintable(dec) {
        return dec
    }
    return pt
}

// ═══════════════════ پارسر envelope ═══════════════════

// پایان JSON متوازن را از start پیدا می‌کند (رشته‌ها و escape ها را رعایت می‌کند)
func balancedJSONEnd(b []byte, start int) int {
    depth, inStr, esc := 0, false, false
    for i := start; i < len(b); i++ {
        c := b[i]
        if esc {
            esc = false
            continue
        }
        if c == '\\' {
            esc = true
            continue
        }
        if c == '"' {
            inStr = !inStr
            continue
        }
        if inStr {
            continue
        }
        if c == '{' {
            depth++
        } else if c == '}' {
            depth--
            if depth == 0 {
                return i
            }
        }
    }
    return -1
}

func parseNpvsEnvelope(b []byte) (*npvsEnvelope, error) {
    if len(b) < 16 || !bytes.HasPrefix(b, []byte("NPVS")) {
        return nil, &npvsParseError{msg: "ساختار NPVS شناخته نشد (magic)", debug: npvsDebugDump(b)}
    }
    ver := int(b[4])
    hdrLen := -1
    if len(b) >= 9 {
        hdrLen = int(binary.BigEndian.Uint32(b[5:9]))
    }

    // ─── مسیر سریع: فریمینگ استاندارد (v0/v1 و v5 اگر فریمینگ را حفظ کرده باشد) ───
    if len(b) >= 89 && ver <= npvsMaxVersion && hdrLen > 2 && 9+hdrLen < len(b) {
        e := &npvsEnvelope{headerRaw: b[9 : 9+hdrLen]}
        if hdrJSON, ok := npvsHeaderJSON(e.headerRaw); ok {
            if err := json.Unmarshal(hdrJSON, &e.hdr); err == nil {
                off := 9 + hdrLen
                if off+16 <= len(b) {
                    e.nonce = b[off : off+12]
                    bodyLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
                    off += 16
                    if bodyLen >= 16 && off+bodyLen <= len(b) {
                        e.body = b[off : off+bodyLen]
                        return e, nil
                    }
                    if off < len(b) {
                        e.body = b[off:]
                        return e, nil
                    }
                }
            }
        }
    }

    // ─── fallback: جستجوی JSON متوازن در نقاط مختلف فایل (حداکثر ۶۰ تلاش) ───
    tried := 0
    for i := bytes.IndexByte(b, '{'); i >= 0 && i < len(b)-10 && tried < 60; {
        tried++
        var next int = -1
        if n := bytes.IndexByte(b[i+1:], '{'); n >= 0 {
            next = i + 1 + n
        }
        if end := balancedJSONEnd(b, i); end > i {
            e := &npvsEnvelope{headerRaw: b[i : end+1]}
            if hdrJSON, ok := npvsHeaderJSON(e.headerRaw); ok {
                if err := json.Unmarshal(hdrJSON, &e.hdr); err == nil {
                    tail := b[end+1:]
                    if len(tail) >= 28 {
                        e.nonce = tail[:12]
                        e.body = tail[12:]
                    } else if len(tail) > 16 {
                        e.body = tail
                    }
                    return e, nil
                }
            }
        }
        i = next
    }

    // ─── 🐞 شکست: لاگ سرور + دیباگ به تلگرام ───
    dbg := npvsDebugDump(b)
    log.Printf("[NPVS] parse failed: ver=%d hdrLen=%d size=%d", ver, hdrLen, len(b))
    msg := "ساختار NPVS شناخته نشد"
    if ver > npvsMaxVersion {
        msg = fmt.Sprintf("نسخه NPVS=%d پشتیبانی نمی‌شود", ver)
    }
    return nil, &npvsParseError{msg: msg, debug: dbg}
}

func npvsChachaOpen(key, nonce, ctTag, aad []byte) ([]byte, error) {
    aead, err := chacha20poly1305.New(key)
    if err != nil {
        return nil, err
    }
    return aead.Open(nil, nonce, ctTag, aad)
}

func npvsB64URL(s string) ([]byte, error) {
    if r, err := base64.URLEncoding.DecodeString(s); err == nil {
        return r, nil
    }
    if m := len(s) % 4; m != 0 {
        s += strings.Repeat("=", 4-m)
    }
    return base64.URLEncoding.DecodeString(s)
}

// ═══════════════════ White-Box — ⚡ با کش کامل ═══════════════════

const wbTlastSize = 4096
const wbTableSize = 16384
const wbXorSize = 24576

var (
    wbShiftRows = [16]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}
    wbKdfPrefix = []byte("npvtunnel/appkey/v1 ")
)

var (
    wbXorBin        []byte
    wbTy            [16][256]uint32
    wbMbl           [16][256]uint32
    wbTlastVariants []*[16][256]byte
    wbOnce          sync.Once
)

var npvsRepoBases = []string{
    "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/main/internal/modules/impl/assets/npvs/",
    "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/master/internal/modules/impl/assets/npvs/",
    "https://cdn.jsdelivr.net/gh/KernelDotDLL/Pantegnos@main/internal/modules/impl/assets/npvs/",
    "https://cdn.jsdelivr.net/gh/KernelDotDLL/Pantegnos@master/internal/modules/impl/assets/npvs/",
}

// 💾 کش دائمی روی دیسک → بعد از ری‌استارت هم بدون شبکه کار می‌کند
func npvsGetBlob(name string, want int) []byte {
    cache := "npvs_cache_" + name
    if b, err := os.ReadFile(cache); err == nil && len(b) == want {
        return b
    }

    for _, p := range []string{os.Getenv("NPVS_DIR"), "npvs", "assets/npvs", "."} {
        if p == "" {
            continue
        }
        if b, err := os.ReadFile(p + "/" + name); err == nil && len(b) == want {
            _ = os.WriteFile(cache, b, 0644)
            return b
        }
    }

    for _, u := range npvsRepoBases {
        b, err := fetchURL(u + name)
        if err == nil && len(b) == want {
            _ = os.WriteFile(cache, b, 0644)
            return b
        }
    }
    return nil
}

func preloadNPVS() {
    go func() {
        start := time.Now()
        loadWB()
        log.Printf("⚡ جداول NPVS از قبل آماده شد (%v)", time.Since(start).Round(time.Millisecond))
    }()
}

func loadWB() {
    wbOnce.Do(func() {
        if b := npvsGetBlob("tyboxes.bin", wbTableSize); b != nil {
            for i := 0; i < 16; i++ {
                for j := 0; j < 256; j++ {
                    k := (i*256 + j) * 4
                    wbTy[i][j] = binary.BigEndian.Uint32(b[k:])
                }
            }
        } else {
            wbTy = tyBoxes
        }

        if b := npvsGetBlob("mbl.bin", wbTableSize); b != nil {
            for i := 0; i < 16; i++ {
                for j := 0; j < 256; j++ {
                    k := (i*256 + j) * 4
                    wbMbl[i][j] = binary.BigEndian.Uint32(b[k:])
                }
            }
        } else {
            wbMbl = mbl
        }

        if b := npvsGetBlob("xor.bin", wbXorSize); b != nil {
            wbXorBin = b
        } else {
            wbXorBin = make([]byte, wbXorSize)
            for t := 0; t < 96; t++ {
                for a := 0; a < 16; a++ {
                    for bb := 0; bb < 16; bb++ {
                        wbXorBin[(t<<8)+(a<<4)+bb] = xorTable[t][a][bb]
                    }
                }
            }
        }

        base := tboxesLast
        wbTlastVariants = append(wbTlastVariants, &base)
        for _, name := range []string{"tboxes_last.bin", "tboxes_last_v2.bin"} {
            if b := npvsGetBlob(name, wbTlastSize); b != nil {
                var t [16][256]byte
                for i := 0; i < 16; i++ {
                    copy(t[i][:], b[i*256:(i+1)*256])
                }
                wbTlastVariants = append(wbTlastVariants, &t)
            }
        }
        log.Printf("✅ جداول White-Box NPVS آماده (%d نسخه tboxes_last)", len(wbTlastVariants))
    })
}

func wbShift(s *[16]byte) {
    var t [16]byte
    for i := 0; i < 16; i++ {
        t[i] = s[wbShiftRows[i]]
    }
    *s = t
}

func wbXorLookup(t, a, b int) byte {
    return wbXorBin[(t<<8)+(a<<4)+b]
}

func wbMix(grp, k int, a, b, c, d uint32) byte {
    t := grp*24 + k*6
    hi := uint(28 - 8*k)
    lo := uint(24 - 8*k)
    p1 := wbXorLookup(t, int(a>>hi)&15, int(b>>hi)&15)
    p2 := wbXorLookup(t+1, int(c>>hi)&15, int(d>>hi)&15)
    p3 := wbXorLookup(t+2, int(a>>lo)&15, int(b>>lo)&15)
    p4 := wbXorLookup(t+3, int(c>>lo)&15, int(d>>lo)&15)
    return wbXorLookup(t+4, int(p1), int(p2))<<4 | wbXorLookup(t+5, int(p3), int(p4))
}

func wbApplyRow(s *[16]byte, base int, tab *[16][256]uint32, grp int) {
    a := tab[base+0][s[base+0]]
    b := tab[base+1][s[base+1]]
    c := tab[base+2][s[base+2]]
    d := tab[base+3][s[base+3]]
    for k := 0; k < 4; k++ {
        s[base+k] = wbMix(grp, k, a, b, c, d)
    }
}

func wbBlock(in *[16]byte, tlast *[16][256]byte) (out [16]byte) {
    s := *in
    wbShift(&s)
    for grp := 0; grp < 4; grp++ {
        base := grp * 4
        wbApplyRow(&s, base, &wbTy, grp)
        wbApplyRow(&s, base, &wbMbl, grp)
    }
    wbShift(&s)
    for i := 0; i < 16; i++ {
        out[i] = tlast[i][s[i]]
    }
    return out
}

func wbCTR(nonce, ct []byte, tlast *[16][256]byte) []byte {
    var counter [16]byte
    copy(counter[:], nonce[:16])
    out := make([]byte, len(ct))
    for i := 0; i < len(ct); i += 16 {
        ks := wbBlock(&counter, tlast)
        n := len(ct) - i
        if n > 16 {
            n = 16
        }
        for j := 0; j < n; j++ {
            out[i+j] = ct[i+j] ^ ks[j]
        }
        for p := 15; p >= 0; p-- {
            counter[p]++
            if counter[p] != 0 {
                break
            }
        }
    }
    return out
}

func custodianKDKs(salt []byte) [][]byte {
    if len(salt) < 16 {
        return nil
    }
    loadWB()
    material := make([]byte, 32)
    copy(material, salt[:16])
    var kdks [][]byte
    for _, tlast := range wbTlastVariants {
        stream := wbCTR(material[:16], material[16:], tlast)
        sum := sha256.Sum256(append(append([]byte{}, wbKdfPrefix...), stream...))
        kdks = append(kdks, sum[:])
    }
    return kdks
}

// ═══════════════════ باز کردن قفل‌ها ═══════════════════

func npvsUnwrapAppKey(a *npvsAppKeyWrap) ([]byte, error) {
    if a.Kdf != "wbaes-ctr-sha256" {
        return nil, fmt.Errorf("KDF: %s", a.Kdf)
    }
    salt, err := npvsB64URL(a.Salt)
    if err != nil || len(salt) != 16 {
        return nil, fmt.Errorf("salt نامعتبر")
    }
    wrap, err := npvsB64URL(a.Wrap)
    if err != nil || len(wrap) != npvsWrapSize {
        return nil, fmt.Errorf("wrap نامعتبر")
    }
    kdks := custodianKDKs(salt)
    if len(kdks) == 0 {
        return nil, fmt.Errorf("جدول‌ها در دسترس نیستند")
    }
    for _, kdk := range kdks {
        if dek, err := npvsChachaOpen(kdk, wrap[:12], wrap[12:], salt); err == nil {
            return dek, nil
        }
    }
    return nil, fmt.Errorf("کلید custodian جواب نداد (keyId %d)", a.KeyID)
}

func npvsUnwrapPassphrase(p *npvsPassphraseWrap, password string) ([]byte, error) {
    if p.Kdf != "pbkdf2-hmac-sha256" {
        return nil, fmt.Errorf("KDF: %s", p.Kdf)
    }
    if password == "" {
        return nil, fmt.Errorf("رمز لازم است")
    }
    salt, err := npvsB64URL(p.Salt)
    if err != nil || len(salt) < 16 {
        return nil, fmt.Errorf("salt نامعتبر")
    }
    wrap, err := npvsB64URL(p.Wrap)
    if err != nil || len(wrap) != npvsWrapSize {
        return nil, fmt.Errorf("wrap نامعتبر")
    }
    derived := pbkdf2.Key([]byte(password), salt, p.Iters, 32, sha256.New)
    dek, err := npvsChachaOpen(derived, wrap[:12], wrap[12:], salt)
    if err != nil {
        return nil, fmt.Errorf("رمز اشتباه")
    }
    return dek, nil
}

func npvsOpenBody(dek, nonce, body, aad []byte) ([]byte, error) {
    if len(body) < 16 {
        return nil, fmt.Errorf("بدنه ناقص — فایل را «آپلود» کنید نه متن")
    }
    bodies := [][]byte{body}
    if len(body) > 68 {
        bodies = append(bodies, body[:len(body)-64])
    }
    if len(body) > 20 {
        bodies = append(bodies, body[4:])
    }
    if len(body) > 72 {
        bodies = append(bodies, body[4:len(body)-64])
    }

    nonces := [][]byte{}
    if len(nonce) == 12 {
        nonces = append(nonces, nonce)
    }
    var zero12 [12]byte
    nonces = append(nonces, zero12[:])

    aads := [][]byte{nil}
    if len(aad) > 0 {
        aads = [][]byte{aad, nil}
    }

    for _, n := range nonces {
        for _, ct := range bodies {
            for _, ad := range aads {
                if pt, err := npvsChachaOpen(dek, n, ct, ad); err == nil {
                    return pt, nil
                }
            }
        }
    }
    return nil, fmt.Errorf("بدنه باز نشد")
}

// ═══════════════════ نقطه ورود ═══════════════════

func handleNPVS(data []byte, chatID int64) (*processResult, error, bool) {
    env, err := parseNpvsEnvelope(data)
    if err != nil {
        // 🐞 دامپ کامل به‌صورت فایل + پیام دیباگ داخل err
        sendNPVSDebugDump(chatID, data)
        return nil, err, false
    }

    if env.hdr.Passphrase != nil {
        setPendingPass(chatID, "npvs", data)
        if env.hdr.Policy.DisplayMessage != "" {
            reply(chatID, "💡 "+env.hdr.Policy.DisplayMessage)
        }
        return nil, nil, true
    }

    res := &processResult{}

    if env.hdr.AppKey != nil {
        dek, uerr := npvsUnwrapAppKey(env.hdr.AppKey)
        if uerr == nil {
            if pt, berr := npvsOpenBody(dek, env.nonce, env.body, env.headerRaw); berr == nil {
                decoded := decodeNpvSentinels(string(npvsPlaintext(pt))) // 🆕 decompress هم چک می‌شود
                res.URIs = regexExtractFromText(decoded)
                if len(res.URIs) > 0 {
                    return res, nil, false
                }
                if debugModeEnabled() {
                    res.Raw = append(res.Raw, npvsDebugInfo([]byte(decoded)))
                } else {
                    res.Raw = append(res.Raw, npvsNoLinkMessage())
                }
                return res, nil, false
            } else {
                // 🐞 unwrap موفق ولی body باز نشد → دیباگ به تلگرام
                dbg := fmt.Sprintf(
                    "🐞 NPVS DEBUG (body)\n━━━━━━━━━━━━━━\nnonceLen=%d bodyLen=%d aadLen=%d\nerr=%v",
                    len(env.nonce), len(env.body), len(env.headerRaw), berr)
                log.Printf("[NPVS] %s", dbg)
                reply(chatID, dbg)
            }
        } else {
            // 🐞 unwrap نشد → جزئیات wrap به تلگرام
            saltLen, wrapLen := 0, 0
            if s, e1 := npvsB64URL(env.hdr.AppKey.Salt); e1 == nil {
                saltLen = len(s)
            }
            if w, e2 := npvsB64URL(env.hdr.AppKey.Wrap); e2 == nil {
                wrapLen = len(w)
            }
            dbg := fmt.Sprintf(
                "🐞 NPVS DEBUG (appKey)\n━━━━━━━━━━━━━━\nkdf=%s\nkeyId=%d\nsaltLen=%d wrapLen=%d\ntlastVariants=%d\nerr=%v",
                env.hdr.AppKey.Kdf, env.hdr.AppKey.KeyID, saltLen, wrapLen,
                len(wbTlastVariants), uerr)
            log.Printf("[NPVS] %s", dbg)
            reply(chatID, dbg)
        }
    }

    var sb strings.Builder
    sb.WriteString("🔧 " + npvsEngine + "\n")
    sb.WriteString(fmt.Sprintf("Config ID: %s\n", env.hdr.ConfigID))
    if env.hdr.Policy.DisplayMessage != "" {
        sb.WriteString("💬 " + env.hdr.Policy.DisplayMessage + "\n")
    }
    if env.hdr.AppKey != nil {
        sb.WriteString("⚠️ قفل appKey باز نشد")
    } else if len(env.hdr.Recipients) > 0 {
        sb.WriteString("🔒 E2E — فقط با کلید خصوصی گیرنده")
    } else {
        sb.WriteString("📡 شناسه ارجاع")
    }
    res.Raw = append(res.Raw, sb.String())
    return res, nil, false
}

func tryNPVSPassphrase(fileData []byte, password string) (*processResult, error) {
    env, err := parseNpvsEnvelope(fileData)
    if err != nil {
        return nil, err
    }
    if env.hdr.Passphrase == nil {
        return nil, fmt.Errorf("این فایل رمز ندارد")
    }

    attempts := []string{
        password,
        strings.TrimSpace(password),
        strings.Join(strings.Fields(password), ""),
        strings.ToUpper(strings.Join(strings.Fields(password), "")),
        strings.ToLower(strings.Join(strings.Fields(password), "")),
    }
    seen := map[string]bool{}
    var dek []byte
    for _, pwd := range attempts {
        if pwd == "" || seen[pwd] {
            continue
        }
        seen[pwd] = true
        if d, uerr := npvsUnwrapPassphrase(env.hdr.Passphrase, pwd); uerr == nil {
            dek = d
            break
        }
    }
    if dek == nil {
        // 🐞 جزئیات wrap در پیام «رمز اشتباه» → تشخیص آسان
        pw := env.hdr.Passphrase
        saltLen, wrapLen := 0, 0
        if s, e1 := npvsB64URL(pw.Salt); e1 == nil {
            saltLen = len(s)
        }
        if w, e2 := npvsB64URL(pw.Wrap); e2 == nil {
            wrapLen = len(w)
        }
        return nil, fmt.Errorf(
            "🔑 رمز اشتباه — دوباره رمز را بفرستید\n🐞 kdf=%s iters=%d saltLen=%d wrapLen=%d",
            pw.Kdf, pw.Iters, saltLen, wrapLen)
    }

    pt, err := npvsOpenBody(dek, env.nonce, env.body, env.headerRaw)
    if err != nil {
        return nil, fmt.Errorf("%v\n🐞 nonceLen=%d bodyLen=%d aadLen=%d",
            err, len(env.nonce), len(env.body), len(env.headerRaw))
    }

    decoded := decodeNpvSentinels(string(npvsPlaintext(pt))) // 🆕 decompress هم چک می‌شود

    res := &processResult{}
    res.URIs = regexExtractFromText(decoded)
    if len(res.URIs) == 0 {
        if debugModeEnabled() {
            res.Raw = append(res.Raw, npvsDebugInfo([]byte(decoded)))
        } else {
            res.Raw = append(res.Raw, npvsNoLinkMessage())
        }
    }
    return res, nil
}
