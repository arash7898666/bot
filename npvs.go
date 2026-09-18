package main

import (
    "bytes"
    "compress/flate"
    "compress/gzip"
    "compress/zlib"
    "crypto/aes"
    "crypto/cipher"
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
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/chacha20"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/pbkdf2"
)

const npvsWrapSize = 60
const npvsEngine = "NPVS Engine v5.4"

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

// ═══════════════════ 🐞 دیباگ ═══════════════════

type npvsParseError struct {
    msg   string
    debug string
}

func (e *npvsParseError) Error() string { return e.msg + "\n\n" + e.debug }

func npvsEnvelopeHollow(e *npvsEnvelope) bool {
    return e.hdr.ConfigID == "" && e.hdr.Passphrase == nil &&
        e.hdr.AppKey == nil && len(e.hdr.Recipients) == 0
}

func npvsAsciiRuns(b []byte, minLen, maxRuns int) []string {
    var runs []string
    start := -1
    for i := 0; i <= len(b); i++ {
        if i < len(b) && b[i] >= 0x20 && b[i] < 0x7f {
            if start < 0 {
                start = i
            }
        } else {
            if start >= 0 && i-start >= minLen {
                runs = append(runs, fmt.Sprintf("@0x%x: %q", start, string(b[start:i])))
                if len(runs) >= maxRuns {
                    return runs
                }
            }
            start = -1
        }
    }
    return runs
}

func npvsDebugDump(b []byte) string {
    ver, hdrLen := -1, -1
    if len(b) >= 9 {
        ver = int(b[4])
        hdrLen = int(binary.BigEndian.Uint32(b[5:9]))
    }
    var sb strings.Builder
    sb.WriteString("🐞 NPVS DEBUG\n━━━━━━━━━━━━━━\n")
    fmt.Fprintf(&sb, "size=%d ver=%d hdrLen=%d\n", len(b), ver, hdrLen)

    if hdrLen > 2 && 9+hdrLen <= len(b) {
        hdr := b[9 : 9+hdrLen]
        pr := 0
        for _, c := range hdr {
            if c >= 0x20 && c < 0x7f {
                pr++
            }
        }
        fmt.Fprintf(&sb, "header printable=%.0f%% (≈37%% = encrypted)\n",
            100*float64(pr)/float64(len(hdr)))

        off := 9 + hdrLen
        if off+16 <= len(b) {
            bodyLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
            expect := len(b) - 9 - hdrLen - 16 - 64
            fmt.Fprintf(&sb, "nonce@%d bodyLen=%d (expected=%d) exactFit=%v\n",
                off, bodyLen, expect, off+16+bodyLen+64 == len(b))
        }
        if 9+96 <= len(b) {
            sb.WriteString("hdr[0:96]:\n" + hex.EncodeToString(b[9:9+96]) + "\n")
        }
    }

    sb.WriteString("ascii-runs(≥6):\n")
    for _, r := range npvsAsciiRuns(b, 6, 40) {
        sb.WriteString("  " + r + "\n")
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

func sendNPVSDebugDump(chatID int64, data []byte) {
    doc := tgbotapi.NewDocument(chatID, tgbotapi.FileBytes{
        Name:  "npvs_v5_dump.txt",
        Bytes: []byte(npvsHexdump(data, 32)),
    })
    if _, err := bot.Send(doc); err != nil {
        log.Printf("[NPVS] send dump failed: %v", err)
    }
}

// ═══════════════════ decompress / انکودینگ هدر ═══════════════════

func npvsTryDecompress(b []byte) ([]byte, bool) {
    if len(b) < 2 {
        return nil, false
    }
    limit := int64(8 << 20)

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

func npvsHeaderJSON(raw []byte) ([]byte, bool) {
    if json.Valid(raw) {
        return raw, true
    }

    var m map[string]any
    if err := msgpack.Unmarshal(raw, &m); err == nil && len(m) > 0 {
        if jb, jerr := json.Marshal(m); jerr == nil {
            return jb, true
        }
    }
    if len(raw) > 1 {
        var m2 map[string]any
        if err := msgpack.Unmarshal(raw[1:], &m2); err == nil && len(m2) > 0 {
            if jb, jerr := json.Marshal(m2); jerr == nil {
                return jb, true
            }
        }
    }

    for _, off := range []int{1, 2, 4, 8} {
        if len(raw) > off && raw[off] == '{' && json.Valid(raw[off:]) {
            return raw[off:], true
        }
    }

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

    if len(b) >= 89 && ver <= npvsMaxVersion && hdrLen > 2 && 9+hdrLen < len(b) {
        e := &npvsEnvelope{headerRaw: b[9 : 9+hdrLen]}
        if hdrJSON, ok := npvsHeaderJSON(e.headerRaw); ok {
            if err := json.Unmarshal(hdrJSON, &e.hdr); err == nil && !npvsEnvelopeHollow(e) {
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
                if err := json.Unmarshal(hdrJSON, &e.hdr); err == nil && !npvsEnvelopeHollow(e) {
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

    dbg := npvsDebugDump(b)
    log.Printf("[NPVS] parse failed: ver=%d hdrLen=%d size=%d", ver, hdrLen, len(b))
    msg := "ساختار NPVS شناخته نشد (هدر v5 احتمالاً رمزشده است)"
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

// ═══════════════════ باز کردن قفل‌ها (v1) ═══════════════════

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

// ═══════ v5.4: نقشه + پروب بدون رمز + حمله گسترده ═══════

type npvs5TLV struct {
    ID   int
    Data []byte
}

type npvs5FileMap struct {
    Hdr       []byte
    Salt      []byte
    Nonce32   []byte
    Block     []byte
    BodyNonce []byte
    Body      []byte
    Prelude32 []byte
    Records   []npvs5TLV
}

// نقشه v5 (از hexdump کشف شد):
//   Hdr[0]=ver | Hdr[1:33]=pub32 | Hdr[33:49]=salt16 | Hdr[49..]=TLVها
//   Hdr[100:132]=nonce32 | Hdr[132]=0x23 | Hdr[133:137]=len(4BE)=1049 | Hdr[137:]=بلوک رمز
//   Body = "NPF"+0x01 | prelude32 (Body[4:36]) | count(2BE)=تعداد+1 | رکوردها {id(2BE)|len(4BE)|data}
func npvs5MapFile(f []byte) (*npvs5FileMap, error) {
    if len(f) < 120 || !bytes.HasPrefix(f, []byte("NPVS")) {
        return nil, fmt.Errorf("فایل NPVS نیست")
    }
    hdrLen := int(binary.BigEndian.Uint32(f[5:9]))
    if hdrLen < 137 || 9+hdrLen+16 > len(f) {
        return nil, fmt.Errorf("فریمینگ v5 نامعتبر: hdrLen=%d", hdrLen)
    }
    m := &npvs5FileMap{Hdr: f[9 : 9+hdrLen]}
    m.Salt = m.Hdr[33:49]
    m.Nonce32 = m.Hdr[100:132]
    declared := int(binary.BigEndian.Uint32(m.Hdr[133:137]))
    if declared >= 17 && 137+declared <= len(m.Hdr) {
        m.Block = m.Hdr[137 : 137+declared]
    } else {
        m.Block = m.Hdr[137:]
    }
    off := 9 + hdrLen
    m.BodyNonce = f[off : off+12]
    bodyLen := int(binary.BigEndian.Uint32(f[off+12 : off+16]))
    off += 16
    if bodyLen < 16 || off+bodyLen > len(f) {
        bodyLen = len(f) - off
    }
    m.Body = f[off : off+bodyLen]
    if bytes.HasPrefix(m.Body, []byte("NPF")) && len(m.Body) >= 44 {
        m.Prelude32 = m.Body[4:36]
        roff := 38
        for roff+6 <= len(m.Body) {
            id := int(binary.BigEndian.Uint16(m.Body[roff : roff+2]))
            ln := int(binary.BigEndian.Uint32(m.Body[roff+2 : roff+6]))
            if id <= 0 || id > 0x4000 || ln <= 0 || roff+6+ln > len(m.Body) {
                break
            }
            m.Records = append(m.Records, npvs5TLV{ID: id, Data: m.Body[roff+6 : roff+6+ln]})
            roff += 6 + ln
        }
    }
    return m, nil
}

func npvs5min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func npvs5Analyze(m *npvs5FileMap) string {
    var sb strings.Builder
    sb.WriteString("🗺️ نقشه v5:\n")
    fmt.Fprintf(&sb, "  salt=%x…\n", m.Salt[:6])
    if len(m.Nonce32) >= 8 {
        fmt.Fprintf(&sb, "  nonce32=%x…\n", m.Nonce32[:8])
    }
    if len(m.Prelude32) >= 8 {
        fmt.Fprintf(&sb, "  prelude32=%x…\n", m.Prelude32[:8])
    }
    fmt.Fprintf(&sb, "  block=%d بایت | NPF=%v | records=%d\n",
        len(m.Block), bytes.HasPrefix(m.Body, []byte("NPF")), len(m.Records))
    for i, r := range m.Records {
        if i >= 12 {
            fmt.Fprintf(&sb, "  … و %d رکورد دیگر\n", len(m.Records)-12)
            break
        }
        fmt.Fprintf(&sb, "  rec id=0x%04x len=%d\n", r.ID, len(r.Data))
    }
    return sb.String()
}

// ─── ابزارهای رمز ───

var npvs5IterCandidates = []int{600000, 310000, 100000, 10000, 1000, 100, 9, 1}

func npvsAesGcmOpen(key, nonce, ct, aad []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    return gcm.Open(nil, nonce, ct, aad)
}

func npvsAesCTRStream(key, iv, ct []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    out := make([]byte, len(ct))
    cipher.NewCTR(block, iv).XORKeyStream(out, ct)
    return out, nil
}

func npvsChacha20Stream(key, nonce, ct []byte) ([]byte, error) {
    s, err := chacha20.NewUnauthenticatedCipher(key, nonce)
    if err != nil {
        return nil, err
    }
    out := make([]byte, len(ct))
    s.XORKeyStream(out, ct)
    return out, nil
}

// تشخیص متن کانفیگ — برای مسیرهای بدون تگ (CTR) سخت‌گیرانه است
func npvs5LikelyConfig(pt []byte) bool {
    if len(pt) < 12 {
        return false
    }
    pr := 0
    for _, c := range pt {
        if (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t' {
            pr++
        }
    }
    if float64(pr)/float64(len(pt)) < 0.95 {
        return false
    }
    s := strings.ToLower(string(pt))
    return strings.Contains(s, `"`) || strings.Contains(s, "{") ||
        strings.Contains(s, "vless") || strings.Contains(s, "vmess") ||
        strings.Contains(s, "trojan") || strings.Contains(s, "ss:")
}

type npvs5Key struct {
    name string
    key  []byte
}

// کش KDF — PBKDF2/Argon2 سنگین هستند
var npvs5KdfCache sync.Map

func npvs5DeriveKeys(pass string, salt []byte) []npvs5Key {
    ck := pass + "\x00" + hex.EncodeToString(salt)
    if v, ok := npvs5KdfCache.Load(ck); ok {
        return v.([]npvs5Key)
    }
    var out []npvs5Key
    pw := []byte(pass)
    mk := func(name string, b []byte) { out = append(out, npvs5Key{name, b}) }

    h := sha256.Sum256(append(append([]byte{}, pw...), salt...))
    mk("sha256(pw|salt)", h[:])
    h = sha256.Sum256(append(append([]byte{}, salt...), pw...))
    mk("sha256(salt|pw)", h[:])
    h = sha256.Sum256(pw)
    mk("sha256(pw)", h[:])

    for _, it := range npvs5IterCandidates {
        mk(fmt.Sprintf("pbkdf2-%d", it), pbkdf2.Key(pw, salt, it, 32, sha256.New))
    }
    mk("argon2id-t1", argon2.IDKey(pw, salt, 1, 64*1024, 4, 32))
    mk("argon2id-t3", argon2.IDKey(pw, salt, 3, 64*1024, 4, 32))

    npvs5KdfCache.Store(ck, out)
    return out
}

// ─── کاندیدهای salt و nonce (بر اساس نقشه) ───

type npvs5Blob struct {
    name string
    data []byte
}

func npvs5SaltCandidates(m *npvs5FileMap) []npvs5Blob {
    out := []npvs5Blob{{"salt16", m.Salt}}
    if len(m.Prelude32) == 32 {
        out = append(out,
            npvs5Blob{"prelude32", m.Prelude32},
            npvs5Blob{"pre32[:16]", m.Prelude32[:16]})
    }
    if len(m.Hdr) >= 98 {
        out = append(out, npvs5Blob{"hdr64[:16]", m.Hdr[64:80]})
    }
    if len(m.Nonce32) >= 16 {
        out = append(out, npvs5Blob{"n32[:16]", m.Nonce32[:16]})
    }
    if len(m.BodyNonce) == 12 {
        out = append(out, npvs5Blob{"bodyNonce", m.BodyNonce})
    }
    return out
}

func npvs5NonceCandidates(m *npvs5FileMap) []npvs5Blob {
    out := []npvs5Blob{{"zero", make([]byte, 12)}}
    if len(m.BodyNonce) == 12 {
        out = append(out, npvs5Blob{"bodyNonce", m.BodyNonce})
    }
    if len(m.Prelude32) == 32 {
        out = append(out,
            npvs5Blob{"pre[0:12]", m.Prelude32[0:12]},
            npvs5Blob{"pre[10:22]", m.Prelude32[10:22]},
            npvs5Blob{"pre[16:28]", m.Prelude32[16:28]},
            npvs5Blob{"pre[20:32]", m.Prelude32[20:32]})
    }
    if len(m.Nonce32) >= 32 {
        out = append(out,
            npvs5Blob{"n32[0:12]", m.Nonce32[0:12]},
            npvs5Blob{"n32[8:20]", m.Nonce32[8:20]},
            npvs5Blob{"n32[20:32]", m.Nonce32[20:32]})
    }
    if len(m.Block) >= 12 {
        out = append(out, npvs5Blob{"block[0:12]", m.Block[:12]})
    }
    return out
}

// ─── باز کردن بلوک هدر با رمز ───
// ⚠️ دیگر گیت plausibility نداریم: تگ AEAD خودش صحت را تضمین می‌کند
// (باگ v5.3: محتوای باینری سفارشی رد می‌شد!)
func npvs5OpenBlock(pass string, m *npvs5FileMap) ([]byte, []byte, string) {
    for _, sc := range npvs5SaltCandidates(m) {
        keys := npvs5DeriveKeys(pass, sc.data)
        for _, k := range keys {
            // حالت A: Block = nonce12 + ct
            if len(m.Block) >= 28 {
                for _, ad := range [][]byte{nil, m.Hdr[:49], m.Hdr[:100], m.Hdr[:133], m.Hdr[:137], m.Hdr, m.Prelude32} {
                    if pt, err := npvsChachaOpen(k.key, m.Block[:12], m.Block[12:], ad); err == nil {
                        return pt, k.key, sc.name + "/" + k.name + "|chacha|block-nonce"
                    }
                    if pt, err := npvsAesGcmOpen(k.key, m.Block[:12], m.Block[12:], ad); err == nil {
                        return pt, k.key, sc.name + "/" + k.name + "|aesgcm|block-nonce"
                    }
                }
            }
            // حالت B: Block کامل = ct با nonce کاندید
            for _, nc := range npvs5NonceCandidates(m) {
                for _, ad := range [][]byte{nil, m.Hdr[:49], m.Hdr[:100], m.Hdr[:133], m.Hdr[:137], m.Hdr} {
                    if pt, err := npvsChachaOpen(k.key, nc.data, m.Block, ad); err == nil {
                        return pt, k.key, sc.name + "/" + k.name + "|chacha|" + nc.name
                    }
                    if pt, err := npvsAesGcmOpen(k.key, nc.data, m.Block, ad); err == nil {
                        return pt, k.key, sc.name + "/" + k.name + "|aesgcm|" + nc.name
                    }
                }
            }
            // حالت C: XChaCha با ۲۴ بایت از nonce32
            if len(m.Nonce32) >= 24 {
                if xa, err := chacha20poly1305.NewX(k.key); err == nil {
                    for _, n := range [][]byte{m.Nonce32[:24], m.Nonce32[8:32]} {
                        for _, ad := range [][]byte{nil, m.Hdr[:100], m.Hdr} {
                            if pt, err := xa.Open(nil, n, m.Block, ad); err == nil {
                                return pt, k.key, sc.name + "/" + k.name + "|xchacha"
                            }
                        }
                    }
                }
            }
        }
    }
    return nil, nil, ""
}

func npvs5FindDek(pt []byte) []byte {
    var m map[string]any
    if err := json.Unmarshal(pt, &m); err != nil {
        return nil
    }
    for _, k := range []string{"dek", "cek", "key", "dekHex", "contentKey"} {
        if v, ok := m[k].(string); ok && v != "" {
            if b, err := hex.DecodeString(v); err == nil && len(b) == 32 {
                return b
            }
            if b, err := npvsB64URL(v); err == nil && len(b) == 32 {
                return b
            }
        }
    }
    return nil
}

func npvsOpenBodyMulti(dek, nonce, body []byte, extraAads [][]byte) ([]byte, error) {
    if len(body) < 16 {
        return nil, fmt.Errorf("بدنه ناقص")
    }
    bodies := [][]byte{body}
    if len(body) > 68 {
        bodies = append(bodies, body[:len(body)-64])
    }
    if len(body) > 20 {
        bodies = append(bodies, body[4:])
    }
    nonces := [][]byte{}
    if len(nonce) == 12 {
        nonces = append(nonces, nonce)
    }
    var zero12 [12]byte
    nonces = append(nonces, zero12[:])
    aads := append([][]byte{nil}, extraAads...)
    for _, n := range nonces {
        for _, ct := range bodies {
            for _, ad := range aads {
                if pt, err := npvsChachaOpen(dek, n, ct, ad); err == nil {
                    return pt, nil
                }
                if pt, err := npvsAesGcmOpen(dek, n, ct, ad); err == nil {
                    return pt, nil
                }
            }
        }
    }
    return nil, fmt.Errorf("بدنه باز نشد")
}

// ─── موتور اسکیمای رکوردها: با هر لیست کلیدی امتحان می‌کند ───

func npvs5TryRecordSchemes(keys []npvs5Key, m *npvs5FileMap) (string, string) {
    if len(m.Records) == 0 {
        return "", ""
    }
    nTest := npvs5min(3, len(m.Records))

    tryOpen := func(key, nonce, ct, ad []byte) ([]byte, bool) {
        if len(ct) < 16 || len(nonce) != 12 {
            return nil, false
        }
        // تگ AEAD = تضمین صحت؛ بدون شرط اضافه
        if pt, err := npvsChachaOpen(key, nonce, ct, ad); err == nil {
            return pt, true
        }
        if pt, err := npvsAesGcmOpen(key, nonce, ct, ad); err == nil {
            return pt, true
        }
        // بدون تگ → تشخیص سخت‌گیرانه متن
        if pt, err := npvsChacha20Stream(key, nonce, ct); err == nil && npvs5LikelyConfig(pt) {
            return pt, true
        }
        return nil, false
    }

    idAad := func(id int) []byte { return []byte{byte(id >> 8), byte(id)} }
    nonces := npvs5NonceCandidates(m)
    collect := func(run func(r npvs5TLV) ([]byte, bool)) (string, int) {
        var sb strings.Builder
        ok := 0
        for _, r := range m.Records {
            if pt, hit := run(r); hit {
                ok++
                sb.Write(pt)
                sb.WriteString("\n")
            }
        }
        return sb.String(), ok
    }

    // ۱) اسکیمای ثابت: کلید/nonce/AAD یکسان برای همه
    for _, k := range keys {
        for _, nc := range nonces {
            for _, useID := range []bool{false, true} {
                hits := 0
                for _, r := range m.Records[:nTest] {
                    ad := []byte(nil)
                    if useID {
                        ad = idAad(r.ID)
                    }
                    if _, ok := tryOpen(k.key, nc.data, r.Data, ad); ok {
                        hits++
                    }
                }
                if hits >= nTest-1 && hits > 0 {
                    txt, okCount := collect(func(r npvs5TLV) ([]byte, bool) {
                        ad := []byte(nil)
                        if useID {
                            ad = idAad(r.ID)
                        }
                        return tryOpen(k.key, nc.data, r.Data, ad)
                    })
                    if okCount > 0 {
                        name := k.name + "/" + nc.name
                        if useID {
                            name += "/aad=id"
                        }
                        return txt, fmt.Sprintf("%s: %d/%d", name, okCount, len(m.Records))
                    }
                }
            }
        }
    }

    // ۲) nonce مشتق از شناسه رکورد
    idNonce := func(id int, layout int) []byte {
        n := make([]byte, 12)
        be := []byte{byte(id >> 8), byte(id)}
        switch layout {
        case 0:
            copy(n[4:6], be)
        case 1:
            copy(n[10:12], be)
        case 2:
            copy(n[0:2], be)
        case 3:
            copy(n[8:10], be)
        }
        return n
    }
    for _, k := range keys {
        for layout := 0; layout < 4; layout++ {
            hits := 0
            for _, r := range m.Records[:nTest] {
                if _, ok := tryOpen(k.key, idNonce(r.ID, layout), r.Data, nil); ok {
                    hits++
                }
            }
            if hits >= nTest-1 && hits > 0 {
                txt, okCount := collect(func(r npvs5TLV) ([]byte, bool) {
                    return tryOpen(k.key, idNonce(r.ID, layout), r.Data, nil)
                })
                if okCount > 0 {
                    return txt, fmt.Sprintf("%s/id-nonce-%d: %d/%d", k.name, layout, okCount, len(m.Records))
                }
            }
        }
    }

    // ۳) هر رکورد: data = nonce12 + ct
    for _, k := range keys {
        hits := 0
        for _, r := range m.Records[:nTest] {
            if len(r.Data) >= 28 {
                if _, ok := tryOpen(k.key, r.Data[:12], r.Data[12:], nil); ok {
                    hits++
                }
            }
        }
        if hits >= nTest-1 && hits > 0 {
            txt, okCount := collect(func(r npvs5TLV) ([]byte, bool) {
                if len(r.Data) < 28 {
                    return nil, false
                }
                return tryOpen(k.key, r.Data[:12], r.Data[12:], nil)
            })
            if okCount > 0 {
                return txt, fmt.Sprintf("%s/per-rec-nonce: %d/%d", k.name, okCount, len(m.Records))
            }
        }
    }

    // ۴) استریم یکپارچه (بدون تگ): داده رکوردها پشت سر هم
    var stream []byte
    for _, r := range m.Records {
        stream = append(stream, r.Data...)
    }
    for _, k := range keys {
        for _, nc := range nonces {
            if pt, err := npvsChacha20Stream(k.key, nc.data, stream); err == nil && npvs5LikelyConfig(pt) {
                return string(pt), "STREAM " + k.name + "/" + nc.name
            }
            if pt, err := npvsAesCTRStream(k.key, nc.data, stream); err == nil && npvs5LikelyConfig(pt) {
                return string(pt), "STREAM-CTR " + k.name + "/" + nc.name
            }
        }
    }

    return "", ""
}

// 🔍 پروب بدون رمز: کلیدهای داخل خود فایل (prelude32 و ...)
func npvs5ProbeBody(m *npvs5FileMap) (string, string) {
    if len(m.Records) == 0 {
        return "", ""
    }
    var keys []npvs5Key
    if len(m.Prelude32) == 32 {
        keys = append(keys, npvs5Key{"prelude32", m.Prelude32})
        s := sha256.Sum256(m.Prelude32)
        keys = append(keys, npvs5Key{"sha(pre32)", s[:]})
    }
    if len(m.Nonce32) == 32 {
        keys = append(keys, npvs5Key{"nonce32", m.Nonce32})
        s := sha256.Sum256(m.Nonce32)
        keys = append(keys, npvs5Key{"sha(n32)", s[:]})
    }
    if len(m.Hdr) >= 33 {
        keys = append(keys, npvs5Key{"pub32", m.Hdr[1:33]})
        s := sha256.Sum256(m.Hdr[1:33])
        keys = append(keys, npvs5Key{"sha(pub32)", s[:]})
    }
    s := sha256.Sum256(m.BodyNonce)
    keys = append(keys, npvs5Key{"sha(bodyNonce)", s[:]})
    return npvs5TryRecordSchemes(keys, m)
}

func npvs5BuildResult(pt []byte) *processResult {
    decoded := decodeNpvSentinels(string(npvsPlaintext(pt)))
    res := &processResult{}
    res.URIs = regexExtractFromText(decoded)
    if len(res.URIs) == 0 {
        if debugModeEnabled() {
            res.Raw = append(res.Raw, npvsDebugInfo([]byte(decoded)))
        } else {
            res.Raw = append(res.Raw, npvsNoLinkMessage())
        }
    }
    return res
}

func npvs5Attack(fileData []byte, password string) (*processResult, error) {
    m, err := npvs5MapFile(fileData)
    if err != nil {
        return nil, err
    }

    // 🔍 قدم ۱: پروب بدون رمز
    if txt, how := npvs5ProbeBody(m); txt != "" {
        log.Printf("[NPVS5] probe (no-pass) SUCCESS: %s", how)
        return npvs5BuildResult([]byte(txt)), nil
    }

    // 🔑 قدم ۲: حمله به بلوک هدر با رمز
    pwVariants := []string{
        strings.TrimSpace(password),
        strings.ReplaceAll(strings.TrimSpace(password), "-", ""),
    }
    var pt, key []byte
    var how string
    for i, pwd := range pwVariants {
        if pwd == "" {
            continue
        }
        if p, k, h := npvs5OpenBlock(pwd, m); p != nil {
            pt, key, how = p, k, fmt.Sprintf("%s (pw#%d)", h, i+1)
            break
        }
    }

    var dek []byte
    if pt != nil {
        log.Printf("[NPVS5] header block opened: %s", how)
        var inner npvsHeader
        if err := json.Unmarshal(pt, &inner); err != nil {
            var mm map[string]any
            if err2 := msgpack.Unmarshal(pt, &mm); err2 == nil {
                if jb, jerr := json.Marshal(mm); jerr == nil {
                    _ = json.Unmarshal(jb, &inner)
                }
            }
        }
        if inner.Passphrase != nil {
            if d, e := npvsUnwrapPassphrase(inner.Passphrase, pwVariants[0]); e == nil {
                dek = d
            }
        }
        if dek == nil && inner.AppKey != nil {
            if d, e := npvsUnwrapAppKey(inner.AppKey); e == nil {
                dek = d
            }
        }
        if dek == nil {
            dek = npvs5FindDek(pt)
        }
        if dek == nil {
            dek = key
        }
    }

    if dek != nil {
        // قدم ۳: رکوردها با dek + کلیدهای مشتق از رمز روی همه salt ها
        keys := []npvs5Key{{"dek", dek}}
        if len(pwVariants) > 0 && pwVariants[0] != "" {
            for _, sc := range npvs5SaltCandidates(m) {
                for _, k := range npvs5DeriveKeys(pwVariants[0], sc.data) {
                    keys = append(keys, npvs5Key{sc.name + "/" + k.name, k.key})
                }
            }
        }
        if txt, how2 := npvs5TryRecordSchemes(keys, m); txt != "" {
            log.Printf("[NPVS5] records: %s", how2)
            return npvs5BuildResult([]byte(txt)), nil
        }
        if p2, e2 := npvsOpenBodyMulti(dek, m.BodyNonce, m.Body, [][]byte{nil, m.Hdr}); e2 == nil {
            res := npvs5BuildResult(p2)
            if len(res.URIs) > 0 {
                return res, nil
            }
        }
    }

    if pt != nil {
        log.Printf("[NPVS5] fail after header open: %s\n%s", how, npvs5Analyze(m))
        return nil, fmt.Errorf(
            "🐞 هدر باز شد (%s) ولی رکوردها با هیچ اسکیمایی باز نشدند\n%s\nPT[0:160]: %s",
            how, npvs5Analyze(m), debugPreview(string(pt), 160))
    }
    log.Printf("[NPVS5] block open failed:\n%s", npvs5Analyze(m))
    return nil, fmt.Errorf(
        "🔑 بلوک هدر با این رمز باز نشد\n%s\n🐞 ترکیب‌ها: ۶ salt × ۱۱ KDF × ~۱۲ nonce × چند AAD × ۲ AEAD + XChaCha + پروب بدون رمز",
        npvs5Analyze(m))
}

// ═══════════════════ نقطه ورود ═══════════════════

func handleNPVS(data []byte, chatID int64) (*processResult, error, bool) {
    env, err := parseNpvsEnvelope(data)
    if err != nil {
        sendNPVSDebugDump(chatID, data)
        ver := -1
        if len(data) >= 5 {
            ver = int(data[4])
        }
        if ver >= 2 && ver <= npvsMaxVersion && bytes.HasPrefix(data, []byte("NPVS")) {
            // 🔍 اول پروب بدون رمز — شاید اصلاً رمز نخواهد!
            if m, merr := npvs5MapFile(data); merr == nil {
                if txt, how := npvs5ProbeBody(m); txt != "" {
                    log.Printf("[NPVS5] probe (no-pass) SUCCESS: %s", how)
                    return npvs5BuildResult([]byte(txt)), nil, false
                }
            }
            setPendingPass(chatID, "npvs", data)
            reply(chatID, "🔐 فایل NPVS v5 — هدر رمزشده است.\n🔑 رمز (Key) را بفرستید:\n\n"+err.Error())
            return nil, nil, true
        }
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
                decoded := decodeNpvSentinels(string(npvsPlaintext(pt)))
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
                dbg := fmt.Sprintf(
                    "🐞 NPVS DEBUG (body)\n━━━━━━━━━━━━━━\nnonceLen=%d bodyLen=%d aadLen=%d\nerr=%v",
                    len(env.nonce), len(env.body), len(env.headerRaw), berr)
                log.Printf("[NPVS] %s", dbg)
                reply(chatID, dbg)
            }
        } else {
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
        if bytes.HasPrefix(fileData, []byte("NPVS")) && len(fileData) >= 5 && fileData[4] >= 2 {
            return npvs5Attack(fileData, password)
        }
        return nil, err
    }
    if env.hdr.Passphrase == nil {
        return nil, fmt.Errorf("این فایل رمز ندارد")
    }

    noDash := strings.ReplaceAll(password, "-", "")
    attempts := []string{
        password,
        strings.TrimSpace(password),
        strings.Join(strings.Fields(password), ""),
        noDash,
        strings.ToUpper(noDash),
        strings.ToLower(noDash),
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

    decoded := decodeNpvSentinels(string(npvsPlaintext(pt)))

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
