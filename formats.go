package main

import (
    "bytes"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "log"
    "net/url"
    "regexp"
    "strings"
    "sync"
    "unicode/utf16"

    "github.com/vmihailenco/msgpack/v5"
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/pbkdf2"
)

// ═══════════════════════════════════════════════════════════════
//  formats.go — SlipNet • NetMod • HAT • Happ • EHI • DarkTunnel
// ═══════════════════════════════════════════════════════════════

// ─────────────── تشخیص لینک + پاک‌سازی کاراکترهای نامرئی ───────────────

var (
    slipnetLinkRe = regexp.MustCompile(`(?:slipnet-bundle-enc|slipnet-enc|slipnet)://[A-Za-z0-9+/=\-_]+`)
    happLinkRe    = regexp.MustCompile(`happ://[^\s"']+`)
    nmLinkRe      = regexp.MustCompile(`nm-[a-z]+://[A-Za-z0-9+/=\-_]+`)
)

var invisibleRe = regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{200E}\x{200F}\x{202A}\x{202B}\x{202C}\x{202D}\x{202E}\x{2066}\x{2067}\x{2068}\x{2069}\x{FEFF}]`)

func cleanInvisible(s string) string {
    return invisibleRe.ReplaceAllString(s, "")
}

// 🆕 debugHeadNPVT — هلپر دیباگ (مشترک با main.go)
func debugHeadNPVT(s string, n int) string {
    s = strings.TrimSpace(s)
    if len(s) > n {
        s = s[:n]
    }
    s = strings.ReplaceAll(s, "\n", "⏎")
    s = strings.ReplaceAll(s, "\r", "")
    return s
}

// 🆕 نسخه جدید: NPVS رو هم هندل می‌کنه + لاگ مسیریابی
func processRouted(data []byte, ext string, chatID int64) (*processResult, error, bool) {
    // 🆕 دیباگ مسیریابی — ببینیم فایل واقعاً چیست
    if len(data) > 16 {
        head := data[:16]
        log.Printf("[ROUTE] ext=%q size=%d head=%x | text_head=%q",
            ext, len(data), head, debugHeadNPVT(string(data), 60))
    }

    switch ext {
    case ".slip":
        return processSlipnet(data, chatID)
    case ".nm":
        res, err := processNetmodContent(data)
        return res, err, false
    case ".hat":
        res, err := processHatContent(data)
        return res, err, false
    case ".happ":
        res, err := processHappContent(data)
        return res, err, false
    case ".ehi", ".ehip":
        res, err := processEHIContent(data)
        return res, err, false
    case ".dark":
        res, err := processDarkContent(data)
        return res, err, false
    case ".npvs":
        return handleNPVS(data, chatID)
    }

    text := cleanInvisible(string(data))

    // تشخیص NPVS در متن (هر جای متن)
    if strings.Contains(text, "NPVS") {
        log.Printf("[ROUTE] NPVS detected in text (ext=%q)", ext)
        return handleNPVS(data, chatID)
    }

    if m := slipnetLinkRe.FindString(text); m != "" {
        return processSlipnet([]byte(m), chatID)
    }
    if m := happLinkRe.FindString(text); m != "" {
        if res, err := processHappContent([]byte(m)); err == nil && res != nil {
            return res, nil, false
        }
    }
    if m := nmLinkRe.FindString(text); m != "" {
        if res, err := processNetmodContent([]byte(m)); err == nil && res != nil {
            return res, nil, false
        }
    }

    res, err := processInput([]byte(text))
    return res, err, false
}

// ─────────────── باندل رمزدار SlipNet ───────────────

func trySlipnetBundleDecrypt(bundleData []byte, password string) (*processResult, error) {
    plaintext, err := slipDecryptBundle(bundleData, password)
    if err != nil {
        return nil, err
    }
    res := &processResult{}
    res.Raw = append(res.Raw, parseSlipProfile(plaintext))
    if uri := slipExtractVless(plaintext); uri != "" {
        res.URIs = append(res.URIs, uri)
    }
    if uris := scanPlainURIs([]byte(plaintext)); len(uris) > 0 {
        res.URIs = append(res.URIs, uris...)
    }
    return res, nil
}

// ✅ نسخه جدید: بدون فایل txt — همه پیام
func sendBundleResult(chatID int64, res *processResult) {
    if res == nil || (len(res.URIs) == 0 && len(res.Raw) == 0) {
        reply(chatID, "⚠️ محتوایی استخراج نشد.")
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
    summary := fmt.Sprintf("✅ %d کانفیگ • %d بلوک خام\n🤖 %s", len(res.URIs), len(res.Raw), botVersion)
    reply(chatID, summary)
    replyLines(chatID, lines)
}

// ─────────────── ابزارهای مشترک ───────────────

func decryptAESECBShared(ciphertext, key []byte) ([]byte, error) {
    block, err := aesNewCipher(key)
    if err != nil {
        return nil, err
    }
    if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
        return nil, fmt.Errorf("طول متن رمز با سایز بلک هم‌خوانی ندارد")
    }
    plaintext := make([]byte, len(ciphertext))
    bs := block.BlockSize()
    for start := 0; start < len(ciphertext); start += bs {
        block.Decrypt(plaintext[start:start+bs], ciphertext[start:start+bs])
    }
    return plaintext, nil
}

func aesNewCipher(key []byte) (cipherBlock, error) {
    return newAESBlock(key)
}

// بسته‌بندی crypto/aes — برای جلوگیری از import مستقیم در این فایل
type cipherBlock interface {
    BlockSize() int
    Decrypt(dst, src []byte)
}

func newAESBlock(key []byte) (cipherBlock, error) {
    return aesNewCipherReal(key)
}

// ─────────────── PKCS7 و ابزار ───────────────

func pkcs7UnpadSoft(data []byte, blockSize int) ([]byte, error) {
    if len(data) == 0 || len(data)%blockSize != 0 {
        return nil, fmt.Errorf("invalid padding length")
    }
    padLen := int(data[len(data)-1])
    if padLen >= 1 && padLen <= blockSize {
        valid := true
        for i := len(data) - padLen; i < len(data); i++ {
            if int(data[i]) != padLen {
                valid = false
                break
            }
        }
        if valid {
            return data[:len(data)-padLen], nil
        }
    }
    result := data
    for len(result) > 0 {
        last := result[len(result)-1]
        if last < 32 || last == ' ' {
            result = result[:len(result)-1]
        } else {
            break
        }
    }
    return result, nil
}

func trimNullBytes(data []byte) []byte {
    return []byte(strings.TrimRight(string(data), "\x00"))
}

// ═══════════════════ SlipNet (.slip) ═══════════════════

const (
    slipKeyHex        = "214F052025B2F949605A5429EC3D5FA80C2022C168AD946E68852D447214DBD3"
    slipFormatVersion = 0x01
    slipSaltLen       = 16
    slipIVLen         = 12
    slipPBKDF2Iters   = 600000
    slipKeySize       = 32
)

var slipSchemas = func() map[string][]string {
    extend := func(base []string, extra ...string) []string {
        out := make([]string, 0, len(base)+len(extra))
        out = append(out, base...)
        return append(out, extra...)
    }

    v1 := []string{"Version", "Tunnel Type/Mode", "Name", "Domain", "Resolvers", "AuthMode", "KeepAlive", "CC", "Port", "Host", "GSO"}
    v20 := extend(v1,
        "DNSTT Public Key", "SOCKS Username", "SOCKS Password", "SSH Enabled", "SSH Username",
        "SSH Password", "SSH Port", "Forward DNS thru SSH", "SSH Host", "Use Server DNS",
        "DoH URL", "DNS Transport", "SSH Auth Type", "SSH Private Key (B64)", "SSH Key Passphrase (B64)",
        "Tor Bridge Lines (B64)", "DNSTT Authoritative", "Naive Port", "Naive Username", "Naive Password (B64)",
        "Is Locked", "Lock Password Hash", "Expiration Date", "Allow Sharing", "Bound Device ID",
        "Resolvers Hidden", "Hidden Resolvers", "NoizDNS Stealth", "DNS Payload Size", "SOCKS5 Server Port",
        "VayDNS DNSTT Compat", "VayDNS Record Type", "VayDNS Max Qname Len", "VayDNS RPS", "VayDNS Idle Timeout",
        "VayDNS Keepalive", "VayDNS UDP Timeout", "VayDNS Max Num Labels", "VayDNS Client Id Size",
    )
    v21 := extend(v20,
        "SSH TLS Enabled", "SSH TLS SNI", "SSH HTTP Proxy Host", "SSH HTTP Proxy Port", "SSH HTTP Proxy Custom Host",
        "SSH WS Enabled", "SSH WS Path", "SSH WS Use TLS", "SSH WS Custom Host",
    )
    v22 := extend(v21, "SSH Payload (B64)")
    v24 := extend(v22, "Resolver Mode", "RR Spread Count")
    v25 := extend(v24,
        "VLESS UUID", "VLESS Security", "VLESS Transport", "VLESS WS Path", "CDN IP",
        "CDN Port", "SNI Fragment Enabled", "SNI Fragment Strategy", "SNI Fragment Delay MS", "Legacy SNI (Empty)",
    )
    v27 := extend(v25,
        "CH Padding Enabled", "WS Header Obfuscation", "WS Padding Enabled",
        "SNI Spoof TTL", "Fake Decoy Host", "TCP Max Seg",
    )
    v28 := extend(v27, "VLESS SNI")

    return map[string][]string{
        "1": v1, "20": v20, "21": v21, "22": v22, "23": v24, "24": v24,
        "25": v25, "26": v27, "27": v27, "28": v28,
    }
}()

var slipFieldIndex = func() map[string]map[string]int {
    out := map[string]map[string]int{}
    for ver, schema := range slipSchemas {
        m := make(map[string]int, len(schema))
        for i, label := range schema {
            m[label] = i
        }
        out[ver] = m
    }
    return out
}()

func parseSlipProfile(decryptedText string) string {
    decryptedText = strings.TrimSuffix(decryptedText, "|")
    parts := strings.Split(decryptedText, "|")
    if len(parts) == 0 || parts[0] == "" {
        return "[!] Empty decrypted text"
    }
    verStr := parts[0]
    schema, exists := slipSchemas[verStr]

    var sb strings.Builder
    sb.WriteString(fmt.Sprintf("\n[+] Profile Version: %s\n", verStr))

    for i, value := range parts {
        label := ""
        if exists && i < len(schema) {
            label = schema[i]
        } else {
            label = fmt.Sprintf("Field %d", i)
        }
        displayValue := value
        if displayValue == "" {
            displayValue = "(empty)"
        }
        switch label {
        case "Is Locked", "SSH TLS Enabled", "SSH WS Enabled", "SSH WS Use TLS",
            "SNI Fragment Enabled", "CH Padding Enabled", "WS Header Obfuscation", "WS Padding Enabled":
            if value == "1" {
                displayValue = "🔒 YES"
            } else {
                displayValue = "🔓 NO"
            }
        case "VayDNS DNSTT Compat", "Resolvers Hidden", "GSO", "DNSTT Authoritative",
            "SSH Enabled", "Forward DNS thru SSH", "Use Server DNS", "Allow Sharing", "NoizDNS Stealth":
            if value == "1" {
                displayValue = "✅ TRUE"
            } else {
                displayValue = "❌ FALSE"
            }
        }
        sb.WriteString(fmt.Sprintf("%s: %s\n", label, displayValue))
    }
    return sb.String()
}

func slipField(parts []string, name string) string {
    if len(parts) == 0 {
        return ""
    }
    m, ok := slipFieldIndex[parts[0]]
    if !ok {
        return ""
    }
    i, ok := m[name]
    if !ok || i >= len(parts) {
        return ""
    }
    return strings.TrimSpace(parts[i])
}

func slipExtractVless(plaintext string) string {
    plaintext = strings.TrimSuffix(plaintext, "|")
    parts := strings.Split(plaintext, "|")
    if len(parts) < 2 {
        return ""
    }

    if !strings.EqualFold(slipField(parts, "Tunnel Type/Mode"), "vless") {
        return ""
    }
    uuid := slipField(parts, "VLESS UUID")
    if uuid == "" {
        return ""
    }

    addr := slipField(parts, "CDN IP")
    port := slipField(parts, "CDN Port")
    if addr == "" {
        addr = slipField(parts, "Domain")
    }
    if port == "" {
        port = slipField(parts, "Port")
    }
    if addr == "" || port == "" {
        return ""
    }

    q := url.Values{}

    transport := slipField(parts, "VLESS Transport")
    if transport == "" {
        transport = "tcp"
    }
    q.Set("type", transport)

    security := slipField(parts, "VLESS Security")
    if security == "" {
        security = "none"
    }
    q.Set("security", security)

    domain := slipField(parts, "Domain")

    if transport == "ws" {
        if p := slipField(parts, "VLESS WS Path"); p != "" {
            q.Set("path", p)
        }
        if domain != "" {
            q.Set("host", domain)
        }
    }

    if security == "tls" || security == "reality" {
        sni := slipField(parts, "VLESS SNI")
        if sni == "" {
            sni = domain
        }
        if sni != "" {
            q.Set("sni", sni)
        }
    }

    remarks := slipField(parts, "Name")
    return fmt.Sprintf("vless://%s@%s:%s?%s#%s",
        uuid, formatHost(addr), port, formatQuery(q), cleanRemarks(remarks))
}

var slipAEAD = func() cipherAEAD {
    key, _ := hex.DecodeString(slipKeyHex)
    return newAESGCM(key)
}()

type cipherAEAD interface {
    Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

func slipDecryptBlob(blobStr string) (string, error) {
    data, ok := decodeB64Loose(strings.Join(strings.Fields(blobStr), ""))
    if !ok {
        return "", fmt.Errorf("base64 نامعتبر")
    }
    if len(data) < 13 {
        return "", fmt.Errorf("blob too short")
    }
    plaintext, err := slipAEAD.Open(nil, data[1:13], data[13:], nil)
    if err != nil {
        return "", fmt.Errorf("decryption failed")
    }
    return string(plaintext), nil
}

func slipDecryptBundle(data []byte, password string) (string, error) {
    minRequiredLength := 1 + slipSaltLen + slipIVLen + 16
    if len(data) < minRequiredLength {
        return "", fmt.Errorf("باندل ناقص است")
    }
    if data[0] != slipFormatVersion {
        return "", fmt.Errorf("نسخه پشتیبانی‌نشده: 0x%02x", data[0])
    }
    salt := data[1 : 1+slipSaltLen]
    iv := data[1+slipSaltLen : 1+slipSaltLen+slipIVLen]
    ct := data[1+slipSaltLen+slipIVLen:]

    derivedKey := pbkdf2.Key([]byte(password), salt, slipPBKDF2Iters, slipKeySize, sha256New)
    aesgcm, err := newAESGCM(derivedKey)
    if err != nil {
        return "", err
    }
    plaintext, err := aesgcm.Open(nil, iv, ct, nil)
    if err != nil {
        return "", fmt.Errorf("رمز اشتباه است")
    }
    return string(plaintext), nil
}

func processSlipnet(data []byte, chatID int64) (*processResult, error, bool) {
    text := strings.TrimSpace(string(data))
    for _, p := range []string{"slipnet-bundle-enc://", "slipnet-enc://", "slipnet://"} {
        if strings.HasPrefix(text, p) {
            text = strings.TrimPrefix(text, p)
        }
    }
    text = strings.Join(strings.Fields(text), "")

    res := &processResult{}

    // ۱) رمزگشایی با کلید ثابت
    if plaintext, err := slipDecryptBlob(text); err == nil {
        res.Raw = append(res.Raw, parseSlipProfile(plaintext))
        if uri := slipExtractVless(plaintext); uri != "" {
            res.URIs = append(res.URIs, uri)
        }
        if uris := scanPlainURIs([]byte(plaintext)); len(uris) > 0 {
            res.URIs = append(res.URIs, uris...)
        }
        res.URIs = dedupe(res.URIs)
        return res, nil, false
    }

    // ۲) باندل رمزدار؟ → ربات رمز را می‌خواهد
    if b, ok := decodeB64Loose(text); ok && len(b) >= 1+slipSaltLen+slipIVLen+16 {
        if b[0] == slipFormatVersion {
            setPendingPass(chatID, "slip", b)
            return nil, nil, true
        }
    }

    // ۳) پروفایل ساده (بدون رمزنگاری)
    if b, ok := decodeB64Loose(text); ok {
        s := string(b)
        parts := strings.Split(strings.TrimSuffix(s, "|"), "|")
        if len(parts) > 1 {
            if _, known := slipSchemas[parts[0]]; known {
                res.Raw = append(res.Raw, parseSlipProfile(s))
                if uri := slipExtractVless(s); uri != "" {
                    res.URIs = append(res.URIs, uri)
                }
                return res, nil, false
            }
        }
    }

    return nil, fmt.Errorf("رمزگشایی SlipNet ناموفق بود"), false
}

// ═══════════════════ NetMod (.nm) ═══════════════════

const netmodAesKey = "_netsyna_netmod_"

func processNetmodContent(data []byte) (*processResult, error) {
    text := strings.TrimSpace(string(data))
    if strings.HasPrefix(text, "nm-") {
        if i := strings.Index(text, "://"); i >= 0 {
            text = text[i+3:]
        }
    }
    text = strings.Join(strings.Fields(text), "")

    ciphertext, ok := decodeB64Loose(text)
    if !ok {
        return nil, fmt.Errorf("base64 نامعتبر")
    }
    plaintext, err := decryptAESECBShared(ciphertext, []byte(netmodAesKey))
    if err != nil {
        return nil, err
    }
    plaintext = trimNullBytes(plaintext)
    if !isMostlyPrintable(plaintext) {
        return nil, fmt.Errorf("خروجی رمزگشایی نامعتبر بود")
    }
    res := &processResult{}
    consumeJSONBlob(plaintext, res)
    return res, nil
}

// ═══════════════════ HA Tunnel Plus (.hat) ═══════════════════

const hatImportKey = "8515D40BD04D8C97"

func processHatContent(data []byte) (*processResult, error) {
    text := strings.Join(strings.Fields(strings.TrimSpace(string(data))), "")
    ciphertext, ok := decodeB64Loose(text)
    if !ok {
        return nil, fmt.Errorf("base64 نامعتبر")
    }
    hasher := sha256New()
    hasher.Write([]byte(hatImportKey))
    derivedKey := hasher.Sum(nil)[:16]

    plaintext, err := decryptAESECBShared(ciphertext, derivedKey)
    if err != nil {
        return nil, err
    }
    unpadded, err := pkcs7UnpadSoft(plaintext, aesBlockSize)
    if err != nil {
        return nil, err
    }
    res := &processResult{}
    consumeJSONBlob(unpadded, res)
    return res, nil
}

// ═══════════════════ Happ (.happ) ═══════════════════

var happPKCS1KeysB64 = []string{
    "MIICXwIBAAKBgQCxsS7PUq1biQlVD92rf6eXKr9oG1/SrYx3qWahZP+Jq35m4Wb/Z+mB6eBWrPzJ/zZpZLWLQorcvOKt+sLaCHyH1HLNkti4jlaEQX6x97XgBm8GK08+lLLWquFDhWRNxsrfzJyNdpVopzBRmCJKTc8ObYyPbrv9T35a8Kd5WqjnUwIDAQABAoGBAJoqe85skPPF5U7jwRM2YhUJhZ+xgGWtJR3834pPslWjcLuZ/F7DrRiF7ZnF5FztDCxMsCXuycPSLWl9EulQS5mrL/fnwpK2jVE8O1Em9RsBOOrWwzuZnAuooRIb/8zC0fvH2oGkk60zSKycMe69uvYUDjhvULX2Spjmf9CS9/HhAkEA3I797En/DrpAZz6NM4GqZ1mkH0kEX/kAHLP1lBgYL1kVK455EG/ecJkMJmtK7A+fWw0N0IcxrpYAbbOAo19vjwJBAM4+0MAZ8TIZUk6Rs2gYUo04A6mYUy5MWtRa9pyFIgD71oHDR+1jrnPLqQyCj0tfbZBc1iVgsisJBpocC8sKaf0CQQDRNd3Mxb/nY2p1xJLBmaxezlvsxSEePB4MG/PFXzmJqBF5uHJD0imIWtR4mOt/ka4R+wbwl1zcAzMy28MYtQ0nAkEAuUILWML0uL+uAw01TeerH1aVU52T+h5z6BPdOTMNHD0arWywCzhi13i03JvaAyYw0F/Tq7dz0txEpeFTZopwMQJBANnHbzB87/xTjDQA4/L8sSU8m0vM1nRWmJIaAC94pcM+KDGLnbBhWrvZGy8Zg8vQwNvdvCLvylk0jVTTFqW3ibM=",
}

type happEngine struct {
    privateKeys map[string]*rsaPrivateKey
    linkRegex   *regexp.Regexp
}

var (
    happEngineOnce sync.Once
    happInst       *happEngine
    happInitErr    error
)

func getHappEngine() (*happEngine, error) {
    happEngineOnce.Do(func() {
        p := &happEngine{privateKeys: make(map[string]*rsaPrivateKey)}
        p.linkRegex = regexp.MustCompile(`^(?:happ://)?([^/]+)/(.+)$`)
        versionMap := []string{"crypt", "crypt2", "crypt3", "crypt4"}
        for idx, b64RawKey := range happPKCS1KeysB64 {
            if idx >= len(versionMap) {
                break
            }
            derBytes, err := base64.StdEncoding.DecodeString(b64RawKey)
            if err != nil {
                happInitErr = fmt.Errorf("decode key %d: %w", idx, err)
                return
            }
            priv, err := parseRSAPrivate(derBytes)
            if err != nil {
                happInitErr = fmt.Errorf("parse key %s: %w", versionMap[idx], err)
                return
            }
            p.privateKeys[versionMap[idx]] = priv
        }
        happInst = p
    })
    return happInst, happInitErr
}

func (p *happEngine) decrypt(link string) (string, error) {
    link = strings.TrimSpace(link)
    if link == "" {
        return "", errors.New("لینک خالی است")
    }
    var version, encryptedData string
    if m := p.linkRegex.FindStringSubmatch(link); m != nil {
        version, encryptedData = m[1], m[2]
    } else {
        encryptedData = link
    }
    keysToTry := []string{version, "crypt", "crypt2", "crypt3", "crypt4"}
    for _, kv := range keysToTry {
        if kv == "" {
            continue
        }
        priv, exists := p.privateKeys[kv]
        if !exists || priv == nil {
            continue
        }
        decrypted, err := happDecryptChunks(encryptedData, priv)
        if err == nil {
            return decrypted, nil
        }
    }
    return "", errors.New("رمزگشایی Happ با هیچ کلیدی موفق نشد")
}

func happDecryptChunks(encryptedB64 string, privateKey *rsaPrivateKey) (string, error) {
    if encryptedB64 == "" {
        return "", errors.New("payload خالی است")
    }
    cipherBytes, err := happB64DecodeURLSafe(encryptedB64)
    if err != nil {
        return "", fmt.Errorf("base64: %w", err)
    }
    keySize := rsaKeySize(privateKey)
    if len(cipherBytes)%keySize != 0 {
        return "", errors.New("سایز داده با کلید هم‌خوانی ندارد")
    }
    var plaintext []byte
    for i := 0; i < len(cipherBytes); i += keySize {
        chunk := cipherBytes[i : i+keySize]
        decryptedChunk, err := rsaDecryptPKCS1(privateKey, chunk)
        if err != nil {
            return "", fmt.Errorf("rsa: %w", err)
        }
        plaintext = append(plaintext, decryptedChunk...)
    }
    return string(plaintext), nil
}

func happB64DecodeURLSafe(s string) ([]byte, error) {
    s = strings.ReplaceAll(s, "-", "+")
    s = strings.ReplaceAll(s, "_", "/")
    switch len(s) % 4 {
    case 2:
        s += "=="
    case 3:
        s += "="
    }
    return base64.StdEncoding.DecodeString(s)
}

func processHappContent(data []byte) (*processResult, error) {
    engine, err := getHappEngine()
    if err != nil {
        return nil, err
    }
    plaintext, err := engine.decrypt(strings.TrimSpace(string(data)))
    if err != nil {
        return nil, err
    }
    pt := []byte(plaintext)
    if !isMostlyPrintable(pt) {
        return nil, fmt.Errorf("خروجی رمزگشایی نامعتبر بود")
    }
    res := &processResult{}
    consumeJSONBlob(pt, res)
    return res, nil
}

// ═══════════════════ HTTP Injector (.ehi) ═══════════════════

var (
    ehiL1Key       = []byte{0x7e, 0x12, 0x10, 0xf7, 0xaa, 0xb9, 0x56, 0xf7, 0xa6, 0x68, 0xbd, 0xa6, 0xe5, 0x7f, 0xed, 0xdb, 0x7f, 0x84, 0xad, 0x84, 0x0a, 0xef, 0x8d, 0x27, 0xb1, 0xb9, 0x69, 0x95, 0x9b, 0xe3, 0xab, 0x6c}
    ehiL2KeyStatic = []byte{0xb2, 0xbc, 0x61, 0x7c, 0x32, 0xd8, 0xb9, 0xeb, 0x19, 0x43, 0xa5, 0xff, 0xa8, 0x05, 0x1e, 0xea}
    ehiMasterKey   = []byte("null=V5kU5+FFrY\x00")

    ehiSideIVs = [][]byte{
        {0x22, 0x1d, 0x57, 0x23, 0x49, 0x55, 0x5f, 0x1d, 0x11, 0x21, 0x33, 0x23, 0x6b, 0x1f, 0x4a, 0x3f},
        {0x55, 0x43, 0x49, 0x4c, 0x53, 0x44, 0x3e, 0x3f, 0x4a, 0x6a, 0x45, 0x39, 0x38, 0x4e, 0x77, 0x6a},
        {0x37, 0x4c, 0x25, 0x41, 0x57, 0x5e, 0x4d, 0x53, 0x1a, 0x3c, 0x32, 0x7b, 0x75, 0x43, 0x1e, 0x5f},
    }
    ehiStandardIVs = [][]byte{
        {0x2c, 0x5d, 0x11, 0x47, 0xbb, 0xad, 0x42, 0x2b, 0x3b, 0x33, 0x4d, 0x4d, 0x23, 0x5f, 0x1a, 0x53},
        {0x52, 0x2b, 0x01, 0x43, 0x3a, 0x5e, 0x8b, 0x2f, 0xc7, 0x54, 0x9e, 0x1a, 0xd3, 0x68, 0xe5, 0x41},
        {0x33, 0x7a, 0x10, 0x35, 0xaa, 0xed, 0xf3, 0x45, 0x8c, 0xa1, 0x67, 0x63, 0x2b, 0x75, 0xd8, 0x39},
    }
    ehiAllIVs    = append(append([][]byte{}, ehiSideIVs...), ehiStandardIVs...)
    ehiCustomEnc = base64.NewEncoding("RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs")
)

func ehiReverseString(s string) string {
    b := []byte(s)
    for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
        b[i], b[j] = b[j], b[i]
    }
    return string(b)
}

func ehiCustomB64Decode(encodedStr string) ([]byte, error) {
    cleanStr := strings.ReplaceAll(encodedStr, "?", "")
    if rem := len(cleanStr) % 4; rem != 0 {
        cleanStr += strings.Repeat("=", 4-rem)
    }
    return ehiCustomEnc.DecodeString(cleanStr)
}

func ehiDecryptXorLayer(ciphertextStr string, key string) (string, error) {
    if strings.TrimSpace(ciphertextStr) == "" {
        return ciphertextStr, nil
    }
    reversed := ehiReverseString(ciphertextStr)
    hexBytesRaw, err := ehiCustomB64Decode(reversed)
    if err != nil {
        return "", err
    }
    hexStr := string(hexBytesRaw)
    if len(hexStr)%2 != 0 {
        hexStr = "0" + hexStr
    }
    rawBytes, err := hex.DecodeString(hexStr)
    if err != nil {
        return "", err
    }
    keyLen := len(key)
    decryptedBytes := make([]byte, 0, len(rawBytes))
    for i, b := range rawBytes {
        xorVal := b ^ key[i%keyLen]
        if xorVal != 0 {
            decryptedBytes = append(decryptedBytes, xorVal)
        }
    }
    plaintext := string(decryptedBytes)
    if len(plaintext) > 0 {
        badChars := 0
        for _, c := range plaintext {
            if c < 32 && c != 9 && c != 10 && c != 13 {
                badChars++
            }
        }
        if float64(badChars)/float64(len(plaintext)) > 0.5 {
            return "", errors.New("entropy check failed")
        }
    }
    return plaintext, nil
}

func ehiDecodeConfigMessage(ciphertextStr string) string {
    if strings.TrimSpace(ciphertextStr) == "" {
        return ciphertextStr
    }
    paddedStr := ciphertextStr
    if rem := len(paddedStr) % 4; rem != 0 {
        paddedStr += strings.Repeat("=", 4-rem)
    }
    rawBytes, err := base64.StdEncoding.DecodeString(paddedStr)
    if err != nil {
        return ciphertextStr
    }
    utf16Runes := utf16.Encode([]rune(string(rawBytes)))
    keyChars := []uint16{'E', 'H', 'I', 'M', 'S', 'G'}
    keyLen := len(keyChars)
    xoredChars := make([]uint16, len(utf16Runes))
    for i, jc := range utf16Runes {
        xoredChars[i] = jc ^ keyChars[i%keyLen]
    }
    return string(utf16.Decode(xoredChars))
}

func ehiNativeXxteaDecrypt(data []byte, key []byte) []byte {
    if len(data) == 0 {
        return []byte{}
    }
    if rem := len(data) % 4; rem != 0 {
        padded := make([]byte, len(data)+(4-rem))
        copy(padded, data)
        data = padded
    }
    k := make([]uint32, 4)
    paddedKey := make([]byte, 16)
    copy(paddedKey, key)
    for i := 0; i < 4; i++ {
        k[i] = binary.LittleEndian.Uint32(paddedKey[i*4 : (i+1)*4])
    }
    n := len(data) / 4
    v := make([]uint32, n)
    for i := 0; i < n; i++ {
        v[i] = binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
    }
    const delta uint32 = 0x9e3779b9
    rounds := 6 + 52/uint32(n)
    sumVal := (rounds * delta) & 0xffffffff
    y := v[0]
    for sumVal != 0 {
        e := (sumVal >> 2) & 3
        for p := n - 1; p > 0; p-- {
            z := v[p-1]
            mx := (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sumVal ^ y) + (k[(uint32(p)&3)^e] ^ z))
            v[p] = (v[p] - mx) & 0xffffffff
            y = v[p]
        }
        z := v[n-1]
        mx := (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sumVal ^ y) + (k[(0&3)^e] ^ z))
        v[0] = (v[0] - mx) & 0xffffffff
        y = v[0]
        sumVal = (sumVal - delta) & 0xffffffff
    }
    decrypted := make([]byte, n*4)
    for i := 0; i < n; i++ {
        binary.LittleEndian.PutUint32(decrypted[i*4:(i+1)*4], v[i])
    }
    length := v[n-1]
    if length > 0 && int(length) <= n*4 {
        return decrypted[:length]
    }
    return bytes.TrimRight(decrypted, "\x00")
}

func ehiParseBytes(fileBytes []byte) ([]byte, error) {
    r := bytes.NewReader(fileBytes)
    readUTF := func() (string, error) {
        var l uint16
        if err := binary.Read(r, binary.BigEndian, &l); err != nil {
            return "", err
        }
        buf := make([]byte, l)
        if _, err := io.ReadFull(r, buf); err != nil {
            return "", err
        }
        return string(buf), nil
    }
    if _, err := readUTF(); err != nil {
        return nil, err
    }
    r.Seek(8, io.SeekCurrent)
    if _, err := readUTF(); err != nil {
        return nil, err
    }
    r.Seek(8, io.SeekCurrent)
    var pLen uint32
    if err := binary.Read(r, binary.BigEndian, &pLen); err != nil {
        return nil, err
    }
    r.Seek(8, io.SeekCurrent)
    payload := make([]byte, pLen)
    if _, err := io.ReadFull(r, payload); err != nil {
        return nil, err
    }
    return payload, nil
}

func ehiPyStr(v interface{}) string {
    switch t := v.(type) {
    case nil:
        return ""
    case string:
        return t
    case bool:
        if t {
            return "True"
        }
        return "False"
    case float64:
        if t == float64(int64(t)) {
            return fmt.Sprintf("%d", int64(t))
        }
        return fmt.Sprintf("%v", t)
    default:
        return fmt.Sprintf("%v", t)
    }
}

func ehiPyTruthy(v interface{}) bool {
    switch t := v.(type) {
    case nil:
        return false
    case string:
        return t != ""
    case bool:
        return t
    case float64:
        return t != 0
    default:
        return true
    }
}

var ehiMasterKeyFields = []struct {
    key          string
    alwaysString bool
}{
    {"configAesKey", false},
    {"configIdentifier", false},
    {"configSalt", false},
    {"configTimestamp", true},
    {"configExpiryTimestamp", true},
    {"lockModes", false},
    {"lockModesHash", false},
    {"configHwid", false},
    {"configLockMobileOperatorId", false},
}

func ehiGenerateMasterKey(config map[string]interface{}) []byte {
    var sb strings.Builder
    for _, f := range ehiMasterKeyFields {
        val, exists := config[f.key]
        if f.alwaysString {
            if !exists {
                val = float64(0)
            }
            sb.WriteString(ehiPyStr(val))
            continue
        }
        if !exists {
            val = ""
        }
        if ehiPyTruthy(val) {
            sb.WriteString(ehiPyStr(val))
        }
    }
    sum := sha256Sum([]byte(sb.String()))
    return sum
}

func ehiPkcs7UnpadStrict(data []byte, blockSize int) ([]byte, error) {
    if len(data) == 0 || len(data)%blockSize != 0 {
        return nil, errors.New("invalid padding length")
    }
    padLen := int(data[len(data)-1])
    if padLen < 1 || padLen > blockSize {
        return nil, errors.New("invalid padding char")
    }
    for _, b := range data[len(data)-padLen:] {
        if int(b) != padLen {
            return nil, errors.New("invalid padding sequence")
        }
    }
    return data[:len(data)-padLen], nil
}

func ehiAesCbcDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
    plaintext, err := aesCBCDecrypt(ciphertext, key, iv)
    if err != nil {
        return nil, err
    }
    return ehiPkcs7UnpadStrict(plaintext, aesBlockSize)
}

func ehiCleanInnerFields(config map[string]interface{}, saltKey string) map[string]interface{} {
    cleaned := make(map[string]interface{}, len(config))
    vitalKeys := map[string]bool{"overwriteServerData": true}
    for k, v := range config {
        valStr, ok := v.(string)
        if !ok || strings.TrimSpace(valStr) == "" {
            cleaned[k] = v
            continue
        }
        var decryptedVal string
        var err error
        if k == "configMessage" {
            decryptedVal = ehiDecodeConfigMessage(valStr)
        } else {
            decryptedVal, err = ehiDecryptXorLayer(valStr, saltKey)
        }
        if err == nil && decryptedVal != "" {
            cleaned[k] = decryptedVal
        } else if vitalKeys[k] {
            cleaned[k] = v
        }
    }
    return cleaned
}

func ehiTryNestedJsonParse(rawStr string) (interface{}, bool) {
    startIdx := strings.Index(rawStr, "{")
    endIdx := strings.LastIndex(rawStr, "}")
    if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
        return nil, false
    }
    var parsedObj interface{}
    if err := json.Unmarshal([]byte(rawStr[startIdx:endIdx+1]), &parsedObj); err != nil {
        return nil, false
    }
    if strVal, ok := parsedObj.(string); ok {
        var innerObj interface{}
        if err := json.Unmarshal([]byte(strVal), &innerObj); err == nil {
            return innerObj, true
        }
    }
    return parsedObj, true
}

func DecryptEHI(fileBytes []byte) (string, error) {
    payload, err := ehiParseBytes(fileBytes)
    if err != nil || len(payload) == 0 {
        return "", errors.New("failed parsing EHI structure")
    }

    var config map[string]interface{}
    isBypass := false

    for idx, iv := range ehiAllIVs {
        l1Dec, err := ehiAesCbcDecrypt(payload, ehiL1Key, iv)
        if err != nil {
            continue
        }
        parts := strings.Split(string(l1Dec), ":")
        if len(parts) < 3 {
            continue
        }
        iv2, err := base64.StdEncoding.DecodeString(parts[0])
        if err != nil {
            continue
        }
        garbageRaw, err := base64.StdEncoding.DecodeString(parts[2])
        if err != nil {
            continue
        }
        garbage, err := ehiAesCbcDecrypt(garbageRaw, ehiL2KeyStatic, iv2)
        if err != nil {
            continue
        }
        finalRaw := ehiNativeXxteaDecrypt(garbage, ehiMasterKey)
        startIdx := bytes.IndexByte(finalRaw, '{')
        if startIdx == -1 {
            continue
        }
        if err := json.Unmarshal(finalRaw[startIdx:], &config); err == nil {
            isBypass = idx < len(ehiSideIVs)
            break
        }
    }

    if config == nil {
        return "", errors.New("decryption signature mismatch across standard matrix maps")
    }

    targetSalt := "EVZJNI"
    if s, ok := config["configSalt"].(string); ok && s != "" {
        targetSalt = s
    }

    var parsedFinal map[string]interface{}

    if isBypass {
        parsedFinal = config
    } else {
        targetData, _ := config["configData"].(string)
        aaaResult, err := ehiDecryptXorLayer(targetData, targetSalt)
        if err != nil {
            return "", fmt.Errorf("xor layer decryption failure: %w", err)
        }
        rawPayload, err := base64.StdEncoding.DecodeString(aaaResult)
        if err != nil || len(rawPayload) <= 50 {
            return "", errors.New("malformed secondary raw payload length parameters")
        }
        timeCost := binary.LittleEndian.Uint32(rawPayload[1:5])
        memoryCost := binary.LittleEndian.Uint32(rawPayload[5:9])
        parallelism := rawPayload[9]
        salt := rawPayload[0x0a:0x1a]
        nonce := rawPayload[0x1a:0x32]
        aad := rawPayload[:0x1a]
        masterKey := ehiGenerateMasterKey(config)
        argonKey := argon2.IDKey(masterKey, salt, timeCost, memoryCost, parallelism, 32)
        aead, err := chacha20poly1305.NewX(argonKey)
        if err != nil {
            return "", err
        }
        decryptedJsonBytes, err := aead.Open(nil, nonce, rawPayload[0x32:], aad)
        if err != nil {
            return "", err
        }
        if err := json.Unmarshal(decryptedJsonBytes, &parsedFinal); err != nil {
            return "", err
        }
    }

    cleanedFinalJson := ehiCleanInnerFields(parsedFinal, targetSalt)

    for _, jsonField := range []string{"v2rRawJson", "overwriteServerData"} {
        if rawStr, ok := cleanedFinalJson[jsonField].(string); ok {
            if parsedObj, success := ehiTryNestedJsonParse(rawStr); success {
                cleanedFinalJson[jsonField] = parsedObj
            }
        }
    }

    prettyJSON, err := json.MarshalIndent(cleanedFinalJson, "", "    ")
    if err != nil {
        return "", err
    }
    return string(prettyJSON), nil
}

func processEHIContent(data []byte) (*processResult, error) {
    jsonOut, err := DecryptEHI(data)
    if err != nil {
        return nil, err
    }
    res := &processResult{}
    consumeJSONBlob([]byte(jsonOut), res)
    if uris := scanPlainURIs([]byte(jsonOut)); len(uris) > 0 {
        res.URIs = append(res.URIs, uris...)
    }
    res.URIs = dedupe(res.URIs)
    return res, nil
}

// ═══════════════════ DarkTunnel (.dark) ═══════════════════

var (
    darkKey256 = []byte("$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd")
    darkKey192 = []byte("F)J@NcRfUjXn2r4u7x!A%D*G")
    darkIV     = darkMustHex("232e39185523184a5723586242200e05")
)

func darkMustHex(h string) []byte {
    b, err := hex.DecodeString(h)
    if err != nil {
        panic(err)
    }
    return b
}

func darkB64DecodeSafe(data string) ([]byte, error) {
    cleanData := strings.ReplaceAll(data, "-", "+")
    cleanData = strings.ReplaceAll(cleanData, "_", "/")
    if pad := len(cleanData) % 4; pad != 0 {
        cleanData += strings.Repeat("=", 4-pad)
    }
    return base64.StdEncoding.DecodeString(cleanData)
}

func darkAesCFBDecrypt(data, key, iv []byte) ([]byte, error) {
    return aesCFBDecrypt(data, key, iv)
}

var darkPrintableRe = regexp.MustCompile(`^[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*$`)
var darkJsonKeyFixRe = regexp.MustCompile(`(:\s*)(\$[A-Za-z0-9_]+)`)

func darkIsUTF8Printable(value []byte) bool {
    if len(value) == 0 {
        return false
    }
    return darkPrintableRe.Match(value)
}

func darkTryParseJSONString(value string) interface{} {
    trimmed := strings.TrimSpace(value)
    if !((strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
        (strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"))) {
        return value
    }
    fixedJSON := darkJsonKeyFixRe.ReplaceAllString(trimmed, `${1}"${2}"`)
    var parsed interface{}
    if err := json.Unmarshal([]byte(fixedJSON), &parsed); err == nil {
        return darkNormalizeForJSON(parsed)
    }
    return value
}

func darkNormalizeForJSON(value interface{}) interface{} {
    switch v := value.(type) {
    case map[string]interface{}:
        cleaned := make(map[string]interface{})
        for key, val := range v {
            if key != "Password" {
                cleaned[key] = darkNormalizeForJSON(val)
            }
        }
        return cleaned
    case []interface{}:
        cleaned := make([]interface{}, len(v))
        for i, val := range v {
            cleaned[i] = darkNormalizeForJSON(val)
        }
        return cleaned
    case []byte:
        if darkIsUTF8Printable(v) {
            return darkTryParseJSONString(string(v))
        }
        ints := make([]int, len(v))
        for i, b := range v {
            ints[i] = int(b)
        }
        return ints
    case string:
        return darkTryParseJSONString(v)
    }
    return value
}

func darkCleanEncrypted(value interface{}, key, iv []byte) interface{} {
    switch v := value.(type) {
    case map[string]interface{}:
        cleaned := make(map[string]interface{})
        for k, val := range v {
            if strings.HasPrefix(k, "Encrypted") {
                if byteData, ok := val.([]byte); ok && len(byteData) > 0 {
                    if dec, err := darkAesCFBDecrypt(byteData, key, iv); err == nil {
                        cleaned[k] = dec
                        continue
                    }
                }
            }
            cleaned[k] = darkCleanEncrypted(val, key, iv)
        }
        return cleaned
    case []interface{}:
        cleaned := make([]interface{}, len(v))
        for i, val := range v {
            cleaned[i] = darkCleanEncrypted(val, key, iv)
        }
        return cleaned
    }
    return value
}

func darkDecrypt(payload string) (string, error) {
    outerBytes, err := darkB64DecodeSafe(strings.Join(strings.Fields(payload), ""))
    if err != nil {
        return "", err
    }
    var outer map[string]interface{}
    if err := json.Unmarshal(outerBytes, &outer); err != nil {
        return "", err
    }
    encLockedConfigStr, ok := outer["encryptedLockedConfig"].(string)
    if !ok {
        return "", fmt.Errorf("missing or invalid encryptedLockedConfig key")
    }
    encryptedLockedConfig, err := darkB64DecodeSafe(encLockedConfigStr)
    if err != nil {
        return "", err
    }
    decryptedOuter, err := darkAesCFBDecrypt(encryptedLockedConfig, darkKey256, darkIV)
    if err != nil {
        return "", err
    }
    var unpackedOuter map[string]interface{}
    if err := msgpack.Unmarshal(decryptedOuter, &unpackedOuter); err != nil {
        return "", err
    }
    if encInnerVal, found := unpackedOuter["EncryptedLockedConfig"]; found {
        if encInnerBytes, ok := encInnerVal.([]byte); ok {
            decryptedInner, err := darkAesCFBDecrypt(encInnerBytes, darkKey192, darkIV)
            if err == nil {
                var unpackedInner interface{}
                if err := msgpack.Unmarshal(decryptedInner, &unpackedInner); err == nil {
                    unpackedOuter["EncryptedLockedConfig"] = darkCleanEncrypted(unpackedInner, darkKey192, darkIV)
                }
            }
        }
    }
    outer["encryptedLockedConfig"] = unpackedOuter
    normalized := darkNormalizeForJSON(outer)
    jsonOut, err := json.MarshalIndent(normalized, "", "    ")
    if err != nil {
        return "", err
    }
    return string(jsonOut), nil
}

func processDarkContent(data []byte) (*processResult, error) {
    text := strings.TrimSpace(string(data))
    jsonOut, err := darkDecrypt(text)
    if err != nil {
        return nil, err
    }
    res := &processResult{}
    consumeJSONBlob([]byte(jsonOut), res)
    if uris := scanPlainURIs([]byte(jsonOut)); len(uris) > 0 {
        res.URIs = append(res.URIs, uris...)
    }
    res.URIs = dedupe(res.URIs)
    return res, nil
}
