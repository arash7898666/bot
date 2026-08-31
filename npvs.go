package main

import (
    "bytes"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "log"
    "os"
    "strings"
    "sync"
    "time"

    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/pbkdf2"
)

// ═══════════════════════════════════════════════════════════════
//  npvs.go — NapsternetV v2 (.npvs)
//  appKey (Anyone with the app) + Passphrase (رمز دلخواه)
//  جداول White-Box از tables.txt موجود ساخته می‌شوند — طبق README
//  ریپو، جداول ty/mbl/xor بین بیلدهای اپ مشترک‌اند و فقط
//  tboxes_last تغییر می‌کند (چند نسخه امتحان می‌شود).
// ═══════════════════════════════════════════════════════════════

const npvsWrapSize = 60

// ─────────────── رمزهای در انتظار (SlipNet + NPVS) ───────────────

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

// ─────────────── ساختارهای NPVS ───────────────

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

type npvsConfigPolicy struct {
    AttestationLevel    string  `json:"attestationLevel"`
    ConfigVersion       int     `json:"configVersion"`
    CustomServerMessage string  `json:"customServerMessage"`
    DisplayMessage      string  `json:"displayMessage"`
    ExpiresAt           *string `json:"expiresAt"`
    OnlyMobileNetwork   bool    `json:"onlyMobileNetwork"`
}

type npvsHeader struct {
    V        int    `json:"v"`
    ConfigID string `json:"configId"`
    IssuedAt string `json:"issuedAt"`
    Creator  struct {
        Fp string `json:"fp"`
        Pk string `json:"pk"`
    } `json:"creator"`
    AppKey     *npvsAppKeyWrap     `json:"appKey"`
    Passphrase *npvsPassphraseWrap `json:"passphrase"`
    Policy     npvsConfigPolicy    `json:"policy"`
    Recipients []json.RawMessage   `json:"recipients"`
}

type npvsEnvelope struct {
    headerRaw []byte
    hdr       npvsHeader
    nonce     []byte
    body      []byte
}

func npvsJSONEnd(b []byte, start int) int {
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

// مسیر باینری: NPVS + ver(1) + hdrLen(4BE) + JSON + nonce(12) + bodyLen(4BE) + body + sig(64)
// مسیر متنی (fallback): NPVS%{JSON} + دنباله — برای وقتی متن آسیب دیده
func parseNpvsEnvelope(b []byte) (*npvsEnvelope, error) {
    if len(b) >= 89 && bytes.HasPrefix(b, []byte("NPVS")) && b[4] <= 1 {
        hdrLen := int(binary.BigEndian.Uint32(b[5:9]))
        if hdrLen > 2 && 9+hdrLen < len(b) {
            e := &npvsEnvelope{headerRaw: b[9 : 9+hdrLen]}
            if err := json.Unmarshal(e.headerRaw, &e.hdr); err == nil {
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

    if bytes.HasPrefix(b, []byte("NPVS")) {
        start := bytes.IndexByte(b, '{')
        if start > 4 {
            if end := npvsJSONEnd(b, start); end > start {
                e := &npvsEnvelope{headerRaw: b[start : end+1]}
                if err := json.Unmarshal(e.headerRaw, &e.hdr); err == nil {
                    tail := b[end+1:]
                    if len(tail) >= 28 {
                        e.nonce = tail[:12]
                        e.body = tail[12:] // شامل طول+بدنه+امضا — واریانت‌ها در npvsOpenBody امتحان می‌شوند
                    }
                    return e, nil
                }
            }
        }
    }
    return nil, fmt.Errorf("ساختار NPVS شناخته نشد")
}

func npvsCreatorMessage(hdr *npvsHeader) string {
    var parts []string
    for _, m := range []string{hdr.Policy.DisplayMessage, hdr.Policy.CustomServerMessage} {
        if m = strings.TrimSpace(strings.ReplaceAll(m, "\r\n", "\n")); m != "" {
            parts = append(parts, m)
        }
    }
    return strings.Join(parts, "\n")
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

// ─────────────── White-Box NPVS ───────────────

const (
    wbTlastSize = 4096
    wbTableSize = 16384
    wbXorSize   = 24576
)

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
    wbErr           error
)

var npvsRepoBases = []string{
    "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/main/internal/modules/impl/assets/npvs/",
    "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/master/internal/modules/impl/assets/npvs/",
    "https://raw.githubusercontent.com/FrontierTM/Pantegnos/main/internal/modules/impl/assets/npvs/",
    "https://raw.githubusercontent.com/FrontierTM/Pantegnos/master/internal/modules/impl/assets/npvs/",
    "https://cdn.jsdelivr.net/gh/KernelDotDLL/Pantegnos@main/internal/modules/impl/assets/npvs/",
    "https://cdn.jsdelivr.net/gh/KernelDotDLL/Pantegnos@master/internal/modules/impl/assets/npvs/",
}

func npvsGetBlob(name string, want int) ([]byte, error) {
    for _, p := range []string{os.Getenv("NPVS_DIR"), "npvs", "assets/npvs", "."} {
        if p == "" {
            continue
        }
        if b, err := os.ReadFile(p + "/" + name); err == nil && len(b) == want {
            return b, nil
        }
    }

    cache := "npvs_cache_" + name
    if b, err := os.ReadFile(cache); err == nil && len(b) == want {
        return b, nil
    }

    urls := append([]string{}, npvsRepoBases...)
    if base := os.Getenv("NPVS_BASE_URL"); base != "" {
        if !strings.HasSuffix(base, "/") {
            base += "/"
        }
        urls = append([]string{base}, urls...)
    }
    for _, u := range urls {
        b, err := fetchURL(u + name)
        if err != nil || len(b) != want {
            continue
        }
        _ = os.WriteFile(cache, b, 0644)
        return b, nil
    }
    return nil, fmt.Errorf("blob %s در دسترس نیست", name)
}

func tlastEqual(a, b *[16][256]byte) bool {
    for i := 0; i < 16; i++ {
        if !bytes.Equal(a[i][:], b[i][:]) {
            return false
        }
    }
    return true
}

func loadWB() error {
    wbOnce.Do(func() {
        // ۱) جداول مشترک — از tables.txt (همان جداول NPVT که tables_loader.go بارگذاری کرده)
        wbTy = tyBoxes
        wbMbl = mbl
        wbXorBin = make([]byte, wbXorSize)
        for t := 0; t < 96; t++ {
            for a := 0; a < 16; a++ {
                for b := 0; b < 16; b++ {
                    wbXorBin[(t<<8)+(a<<4)+b] = xorTable[t][a][b]
                }
            }
        }

        // ۲) tboxes_last — نسخه محلی + نسخه‌های دانلودی (بدون تکرار)
        base := tboxesLast
        wbTlastVariants = append(wbTlastVariants, &base)
        for _, name := range []string{"tboxes_last.bin", "tboxes_last_v2.bin"} {
            b, err := npvsGetBlob(name, wbTlastSize)
            if err != nil {
                continue // اختیاری — نسخه محلی موجود است
            }
            var t [16][256]byte
            for i := 0; i < 16; i++ {
                copy(t[i][:], b[i*256:(i+1)*256])
            }
            dup := false
            for _, v := range wbTlastVariants {
                if tlastEqual(v, &t) {
                    dup = true
                    break
                }
            }
            if !dup {
                wbTlastVariants = append(wbTlastVariants, &t)
            }
        }

        // ۳) اگر جداول مشترک رسمی دانلود شد، جایگزین (نسخه جدیدتر ریپو)
        if b, err := npvsGetBlob("tyboxes.bin", wbTableSize); err == nil {
            for i := 0; i < 16; i++ {
                for j := 0; j < 256; j++ {
                    k := (i*256 + j) * 4
                    wbTy[i][j] = binary.BigEndian.Uint32(b[k:])
                }
            }
        }
        if b, err := npvsGetBlob("mbl.bin", wbTableSize); err == nil {
            for i := 0; i < 16; i++ {
                for j := 0; j < 256; j++ {
                    k := (i*256 + j) * 4
                    wbMbl[i][j] = binary.BigEndian.Uint32(b[k:])
                }
            }
        }
        if b, err := npvsGetBlob("xor.bin", wbXorSize); err == nil {
            wbXorBin = b
        }

        log.Printf("✅ جداول White-Box NPVS آماده (%d نسخه tboxes_last)", len(wbTlastVariants))
    })
    return wbErr
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

// KDK = SHA256("npvtunnel/appkey/v1 " + WB-CTR(salt, 16 بایت صفر)) — برای هر نسخه tboxes_last
func custodianKDKs(salt []byte) [][]byte {
    if len(salt) < 16 || loadWB() != nil {
        return nil
    }
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

// ─────────────── باز کردن قفل‌ها ───────────────

func npvsUnwrapAppKey(a *npvsAppKeyWrap) ([]byte, error) {
    if a.Kdf != "wbaes-ctr-sha256" {
        return nil, fmt.Errorf("KDF ناشناخته: %s", a.Kdf)
    }
    salt, err := npvsB64URL(a.Salt)
    if err != nil || len(salt) != 16 {
        return nil, fmt.Errorf("salt نامعتبر")
    }
    wrap, err := npvsB64URL(a.Wrap)
    if err != nil || len(wrap) != npvsWrapSize {
        return nil, fmt.Errorf("wrap باید %d بایت باشد", npvsWrapSize)
    }
    kdks := custodianKDKs(salt)
    if len(kdks) == 0 {
        return nil, fmt.Errorf("جدول‌های White-Box در دسترس نیستند")
    }
    for _, kdk := range kdks {
        if dek, err := npvsChachaOpen(kdk, wrap[:12], wrap[12:], salt); err == nil {
            return dek, nil
        }
    }
    return nil, fmt.Errorf("هیچ کلید custodian جواب نداد (keyId %d — %d کلید امتحان شد)", a.KeyID, len(kdks))
}

func npvsUnwrapPassphrase(p *npvsPassphraseWrap, password string) ([]byte, error) {
    if p.Kdf != "pbkdf2-hmac-sha256" {
        return nil, fmt.Errorf("KDF ناشناخته: %s", p.Kdf)
    }
    if password == "" {
        return nil, fmt.Errorf("رمز لازم است")
    }
    if p.Iters < 1 || p.Iters > 10000000 {
        return nil, fmt.Errorf("تعداد تکرار نامعتبر: %d", p.Iters)
    }
    salt, err := npvsB64URL(p.Salt)
    if err != nil || len(salt) < 16 {
        return nil, fmt.Errorf("salt نامعتبر")
    }
    wrap, err := npvsB64URL(p.Wrap)
    if err != nil || len(wrap) != npvsWrapSize {
        return nil, fmt.Errorf("wrap باید %d بایت باشد", npvsWrapSize)
    }
    derived := pbkdf2.Key([]byte(password), salt, p.Iters, 32, sha256.New)
    dek, err := npvsChachaOpen(derived, wrap[:12], wrap[12:], salt)
    if err != nil {
        return nil, fmt.Errorf("رمز اشتباه است")
    }
    return dek, nil
}

// چند کاندید بدنه: کامل / بدون ۴ بایت طول اول / بدون ۶۴ بایت امضا آخر / بدون هر دو
func npvsOpenBody(dek, nonce, body, aad []byte) ([]byte, error) {
    if len(body) < 16 {
        return nil, fmt.Errorf("بدنه فایل ناقص است")
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

    var lastErr error
    for _, n := range nonces {
        for _, ct := range bodies {
            for _, ad := range aads {
                pt, err := npvsChachaOpen(dek, n, ct, ad)
                if err == nil {
                    return pt, nil
                }
                lastErr = err
            }
        }
    }
    return nil, fmt.Errorf("بدنه باز نشد — فایل را «آپلود» کنید نه متن: %v", lastErr)
}

// ─────────────── Sentinel ها (npvs1:...) ───────────────

const npvSentinelPrefix = "npvs1:"
const npvSentinelAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"

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

// ─────────────── نقطه ورود ───────────────

func handleNPVS(data []byte, chatID int64) (*processResult, error, bool) {
    env, err := parseNpvsEnvelope(data)
    if err != nil {
        return nil, err, false
    }

    // ۱) رمز دلخواه → بپرس
    if env.hdr.Passphrase != nil {
        setPendingPass(chatID, "npvs", data)
        if hint := npvsCreatorMessage(&env.hdr); hint != "" {
            reply(chatID, "💡 پیام سازنده: "+hint)
        }
        return nil, nil, true
    }

    res := &processResult{}

    // ۲) appKey → باز کردن کامل
    if env.hdr.AppKey != nil {
        dek, uerr := npvsUnwrapAppKey(env.hdr.AppKey)
        if uerr == nil {
            pt, berr := npvsOpenBody(dek, env.nonce, env.body, env.headerRaw)
            if berr == nil {
                text := decodeNpvSentinels(string(pt))
                consumeJSONBlob([]byte(text), res)
                if uris := scanPlainURIs([]byte(text)); len(uris) > 0 {
                    res.URIs = append(res.URIs, uris...)
                }
                res.URIs = dedupe(res.URIs)
                if len(res.URIs) == 0 && len(res.Raw) == 0 && len(text) > 0 {
                    res.Raw = append(res.Raw, text)
                }
                return res, nil, false
            }
            var sb strings.Builder
            sb.WriteString("═══ NPVS ═══\n")
            sb.WriteString(fmt.Sprintf("Config ID: %s\n", env.hdr.ConfigID))
            sb.WriteString("🔓 قفل appKey باز شد ولی بدنه باز نشد.\n")
            sb.WriteString("⚠️ " + berr.Error())
            res.Raw = append(res.Raw, sb.String())
            return res, nil, false
        }

        var sb strings.Builder
        sb.WriteString("═══ NPVS ═══\n")
        sb.WriteString(fmt.Sprintf("Config ID: %s\n", env.hdr.ConfigID))
        if msg := npvsCreatorMessage(&env.hdr); msg != "" {
            sb.WriteString(fmt.Sprintf("پیام سازنده: %s\n", msg))
        }
        sb.WriteString("\n⚠️ قفل appKey: " + uerr.Error())
        res.Raw = append(res.Raw, sb.String())
        return res, nil, false
    }

    // ۳) بدون قفل شناخته‌شده
    var sb strings.Builder
    sb.WriteString("═══ NPVS ═══\n")
    sb.WriteString(fmt.Sprintf("Config ID: %s\n", env.hdr.ConfigID))
    if msg := npvsCreatorMessage(&env.hdr); msg != "" {
        sb.WriteString(fmt.Sprintf("پیام سازنده: %s\n", msg))
    }
    if len(env.hdr.Recipients) > 0 {
        sb.WriteString("\n🔒 فایل برای گیرندگان خاص (E2E) رمز شده — فقط با کلید خصوصی گیرنده باز می‌شود.")
    } else {
        sb.WriteString("\n📡 این فایل فقط شناسه ارجاع است — کانفیگ روی سرور سازنده نگه‌داری می‌شود.")
    }
    res.Raw = append(res.Raw, sb.String())
    return res, nil, false
}

// رمز → باز کردن NPVS (نسخه‌های مختلف رمز هم امتحان می‌شود: با فاصله، بدون فاصله، کوچک/بزرگ)
func tryNPVSPassphrase(fileData []byte, password string) (*processResult, error) {
    env, err := parseNpvsEnvelope(fileData)
    if err != nil {
        return nil, err
    }
    if env.hdr.Passphrase == nil {
        return nil, fmt.Errorf("این فایل رمز شخصی ندارد")
    }

    attempts := []string{password}
    trimmed := strings.TrimSpace(password)
    attempts = append(attempts, trimmed)
    attempts = append(attempts, strings.Join(strings.Fields(trimmed), ""))
    attempts = append(attempts, strings.ToUpper(strings.Join(strings.Fields(trimmed), "")))
    attempts = append(attempts, strings.ToLower(strings.Join(strings.Fields(trimmed), "")))
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
        return nil, fmt.Errorf("رمز اشتباه است — همان رمزی که سازنده اعلام کرده را بفرستید")
    }

    pt, err := npvsOpenBody(dek, env.nonce, env.body, env.headerRaw)
    if err != nil {
        return nil, err
    }
    text := decodeNpvSentinels(string(pt))
    res := &processResult{}
    consumeJSONBlob([]byte(text), res)
    if uris := scanPlainURIs([]byte(text)); len(uris) > 0 {
        res.URIs = append(res.URIs, uris...)
    }
    res.URIs = dedupe(res.URIs)
    if len(res.URIs) == 0 && len(res.Raw) == 0 && len(text) > 0 {
        res.Raw = append(res.Raw, text)
    }
    return res, nil
}
