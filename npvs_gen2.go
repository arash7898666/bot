package main

import (
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/url"
    "sort"
    "strconv"
    "strings"

    "golang.org/x/crypto/hkdf"
    "golang.org/x/crypto/pbkdf2"
)

// ═══════ NPVS v5 (Gen2) + NPVO1 (open) + مارکرهای قدیمی — پورت Pantegnos ═══════

// 🐞 مهر نسخه — در خروجی دیباگ دیده می‌شود تا مطمئن شویم باینری جدید اجراست
const npvsGen2BuildTag = "G2-DBG4"

const (
    npvGen2EnvelopeVersion   = 5
    npvGen2HeaderFixed       = 135
    npvGen2MetadataInfo      = "NPVS-v5/metadata"
    npvGen2FieldKeyInfo      = "NPV-fields-v1/field/"
    npvGen2RecordAADInfo     = "NPV-fields-v1/record/"
    npvGen2BodyMagic         = "NPF\x01"
    npvGen2KeyBlockOffset    = 53
    npvGen2SentinelSeq       = 0xFFFF
    npvGen2MethodRecipient   = 0
    npvGen2MethodPass        = 1
    npvGen2MethodAppKey      = 2
    npvGen2RecipientPkSize   = 32
    npvGen2RecipientWrapSize = 0x5d
    npvGen2PassBlockSize     = 80
    npvGen2AppKeyBlockSize   = 78
    npvGen2KeySize           = 32
    npvGen2SigSize           = 64

    npvOpenMarker   = "NPVO1"
    npvSubMarker    = "NPVTSUB1"
    npvLegacyMarker = "NPVT1"
    npvOpenMaxSize  = 8 << 20
)

// ─── مارکرها ───

func isNpvOpenEnvelope(b []byte) bool {
    head := strings.TrimLeft(string(b), " \t\r\n")
    return strings.HasPrefix(head, npvOpenMarker)
}

func npvLegacyMarkerOf(b []byte) string {
    head := strings.TrimLeft(string(b), " \t\r\n")
    switch {
    case strings.HasPrefix(head, npvSubMarker):
        return npvSubMarker
    case strings.HasPrefix(head, npvLegacyMarker):
        return npvLegacyMarker
    }
    return ""
}

func npvOpenStripMarker(s, marker string) string {
    s = strings.ReplaceAll(s, marker+"\n", "")
    return strings.ReplaceAll(s, marker, "")
}

// ─── NPVO1: حالت Keep open ───

type npvOpenEnvelope struct {
    Configs []any `json:"configs"`
}

func parseNpvOpenEnvelope(b []byte) (*npvOpenEnvelope, error) {
    if len(b) > npvOpenMaxSize {
        return nil, fmt.Errorf("npvs open: فایل بیش از حد بزرگ: %d بایت", len(b))
    }
    body := npvOpenStripMarker(string(b), npvOpenMarker)
    if strings.TrimSpace(body) == "" {
        return nil, fmt.Errorf("npvs open: محتوای خالی بعد از مارکر")
    }
    var env npvOpenEnvelope
    if err := json.Unmarshal([]byte(body), &env); err != nil {
        return nil, fmt.Errorf("npvs open: payload لیست کانفیگ نیست: %w", err)
    }
    if len(env.Configs) == 0 {
        return nil, fmt.Errorf("npvs open: کانفیگی در payload نیست")
    }
    return &env, nil
}

func npvOpenDecodeSentinels(v any) any {
    switch t := v.(type) {
    case string:
        return decodeNpvSentinels(t)
    case map[string]any:
        out := make(map[string]any, len(t))
        for k, x := range t {
            out[k] = npvOpenDecodeSentinels(x)
        }
        return out
    case []any:
        out := make([]any, len(t))
        for i, x := range t {
            out[i] = npvOpenDecodeSentinels(x)
        }
        return out
    default:
        return v
    }
}

func npvsOpenDecrypt(data []byte) (*processResult, error) {
    env, err := parseNpvOpenEnvelope(data)
    if err != nil {
        return nil, err
    }
    res := &processResult{}
    for _, cfg := range env.Configs {
        for _, l := range strings.Split(npvGen2Link(npvOpenDecodeSentinels(cfg)), "\n") {
            if p := strings.TrimSpace(l); p != "" {
                res.URIs = append(res.URIs, p)
            }
        }
    }
    res.URIs = dedupeByURI(res.URIs)
    return res, nil
}

// ─── ساختار Gen2 ───

type npvGen2Envelope struct {
    header     []byte
    prefix     []byte
    configID   []byte
    creator    []byte
    salt       []byte
    wrap       []byte
    metaBlob   []byte
    nonce      []byte
    body       []byte
    sig        []byte
    method     int
    iters      int
    recipients int
}

func (e *npvGen2Envelope) needsPassphrase() bool {
    return e.method == npvGen2MethodPass
}

func (e *npvGen2Envelope) unlockHint(err error) error {
    switch e.method {
    case npvGen2MethodPass:
        return fmt.Errorf("%w\n[!] این کانفیگ با Passphrase قفل شده (متد ۱)؛ رمز را از سازنده بگیرید", err)
    case npvGen2MethodRecipient:
        return fmt.Errorf("%w\n[!] این کانفیگ برای %d نفر خاص قفل شده (متد ۰/E2E)؛ فقط با کلید خصوصی همان گیرنده باز می‌شود", err, e.recipients)
    }
    return err
}

type npvGen2Field struct {
    seq   uint16
    flags uint16
    blob  []byte
}

type npvGen2MetadataPolicy struct {
    AttestationLevel    string `json:"attestationLevel"`
    ConfigVersion       int    `json:"configVersion"`
    CustomServerMessage string `json:"customServerMessage"`
    DisplayMessage      string `json:"displayMessage"`
    OnlyMobileNetwork   bool   `json:"onlyMobileNetwork"`
}

type npvGen2Metadata struct {
    IssuedAt string                `json:"issuedAt"`
    Policy   npvGen2MetadataPolicy `json:"policy"`
}

func isNpvGen2Envelope(b []byte) bool {
    return len(b) >= 9 && string(b[:4]) == "NPVS" && b[4] == npvGen2EnvelopeVersion
}

func parseNpvGen2Envelope(b []byte) (*npvGen2Envelope, error) {
    if !isNpvGen2Envelope(b) {
        return nil, fmt.Errorf("npvs gen2: not a v5 compact envelope")
    }

    hdrLen := int(binary.BigEndian.Uint32(b[5:9]))
    if hdrLen < npvGen2HeaderFixed || 9+hdrLen > len(b) {
        return nil, fmt.Errorf("npvs gen2: bad header length %d", hdrLen)
    }
    h := b[9 : 9+hdrLen]
    if h[0] != 1 {
        return nil, fmt.Errorf("npvs gen2: compact header version %d is unsupported", h[0])
    }
    e := &npvGen2Envelope{
        header:   h,
        configID: h[1:17],
        creator:  h[17:50],
        method:   int(h[50]),
    }

    switch e.method {
    case npvGen2MethodRecipient, npvGen2MethodPass, npvGen2MethodAppKey:
    default:
        return nil, fmt.Errorf("npvs gen2: unknown unlock method %d", e.method)
    }

    e.recipients = int(binary.BigEndian.Uint16(h[51:53]))
    if e.recipients > 0x400 {
        return nil, fmt.Errorf("npvs gen2: %d recipients is too many", e.recipients)
    }
    if e.method == npvGen2MethodRecipient && e.recipients == 0 {
        return nil, fmt.Errorf("npvs gen2: invalid compact envelope header")
    }

    off := npvGen2KeyBlockOffset + e.recipients*(npvGen2RecipientPkSize+npvGen2RecipientWrapSize)

    switch e.method {
    case npvGen2MethodPass:
        if off+npvGen2PassBlockSize+4 > len(h) {
            return nil, fmt.Errorf("npvs gen2: truncated passphrase block")
        }
        e.iters = int(binary.BigEndian.Uint32(h[off : off+4]))
        if e.iters < 1 || e.iters > 10000000 {
            return nil, fmt.Errorf("npvs gen2: bad passphrase iteration count %d", e.iters)
        }
        e.salt = h[off+4 : off+20]
        e.wrap = h[off+20 : off+npvGen2PassBlockSize]
        off += npvGen2PassBlockSize
    case npvGen2MethodAppKey:
        if off+npvGen2AppKeyBlockSize+4 > len(h) {
            return nil, fmt.Errorf("npvs gen2: truncated app-key block")
        }
        if binary.BigEndian.Uint16(h[off:off+2]) != npvGen2MethodAppKey {
            return nil, fmt.Errorf("npvs gen2: missing app-key block")
        }
        e.salt = h[off+2 : off+18]
        e.wrap = h[off+18 : off+npvGen2AppKeyBlockSize]
        off += npvGen2AppKeyBlockSize
    }

    if off+4 > len(h) {
        return nil, fmt.Errorf("npvs gen2: truncated sealed metadata length")
    }
    metaLen := int(binary.BigEndian.Uint32(h[off : off+4]))
    if metaLen < 16 || off+4+metaLen > len(h) {
        return nil, fmt.Errorf("npvs gen2: bad sealed metadata length %d", metaLen)
    }

    e.prefix = h[:off]
    e.metaBlob = h[off+4 : off+4+metaLen]

    off = 9 + hdrLen
    if off+16 > len(b) {
        return nil, fmt.Errorf("npvs gen2: truncated body header")
    }
    e.nonce = b[off : off+12]

    bodyLen := int(binary.BigEndian.Uint32(b[off+12 : off+16]))
    off += 16
    if bodyLen < 32 || off+bodyLen+npvGen2SigSize > len(b) {
        return nil, fmt.Errorf("npvs gen2: bad body length %d", bodyLen)
    }
    e.body = b[off : off+bodyLen]
    e.sig = b[off+bodyLen : off+bodyLen+npvGen2SigSize]

    return e, nil
}

// ─── باز کردن Gen2 — متدهای ۱ و ۲ ───

func (e *npvGen2Envelope) open(passphrase string) (metadata []byte, fields map[uint16][]byte, err error) {
    var kdk []byte

    switch e.method {
    case npvGen2MethodPass:
        if passphrase == "" {
            return nil, nil, fmt.Errorf("npvs gen2: رمز لازم است")
        }
        kdk = pbkdf2.Key([]byte(passphrase), e.salt, e.iters, npvGen2KeySize, sha256.New)

    case npvGen2MethodAppKey:
        a16, aerr := npvGen2A16(e.salt)
        if aerr != nil {
            return nil, nil, aerr
        }
        sum := npvGen2KDK(a16, e.configID)
        kdk = sum[:]

    default:
        return nil, nil, fmt.Errorf("npvs gen2: متد %d به کلید خصوصی گیرنده نیاز دارد", e.method)
    }

    dek, derr := npvsChachaOpen(kdk, e.wrap[:12], e.wrap[12:], e.salt)
    if derr != nil {
        if e.method == npvGen2MethodPass {
            return nil, nil, fmt.Errorf("npvs gen2: رمز اشتباه (passphrase wrap باز نشد)")
        }
        return nil, nil, fmt.Errorf("npvs gen2: app-key wrap did not open: %w", derr)
    }

    metaKey := npvGen2HKDF(dek, e.nonce, npvGen2MetadataInfo)
    metadata, merr := npvsChachaOpen(metaKey, e.nonce, e.metaBlob, e.prefix)
    if merr != nil {
        return nil, nil, fmt.Errorf("npvs gen2: sealed metadata did not open: %w", merr)
    }

    contentID, rows, berr := parseNpvGen2Body(e.body)
    if berr != nil {
        return nil, nil, berr
    }

    fields = make(map[uint16][]byte, len(rows))
    for _, row := range rows {
        key := npvGen2HKDF(dek, contentID, npvGen2FieldKeyInfo+string(npvGen2BE16Bytes(row.seq)))
        ptLen := len(row.blob) - 16
        if ptLen < 0 {
            continue
        }
        aad := npvGen2Concat([]byte(npvGen2RecordAADInfo), contentID,
            npvGen2BE16Bytes(row.seq), npvGen2BE32Bytes(uint32(ptLen)))
        pt, oerr := npvsChachaOpen(key, make([]byte, 12), row.blob, aad)
        if oerr != nil {
            continue
        }
        fields[row.seq] = pt
    }

    return metadata, fields, nil
}

func parseNpvGen2Body(b []byte) (contentID []byte, rows []npvGen2Field, err error) {
    if len(b) < 32+2+32 || string(b[:4]) != npvGen2BodyMagic {
        return nil, nil, fmt.Errorf("npvs gen2: bad NPF body")
    }
    contentID = b[4:36]
    count := int(binary.BigEndian.Uint16(b[36:38]))
    off := 38

    rows = make([]npvGen2Field, 0, count)
    for i := 0; i < count; i++ {
        if off+6 > len(b) {
            return nil, nil, fmt.Errorf("npvs gen2: truncated NPF field header")
        }
        row := npvGen2Field{
            seq:   binary.BigEndian.Uint16(b[off : off+2]),
            flags: binary.BigEndian.Uint16(b[off+2 : off+4]),
        }
        blobLen := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
        if off+6+blobLen > len(b) {
            return nil, nil, fmt.Errorf("npvs gen2: truncated NPF field blob")
        }
        row.blob = b[off+6 : off+6+blobLen]
        rows = append(rows, row)
        off += 6 + blobLen
    }
    return contentID, rows, nil
}

func npvGen2BE16Bytes(v uint16) []byte {
    b := make([]byte, 2)
    binary.BigEndian.PutUint16(b, v)
    return b
}

func npvGen2BE32Bytes(v uint32) []byte {
    b := make([]byte, 4)
    binary.BigEndian.PutUint32(b, v)
    return b
}

func npvGen2Concat(parts ...[]byte) []byte {
    var out []byte
    for _, p := range parts {
        out = append(out, p...)
    }
    return out
}

func npvGen2HKDF(ikm, salt []byte, info string) []byte {
    if len(salt) == 0 {
        salt = make([]byte, npvGen2KeySize)
    }
    out := make([]byte, npvGen2KeySize)
    _, _ = io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte(info)), out)
    return out
}

// ─── هلپرهای map-safe ───

func npvGen2GetMap(v any) map[string]any {
    m, _ := v.(map[string]any)
    return m
}

func npvGen2GetArr(v any) []any {
    a, _ := v.([]any)
    return a
}

func npvGen2GetStr(m map[string]any, k string) string {
    if m == nil {
        return ""
    }
    return npvGen2Text(m[k])
}

func npvGen2GetInt(m map[string]any, k string) int {
    if m == nil {
        return 0
    }
    switch t := m[k].(type) {
    case float64:
        return int(t)
    case string:
        return npvGen2Int(t)
    }
    return 0
}

func npvGen2SortedKeysOf(m map[string]any) string {
    keys := make([]string, 0, len(m))
    for k := range m {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    return strings.Join(keys, ",")
}

// ─── 🐞 پارسر مستقیم v2rayJson — نسخه دیباگ‌دار ───

func npvGen2V2RayJSONLinksDbg(raw any) ([]string, string) {
    var root map[string]any
    switch v := raw.(type) {
    case string:
        if strings.TrimSpace(v) == "" {
            return nil, "empty"
        }
        clean := cleanEmbeddedJSON(v)
        if !json.Valid(clean) {
            return nil, "invalid-json head=" + debugPreview(string(clean), 60)
        }
        if err := json.Unmarshal(clean, &root); err != nil {
            return nil, "unmarshal:" + err.Error()
        }
    case map[string]any:
        root = v
    default:
        return nil, "type:" + fmt.Sprintf("%T", raw)
    }
    if root == nil {
        return nil, "nil-root"
    }
    obs := npvGen2GetArr(root["outbounds"])
    if len(obs) == 0 {
        return nil, "no-outbounds keys=" + debugPreview(npvGen2SortedKeysOf(root), 80)
    }
    var uris []string
    for _, ob := range obs {
        m := npvGen2GetMap(ob)
        if m == nil {
            continue
        }
        proto := strings.ToLower(npvGen2GetStr(m, "protocol"))
        switch proto {
        case "trojan", "vless", "vmess", "shadowsocks":
            if u := npvGen2OutboundToURI(proto, m, npvGen2Text(root["remarks"])); u != "" {
                uris = append(uris, u)
            }
        }
    }
    if len(uris) == 0 {
        return nil, fmt.Sprintf("outbounds=%d but-0-links", len(obs))
    }
    return uris, ""
}

func npvGen2OutboundToURI(proto string, ob map[string]any, remarks string) string {
    settings := npvGen2GetMap(ob["settings"])
    stream := npvGen2GetMap(ob["streamSettings"])

    host, port, password, uuid, flow, method := "", 0, "", "", "", ""
    switch proto {
    case "trojan", "shadowsocks":
        servers := npvGen2GetArr(settings["servers"])
        if len(servers) == 0 {
            return ""
        }
        s := npvGen2GetMap(servers[0])
        host = npvGen2GetStr(s, "address")
        port = npvGen2GetInt(s, "port")
        password = npvGen2GetStr(s, "password")
        if proto == "shadowsocks" {
            method = npvGen2GetStr(s, "method")
        }
    case "vless", "vmess":
        vnext := npvGen2GetArr(settings["vnext"])
        if len(vnext) == 0 {
            return ""
        }
        v := npvGen2GetMap(vnext[0])
        host = npvGen2GetStr(v, "address")
        port = npvGen2GetInt(v, "port")
        users := npvGen2GetArr(v["users"])
        if len(users) == 0 {
            return ""
        }
        u := npvGen2GetMap(users[0])
        uuid = npvGen2GetStr(u, "id")
        password = uuid
        flow = npvGen2GetStr(u, "flow")
        method = npvGen2Or(npvGen2GetStr(u, "security"), "auto")
    }
    if host == "" || port == 0 || password == "" {
        return ""
    }
    if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
        host = "[" + host + "]"
    }

    q := url.Values{}
    network := strings.ToLower(npvGen2GetStr(stream, "network"))
    if network == "" {
        network = "tcp"
    }
    security := strings.ToLower(npvGen2GetStr(stream, "security"))
    if security == "" {
        security = "none"
    }
    q.Set("type", network)
    q.Set("security", security)

    tls := npvGen2GetMap(stream["tlsSettings"])
    reality := npvGen2GetMap(stream["realitySettings"])
    ws := npvGen2GetMap(stream["wsSettings"])
    grpc := npvGen2GetMap(stream["grpcSettings"])

    switch network {
    case "ws":
        npvGen2Set(q, "path", npvGen2GetStr(ws, "path"))
        h := npvGen2GetStr(ws, "host")
        if h == "" {
            if hd := npvGen2GetMap(ws["headers"]); hd != nil {
                h = npvGen2GetStr(hd, "Host")
            }
        }
        npvGen2Set(q, "host", h)
    case "grpc":
        npvGen2Set(q, "serviceName", npvGen2GetStr(grpc, "serviceName"))
        npvGen2Set(q, "mode", npvGen2Or(npvGen2GetStr(grpc, "mode"), "gun"))
    case "httpupgrade", "xhttp":
        npvGen2Set(q, "path", npvGen2GetStr(npvGen2GetMap(stream[network+"Settings"]), "path"))
        npvGen2Set(q, "host", npvGen2GetStr(npvGen2GetMap(stream[network+"Settings"]), "host"))
    }

    switch security {
    case "tls":
        npvGen2Set(q, "sni", npvGen2GetStr(tls, "serverName"))
        npvGen2Set(q, "fp", npvGen2GetStr(tls, "fingerprint"))
        if alpn := npvGen2GetArr(tls["alpn"]); len(alpn) > 0 {
            var parts []string
            for _, a := range alpn {
                parts = append(parts, npvGen2Text(a))
            }
            q.Set("alpn", strings.Join(parts, ","))
        }
        if strings.EqualFold(npvGen2GetStr(tls, "allowInsecure"), "true") {
            q.Set("allowInsecure", "1")
        }
    case "reality":
        npvGen2Set(q, "sni", npvGen2GetStr(reality, "serverName"))
        npvGen2Set(q, "fp", npvGen2GetStr(reality, "fingerprint"))
        npvGen2Set(q, "pbk", npvGen2GetStr(reality, "publicKey"))
        npvGen2Set(q, "sid", npvGen2GetStr(reality, "shortId"))
    }

    rem := cleanRemarks(remarks)
    switch proto {
    case "trojan":
        if flow != "" {
            q.Set("flow", flow)
        }
        return fmt.Sprintf("trojan://%s@%s:%d?%s#%s",
            url.PathEscape(password), host, port, q.Encode(), rem)
    case "vless":
        q.Set("encryption", "none")
        if flow != "" {
            q.Set("flow", flow)
        }
        return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
            password, host, port, q.Encode(), rem)
    case "shadowsocks":
        if method == "" {
            method = "aes-256-gcm"
        }
        ui := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
        return fmt.Sprintf("ss://%s@%s:%d#%s", ui, host, port, rem)
    case "vmess":
        netPath, netHost := "", ""
        switch network {
        case "ws":
            netPath = npvGen2GetStr(ws, "path")
            netHost = npvGen2GetStr(ws, "host")
        case "grpc":
            netPath = npvGen2GetStr(grpc, "serviceName")
        }
        sni := npvGen2GetStr(tls, "serverName")
        tlsFlag := ""
        if security == "tls" || security == "reality" {
            tlsFlag = "tls"
        }
        obj := map[string]string{
            "v": "2", "ps": rem, "add": host, "port": strconv.Itoa(port),
            "id": uuid, "aid": "0", "scy": npvGen2Or(method, "auto"),
            "net": network, "type": "none", "host": netHost, "path": netPath,
            "tls": tlsFlag, "sni": sni,
        }
        b, err := json.Marshal(obj)
        if err != nil {
            return ""
        }
        return "vmess://" + base64.StdEncoding.EncodeToString(b)
    }
    return ""
}

// ─── ساخت لینک‌ها ───

func npvGen2Links(fields map[uint16][]byte) ([]string, error) {
    table, ok := fields[npvGen2SentinelSeq]
    if !ok {
        return nil, nil
    }
    var spec struct {
        Configs []any `json:"configs"`
    }
    if err := json.Unmarshal(table, &spec); err != nil {
        return nil, fmt.Errorf("npvs gen2: sentinel table: %w", err)
    }
    links := make([]string, 0, len(spec.Configs))
    for _, cfg := range spec.Configs {
        links = append(links, npvGen2Link(npvGen2Substitute(cfg, fields)))
    }
    return links, nil
}

// 🐞 npvGen2Link — ۵ لایه + fallback با مهر نسخه و گزارش لایه‌ها
func npvGen2Link(cfg any) string {
    obj, ok := cfg.(map[string]any)
    if !ok {
        return npvGen2Text(cfg)
    }
    remarks := npvGen2Text(obj["name"])
    address := npvGen2Text(obj["address"])

    var dbg []string
    dbg = append(dbg, "build="+npvsGen2BuildTag)

    // لایه ۱: پارسر مستقیم v2rayJson (رشته یا آبجکت)
    for _, key := range []string{"v2rayJson", "v2rRawJson"} {
        raw, present := obj[key]
        if !present {
            dbg = append(dbg, key+":absent")
            continue
        }
        switch t := raw.(type) {
        case string:
            dbg = append(dbg, fmt.Sprintf("%s:str(%d)", key, len(t)))
        case map[string]any:
            dbg = append(dbg, key+":map")
        default:
            dbg = append(dbg, fmt.Sprintf("%s:%T", key, raw))
        }
        if uris, info := npvGen2V2RayJSONLinksDbg(raw); len(uris) > 0 {
            log.Printf("[NPVS-GEN2] L1(%s): %d links", key, len(uris))
            return strings.Join(uris, "\n")
        } else if info != "" {
            dbg = append(dbg, key+"→"+info)
        }
    }

    // لایه ۲: موتورهای main.go
    for _, key := range []string{"v2rayJson", "v2rRawJson"} {
        if vj, ok := obj[key].(string); ok && strings.TrimSpace(vj) != "" {
            clean := cleanEmbeddedJSON(vj)
            if uris, err := extractURIsFromConfig(clean); err == nil && len(uris) > 0 {
                log.Printf("[NPVS-GEN2] L2(%s): %d links", key, len(uris))
                return strings.Join(uris, "\n")
            } else if err != nil {
                dbg = append(dbg, "L2err:"+err.Error())
            }
            if uris := regexExtractFromText(string(clean)); len(uris) > 0 {
                log.Printf("[NPVS-GEN2] L2-regex(%s)", key)
                return strings.Join(uris, "\n")
            }
        }
    }

    // لایه ۳: پروفایل‌های ساختاری
    if profile, ok := obj["v2rayProfile"].(map[string]any); ok {
        return npvGen2V2RayLink(remarks, address, npvGen2FlatMap(profile))
    }
    if ssh, ok := obj["sshConfig"].(map[string]any); ok {
        return npvGen2SSHText(remarks, npvGen2FlatMap(ssh))
    }
    for _, kind := range []string{"socksConfig", "socksProfile", "httpConfig", "httpProfile", "proxyConfig"} {
        if sub, ok := obj[kind].(map[string]any); ok {
            return npvGen2ProxyText(remarks, address, kind, npvGen2FlatMap(sub))
        }
    }

    // لایه ۴: اسکن کل آبجکت با regex
    if b, err := json.Marshal(obj); err == nil {
        if uris := regexExtractFromText(string(b)); len(uris) > 0 {
            log.Printf("[NPVS-GEN2] L4 object-scan: %d links", len(uris))
            return strings.Join(uris, "\n")
        }
        dbg = append(dbg, "L4:0")
    }

    // 🐞 fallback — با مهر نسخه و گزارش کامل
    kv := npvGen2KeyValues(npvGen2FlatMap(obj))
    return "🐞[" + strings.Join(dbg, " | ") + "]\n" + kv
}

func npvGen2V2RayLink(remarks, address string, p map[string]string) string {
    host := npvGen2Or(p["server"], address)
    port := npvGen2Int(p["serverPort"])
    if port == 0 {
        port = npvGen2Int(p["port"])
    }
    switch npvGen2Int(p["configType"]) {
    case 1:
        return npvGen2VMessLink(host, port, remarks, p)
    case 5:
        return npvGen2VLESSLink(host, port, remarks, p)
    case 6:
        return npvGen2TrojanLink(host, port, remarks, p)
    case 3:
        return npvGen2ShadowsocksLink(host, port, remarks, p)
    }
    return npvGen2KeyValues(p)
}

func npvGen2VLESSLink(host string, port int, remarks string, p map[string]string) string {
    q := npvGen2StreamQuery(p)
    q.Set("encryption", npvGen2VLESSEncryption(p["method"]))
    npvGen2Set(q, "flow", p["flow"])
    return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
        p["password"], host, port, q.Encode(), url.PathEscape(remarks))
}

func npvGen2TrojanLink(host string, port int, remarks string, p map[string]string) string {
    q := npvGen2StreamQuery(p)
    npvGen2Set(q, "flow", p["flow"])
    return fmt.Sprintf("trojan://%s@%s:%d?%s#%s",
        url.PathEscape(p["password"]), host, port, q.Encode(), url.PathEscape(remarks))
}

func npvGen2ShadowsocksLink(host string, port int, remarks string, p map[string]string) string {
    userInfo := base64.StdEncoding.EncodeToString([]byte(p["method"] + ":" + p["password"]))
    return fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, host, port, url.PathEscape(remarks))
}

func npvGen2VMessLink(host string, port int, remarks string, p map[string]string) string {
    headerType := npvGen2Or(p["headerType"], "none")
    hostHeader, path := p["host"], p["path"]

    switch npvGen2Network(p) {
    case "kcp":
        path = npvGen2Or(path, p["seed"])
    case "grpc":
        headerType = p["mode"]
        path = npvGen2Or(path, p["serviceName"])
        hostHeader = npvGen2Or(hostHeader, p["authority"])
    }

    obj := map[string]string{
        "v": "2", "ps": remarks, "add": host, "port": strconv.Itoa(port),
        "id": p["password"], "aid": strconv.Itoa(npvGen2Int(p["alterId"])),
        "scy": npvGen2Or(p["method"], "auto"), "net": npvGen2Or(p["network"], "tcp"),
        "type": headerType, "host": hostHeader, "path": path,
        "tls": npvGen2VMessTLS(p), "sni": p["sni"], "fp": p["fingerPrint"],
        "alpn": p["alpn"], "insecure": npvGen2VMessInsecure(p),
    }
    b, err := json.Marshal(obj)
    if err != nil {
        return npvGen2KeyValues(p)
    }
    return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func npvGen2Network(p map[string]string) string {
    switch network := strings.ToLower(strings.TrimSpace(p["network"])); network {
    case "tcp", "kcp", "ws", "httpupgrade", "xhttp", "http", "h2", "grpc":
        return network
    }
    return "tcp"
}

func npvGen2VMessTLS(p map[string]string) string {
    if security := p["security"]; security == "tls" || security == "reality" {
        return "tls"
    }
    return ""
}

func npvGen2VMessInsecure(p map[string]string) string {
    if p["security"] != "tls" {
        return ""
    }
    if npvGen2AllowInsecure(p) {
        return "1"
    }
    return "0"
}

func npvGen2StreamQuery(p map[string]string) url.Values {
    network := npvGen2Or(p["network"], "tcp")
    security := npvGen2Or(p["security"], "none")

    q := url.Values{}
    q.Set("type", network)
    q.Set("security", security)

    switch network {
    case "ws":
        npvGen2Set(q, "path", p["path"])
        npvGen2Set(q, "host", p["host"])
    case "grpc":
        npvGen2Set(q, "serviceName", p["serviceName"])
        npvGen2Set(q, "mode", npvGen2Or(p["mode"], p["xhttpMode"], "gun"))
        npvGen2Set(q, "authority", p["authority"])
    case "kcp":
        npvGen2Set(q, "headerType", p["headerType"])
        npvGen2Set(q, "seed", p["seed"])
    case "quic":
        npvGen2Set(q, "key", p["key"])
        npvGen2Set(q, "headerType", p["headerType"])
    case "xhttp", "httpupgrade":
        npvGen2Set(q, "path", p["path"])
        npvGen2Set(q, "host", p["host"])
        npvGen2Set(q, "mode", npvGen2Or(p["xhttpMode"], p["mode"]))
        npvGen2Set(q, "extra", p["xhttpExtra"])
    case "tcp", "raw":
        if headerType := p["headerType"]; headerType != "" && headerType != "none" {
            q.Set("headerType", headerType)
            npvGen2Set(q, "host", p["host"])
            npvGen2Set(q, "path", p["path"])
        }
    }

    switch security {
    case "tls":
        npvGen2Set(q, "sni", p["sni"])
        npvGen2Set(q, "fp", p["fingerPrint"])
        npvGen2Set(q, "alpn", p["alpn"])
        if npvGen2AllowInsecure(p) {
            q.Set("allowInsecure", "1")
        }
    case "reality":
        npvGen2Set(q, "sni", p["sni"])
        npvGen2Set(q, "fp", p["fingerPrint"])
        npvGen2Set(q, "pbk", p["publicKey"])
        npvGen2Set(q, "sid", p["shortId"])
        npvGen2Set(q, "spx", p["spiderX"])
    }
    return q
}

func npvGen2SSHText(remarks string, s map[string]string) string {
    target := s["sshHost"]
    if s["sshPort"] != "" {
        target += ":" + s["sshPort"]
    }
    query := url.Values{}
    npvGen2Set(query, "remarks", remarks)
    npvGen2Set(query, "sshConfigType", s["sshConfigType"])
    npvGen2Set(query, "httpProxy", s["httpProxy"])
    userInfo := url.UserPassword(s["sshUsername"], s["sshPassword"]).String()
    return "ssh://" + userInfo + "@" + target + "?" + query.Encode() + "#" + s["payload"]
}

func npvGen2ProxyText(remarks, address, kind string, p map[string]string) string {
    scheme := strings.TrimSuffix(strings.TrimSuffix(kind, "Config"), "Profile")
    target := npvGen2Or(p["server"], npvGen2Or(p["host"], address))
    if port := npvGen2Or(p["serverPort"], npvGen2Or(p["port"], p["localPort"])); port != "" {
        target += ":" + port
    }
    query := url.Values{}
    npvGen2Set(query, "remarks", remarks)
    for _, key := range npvGen2SortedKeys(p) {
        switch key {
        case "remarks", "server", "host", "port", "serverPort", "localPort":
            continue
        }
        npvGen2Set(query, key, p[key])
    }
    link := url.URL{Scheme: scheme, Host: target, RawQuery: query.Encode()}
    if user := p["username"]; user != "" {
        link.User = url.UserPassword(user, p["password"])
    } else if pass := p["password"]; pass != "" {
        link.User = url.User(pass)
    }
    return link.String()
}

func npvGen2KeyValues(p map[string]string) string {
    parts := make([]string, 0, len(p))
    for _, key := range npvGen2SortedKeys(p) {
        if p[key] == "" {
            continue
        }
        parts = append(parts, key+"="+p[key])
    }
    return strings.Join(parts, " ")
}

func npvGen2SortedKeys(p map[string]string) []string {
    keys := make([]string, 0, len(p))
    for k := range p {
        keys = append(keys, k)
    }
    sort.Strings(keys)
    return keys
}

func npvGen2SortedSeqs(m map[uint16][]byte) []uint16 {
    out := make([]uint16, 0, len(m))
    for k := range m {
        out = append(out, k)
    }
    sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
    return out
}

func npvGen2Substitute(v any, fields map[uint16][]byte) any {
    switch t := v.(type) {
    case float64:
        return decodeNpvSentinels(npvGen2FieldText(fields[uint16(t)]))
    case map[string]any:
        out := make(map[string]any, len(t))
        for k, x := range t {
            out[k] = npvGen2Substitute(x, fields)
        }
        return out
    case []any:
        out := make([]any, len(t))
        for i, x := range t {
            out[i] = npvGen2Substitute(x, fields)
        }
        return out
    default:
        return v
    }
}

func npvGen2FieldText(raw []byte) string {
    s := strings.TrimSpace(string(raw))
    if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
        var v string
        if err := json.Unmarshal([]byte(s), &v); err == nil {
            return v
        }
        return s[1 : len(s)-1]
    }
    return s
}

func npvGen2FlatMap(obj map[string]any) map[string]string {
    flat := make(map[string]string, len(obj))
    for k, v := range obj {
        flat[k] = npvGen2Text(v)
    }
    return flat
}

func npvGen2Text(v any) string {
    switch t := v.(type) {
    case nil:
        return ""
    case string:
        return t
    case float64:
        if t == float64(int64(t)) {
            return fmt.Sprintf("%d", int64(t))
        }
        return fmt.Sprintf("%v", t)
    case bool:
        return fmt.Sprintf("%t", t)
    }
    b, err := json.Marshal(v)
    if err != nil {
        return ""
    }
    return string(b)
}

func npvGen2Int(s string) int {
    n, err := strconv.Atoi(strings.TrimSpace(s))
    if err != nil {
        return 0
    }
    return n
}

func npvGen2AllowInsecure(p map[string]string) bool {
    for _, key := range []string{"tlsAllowInsecure", "insecure"} {
        switch strings.ToLower(strings.TrimSpace(p[key])) {
        case "true", "1", "yes":
            return true
        case "false", "0", "no":
            return false
        }
    }
    return false
}

func npvGen2Set(values url.Values, key, value string) {
    if value != "" {
        values.Set(key, value)
    }
}

func npvGen2Or(values ...string) string {
    for _, v := range values {
        if v != "" {
            return v
        }
    }
    return ""
}

func npvGen2VLESSEncryption(method string) string {
    if strings.TrimSpace(method) == "" {
        return "none"
    }
    return method
}

func (e *npvGen2Envelope) creatorMessage(metadata []byte) string {
    var meta npvGen2Metadata
    if err := json.Unmarshal(metadata, &meta); err != nil {
        return ""
    }
    var parts []string
    seen := map[string]bool{}
    for _, m := range []string{meta.Policy.DisplayMessage, meta.Policy.CustomServerMessage} {
        if m = strings.TrimSpace(strings.ReplaceAll(m, "\r\n", "\n")); m != "" && !seen[m] {
            seen[m] = true
            parts = append(parts, m)
        }
    }
    return strings.Join(parts, "\n")
}

func npvGen2RawFields(fields map[uint16][]byte) string {
    var sb strings.Builder
    for _, seq := range npvGen2SortedSeqs(fields) {
        if seq == npvGen2SentinelSeq {
            continue
        }
        fmt.Fprintf(&sb, "// seq=%-5d %s\n", seq, npvGen2FieldText(fields[seq]))
    }
    return strings.TrimSuffix(sb.String(), "\n")
}

// ═══════ ورودی Gen2 برای ربات ═══════

func npvsGen2Decrypt(fileData []byte, password string) (res *processResult, err error) {
    defer func() {
        if r := recover(); r != nil {
            res, err = nil, fmt.Errorf("🐞 خطای داخلی Gen2 (%s): %v", npvsGen2BuildTag, r)
        }
    }()

    env, err := parseNpvGen2Envelope(fileData)
    if err != nil {
        return nil, err
    }
    if env.method == npvGen2MethodRecipient {
        return nil, env.unlockHint(fmt.Errorf("npvs gen2: E2E"))
    }

    var metadata []byte
    var fields map[uint16][]byte

    if env.method == npvGen2MethodAppKey {
        metadata, fields, err = env.open("")
    } else {
        trimmed := strings.TrimSpace(password)
        noDash := strings.ReplaceAll(trimmed, "-", "")
        attempts := []string{trimmed, noDash, strings.ToUpper(noDash), strings.ToLower(noDash)}
        seen := map[string]bool{}
        for _, pw := range attempts {
            if pw == "" || seen[pw] {
                continue
            }
            seen[pw] = true
            metadata, fields, err = env.open(pw)
            if err == nil {
                break
            }
        }
    }
    if err != nil {
        return nil, env.unlockHint(err)
    }

    res = &processResult{}
    if msg := env.creatorMessage(metadata); msg != "" {
        res.Raw = append(res.Raw, "💬 "+msg)
    }

    links, lerr := npvGen2Links(fields)
    if lerr != nil {
        return nil, lerr
    }
    if len(links) > 0 {
        var flat []string
        for _, l := range links {
            for _, part := range strings.Split(l, "\n") {
                if p := strings.TrimSpace(part); p != "" {
                    flat = append(flat, p)
                }
            }
        }
        res.URIs = dedupeByURI(flat)
        log.Printf("[NPVS-GEN2] ✅ %d لینک تولید شد (build=%s)", len(res.URIs), npvsGen2BuildTag)
        return res, nil
    }
    if text := npvGen2RawFields(fields); text != "" {
        res.Raw = append(res.Raw, text)
        return res, nil
    }
    res.Raw = append(res.Raw, npvsNoLinkMessage())
    return res, nil
}
