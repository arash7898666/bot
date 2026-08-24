package main

import (
    "bytes"
    "fmt"
    "io"
    "net/http"
    "os"
    "strconv"
    "strings"
    "time"
)

// ═══════════════════════════════════════════════════════════════
//  tables_loader.go — بارگذاری خودکار جداول رمزنگاری White-Box AES
//
//  این فایل موقع راه‌اندازی ربات:
//   ۱) دنبال فایل محلی می‌گرده (TABLES_FILE یا tables.txt یا npvt.txt)
//   ۲) کشِ دانلود قبلی رو چک می‌کنه
//   ۳) خودش از گیت‌هاب دانلود می‌کنه
//
//  ⚠️ هیچ فایل خامی با پسوند .go داخل پوشه پروژه نگذارید!
//     (اسمش رو مثلاً tables.txt بگذارید)
// ═══════════════════════════════════════════════════════════════

var (
    tyBoxes    [16][256]uint32
    xorTable   [96][16][16]uint8
    mbl        [16][256]uint32
    tboxesLast [16][256]uint8
)

const tablesCacheFile = "npvt_tables_cache.txt"

var tableURLs = []string{
    "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/main/modules/impl/npvt.go",
    "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/master/modules/impl/npvt.go",
    "https://cdn.jsdelivr.net/gh/KernelDotDLL/Pantegnos@main/modules/impl/npvt.go",
    "https://cdn.jsdelivr.net/gh/KernelDotDLL/Pantegnos@master/modules/impl/npvt.go",
}

func init() {
    if err := loadTables(); err != nil {
        fmt.Println("❌ بارگذاری جداول ناموفق:", err)
        fmt.Println("راهنما: در گیت‌هاب فایل npvt.go را باز کنید، Raw بزنید،")
        fmt.Println("صفحه را ذخیره کنید و با نام tables.txt کنار ربات بگذارید.")
        os.Exit(1)
    }
}

func loadTables() error {
    src, fromNet, err := findTablesSource()
    if err != nil {
        return err
    }
    if err := parseAndFillTables(src); err != nil {
        return err
    }
    if fromNet {
        _ = os.WriteFile(tablesCacheFile, src, 0644)
    }
    fmt.Println("✅ جداول رمزنگاری بارگذاری شد")
    return nil
}

func findTablesSource() ([]byte, bool, error) {
    candidates := []string{
        os.Getenv("TABLES_FILE"),
        "tables.txt",
        "npvt.txt",
        "npvt.go.txt",
        tablesCacheFile,
    }
    for _, p := range candidates {
        if p == "" {
            continue
        }
        if b, err := os.ReadFile(p); err == nil {
            return b, false, nil
        }
    }

    var lastErr error
    for _, u := range append([]string{os.Getenv("TABLES_URL")}, tableURLs...) {
        if u == "" {
            continue
        }
        b, err := fetchURL(u)
        if err != nil {
            lastErr = err
            continue
        }
        return b, true, nil
    }
    return nil, false, fmt.Errorf("هیچ منبعی در دسترس نبود (آخرین خطا: %v)", lastErr)
}

func fetchURL(u string) ([]byte, error) {
    client := &http.Client{Timeout: 60 * time.Second}
    resp, err := client.Get(u)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("HTTP %d — %s", resp.StatusCode, u)
    }
    return io.ReadAll(io.LimitReader(resp.Body, 50<<20))
}

func parseAndFillTables(src []byte) error {
    steps := []struct {
        name string
        want int
        fill func([]uint64) error
    }{
        {"tyBoxes", 16 * 256, fillTyBoxes},
        {"mbl", 16 * 256, fillMbl},
        {"xorTable", 96 * 16 * 16, fillXorTable},
        {"tboxesLast", 16 * 256, fillTboxesLast},
    }
    for _, s := range steps {
        vals, err := extractNumbers(src, s.name)
        if err != nil {
            return err
        }
        if len(vals) != s.want {
            return fmt.Errorf("%s: %d عدد پیدا شد ولی %d لازم است — فایل ناقص است", s.name, len(vals), s.want)
        }
        if err := s.fill(vals); err != nil {
            return err
        }
    }

    // بررسی سلامت با مقادیر شناخته‌شده
    if tyBoxes[0][0] != 3213434693 || tyBoxes[1][0] != 2095281880 || mbl[0][0] != 0 {
        return fmt.Errorf("جداول با نسخه مورد انتظار نمی‌خوانند — فایل اشتباه است")
    }
    return nil
}

// از سورس Go، بلاک «var NAME = ...{...}» را پیدا و همه اعدادش را درمی‌آورد
func extractNumbers(src []byte, name string) ([]uint64, error) {
    i := bytes.Index(src, []byte("var "+name+" ="))
    if i < 0 {
        return nil, fmt.Errorf("var %s در فایل پیدا نشد", name)
    }
    rest := src[i:]
    open := bytes.IndexByte(rest, '{')
    if open < 0 {
        return nil, fmt.Errorf("%s: براکت باز پیدا نشد", name)
    }
    depth, end := 0, -1
    for j := open; j < len(rest); j++ {
        switch rest[j] {
        case '{':
            depth++
        case '}':
            depth--
            if depth == 0 {
                end = j
            }
        }
        if end >= 0 {
            break
        }
    }
    if end < 0 {
        return nil, fmt.Errorf("%s: جدول ناقص است (براکت بسته پیدا نشد)", name)
    }

    fields := strings.FieldsFunc(string(rest[open+1:end]), func(r rune) bool {
        return r == '{' || r == '}' || r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
    })
    vals := make([]uint64, 0, len(fields))
    for _, f := range fields {
        v, err := strconv.ParseUint(f, 10, 64)
        if err != nil {
            return nil, fmt.Errorf("%s: عدد نامعتبر %q", name, f)
        }
        vals = append(vals, v)
    }
    return vals, nil
}

func fillTyBoxes(v []uint64) error {
    k := 0
    for i := 0; i < 16; i++ {
        for j := 0; j < 256; j++ {
            tyBoxes[i][j] = uint32(v[k])
            k++
        }
    }
    return nil
}

func fillMbl(v []uint64) error {
    k := 0
    for i := 0; i < 16; i++ {
        for j := 0; j < 256; j++ {
            mbl[i][j] = uint32(v[k])
            k++
        }
    }
    return nil
}

func fillTboxesLast(v []uint64) error {
    k := 0
    for i := 0; i < 16; i++ {
        for j := 0; j < 256; j++ {
            if v[k] > 255 {
                return fmt.Errorf("tboxesLast: مقدار نامعتبر %d", v[k])
            }
            tboxesLast[i][j] = uint8(v[k])
            k++
        }
    }
    return nil
}

func fillXorTable(v []uint64) error {
    k := 0
    for i := 0; i < 96; i++ {
        for j := 0; j < 16; j++ {
            for l := 0; l < 16; l++ {
                if v[k] > 15 {
                    return fmt.Errorf("xorTable: مقدار نامعتبر %d (باید ۰ تا ۱۵ باشد)", v[k])
                }
                xorTable[i][j][l] = uint8(v[k])
                k++
            }
        }
    }
    return nil
}
