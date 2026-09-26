package main

import (
    "bytes"
    "compress/zlib"
    "crypto/sha256"
    "fmt"
    "io"
    "log"
    "os"
    "sync"
)

// ═══════ NPVS Gen2 White-Box — پورت دقیق از Pantegnos npvs_gen2_wb.go ═══════

const (
    npvGen2BlockSize   = 57344
    npvGen2BlockCount  = 13
    npvGen2PageSize    = 4096
    npvGen2TablesSize  = npvGen2BlockCount*npvGen2BlockSize + npvGen2PageSize // 749568
    npvGen2AppKeyLabel = "npvtunnel/appkey/v2 "
)

var npvGen2ShiftRows = [16]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}

// gen2_tables.bin.z (فشرده zlib) — محلی یا دانلود از Pantegnos + کش دیسک
func npvGen2GetTablesZ() ([]byte, error) {
    cache := "npvs_cache_gen2_tables.bin.z"
    if b, err := os.ReadFile(cache); err == nil && len(b) > 1000 {
        return b, nil
    }
    for _, p := range []string{os.Getenv("NPVS_DIR"), "npvs", "assets/npvs", "."} {
        if p == "" {
            continue
        }
        full := p + "/gen2_tables.bin.z"
        if b, err := os.ReadFile(full); err == nil && len(b) > 1000 {
            _ = os.WriteFile(cache, b, 0644)
            log.Printf("[NPVS-GEN2] جدول از %s لود شد (%d بایت)", full, len(b))
            return b, nil
        }
    }

    // 🔍 همه مسیرهای محتمل — ✅ ریپوی اصلی: FrontierTM/Pantegnos
    urls := []string{
        "https://raw.githubusercontent.com/FrontierTM/Pantegnos/main/internal/modules/impl/assets/npvs/gen2_tables.bin.z",
        "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/main/internal/modules/impl/assets/npvs/gen2_tables.bin.z",
        "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/master/internal/modules/impl/assets/npvs/gen2_tables.bin.z",
        "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/main/assets/npvs/gen2_tables.bin.z",
        "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/master/assets/npvs/gen2_tables.bin.z",
        "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/main/npvs/gen2_tables.bin.z",
        "https://raw.githubusercontent.com/KernelDotDLL/Pantegnos/master/npvs/gen2_tables.bin.z",
        "https://cdn.jsdelivr.net/gh/FrontierTM/Pantegnos@main/internal/modules/impl/assets/npvs/gen2_tables.bin.z",
        "https://cdn.jsdelivr.net/gh/KernelDotDLL/Pantegnos@main/internal/modules/impl/assets/npvs/gen2_tables.bin.z",
    }
    for _, url := range urls {
        b, err := fetchURL(url)
        if err == nil && len(b) > 1000 {
            _ = os.WriteFile(cache, b, 0644)
            log.Printf("[NPVS-GEN2] ✅ جدول از %s دانلود شد (%d بایت)", url, len(b))
            return b, nil
        }
        log.Printf("[NPVS-GEN2] ❌ %s → err=%v len=%d", url, err, len(b))
    }
    return nil, fmt.Errorf("gen2_tables.bin.z از هیچ مسیری دریافت نشد — لینک Raw را دستی بده")
}

var (
    npvGen2TablesOnce sync.Once
    npvGen2TablesBuf  []byte
    npvGen2TablesErr  error
)

func loadNpvGen2Tables() ([]byte, error) {
    npvGen2TablesOnce.Do(func() {
        zb, err := npvGen2GetTablesZ()
        if err != nil {
            npvGen2TablesErr = err
            return
        }
        zr, err := zlib.NewReader(bytes.NewReader(zb))
        if err != nil {
            npvGen2TablesErr = fmt.Errorf("npvs: gen2 tables: %w", err)
            return
        }
        defer zr.Close()
        tables, err := io.ReadAll(zr)
        if err != nil {
            npvGen2TablesErr = fmt.Errorf("npvs: gen2 tables: %w", err)
            return
        }
        if len(tables) != npvGen2TablesSize {
            npvGen2TablesErr = fmt.Errorf("npvs: gen2 tables: got %d bytes, want %d", len(tables), npvGen2TablesSize)
            return
        }
        npvGen2TablesBuf = tables
        log.Printf("✅ جداول Gen2 White-Box آماده شد (%d بایت)", len(tables))
    })
    return npvGen2TablesBuf, npvGen2TablesErr
}

// پیش‌بارگذاری در استارت
func init() {
    go func() {
        if _, err := loadNpvGen2Tables(); err != nil {
            log.Printf("⚠️ جداول Gen2: %v (فایل‌های appKey باز نمی‌شوند تا رفع شود)", err)
        }
    }()
}

func npvGen2A16(salt []byte) ([16]byte, error) {
    var out [16]byte
    if len(salt) != 16 {
        return out, fmt.Errorf("npvs: gen2 salt must be 16 bytes, got %d", len(salt))
    }

    tables, err := loadNpvGen2Tables()
    if err != nil {
        return out, err
    }

    var state [16]byte
    copy(state[:], salt)

    for b := 0; b < npvGen2BlockCount; b++ {
        block := tables[b*npvGen2BlockSize : (b+1)*npvGen2BlockSize]

        npvGen2Shift(&state)
        for j := 0; j < 4; j++ {
            npvGen2Group(&state, block, j)
        }
    }

    page := tables[npvGen2BlockCount*npvGen2BlockSize:]
    for i := 0; i < 16; i++ {
        out[i] = page[0x100*i+int(state[npvGen2ShiftRows[i]])]
    }
    return out, nil
}

func npvGen2KDK(a16 [16]byte, configID []byte) [32]byte {
    h := sha256.New()
    h.Write([]byte(npvGen2AppKeyLabel))
    h.Write(a16[:])
    h.Write(configID)
    var kdk [32]byte
    copy(kdk[:], h.Sum(nil))
    return kdk
}

func npvGen2Shift(s *[16]byte) {
    var t [16]byte
    for i := 0; i < 16; i++ {
        t[i] = s[npvGen2ShiftRows[i]]
    }
    *s = t
}

func npvGen2Group(state *[16]byte, block []byte, j int) {
    s := state[4*j : 4*j+4]

    args := npvGen2GroupArgs(block, 0x6000, j, s)
    written := npvGen2Sub7DC0(block, j, uint64(args[0]), uint64(args[1]), uint64(args[2]), uint64(args[3]))
    copy(s, written[:])

    args = npvGen2GroupArgs(block, 0xA000, j, s)
    written = npvGen2Sub7DC0(block, j, uint64(args[0]), uint64(args[1]), uint64(args[2]), uint64(args[3]))
    copy(s, written[:])
}

func npvGen2GroupArgs(block []byte, half, j int, s []byte) [4]uint32 {
    base := half + 0x1000*j
    return [4]uint32{
        npvGen2BE32(block, base+4*int(s[0])),
        npvGen2BE32(block, base+0x400+4*int(s[1])),
        npvGen2BE32(block, base+0x800+4*int(s[2])),
        npvGen2BE32(block, base+0xC00+4*int(s[3])),
    }
}

func npvGen2BE32(block []byte, off int) uint32 {
    return uint32(block[off])<<24 | uint32(block[off+1])<<16 | uint32(block[off+2])<<8 | uint32(block[off+3])
}

func npvGen2Sub7DC0(block []byte, i int, x3, x4, x5, x6 uint64) [4]byte {
    m32 := func(v uint64) uint64 { return v & 0xFFFFFFFF }
    at := func(addr uint64) uint64 { return uint64(block[addr]) }

    var out [4]byte
    var x0, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17 uint64

    x2 := uint64(i)
    x3, x4, x5, x6 = m32(x3), m32(x4), m32(x5), m32(x6)

    x8 = m32(x2 + m32(x2<<1))
    x12 = m32(x3 >> 0x14)
    x11 = m32(x3 >> 0x18)
    x13 = (x4 >> 0x18) & 0xf
    x14 = m32(x5 >> 0x18)
    x10 = x6
    x9 = m32(x8 << 3)
    x8 = x4
    x12 &= 0xf0
    x12 += x13
    x13 = m32(x5 >> 0x14)
    x16 = x8 >> 0x1c
    x9 &= 0xFFFFFFFF
    x11 &= 0xf0
    x14 &= 0xf0
    x15 = m32(x6>>0x18) & 0xf
    x13 &= 0xf0
    x17 = m32(x3 >> 0x10)
    x9 <<= 8
    x8 &= 0xf
    x13 += x15
    x17 &= 0xf0
    x11 = x9 + x11
    x14 = x9 + x14
    x12 = x9 + x12
    x16 = at(x11 + x16)
    x14 += x10 >> 28
    x12 = at(x12 + 0x200)
    x13 = x9 + x13
    x0 = m32(x6>>0x14) & 0xf
    x14 = at(x14 + 0x100)
    x15 = x9 + (x16 << 4)
    x13 = at(x13 + 0x300)
    x12 = x9 + (x12 << 4)
    x16 = m32(x4>>0x14) & 0xf
    x10 &= 0xf
    x14 = x15 + x14
    x15 = m32(x5 >> 0x10)
    x12 += x13
    x13 = m32(x3 >> 0xc)
    x14 = at(x14 + 0x400)
    x12 = at(x12 + 0x500)
    x15 &= 0xf0
    x16 = x17 + x16
    x15 += x0
    x0 = m32(x4>>0x10) & 0xf
    x17 = m32(x5 >> 0xc)
    x12 |= x14 << 4
    x13 &= 0xf0
    x14 = m32(x6>>0x10) & 0xf
    x13 += x0
    x17 &= 0xf0
    x16 = x9 + x16
    out[0] = byte(x12)
    x13 = x9 + x13
    x12 = x17 + x14
    x14 = at(x16 + 0x600)
    x13 = at(x13 + 0x800)
    x15 = x9 + x15
    x12 = x9 + x12
    x15 = at(x15 + 0x700)
    x16 = m32(x5 >> 8)
    x12 = at(x12 + 0x900)
    x14 = x9 + (x14 << 4)
    x13 = x9 + (x13 << 4)
    x0 = m32(x6>>0xc) & 0xf
    x17 = m32(x3 >> 8)
    x14 += x15
    x12 = x13 + x12
    x13 = x16 & 0xf0
    x14 = at(x14 + 0xa00)
    x12 = at(x12 + 0xb00)
    x15 = m32(x3 >> 4)
    x13 += x0
    x0 = m32(x4>>8) & 0xf
    x16 = m32(x4>>0xc) & 0xf
    x12 |= x14 << 4
    x14 = x15 & 0xf0
    x17 &= 0xf0
    x14 += x0
    x15 = x9 + 0xc00
    x0 = m32(x5 >> 4)
    x17 = x15 + x17
    out[1] = byte(x12)
    x12 = m32(x6>>8) & 0xf
    x16 = at(x17 + x16)
    x14 = x9 + x14
    x17 = x0 & 0xf0
    x14 = at(x14 + 0xe00)
    x12 = x17 + x12
    x13 = x15 + x13
    x12 = x9 + x12
    x13 = at(x13 + 0x100)
    x15 = x9 + (x16 << 4)
    x12 = at(x12 + 0xf00)
    x14 = x9 + (x14 << 4)
    x16 = 0x1000
    x13 = x15 + x13
    x17 = m32(x6>>4) & 0xf
    x0 = x5 & 0xf0
    x12 = x14 + x12
    x14 = 0x1100
    x13 = at(x13 + x16)
    x12 = at(x12 + x14)
    x14 = 0x1200
    x15 = m32(x4>>4) & 0xf
    x16 = x3 & 0xf0
    x17 = x0 + x17
    x14 = x9 + x14
    x12 |= x13 << 4
    x13 = (x3 & 0xf) << 4
    x16 = x14 + x16
    out[2] = byte(x12)
    x8 = x13 + x8
    x12 = x14 + x17
    x14 = (x5 & 0xf) << 4
    x13 = at(x16 + x15)
    x8 = x9 + x8
    x15 = 0x1400
    x12 = at(x12 + 0x100)
    x8 = at(x8 + x15)
    x10 = x14 + x10
    x14 = 0x1500
    x10 = x9 + x10
    x13 = x9 + (x13 << 4)
    x10 = at(x10 + x14)
    x8 = x9 + (x8 << 4)
    x9 = x13 + x12
    x12 = 0x1600
    x8 += x10
    x10 = 0x1700
    x9 = at(x9 + x12)
    x8 = at(x8 + x10)
    x8 |= x9 << 4
    out[3] = byte(x8)
    return out
}
