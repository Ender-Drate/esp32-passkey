#include "pk_cbor.h"

#include <string.h>

#include <algorithm>
#include <utility>

namespace cbor {

static bool read_len(const uint8_t* buf, size_t len, size_t& off, uint8_t& ai, uint64_t& v) {
    if (off >= len) return false;
    ai = buf[off++] & 0x1F;
    if (ai < 24) {
        v = ai;
        return true;
    }
    uint8_t n;
    switch (ai) {
        case 24: n = 1; break;
        case 25: n = 2; break;
        case 26: n = 4; break;
        case 27: n = 8; break;
        default: return false;  // indefinite lengths / reserved
    }
    if (off + n > len) return false;
    v = 0;
    for (uint8_t i = 0; i < n; i++) v = (v << 8) | buf[off++];
    return true;
}

static bool parse_inner(const uint8_t* buf, size_t len, size_t& off, Value& out, int depth) {
    if (depth > 16 || off >= len) return false;
    uint8_t major = buf[off] >> 5;
    uint8_t ai_peek = buf[off] & 0x1F;
    uint8_t ai;
    uint64_t v = 0;
    if (!read_len(buf, len, off, ai, v)) return false;

    switch (major) {
        case 0:
            out.type = T_UINT;
            out.i = (int64_t)v;
            return true;
        case 1:
            out.type = T_INT;
            out.i = -1 - (int64_t)v;
            return true;
        case 2:
        case 3: {
            if (v > len - off) return false;
            out.type = (major == 2) ? T_BYTES : T_TEXT;
            out.data = buf + off;
            out.len = (size_t)v;
            off += (size_t)v;
            return true;
        }
        case 4: {
            if (v > 4096) return false;
            out.type = T_ARRAY;
            out.items.reserve((size_t)v);
            for (uint64_t i = 0; i < v; i++) {
                Value item;
                if (!parse_inner(buf, len, off, item, depth + 1)) return false;
                out.items.push_back(std::move(item));
            }
            return true;
        }
        case 5: {
            if (v > 2048) return false;
            out.type = T_MAP;
            out.items.reserve((size_t)v * 2);
            for (uint64_t i = 0; i < v; i++) {
                Value k, val;
                if (!parse_inner(buf, len, off, k, depth + 1)) return false;
                if (!parse_inner(buf, len, off, val, depth + 1)) return false;
                out.items.push_back(std::move(k));
                out.items.push_back(std::move(val));
            }
            return true;
        }
        case 6: {
            // tags are transparent for our purposes
            return parse_inner(buf, len, off, out, depth + 1);
        }
        case 7: {
            switch (ai_peek) {
                case 20: out.type = T_BOOL; out.b = false; return true;
                case 21: out.type = T_BOOL; out.b = true; return true;
                case 22: out.type = T_NULL; return true;
                case 23: out.type = T_NULL; return true;
                default: return false;
            }
        }
        default:
            return false;
    }
}

bool parse(const uint8_t* buf, size_t len, Value& out) {
    size_t off = 0;
    out = Value();
    return parse_inner(buf, len, off, out, 0);
}

const Value* Value::get(int64_t key) const {
    if (type != T_MAP) return nullptr;
    for (size_t i = 0; i + 1 < items.size(); i += 2) {
        const Value& k = items[i];
        if (k.is_int() && k.i == key) return &items[i + 1];
    }
    return nullptr;
}

const Value* Value::get(const char* key) const {
    if (type != T_MAP) return nullptr;
    size_t n = strlen(key);
    for (size_t i = 0; i + 1 < items.size(); i += 2) {
        const Value& k = items[i];
        if (k.type == T_TEXT && k.len == n && memcmp(k.data, key, n) == 0) return &items[i + 1];
    }
    return nullptr;
}

void Writer::raw(const void* p, size_t n) {
    const uint8_t* b = (const uint8_t*)p;
    buf.insert(buf.end(), b, b + n);
}

void Writer::header(uint8_t major, uint64_t value) {
    uint8_t m = (uint8_t)(major << 5);
    if (value < 24) {
        uint8_t x = m | (uint8_t)value;
        raw(&x, 1);
    } else if (value <= 0xFF) {
        uint8_t x[2] = {(uint8_t)(m | 24), (uint8_t)value};
        raw(x, 2);
    } else if (value <= 0xFFFF) {
        uint8_t x[3] = {(uint8_t)(m | 25), (uint8_t)(value >> 8), (uint8_t)value};
        raw(x, 3);
    } else if (value <= 0xFFFFFFFFULL) {
        uint8_t x[5] = {(uint8_t)(m | 26), (uint8_t)(value >> 24), (uint8_t)(value >> 16),
                        (uint8_t)(value >> 8), (uint8_t)value};
        raw(x, 5);
    } else {
        uint8_t x[9] = {(uint8_t)(m | 27)};
        for (int i = 0; i < 8; i++) x[1 + i] = (uint8_t)(value >> (56 - 8 * i));
        raw(x, 9);
    }
}

void Writer::bytes(const void* p, size_t n) {
    header(2, n);
    if (n) raw(p, n);
}

void Writer::text(const char* s) { text(s, strlen(s)); }

void Writer::text(const char* s, size_t n) {
    header(3, n);
    if (n) raw(s, n);
}

bool cose_key_p256(const Value& key, uint8_t x[32], uint8_t y[32]) {    if (key.type != T_MAP) return false;
    const Value* kty = key.get(1);
    const Value* crv = key.get(-1);
    const Value* cx = key.get(-2);
    const Value* cy = key.get(-3);
    if (!kty || !crv || !cx || !cy) return false;
    if (kty->as_int(-1) != 2) return false;       // EC2
    if (crv->as_int(-1) != 1) return false;       // P-256
    if (cx->type != T_BYTES || cx->len != 32) return false;
    if (cy->type != T_BYTES || cy->len != 32) return false;
    memcpy(x, cx->data, 32);
    memcpy(y, cy->data, 32);
    return true;
}

namespace {

struct EncKey {
    std::vector<uint8_t> enc;
    const Value* val = nullptr;
};

bool key_less(const EncKey& a, const EncKey& b) {
    size_t n = a.enc.size() < b.enc.size() ? a.enc.size() : b.enc.size();
    int c = n ? memcmp(a.enc.data(), b.enc.data(), n) : 0;
    if (c != 0) return c < 0;
    return a.enc.size() < b.enc.size();
}

void encode_value(const Value& v, Writer& w) {
    switch (v.type) {
        case T_NULL: w.null(); break;
        case T_BOOL: w.boolean(v.b); break;
        case T_UINT:
        case T_INT: w.integer(v.i); break;
        case T_BYTES: w.bytes(v.data, v.len); break;
        case T_TEXT: w.text((const char*)v.data, v.len); break;
        case T_ARRAY:
            w.array(v.items.size());
            for (const Value& it : v.items) encode_value(it, w);
            break;
        case T_MAP: {
            std::vector<EncKey> keys;
            keys.reserve(v.items.size() / 2);
            for (size_t i = 0; i + 1 < v.items.size(); i += 2) {
                EncKey k;
                Writer kw;
                encode_value(v.items[i], kw);
                k.enc = std::move(kw.buf);
                k.val = &v.items[i + 1];
                keys.push_back(std::move(k));
            }
            std::sort(keys.begin(), keys.end(), key_less);
            w.map(keys.size());
            for (const EncKey& k : keys) {
                w.raw(k.enc.data(), k.enc.size());
                encode_value(*k.val, w);
            }
            break;
        }
    }
}

}  // namespace

void encode_canonical(const Value& v, Writer& w) { encode_value(v, w); }

}  // namespace cbor
