// Minimal CBOR (RFC 8949) reader/writer for CTAP2.
// Reader produces a small DOM; byte/text values point into the input buffer.
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <vector>

namespace cbor {

enum Type : uint8_t {
    T_NULL = 0,
    T_BOOL,
    T_INT,      // negative integer
    T_UINT,     // non-negative integer
    T_BYTES,
    T_TEXT,
    T_ARRAY,
    T_MAP,
};

struct Value {
    Type type = T_NULL;
    bool b = false;
    int64_t i = 0;
    const uint8_t* data = nullptr;
    size_t len = 0;
    std::vector<Value> items;   // array elements, or map [key0,val0,key1,val1,...]

    bool is_int() const { return type == T_UINT || type == T_INT; }
    int64_t as_int(int64_t def = 0) const { return is_int() ? i : def; }
    bool as_bool(bool def = false) const { return type == T_BOOL ? b : def; }

    const Value* get(int64_t key) const;
    const Value* get(const char* key) const;
    size_t map_size() const { return type == T_MAP ? items.size() / 2 : 0; }
};

// Parses exactly one item at the start of buf. Returns false on malformed input.
bool parse(const uint8_t* buf, size_t len, Value& out);

class Writer {
public:
    std::vector<uint8_t> buf;

    void reserve(size_t n) { buf.reserve(n); }
    size_t size() const { return buf.size(); }
    const uint8_t* data() const { return buf.data(); }
    void clear() { buf.clear(); }

    void raw(const void* p, size_t n);
    void header(uint8_t major, uint64_t value);
    void uint(uint64_t v) { header(0, v); }
    void nint(int64_t v) { header(1, (uint64_t)(-1 - v)); }
    void integer(int64_t v) { if (v >= 0) uint((uint64_t)v); else nint(v); }
    void bytes(const void* p, size_t n);
    void text(const char* s);
    void text(const char* s, size_t n);
    void array(size_t n) { header(4, n); }
    void map(size_t n) { header(5, n); }
    void boolean(bool v) { uint8_t x[2] = {0xF5, 0xF4}; raw(&x[v ? 0 : 1], 1); }
    void null() { uint8_t x = 0xF6; raw(&x, 1); }
    void tag(uint64_t t) { header(6, t); }

    // Convenience: append a text key/value pair to an open map.
    void key(const char* k) { text(k); }
    void key(int64_t k) { integer(k); }
};

// Decode a COSE_Key (EC2 P-256) into x/y. Returns false if the key is not EC2/P-256.
bool cose_key_p256(const Value& key, uint8_t x[32], uint8_t y[32]);

// Re-encode a value using the CTAP2 canonical rules (definite lengths,
// shortest integer encoding, map keys sorted by encoded bytes).
void encode_canonical(const Value& v, Writer& w);

}  // namespace cbor
