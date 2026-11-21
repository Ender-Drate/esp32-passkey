package io.github.enderdrate.techxpasskey.ctap;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal CBOR (RFC 8949) codec used by CTAP2.
 *
 * Encoding emits canonical maps (keys sorted by their encoded bytes) so that
 * the pinUvAuthParam messages computed here match the authenticator's
 * canonical re-encoding.
 */
public final class Cbor {

    private Cbor() {
    }

    // ---------------------------------------------------------------- encode
    public static byte[] encode(Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        write(out, value);
        return out.toByteArray();
    }

    @SuppressWarnings("unchecked")
    private static void write(ByteArrayOutputStream out, Object v) {
        if (v == null) {
            out.write(0xF6);
        } else if (v instanceof Boolean) {
            out.write(((Boolean) v) ? 0xF5 : 0xF4);
        } else if (v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte) {
            long n = ((Number) v).longValue();
            if (n >= 0) {
                typeAndLength(out, 0, n);
            } else {
                typeAndLength(out, 1, -1 - n);
            }
        } else if (v instanceof byte[]) {
            byte[] b = (byte[]) v;
            typeAndLength(out, 2, b.length);
            out.write(b, 0, b.length);
        } else if (v instanceof String) {
            byte[] b = ((String) v).getBytes(StandardCharsets.UTF_8);
            typeAndLength(out, 3, b.length);
            out.write(b, 0, b.length);
        } else if (v instanceof List) {
            List<?> list = (List<?>) v;
            typeAndLength(out, 4, list.size());
            for (Object item : list) {
                write(out, item);
            }
        } else if (v instanceof Map) {
            List<Map.Entry<?, ?>> entries = new ArrayList<>(((Map<?, ?>) v).entrySet());
            final Map<Object, byte[]> encodedKeys = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : entries) {
                encodedKeys.put(e.getKey(), encode(e.getKey()));
            }
            entries.sort(new Comparator<Map.Entry<?, ?>>() {
                @Override
                public int compare(Map.Entry<?, ?> a, Map.Entry<?, ?> b) {
                    return compareBytes(encodedKeys.get(a.getKey()), encodedKeys.get(b.getKey()));
                }
            });
            typeAndLength(out, 5, entries.size());
            for (Map.Entry<?, ?> e : entries) {
                byte[] kb = encodedKeys.get(e.getKey());
                out.write(kb, 0, kb.length);
                write(out, e.getValue());
            }
        } else {
            throw new IllegalArgumentException("unsupported CBOR value: " + v.getClass());
        }
    }

    private static int compareBytes(byte[] a, byte[] b) {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int d = (a[i] & 0xFF) - (b[i] & 0xFF);
            if (d != 0) return d;
        }
        return a.length - b.length;
    }

    private static void typeAndLength(ByteArrayOutputStream out, int major, long value) {
        int m = major << 5;
        if (value < 24) {
            out.write(m | (int) value);
        } else if (value <= 0xFF) {
            out.write(m | 24);
            out.write((int) value);
        } else if (value <= 0xFFFF) {
            out.write(m | 25);
            out.write((int) (value >> 8) & 0xFF);
            out.write((int) value & 0xFF);
        } else if (value <= 0xFFFFFFFFL) {
            out.write(m | 26);
            for (int i = 3; i >= 0; i--) {
                out.write((int) (value >> (8 * i)) & 0xFF);
            }
        } else {
            out.write(m | 27);
            for (int i = 7; i >= 0; i--) {
                out.write((int) (value >> (8 * i)) & 0xFF);
            }
        }
    }

    // ---------------------------------------------------------------- decode
    public static Object decode(byte[] data) {
        int[] off = {0};
        Object value = read(data, off);
        if (off[0] != data.length) {
            throw new IllegalArgumentException("extraneous CBOR data");
        }
        return value;
    }

    private static Object read(byte[] b, int[] off) {
        if (off[0] >= b.length) throw new IllegalArgumentException("truncated CBOR");
        int ib = b[off[0]++] & 0xFF;
        int major = ib >> 5;
        int ai = ib & 0x1F;
        long value;
        if (ai < 24) {
            value = ai;
        } else if (ai == 24) {
            value = b[off[0]++] & 0xFF;
        } else if (ai == 25) {
            value = ((long) (b[off[0]] & 0xFF) << 8) | (b[off[0] + 1] & 0xFF);
            off[0] += 2;
        } else if (ai == 26) {
            value = 0;
            for (int i = 0; i < 4; i++) {
                value = (value << 8) | (b[off[0]++] & 0xFF);
            }
        } else if (ai == 27) {
            value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | (b[off[0]++] & 0xFF);
            }
        } else {
            throw new IllegalArgumentException("unsupported CBOR length encoding");
        }

        switch (major) {
            case 0:
                return value;
            case 1:
                return -1 - value;
            case 2: {
                int len = (int) value;
                if (off[0] + len > b.length) throw new IllegalArgumentException("truncated bytes");
                byte[] out = new byte[len];
                System.arraycopy(b, off[0], out, 0, len);
                off[0] += len;
                return out;
            }
            case 3: {
                int len = (int) value;
                if (off[0] + len > b.length) throw new IllegalArgumentException("truncated text");
                String s = new String(b, off[0], len, StandardCharsets.UTF_8);
                off[0] += len;
                return s;
            }
            case 4: {
                int len = (int) value;
                List<Object> list = new ArrayList<>(len);
                for (int i = 0; i < len; i++) {
                    list.add(read(b, off));
                }
                return list;
            }
            case 5: {
                int len = (int) value;
                Map<Object, Object> map = new LinkedHashMap<>();
                for (int i = 0; i < len; i++) {
                    Object k = read(b, off);
                    Object v = read(b, off);
                    map.put(k, v);
                }
                return map;
            }
            case 6:
                return read(b, off);
            case 7:
                if (ai == 20) return false;
                if (ai == 21) return true;
                if (ai == 22) return null;
                throw new IllegalArgumentException("unsupported CBOR simple value");
            default:
                throw new IllegalArgumentException("bad CBOR major type");
        }
    }

    // ---------------------------------------------------------------- helpers
    public static Map<Object, Object> map(Object... kv) {
        Map<Object, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }

    public static List<Object> list(Object... items) {
        List<Object> l = new ArrayList<>(items.length);
        for (Object o : items) l.add(o);
        return l;
    }

    public static Object get(Object map, long key) {
        if (!(map instanceof Map)) return null;
        for (Map.Entry<?, ?> e : ((Map<?, ?>) map).entrySet()) {
            if (e.getKey() instanceof Number && ((Number) e.getKey()).longValue() == key) {
                return e.getValue();
            }
        }
        return null;
    }

    public static Object get(Object map, String key) {
        if (!(map instanceof Map)) return null;
        return ((Map<?, ?>) map).get(key);
    }

    public static long asLong(Object o, long def) {
        return o instanceof Number ? ((Number) o).longValue() : def;
    }

    public static String asString(Object o, String def) {
        return o instanceof String ? (String) o : def;
    }

    public static byte[] asBytes(Object o) {
        return o instanceof byte[] ? (byte[]) o : new byte[0];
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asList(Object o) {
        return o instanceof List ? (List<Object>) o : new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    public static Map<Object, Object> asMap(Object o) {
        return o instanceof Map ? (Map<Object, Object>) o : new LinkedHashMap<>();
    }

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    public static byte[] slice(byte[] data, int from) {
        byte[] out = new byte[data.length - from];
        System.arraycopy(data, from, out, 0, out.length);
        return out;
    }
}
