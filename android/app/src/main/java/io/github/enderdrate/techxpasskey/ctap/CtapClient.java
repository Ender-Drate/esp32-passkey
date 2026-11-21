package io.github.enderdrate.techxpasskey.ctap;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.github.enderdrate.techxpasskey.ble.BleClient;

/** CTAP 2.1 client for the TechXPassKey BLE authenticator. */
public class CtapClient {

    public static class CtapException extends IOException {
        public final int code;

        CtapException(int code) {
            super(statusName(code) + String.format(" (0x%02x)", code));
            this.code = code;
        }
    }

    public static class Info {
        public List<String> versions = new ArrayList<>();
        public byte[] aaguid = new byte[0];
        public Map<String, Boolean> options = new LinkedHashMap<>();
        public int maxMsgSize = 1024;
        public List<Long> pinProtocols = new ArrayList<>();
        public long firmwareVersion = 0;
        public int minPinLength = 4;
        public int remaining = 0;
        public int maxLargeBlob = 0;
        public List<String> transports = new ArrayList<>();

        public boolean pinSet() {
            return Boolean.TRUE.equals(options.get("clientPin"));
        }

        public boolean supports(String option) {
            return Boolean.TRUE.equals(options.get(option));
        }
    }

    public static class Credential {
        public String rpId = "";
        public String userName = "";
        public String displayName = "";
        public byte[] credId = new byte[0];
        public int credProtect = 0;
    }

    private static class PinSession {
        PinProtocol pp;
        Map<Object, Object> platformKey;
    }

    private final BleClient ble;
    private Info info;

    public CtapClient(BleClient ble) {
        this.ble = ble;
    }

    public Info getInfo() throws IOException {
        Map<Object, Object> m = callCbor(0x04, new LinkedHashMap<Object, Object>(), 15000);
        Info out = new Info();
        for (Object v : Cbor.asList(Cbor.get(m, 1))) {
            if (v instanceof String) out.versions.add((String) v);
        }
        out.aaguid = Cbor.asBytes(Cbor.get(m, 3));
        out.options.clear();
        for (Map.Entry<?, ?> e : Cbor.asMap(Cbor.get(m, 4)).entrySet()) {
            if (e.getKey() instanceof String) {
                out.options.put((String) e.getKey(), Boolean.TRUE.equals(e.getValue()));
            }
        }
        out.maxMsgSize = (int) Cbor.asLong(Cbor.get(m, 5), 1024);
        for (Object v : Cbor.asList(Cbor.get(m, 6))) {
            out.pinProtocols.add(Cbor.asLong(v, 1));
        }
        out.firmwareVersion = Cbor.asLong(Cbor.get(m, 0x0E), 0);
        out.minPinLength = (int) Cbor.asLong(Cbor.get(m, 0x0D), 4);
        out.remaining = (int) Cbor.asLong(Cbor.get(m, 0x14), 0);
        out.maxLargeBlob = (int) Cbor.asLong(Cbor.get(m, 0x0B), 0);
        for (Object v : Cbor.asList(Cbor.get(m, 9))) {
            if (v instanceof String) out.transports.add((String) v);
        }
        info = out;
        return out;
    }

    // ------------------------------------------------------------------- PIN
    public void setPin(String newPin) throws IOException {
        if (newPin.length() < info.minPinLength || newPin.length() > 63) {
            throw new IOException("PIN 长度必须在 " + info.minPinLength + "–63 之间");
        }
        PinSession s = handshake();
        byte[] newPinEnc = s.pp.encrypt(padPin(newPin));
        Map<Object, Object> params = Cbor.map(
                3, s.platformKey,
                4, s.pp.authenticate(newPinEnc),
                5, newPinEnc);
        clientPin(0x03, params);
    }

    public void changePin(String currentPin, String newPin) throws IOException {
        if (newPin.length() < info.minPinLength || newPin.length() > 63) {
            throw new IOException("新 PIN 长度必须在 " + info.minPinLength + "–63 之间");
        }
        PinSession s = handshake();
        byte[] hashEnc = s.pp.encrypt(pinHash(currentPin));
        byte[] newPinEnc = s.pp.encrypt(padPin(newPin));
        Map<Object, Object> params = Cbor.map(
                3, s.platformKey,
                4, s.pp.authenticate(Cbor.concat(newPinEnc, hashEnc)),
                5, newPinEnc,
                6, hashEnc);
        clientPin(0x04, params);
    }

    private PinSession handshake() throws IOException {
        PinSession s = new PinSession();
        Map<Object, Object> ka = clientPin(0x02, new LinkedHashMap<Object, Object>());
        Map<Object, Object> cose = Cbor.asMap(Cbor.get(ka, 1));
        s.pp = new PinProtocol();
        s.platformKey = s.pp.keyAgreement();
        s.pp.setPeerKey(cose);
        return s;
    }

    /** Gets a pinUvAuthToken with the given permissions (0x03 mc|ga, 0x14 cm|lbw). */
    public PinSession openPin(String pin, int permissions, String rpId) throws IOException {
        PinSession s = handshake();
        byte[] hashEnc = s.pp.encrypt(pinHash(pin));
        Map<Object, Object> params = Cbor.map(
                3, s.platformKey,
                6, hashEnc,
                9, permissions);
        if (rpId != null) params.put(0x0A, rpId);
        params.put(4, s.pp.authenticate(hashEnc));
        Map<Object, Object> resp = clientPin(0x09, params);
        byte[] token = s.pp.decrypt(Cbor.asBytes(Cbor.get(resp, 2)));
        s.pp.setPinToken(token);
        return s;
    }

    private Map<Object, Object> clientPin(int subCommand, Map<Object, Object> params)
            throws IOException {
        Map<Object, Object> req = Cbor.map(1, 2, 2, subCommand);
        req.putAll(params);
        return callCbor(0x06, req, 20000);
    }

    // -------------------------------------------------------- credentials
    public List<Credential> listCredentials(String pin) throws IOException {
        boolean needsPin = info != null && info.pinSet();
        PinSession session = null;
        if (needsPin) {
            if (pin == null || pin.isEmpty()) throw new IOException("设备已设置 PIN，请输入 PIN");
            session = openPin(pin, 0x14, null);
        }

        List<Credential> result = new ArrayList<>();
        Map<Object, Object> first = credentialMgmt(0x02, null, session);
        long totalRps = Cbor.asLong(Cbor.get(first, 5), 0);
        List<Map<Object, Object>> rps = new ArrayList<>();
        rps.add(first);
        for (int i = 1; i < totalRps; i++) {
            rps.add(credentialMgmt(0x03, null, session));
        }
        for (Map<Object, Object> rp : rps) {
            Map<Object, Object> rpEntity = Cbor.asMap(Cbor.get(rp, 3));
            String rpId = Cbor.asString(Cbor.get(rpEntity, "id"), "unknown");
            byte[] rpHash = Cbor.asBytes(Cbor.get(rp, 4));
            Map<Object, Object> firstCred =
                    credentialMgmt(0x04, Cbor.map(1, rpHash), session);
            long total = Cbor.asLong(Cbor.get(firstCred, 9), 1);
            result.add(parseCredential(firstCred, rpId));
            for (int i = 1; i < total; i++) {
                result.add(parseCredential(credentialMgmt(0x05, null, session), rpId));
            }
        }
        return result;
    }

    public void deleteCredential(String pin, byte[] credId) throws IOException {
        boolean needsPin = info != null && info.pinSet();
        PinSession session = null;
        if (needsPin) {
            if (pin == null || pin.isEmpty()) throw new IOException("设备已设置 PIN，请输入 PIN");
            session = openPin(pin, 0x14, null);
        }
        Map<Object, Object> descriptor = Cbor.map("type", "public-key", "id", credId);
        credentialMgmt(0x06, Cbor.map(2, descriptor), session);
    }

    private Map<Object, Object> credentialMgmt(int subCommand, Map<Object, Object> params,
                                               PinSession session) throws IOException {
        Map<Object, Object> req = Cbor.map(1, subCommand);
        if (params != null) req.put(2, params);
        if (session != null) {
            byte[] message = params == null
                    ? new byte[]{(byte) subCommand}
                    : Cbor.concat(new byte[]{(byte) subCommand}, Cbor.encode(params));
            req.put(3, 2);
            req.put(4, PinProtocol.hmac(session.pp.token(), message));
        }
        return callCbor(0x0A, req, 20000);
    }

    private static Credential parseCredential(Map<Object, Object> raw, String rpId) {
        Credential c = new Credential();
        c.rpId = rpId;
        Map<Object, Object> user = Cbor.asMap(Cbor.get(raw, 6));
        c.userName = Cbor.asString(Cbor.get(user, "name"), "");
        c.displayName = Cbor.asString(Cbor.get(user, "displayName"), "");
        Map<Object, Object> descriptor = Cbor.asMap(Cbor.get(raw, 7));
        c.credId = Cbor.asBytes(Cbor.get(descriptor, "id"));
        c.credProtect = (int) Cbor.asLong(Cbor.get(raw, 0x0A), 0);
        return c;
    }

    // ---------------------------------------------------------------- transport
    private Map<Object, Object> callCbor(int command, Map<Object, Object> request, long timeout)
            throws IOException {
        byte[] payload = Cbor.concat(new byte[]{(byte) command}, Cbor.encode(request));
        byte[] response = ble.call(0x90, payload, timeout);
        int status = response[0] & 0xFF;
        if (status != 0) throw new CtapException(status);
        byte[] body = Cbor.slice(response, 1);
        if (body.length == 0) return new LinkedHashMap<>();
        return Cbor.asMap(Cbor.decode(body));
    }

    private static byte[] pinHash(String pin) {
        byte[] digest = PinProtocol.sha256(pin.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(digest, 16);
    }

    private static byte[] padPin(String pin) {
        byte[] bytes = pin.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 63) throw new IllegalArgumentException("PIN 太长");
        byte[] out = new byte[64];
        System.arraycopy(bytes, 0, out, 0, bytes.length);
        return out;
    }

    private static String statusName(int code) {
        switch (code) {
            case 0x11: return "CBOR 类型错误";
            case 0x12: return "CBOR 无效";
            case 0x14: return "缺少参数";
            case 0x19: return "凭据已存在";
            case 0x22: return "凭据无效";
            case 0x27: return "操作被拒绝";
            case 0x2E: return "没有凭据";
            case 0x31: return "PIN 不正确";
            case 0x32: return "PIN 已锁定";
            case 0x33: return "PIN 认证失败";
            case 0x34: return "PIN 认证被锁定";
            case 0x35: return "设备未设置 PIN";
            case 0x36: return "需要 PIN";
            case 0x37: return "PIN 不符合策略";
            case 0x3A: return "操作超时";
            default: return "CTAP 错误";
        }
    }
}
