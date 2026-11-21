package io.github.enderdrate.techxpasskey.ctap;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * CTAP2 PIN/UV auth protocol 2: ECDH P-256 + HKDF-SHA-256,
 * AES-256-CBC (random IV) and HMAC-SHA-256.
 */
public final class PinProtocol {

    private static final SecureRandom RNG = new SecureRandom();

    private KeyPair keyPair;
    private byte[] hmacKey;
    private byte[] aesKey;

    /** Generates the platform key-agreement key and returns its COSE_Key. */
    public Map<Object, Object> keyAgreement() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"), RNG);
            keyPair = kpg.generateKeyPair();
            java.security.interfaces.ECPublicKey pub =
                    (java.security.interfaces.ECPublicKey) keyPair.getPublic();
            byte[] x = toFixed(pub.getW().getAffineX(), 32);
            byte[] y = toFixed(pub.getW().getAffineY(), 32);
            return Cbor.map(
                    1, 2,
                    3, -25,
                    -1, 1,
                    -2, x,
                    -3, y);
        } catch (Exception e) {
            throw new IllegalStateException("EC key generation failed", e);
        }
    }

    /** Derives the shared secret from the authenticator's COSE key. */
    public void setPeerKey(Map<Object, Object> cose) {
        try {
            byte[] x = Cbor.asBytes(Cbor.get(cose, -2));
            byte[] y = Cbor.asBytes(Cbor.get(cose, -3));
            if (x.length != 32 || y.length != 32) {
                throw new IllegalArgumentException("bad authenticator key");
            }
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
            ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            PublicKey peer = KeyFactory.getInstance("EC")
                    .generatePublic(new ECPublicKeySpec(point, spec));

            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(keyPair.getPrivate());
            ka.doPhase(peer, true);
            byte[] z = ka.generateSecret();

            byte[] zeroSalt = new byte[32];
            hmacKey = hkdf(zeroSalt, z, "CTAP2 HMAC key", 32);
            aesKey = hkdf(zeroSalt, z, "CTAP2 AES key", 32);
        } catch (Exception e) {
            throw new IllegalStateException("ECDH failed", e);
        }
    }

    public byte[] encrypt(byte[] plaintext) {
        try {
            byte[] iv = new byte[16];
            RNG.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new IvParameterSpec(iv));
            byte[] ct = cipher.doFinal(plaintext);
            return Cbor.concat(iv, ct);
        } catch (Exception e) {
            throw new IllegalStateException("AES encrypt failed", e);
        }
    }

    public byte[] decrypt(byte[] ivAndCt) {
        try {
            if (ivAndCt.length < 16 || (ivAndCt.length - 16) % 16 != 0) {
                throw new IllegalArgumentException("bad ciphertext length");
            }
            byte[] iv = Arrays.copyOfRange(ivAndCt, 0, 16);
            byte[] ct = Arrays.copyOfRange(ivAndCt, 16, ivAndCt.length);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new IvParameterSpec(iv));
            return cipher.doFinal(ct);
        } catch (Exception e) {
            throw new IllegalStateException("AES decrypt failed", e);
        }
    }

    public byte[] authenticate(byte[] message) {
        return hmac(hmacKey, message);
    }

    public byte[] token() {
        return pinToken;
    }

    private byte[] pinToken;

    public void setPinToken(byte[] token) {
        pinToken = token;
    }

    // ------------------------------------------------------------- primitives
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] hmac(byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC failed", e);
        }
    }

    public static byte[] hkdf(byte[] salt, byte[] ikm, String info, int length) {
        byte[] prk = hmac(salt, ikm);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] t = new byte[0];
        int counter = 1;
        byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
        while (out.size() < length) {
            byte[] input = Cbor.concat(t, infoBytes, new byte[]{(byte) counter});
            t = hmac(prk, input);
            out.write(t, 0, t.length);
            counter++;
        }
        byte[] okm = out.toByteArray();
        return Arrays.copyOf(okm, length);
    }

    public static byte[] toFixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        if (raw.length > length) {
            System.arraycopy(raw, raw.length - length, out, 0, length);
        } else {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }
}
