package de.usd.cstchef.operations.encryption;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;

import org.junit.Test;

public class GcmCipherTest {

    private static final byte[] KEY_128 = "0123456789abcdef".getBytes();
    private static final byte[] NONCE_12 = "0123456789ab".getBytes();
    private static final byte[] IV_16 = "0123456789abcdef".getBytes();

    private byte[] crypt(int mode, String algorithm, String cipherMode, String padding,
            byte[] key, byte[] iv, byte[] input) throws Exception {
        Cipher cipher = CryptOperation.createInitializedCipher(mode, algorithm, cipherMode, padding, key, iv);
        return cipher.doFinal(input);
    }

    @Test
    public void aesGcmRoundTrip() throws Exception {
        byte[] plain = "attack at dawn".getBytes("UTF-8");

        byte[] enc = crypt(Cipher.ENCRYPT_MODE, "AES", "GCM", "NOPADDING", KEY_128, NONCE_12, plain);
        byte[] dec = crypt(Cipher.DECRYPT_MODE, "AES", "GCM", "NOPADDING", KEY_128, NONCE_12, enc);

        assertArrayEquals(plain, dec);
    }

    // GCM appends a 16 byte authentication tag, so ciphertext != plaintext length.
    @Test
    public void aesGcmAppendsAuthTag() throws Exception {
        byte[] plain = new byte[32];

        byte[] enc = crypt(Cipher.ENCRYPT_MODE, "AES", "GCM", "NOPADDING", KEY_128, NONCE_12, plain);

        assertFalse(enc.length == plain.length);
        assert enc.length == plain.length + 16;
    }

    @Test(expected = AEADBadTagException.class)
    public void aesGcmDetectsTampering() throws Exception {
        byte[] plain = "attack at dawn".getBytes("UTF-8");

        byte[] enc = crypt(Cipher.ENCRYPT_MODE, "AES", "GCM", "NOPADDING", KEY_128, NONCE_12, plain);
        enc[0] ^= 0x01;
        crypt(Cipher.DECRYPT_MODE, "AES", "GCM", "NOPADDING", KEY_128, NONCE_12, enc);
    }

    @Test
    public void sm4GcmRoundTrip() throws Exception {
        byte[] plain = "attack at dawn".getBytes("UTF-8");

        byte[] enc = crypt(Cipher.ENCRYPT_MODE, "SM4", "GCM", "NOPADDING", KEY_128, NONCE_12, plain);
        byte[] dec = crypt(Cipher.DECRYPT_MODE, "SM4", "GCM", "NOPADDING", KEY_128, NONCE_12, enc);

        assertArrayEquals(plain, dec);
    }

    // The refactored cipher setup must keep the existing non-AEAD modes working.
    @Test
    public void aesCbcRoundTripStillWorks() throws Exception {
        byte[] plain = "legacy mode".getBytes("UTF-8");

        byte[] enc = crypt(Cipher.ENCRYPT_MODE, "AES", "CBC", "PKCS5PADDING", KEY_128, IV_16, plain);
        byte[] dec = crypt(Cipher.DECRYPT_MODE, "AES", "CBC", "PKCS5PADDING", KEY_128, IV_16, enc);

        assertArrayEquals(plain, dec);
        assertFalse(Arrays.equals(plain, enc));
    }

    @Test
    public void aesEcbRoundTripStillWorks() throws Exception {
        byte[] plain = "legacy mode".getBytes("UTF-8");

        byte[] enc = crypt(Cipher.ENCRYPT_MODE, "AES", "ECB", "PKCS5PADDING", KEY_128, new byte[0], plain);
        byte[] dec = crypt(Cipher.DECRYPT_MODE, "AES", "ECB", "PKCS5PADDING", KEY_128, new byte[0], enc);

        assertArrayEquals(plain, dec);
    }
}
