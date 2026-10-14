package de.usd.cstchef.operations.encryption;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import de.usd.cstchef.operations.encryption.CipherUtils.CipherInfo;

public class CipherUtilsTest {

    private List<String> modesOf(String algorithm) {
        CipherInfo info = CipherUtils.getInstance().getCipherInfo(algorithm);
        return Arrays.asList(info.getModes());
    }

    // Since JDK 9 the providers register GCM only as complete transformations
    // (e.g. "Cipher.AES/GCM/NoPadding"), not in "SupportedModes". CipherUtils
    // must still surface GCM as a selectable mode.
    @Test
    public void aesOffersGcmMode() {
        assertTrue(modesOf("AES").contains("GCM"));
    }

    @Test
    public void sm4OffersGcmMode() {
        assertTrue(modesOf("SM4").contains("GCM"));
    }

    // The classic modes advertised via "SupportedModes" must survive the merge.
    @Test
    public void aesKeepsProviderAdvertisedModes() {
        List<String> modes = modesOf("AES");
        assertTrue(modes.contains("ECB"));
        assertTrue(modes.contains("CBC"));
    }

    // JDK 17 also registers key-wrap transformations ("Cipher.AES/KW/NoPadding").
    // Those are not block cipher modes usable by CryptOperation and must not
    // leak into the mode combo box.
    @Test
    public void aesDoesNotOfferKeyWrapModes() {
        List<String> modes = modesOf("AES");
        assertFalse(modes.contains("KW"));
        assertFalse(modes.contains("KWP"));
    }
}
