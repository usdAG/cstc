package de.usd.cstchef.operations.pgp;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.encryption.PgpDecryption;
import de.usd.cstchef.operations.encryption.PgpEncryption;
import de.usd.cstchef.operations.signature.PgpSign;
import de.usd.cstchef.utils.UnitTestObjectFactory;
import de.usd.cstchef.view.ui.VariableTextArea;
import de.usd.cstchef.view.ui.VariableTextField;

public class PgpOperationsTest {

    private static final char[] PASSPHRASE = "cstc-passphrase".toCharArray();

    private CstcObjectFactory factory;
    private String publicKey;
    private String privateKey;

    @Before
    public void setup() throws Exception {
        if (Security.getProvider(PgpUtils.PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        this.factory = new UnitTestObjectFactory();
        KeyMaterial keyMaterial = generateKeyMaterial();
        this.publicKey = keyMaterial.publicKey;
        this.privateKey = keyMaterial.privateKey;
    }

    @Test
    public void encryptDecryptRoundTrip() throws Exception {
        PgpEncryption encrypt = new PgpEncryption();
        encrypt.factory = this.factory;
        ((VariableTextArea) encrypt.getUIElements().get("Public Key")).setText(this.publicKey);
        ((JComboBox<?>) encrypt.getUIElements().get("Cipher")).setSelectedItem("AES-256");
        ((JCheckBox) encrypt.getUIElements().get("ASCII Armor")).setSelected(true);
        ((JCheckBox) encrypt.getUIElements().get("Integrity Packet")).setSelected(true);

        ByteArray plain = this.factory.createByteArray("PGP keeps this message confidential.");
        ByteArray encrypted = encrypt.performOperation(plain, null);

        PgpDecryption decrypt = new PgpDecryption();
        decrypt.factory = this.factory;
        ((VariableTextArea) decrypt.getUIElements().get("Private Key")).setText(this.privateKey);
        ((VariableTextField) decrypt.getUIElements().get("Passphrase")).setText(new String(PASSPHRASE));

        ByteArray decrypted = decrypt.performOperation(encrypted, null);
        assertArrayEquals(plain.getBytes(), decrypted.getBytes());
    }

    @Test
    public void signProducesVerifiableDetachedSignature() throws Exception {
        PgpSign sign = new PgpSign();
        sign.factory = this.factory;
        ((VariableTextArea) sign.getUIElements().get("Private Key")).setText(this.privateKey);
        ((VariableTextField) sign.getUIElements().get("Passphrase")).setText(new String(PASSPHRASE));
        ((JComboBox<?>) sign.getUIElements().get("Hash")).setSelectedItem("SHA-256");
        ((JCheckBox) sign.getUIElements().get("ASCII Armor")).setSelected(true);

        ByteArray input = this.factory.createByteArray("PGP signatures must verify.");
        ByteArray signature = sign.performOperation(input, null);

        assertTrue(PgpUtils.verifyDetached(input.getBytes(), signature.getBytes(), this.publicKey));
    }

    private static KeyMaterial generateKeyMaterial() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        PGPDigestCalculator sha1Calculator = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        JcaPGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());
        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, pgpKeyPair,
                "cstc@example.org", sha1Calculator, null, null,
                new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256)
                        .setProvider(PgpUtils.PROVIDER),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calculator)
                        .setProvider(PgpUtils.PROVIDER).build(PASSPHRASE));

        PGPSecretKeyRing secretKeyRing = keyRingGenerator.generateSecretKeyRing();
        PGPPublicKeyRing publicKeyRing = keyRingGenerator.generatePublicKeyRing();
        return new KeyMaterial(armor(secretKeyRing.getEncoded()), armor(publicKeyRing.getEncoded()));
    }

    private static String armor(byte[] encoded) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ArmoredOutputStream armoredOutput = new ArmoredOutputStream(output)) {
            armoredOutput.write(encoded);
        }
        return output.toString("UTF-8");
    }

    private static final class KeyMaterial {
        private final String privateKey;
        private final String publicKey;

        private KeyMaterial(String privateKey, String publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }
}