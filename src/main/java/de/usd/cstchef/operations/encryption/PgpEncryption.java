package de.usd.cstchef.operations.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextArea;

@OperationInfos(name = "PGP Encrypt", category = OperationCategory.ENCRYPTION, description = "Encrypt input with an OpenPGP public key (armored output).")
public class PgpEncryption extends Operation {

    private VariableTextArea publicKeyTextArea;

    @Override
    public void createUI() {
        this.publicKeyTextArea = new VariableTextArea();
        this.addUIElement("Public Key", this.publicKeyTextArea);
    }

    protected String getPublicKey() {
        return this.publicKeyTextArea.getText();
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String publicKey = getPublicKey();
        if (publicKey == null || publicKey.trim().isEmpty()) {
            throw new IllegalArgumentException("No public key available.");
        }
        return factory.createByteArray(encrypt(input.getBytes(), publicKey));
    }

    /**
     * Encrypts {@code data} to {@code armoredPublicKey} (an ASCII-armored OpenPGP public key)
     * using an AES-256 session key with integrity protection (MDC) and returns an armored
     * PGP message block. Uses BouncyCastle's lightweight operators so it does not depend on a
     * signed JCE provider (the assembled extension jar is unsigned).
     */
    protected byte[] encrypt(byte[] data, String armoredPublicKey) throws Exception {
        PGPPublicKey encryptionKey = readPublicKey(armoredPublicKey);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(out);

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                        .setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom()));
        encGen.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(encryptionKey));

        OutputStream encOut = encGen.open(armoredOut, new byte[4096]);

        PGPCompressedDataGenerator compGen = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream compOut = compGen.open(encOut);

        PGPLiteralDataGenerator litGen = new PGPLiteralDataGenerator();
        OutputStream litOut = litGen.open(compOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
        litOut.write(data);
        litGen.close();

        compGen.close();
        encGen.close();
        armoredOut.close();

        return out.toByteArray();
    }

    private PGPPublicKey readPublicKey(String armoredPublicKey) throws Exception {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredPublicKey.getBytes())),
                new BcKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> ringIt = pgpPub.getKeyRings();
        while (ringIt.hasNext()) {
            PGPPublicKeyRing ring = ringIt.next();
            Iterator<PGPPublicKey> keyIt = ring.getPublicKeys();
            while (keyIt.hasNext()) {
                PGPPublicKey key = keyIt.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("No encryption key found in the provided public key.");
    }
}
