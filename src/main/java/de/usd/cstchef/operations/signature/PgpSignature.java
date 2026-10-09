package de.usd.cstchef.operations.signature;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.FormatTextField;
import de.usd.cstchef.view.ui.VariableTextArea;

@OperationInfos(name = "PGP Signature", category = OperationCategory.SIGNATURE, description = "Create a detached OpenPGP signature (armored).")
public class PgpSignature extends Operation {

    private VariableTextArea privateKeyTextArea;
    private FormatTextField passphraseField;

    @Override
    public void createUI() {
        this.privateKeyTextArea = new VariableTextArea();
        this.addUIElement("Private Key", this.privateKeyTextArea);

        this.passphraseField = new FormatTextField();
        this.addUIElement("Passphrase", this.passphraseField);
    }

    protected String getPrivateKey() {
        return this.privateKeyTextArea.getText();
    }

    protected String getPassphrase() throws Exception {
        return this.passphraseField.getText().toString();
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String privateKey = getPrivateKey();
        if (privateKey == null || privateKey.trim().isEmpty()) {
            throw new IllegalArgumentException("No private key available.");
        }
        return factory.createByteArray(sign(input.getBytes(), privateKey, getPassphrase()));
    }

    /**
     * Creates a detached, ASCII-armored OpenPGP signature (SHA-256) over {@code data} using
     * {@code armoredPrivateKey} (an ASCII-armored OpenPGP private key) unlocked with
     * {@code passphrase}. Uses BouncyCastle's lightweight operators so it does not depend on a
     * signed JCE provider.
     */
    protected byte[] sign(byte[] data, String armoredPrivateKey, String passphrase) throws Exception {
        PGPSecretKey secretKey = readSigningKey(armoredPrivateKey);
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(
                new BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray()));

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        signatureGenerator.update(data);

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(out);
        BCPGOutputStream bcpgOut = new BCPGOutputStream(armoredOut);
        signatureGenerator.generate().encode(bcpgOut);
        bcpgOut.close();
        armoredOut.close();

        return out.toByteArray();
    }

    private PGPSecretKey readSigningKey(String armoredPrivateKey) throws Exception {
        PGPSecretKeyRingCollection secretKeys = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredPrivateKey.getBytes())),
                new BcKeyFingerprintCalculator());

        Iterator<PGPSecretKeyRing> ringIt = secretKeys.getKeyRings();
        while (ringIt.hasNext()) {
            PGPSecretKeyRing ring = ringIt.next();
            Iterator<PGPSecretKey> keyIt = ring.getSecretKeys();
            while (keyIt.hasNext()) {
                PGPSecretKey key = keyIt.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("No signing key found in the provided private key.");
    }
}
