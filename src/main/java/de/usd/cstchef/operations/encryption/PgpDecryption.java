package de.usd.cstchef.operations.encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Iterator;

import javax.swing.JComboBox;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.FormatTextField;
import de.usd.cstchef.view.ui.VariableTextArea;

@OperationInfos(name = "PGP Decrypt", category = OperationCategory.ENCRYPTION, description = "Decrypt a PGP message with an OpenPGP private key.")
public class PgpDecryption extends Operation {

    private static String[] outModes = new String[] { "Raw", "Hex", "Base64" };

    private VariableTextArea privateKeyTextArea;
    private FormatTextField passphraseField;
    private JComboBox<String> outputMode;

    @Override
    public void createUI() {
        this.privateKeyTextArea = new VariableTextArea();
        this.addUIElement("Private Key", this.privateKeyTextArea);

        this.passphraseField = new FormatTextField();
        this.addUIElement("Passphrase", this.passphraseField);

        this.outputMode = new JComboBox<>(outModes);
        this.addUIElement("Output", this.outputMode);
    }

    protected String getPrivateKey() {
        return this.privateKeyTextArea.getText();
    }

    protected String getPassphrase() throws Exception {
        return this.passphraseField.getText().toString();
    }

    protected String getOutputMode() {
        return (String) this.outputMode.getSelectedItem();
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String privateKey = getPrivateKey();
        if (privateKey == null || privateKey.trim().isEmpty()) {
            throw new IllegalArgumentException("No private key available.");
        }

        byte[] decrypted = decrypt(input.getBytes(), privateKey, getPassphrase());

        String mode = getOutputMode();
        if ("Hex".equals(mode)) {
            decrypted = Hex.encode(decrypted);
        } else if ("Base64".equals(mode)) {
            decrypted = Base64.encode(decrypted);
        }

        return factory.createByteArray(decrypted);
    }

    /**
     * Decrypts an armored (or binary) PGP message {@code message} using {@code armoredPrivateKey}
     * (an ASCII-armored OpenPGP private key) unlocked with {@code passphrase}. Returns the raw
     * decrypted bytes; integrity (MDC) is verified when present. Uses BouncyCastle's lightweight
     * operators so it does not depend on a signed JCE provider.
     */
    protected byte[] decrypt(byte[] message, String armoredPrivateKey, String passphrase) throws Exception {
        PGPSecretKeyRingCollection secretKeys = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(armoredPrivateKey.getBytes())),
                new BcKeyFingerprintCalculator());

        InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(message));
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);

        Object firstObject = pgpFact.nextObject();
        PGPEncryptedDataList encList;
        if (firstObject instanceof PGPEncryptedDataList) {
            encList = (PGPEncryptedDataList) firstObject;
        } else {
            encList = (PGPEncryptedDataList) pgpFact.nextObject();
        }

        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData encryptedData = null;
        Iterator<PGPEncryptedData> it = encList.getEncryptedDataObjects();
        while (it.hasNext()) {
            PGPEncryptedData data = it.next();
            if (data instanceof PGPPublicKeyEncryptedData) {
                PGPPublicKeyEncryptedData pubKeyData = (PGPPublicKeyEncryptedData) data;
                PGPSecretKey secretKey = secretKeys.getSecretKey(pubKeyData.getKeyID());
                if (secretKey != null) {
                    privateKey = secretKey.extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(
                            new BcPGPDigestCalculatorProvider()).build(passphrase.toCharArray()));
                    encryptedData = pubKeyData;
                    break;
                }
            }
        }

        if (privateKey == null) {
            throw new IllegalArgumentException("No matching private key found for the encrypted message.");
        }

        InputStream clear = encryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));

        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
        Object messageObject = plainFact.nextObject();

        if (messageObject instanceof PGPCompressedData) {
            PGPCompressedData compressed = (PGPCompressedData) messageObject;
            plainFact = new JcaPGPObjectFactory(compressed.getDataStream());
            messageObject = plainFact.nextObject();
        }

        if (!(messageObject instanceof PGPLiteralData)) {
            throw new PGPException("Unexpected PGP packet; message does not contain literal data.");
        }

        PGPLiteralData literalData = (PGPLiteralData) messageObject;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputStream literalIn = literalData.getInputStream();
        byte[] buffer = new byte[4096];
        int len;
        while ((len = literalIn.read(buffer)) > 0) {
            out.write(buffer, 0, len);
        }

        if (encryptedData.isIntegrityProtected() && !encryptedData.verify()) {
            throw new PGPException("Message failed integrity check.");
        }

        return out.toByteArray();
    }
}
