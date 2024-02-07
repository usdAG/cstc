package de.usd.cstchef.operations.encryption;

import javax.crypto.Cipher;
import javax.swing.JComboBox;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.encryption.CipherUtils.CipherInfo;
import de.usd.cstchef.operations.signature.KeystoreOperation;

@OperationInfos(name = "RSA Encryption", category = OperationCategory.ENCRYPTION, description = "Encrypt input using a certificate")
public class RsaEncryption extends KeystoreOperation {

    private static String[] inOutModes = new String[] { "Raw", "Hex", "Base64" };

    protected String algorithm = "RSA";
    protected String cipherMode = "ECB";

    protected JComboBox<String> inputMode;
    protected JComboBox<String> outputMode;
    protected JComboBox<String> paddings;

    public RsaEncryption() {
        super();
        this.createMyUI();
    }

    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        if( ! this.certAvailable.isSelected() )
            throw new IllegalArgumentException("No certificate available.");

        String padding = (String)paddings.getSelectedItem();
        Cipher cipher = Cipher.getInstance(String.format("%s/%s/%s", algorithm, cipherMode, padding));
        cipher.init(Cipher.ENCRYPT_MODE, this.cert.getPublicKey());

        String selectedInputMode = (String)inputMode.getSelectedItem();
        String selectedOutputMode = (String)outputMode.getSelectedItem();
        byte[] in = new byte[0];
        if( selectedInputMode.equals("Hex") )
            in = Hex.decode(input.getBytes());
        if( selectedInputMode.equals("Base64") )
            in = Base64.decode(input.getBytes());

        byte[] encrypted = cipher.doFinal(input.getBytes());

        if( selectedOutputMode.equals("Hex") )
            encrypted = Hex.encode(encrypted);
        if( selectedOutputMode.equals("Base64") )
            encrypted = Base64.encode(encrypted);

        return factory.createByteArray(encrypted);
    }

    public void createMyUI() {

        super.createMyUI();

        CipherUtils utils = CipherUtils.getInstance();
        CipherInfo info = utils.getCipherInfo(this.algorithm);

        this.paddings = new JComboBox<>(info.getPaddings());
        this.addUIElement("Padding", this.paddings);

        this.inputMode = new JComboBox<>(inOutModes);
        this.addUIElement("Input", this.inputMode);

        this.outputMode = new JComboBox<>(inOutModes);
        this.addUIElement("Output", this.outputMode);
    }

}
