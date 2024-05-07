package de.usd.cstchef.operations.encryption;

import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JComboBox;

import org.bouncycastle.util.encoders.Hex;

import burp.api.montoya.core.ByteArray;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.encryption.CipherUtils.CipherInfo;
import de.usd.cstchef.view.ui.FormatTextField;

public abstract class CryptOperation extends Operation {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static String[] inOutModes = new String[] { "Raw", "Hex", "Base64" };

    protected String algorithm;
    protected FormatTextField ivTxt;
    protected FormatTextField keyTxt;

    protected JComboBox<String> cipherMode;
    protected JComboBox<String> inputMode;
    protected JComboBox<String> outputMode;
    protected JComboBox<String> paddings;

    public CryptOperation(String algorithm) {
        super();
        this.algorithm = algorithm;
        this.createMyUI();
    }

    protected byte[] crypt(byte[] input, int cipherMode, String algorithm, String mode, String padding)
            throws Exception {
        ByteArray key = keyTxt.getText();
        ByteArray iv = ivTxt.getText();

        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
        Cipher cipher;
        if(algorithm.equals("SM4")){
             cipher = Cipher.getInstance(String.format("%s/%s/%s", algorithm, mode, padding), BouncyCastleProvider.PROVIDER_NAME);
        }
        else{
            cipher = Cipher.getInstance(String.format("%s/%s/%s", algorithm, mode, padding));
        }

        if( mode.equals("ECB") ) {
            cipher.init(cipherMode, secretKeySpec);
        } else {
            cipher.init(cipherMode, secretKeySpec, ivSpec);
        }

        String selectedInputMode = (String)inputMode.getSelectedItem();
        String selectedOutputMode = (String)outputMode.getSelectedItem();

        if( selectedInputMode.equals("Hex") )
            input = Hex.decode(input);
        if( selectedInputMode.equals("Base64") )
            input = Base64.decode(input);

        byte[] encrypted = cipher.doFinal(input);

        if( selectedOutputMode.equals("Hex") )
            encrypted = Hex.encode(encrypted);
        if( selectedOutputMode.equals("Base64") )
            encrypted = Base64.encode(encrypted);

        return encrypted;
    }

    public void createMyUI() {
        this.ivTxt = new FormatTextField();
        this.ivTxt.addOption("Empty");
        this.ivTxt.setDefault("Empty");
        this.addUIElement("IV", this.ivTxt);

        this.keyTxt = new FormatTextField();
        this.addUIElement("Key", this.keyTxt);
        CipherUtils utils = CipherUtils.getInstance();

        CipherInfo info = utils.getCipherInfo(this.algorithm);
        this.cipherMode = new JComboBox<>(info.getModes());
        this.addUIElement("Mode", this.cipherMode);

        this.paddings = new JComboBox<>(info.getPaddings());
        this.addUIElement("Padding", this.paddings);

        this.inputMode = new JComboBox<>(inOutModes);
        this.addUIElement("Input", this.inputMode);

        this.outputMode = new JComboBox<>(inOutModes);
        this.addUIElement("Output", this.outputMode);
    }

}
