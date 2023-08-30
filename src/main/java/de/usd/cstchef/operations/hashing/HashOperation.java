package de.usd.cstchef.operations.hashing;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.swing.JComboBox;

import org.bouncycastle.util.encoders.Hex;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;

public abstract class HashOperation extends Operation {

    private JComboBox<String> sizeBox;
    private String algorithm;

    public HashOperation(String alogrithm) {
        super();
        this.algorithm = alogrithm;
    }

    public HashOperation(String alogrithm, String... sizes) {
        super();
        this.algorithm = alogrithm;
        createMyUI(sizes);
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        return ByteArray.byteArray(this.hash(input.getBytes()));
    }

    protected byte[] hash(byte[] input) throws NoSuchAlgorithmException {
        String algo = this.algorithm + (this.sizeBox != null ? (String) sizeBox.getSelectedItem() : "");

        MessageDigest digest = MessageDigest.getInstance(algo);
        byte[] hash = digest.digest(input);
        return Hex.encode(hash);
    }

    public void createMyUI(String[] sizes) {
        sizeBox = new JComboBox<String>(sizes);
        sizeBox.setSelectedIndex(0);
        this.addUIElement("Size", sizeBox);
    }

}
