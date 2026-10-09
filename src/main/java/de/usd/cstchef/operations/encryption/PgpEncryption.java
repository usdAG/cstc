package de.usd.cstchef.operations.encryption;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.pgp.PgpUtils;
import de.usd.cstchef.view.ui.VariableTextArea;

@OperationInfos(name = "PGP Encryption", category = OperationCategory.ENCRYPTION, description = "Encrypt input using an ASCII-armored or binary PGP public key.")
public class PgpEncryption extends Operation {

    private VariableTextArea publicKey;
    private JComboBox<String> algorithms;
    private JCheckBox asciiArmor;
    private JCheckBox integrityPacket;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        byte[] encrypted = PgpUtils.encrypt(input.getBytes(), this.publicKey.getText(),
                PgpUtils.encryptionAlgorithmForName((String) this.algorithms.getSelectedItem()), this.asciiArmor.isSelected(),
                this.integrityPacket.isSelected());
        return factory.createByteArray(encrypted);
    }

    @Override
    public void createUI() {
        this.publicKey = new VariableTextArea();
        this.addUIElement("Public Key", this.publicKey);

        this.algorithms = new JComboBox<>(new String[] { "AES-128", "AES-192", "AES-256" });
        this.algorithms.setSelectedItem("AES-256");
        this.addUIElement("Cipher", this.algorithms);

        this.asciiArmor = new JCheckBox();
        this.asciiArmor.setSelected(true);
        this.addUIElement("ASCII Armor", this.asciiArmor);

        this.integrityPacket = new JCheckBox();
        this.integrityPacket.setSelected(true);
        this.addUIElement("Integrity Packet", this.integrityPacket);
    }
}