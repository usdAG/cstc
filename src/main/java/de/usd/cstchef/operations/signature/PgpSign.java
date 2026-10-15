package de.usd.cstchef.operations.signature;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.pgp.PgpUtils;
import de.usd.cstchef.view.ui.VariableTextArea;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "PGP Signature", category = OperationCategory.SIGNATURE, description = "Create a detached PGP signature using an ASCII-armored or binary private key.")
public class PgpSign extends Operation {

    private VariableTextArea privateKey;
    private VariableTextField passphrase;
    private JComboBox<String> hashAlgorithm;
    private JCheckBox asciiArmor;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        byte[] signature = PgpUtils.signDetached(input.getBytes(), this.privateKey.getText(),
                this.passphrase.getText().toCharArray(),
                PgpUtils.hashAlgorithmForName((String) this.hashAlgorithm.getSelectedItem()), this.asciiArmor.isSelected());
        return factory.createByteArray(signature);
    }

    @Override
    public void createUI() {
        this.privateKey = new VariableTextArea();
        this.addUIElement("Private Key", this.privateKey);

        this.passphrase = new VariableTextField();
        this.addUIElement("Passphrase", this.passphrase);

        this.hashAlgorithm = new JComboBox<>(new String[] { "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512" });
        this.hashAlgorithm.setSelectedItem("SHA-256");
        this.addUIElement("Hash", this.hashAlgorithm);

        this.asciiArmor = new JCheckBox();
        this.asciiArmor.setSelected(true);
        this.addUIElement("ASCII Armor", this.asciiArmor);
    }
}