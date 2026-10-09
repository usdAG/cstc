package de.usd.cstchef.operations.encryption;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.pgp.PgpUtils;
import de.usd.cstchef.view.ui.VariableTextArea;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "PGP Decryption", category = OperationCategory.ENCRYPTION, description = "Decrypt input using an ASCII-armored or binary PGP private key.")
public class PgpDecryption extends Operation {

    private VariableTextArea privateKey;
    private VariableTextField passphrase;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        byte[] decrypted = PgpUtils.decrypt(input.getBytes(), this.privateKey.getText(), this.passphrase.getText().toCharArray());
        return factory.createByteArray(decrypted);
    }

    @Override
    public void createUI() {
        this.privateKey = new VariableTextArea();
        this.addUIElement("Private Key", this.privateKey);

        this.passphrase = new VariableTextField();
        this.addUIElement("Passphrase", this.passphrase);
    }
}