package de.usd.cstchef.operations.encryption;

import javax.crypto.Cipher;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;

public abstract class DecryptionOperation extends CryptOperation {

    public DecryptionOperation(String algorithm) {
        super(algorithm);
    }

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        /*
         * javax.crypto.Cipher uses PKCS7 internally but names it PKCS5.
         * The only difference between the two padding mechanisms is the
         * block size they're working with and to not confuse the user
         * we name the combobox item accordingly (see GitHub Issue #166)
         */
        String padding = (String) this.paddings.getSelectedItem();
        if(padding.equals("PKCS5PADDING / PKCS7PADDING")) {
            padding = "PKCS5PADDING";
        }

        return factory.createByteArray(this.crypt(input.getBytes(), Cipher.DECRYPT_MODE, this.algorithm, (String) this.cipherMode.getSelectedItem(),
                padding));
    }

}
