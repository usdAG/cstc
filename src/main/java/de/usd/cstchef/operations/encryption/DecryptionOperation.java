package de.usd.cstchef.operations.encryption;

import javax.crypto.Cipher;

import burp.api.montoya.core.ByteArray;

public abstract class DecryptionOperation extends CryptOperation {

    public DecryptionOperation(String algorithm) {
        super(algorithm);
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        return factory.createByteArray(this.crypt(input.getBytes(), Cipher.DECRYPT_MODE, this.algorithm, (String) this.cipherMode.getSelectedItem(),
                (String) this.paddings.getSelectedItem()));
    }

}
