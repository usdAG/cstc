package de.usd.cstchef.operations.encryption;

import javax.crypto.Cipher;

public abstract class DecryptionOperation extends CryptOperation {

    public DecryptionOperation(String algorithm) {
        super(algorithm);
    }

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        return this.crypt(input, Cipher.DECRYPT_MODE, this.algorithm, (String) this.cipherMode.getSelectedItem(),
                (String) this.paddings.getSelectedItem());
    }

}
