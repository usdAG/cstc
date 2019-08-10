package de.usd.cstchef.operations.encrpytion;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "AES Encryption", category = OperationCategory.ENCRYPTION, description = "Encrypts via the aes algorithm.")
public class AesEncryption extends EncryptionOperation {

	public AesEncryption() {
		super("AES");
	}

}
