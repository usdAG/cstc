package de.usd.cstchef.operations.encrpytion;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "AES Decryption", category = OperationCategory.ENCRYPTION, description = "Decrypts via the aes algorithm.")
public class AesDecryption extends DecryptionOperation {

	public AesDecryption() {
		super("AES");
	}

}