package de.usd.cstchef.operations.encryption;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "DES Decryption", category = OperationCategory.ENCRYPTION, description = "Decrypts via the des algorithm.")
public class DesDecryption extends DecryptionOperation {

	public DesDecryption() {
		super("DES");
	}

}
