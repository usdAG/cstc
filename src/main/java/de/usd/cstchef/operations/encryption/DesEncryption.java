package de.usd.cstchef.operations.encryption;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "DES Encryption", category = OperationCategory.ENCRYPTION, description = "Encrypts via the des algorithm.")
public class DesEncryption extends EncryptionOperation {

    public DesEncryption() {
        super("DES");
    }

}
