package de.usd.cstchef.operations.encryption;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "SM4 Encryption", category = OperationCategory.ENCRYPTION, description = "Encrypts via the SM4 algorithm.")
public class SM4Encryption extends EncryptionOperation {

    public SM4Encryption() {
        super("SM4");
    }

}
