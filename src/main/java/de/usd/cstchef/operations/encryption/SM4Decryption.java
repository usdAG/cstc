package de.usd.cstchef.operations.encryption;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "SM4 Decryption", category = OperationCategory.ENCRYPTION, description = "Decrypts via the SM4 algorithm.")
public class SM4Decryption extends DecryptionOperation {

    public SM4Decryption() {
        super("SM4");
    }

}
