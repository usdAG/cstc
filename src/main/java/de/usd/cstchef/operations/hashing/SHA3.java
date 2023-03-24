package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "SHA3", category = OperationCategory.HASHING, description = "The SHA3 algorithm")
public class SHA3 extends HashOperation {

    public SHA3() {
        super("SHA3-", "224", "256", "384", "512");
    }

}
