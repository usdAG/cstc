package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "SM3", category = OperationCategory.HASHING, description = "The SM3 algorithm")
public class SM3 extends HashOperation {

    public SM3() {
        super("SM3");
    }

}
