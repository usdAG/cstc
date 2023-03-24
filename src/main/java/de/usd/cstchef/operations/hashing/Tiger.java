package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Tiger", category = OperationCategory.HASHING, description = "The Tiger algorithm")
public class Tiger extends HashOperation {

    public Tiger() {
        super("Tiger");
    }

}
