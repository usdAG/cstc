package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "MD5", category = OperationCategory.HASHING, description = "The MD5 (Message-Digest 5) algorithm")
public class MD5 extends HashOperation {

    public MD5() {
        super("MD5");
    }


}
