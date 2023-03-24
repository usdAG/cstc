package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Blake", category = OperationCategory.HASHING, description = "The Blake algorithm")
public class Blake extends HashOperation {

    public Blake() {
        super("BLAKE", "2B-512", "2B-384", "2B-256", "2B-160", "2S-256", "2S-224", "2S-160", "2S-128");
    }

}
