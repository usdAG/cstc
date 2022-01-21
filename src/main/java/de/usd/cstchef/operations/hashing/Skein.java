package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Skein", category = OperationCategory.HASHING, description = "The Skein algorithm")
public class Skein extends HashOperation {

    public Skein() {
        super("Skein-", "256-128", "256-160", "256-224", "256-256", "512-128", "512-160", "512-224", "512-256", "512-384", "512-512", "1024-384", "1024-512", "1024-1024");
    }

}
