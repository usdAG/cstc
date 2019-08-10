package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "MD4", category = OperationCategory.HASHING, description = "The MD4 (Message-Digest 4) algorithm")
public class MD4 extends HashOperation {

	public MD4() {
		super("MD4");
	}

}
