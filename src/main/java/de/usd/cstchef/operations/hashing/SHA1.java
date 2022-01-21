package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "SHA1", category = OperationCategory.HASHING, description = "The SHA1 algorithm")
public class SHA1 extends HashOperation {
	
	public SHA1() {
		super("SHA1");
	}

}
