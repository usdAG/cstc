package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "SHA2", category = OperationCategory.HASHING, description = "The SHA2 algorithm")
public class SHA2 extends HashOperation {

	public SHA2() {
		super("SHA-", "224", "256", "384", "512", "512/224", "512/256");
	}

}
