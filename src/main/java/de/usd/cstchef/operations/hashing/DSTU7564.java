package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "DSTU7564", category = OperationCategory.HASHING, description = "The Whirlpool algorithm")
public class DSTU7564 extends HashOperation {

	public DSTU7564() {
		super("DSTU7564-", "256", "384", "512");
	}

}
