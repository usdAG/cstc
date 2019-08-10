package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Gost", category = OperationCategory.HASHING, description = "The Gost algorithm")
public class Gost extends HashOperation {

	public Gost() {
		super("GOST-3411-2012-", "256", "512");
	}

}
