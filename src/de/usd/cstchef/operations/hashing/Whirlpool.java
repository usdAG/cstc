package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Whirlpool", category = OperationCategory.HASHING, description = "The Whirlpool algorithm")
public class Whirlpool extends HashOperation {

	public Whirlpool() {
		super("WHIRLPOOL");
	}

}
