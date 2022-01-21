package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "RIPEMD", category = OperationCategory.HASHING, description = "The RIPEMD algorithm")
public class RIPEMD extends HashOperation {

	public RIPEMD() {
		super("RIPEMD", "256", "128", "160");
	}

}