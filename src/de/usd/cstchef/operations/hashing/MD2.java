package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "MD2", category = OperationCategory.HASHING, description = "The MD2 (Message-Digest 2) algorithm")
public class MD2 extends HashOperation {
	
	public MD2() {
		super("MD2");
	}
	
}
