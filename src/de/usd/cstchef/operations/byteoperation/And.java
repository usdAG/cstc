package de.usd.cstchef.operations.byteoperation;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "And", category = OperationCategory.BYTEOPERATION, description = "Ands the input with the given key.")
public class And extends ByteKeyOperation {

	@Override
	protected byte calculate(byte input, byte var) {
		return (byte) ((input & var) % 255);
	}

}
