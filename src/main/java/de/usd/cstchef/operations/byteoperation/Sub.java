package de.usd.cstchef.operations.byteoperation;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Sub", category = OperationCategory.BYTEOPERATION, description = "Substracts the input with the given key.")
public class Sub extends ByteKeyOperation {

    @Override
    protected byte calculate(byte input, byte var) {
        return (byte) ((input - var) % 255);
    }

}
