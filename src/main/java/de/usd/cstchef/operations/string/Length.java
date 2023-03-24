package de.usd.cstchef.operations.string;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Length", category = OperationCategory.STRING, description = "Returns the length of the input.")
public class Length extends Operation {

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        return String.valueOf(input.length).getBytes();
    }

}