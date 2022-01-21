package de.usd.cstchef.operations.utils;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "No Operation", category = OperationCategory.UTILS, description = "Does nothing :)")
public class NoOperation extends Operation {

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        return input;
    }

}
