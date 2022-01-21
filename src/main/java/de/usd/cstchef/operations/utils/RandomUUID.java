package de.usd.cstchef.operations.utils;

import java.util.UUID;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Random UUID", category = OperationCategory.UTILS, description = "Generate a random UUID.")
public class RandomUUID extends Operation {

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        final String uuid = UUID.randomUUID().toString();
        return uuid.getBytes();
    }

}
