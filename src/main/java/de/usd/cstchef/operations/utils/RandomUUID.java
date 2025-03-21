package de.usd.cstchef.operations.utils;

import java.util.UUID;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Random UUID", category = OperationCategory.UTILS, description = "Generate a random UUID.")
public class RandomUUID extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        final String uuid = UUID.randomUUID().toString();
        return factory.createByteArray(uuid);
    }

}
