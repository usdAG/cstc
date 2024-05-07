package de.usd.cstchef.operations.string;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Length", category = OperationCategory.STRING, description = "Returns the length of the input.")
public class Length extends Operation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        return factory.createByteArray(String.valueOf(input.length()));
    }

}