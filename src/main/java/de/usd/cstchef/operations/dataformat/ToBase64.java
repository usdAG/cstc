package de.usd.cstchef.operations.dataformat;

import java.util.Base64;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "To Base64", category = OperationCategory.DATAFORMAT, description = "Encodes a string to base64.")
public class ToBase64 extends Operation {

    @Override
    protected byte[] perform(byte[] input) {
        return Base64.getEncoder().encode(input);
    }

}
