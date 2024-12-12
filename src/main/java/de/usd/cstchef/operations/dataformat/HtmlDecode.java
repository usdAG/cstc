package de.usd.cstchef.operations.dataformat;

import burp.BurpUtils;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTML Decode", category = OperationCategory.DATAFORMAT, description = "HTML Decode")
public class HtmlDecode extends Operation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        return factory.createByteArray(BurpUtils.getInstance().getApi().utilities().htmlUtils().decode(input.toString()));
    }

}
