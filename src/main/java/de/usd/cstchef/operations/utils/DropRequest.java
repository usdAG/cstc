package de.usd.cstchef.operations.utils;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Drop Request", category = OperationCategory.UTILS, description = "Drops a request on demand. Only works with the Proxy.")
public class DropRequest extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        if(messageType == MessageType.REQUEST) {
            HttpRequest httpRequest = HttpRequest.httpRequest(input).withAddedHeader("X-CSTC-Drop-Request", "cstc");
            return httpRequest.toByteArray();
        }
        else {
            throw new IllegalArgumentException("Input is not a valid HTTP request.");
        }

    }

}
