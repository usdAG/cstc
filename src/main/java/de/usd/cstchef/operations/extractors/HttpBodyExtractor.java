package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "HTTP Body", category = OperationCategory.EXTRACTORS, description = "Extracts the body of a HTTP messages.")
public class HttpBodyExtractor extends Operation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        if(messageType == MessageType.REQUEST){
            return factory.getHttpRequestBody(input);
        }
        else if(messageType == MessageType.RESPONSE){
            return factory.getHttpResponseBody(input);
        }
        else{
            return parseRawMessage(input);
        }
    }
}