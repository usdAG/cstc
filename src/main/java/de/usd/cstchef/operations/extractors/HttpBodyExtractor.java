package de.usd.cstchef.operations.extractors;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Get HTTP Body", category = OperationCategory.EXTRACTORS, description = "Extracts the body of a HTTP messages.")
public class HttpBodyExtractor extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        if(messageType == MessageType.REQUEST){

            ByteArray result = factory.getHttpRequestBody(input);

            if(result.length() == 0) {
                throw new IllegalArgumentException("HTTP request has no body.");
            }
            else {
                return result;
            }
        }
        else if(messageType == MessageType.RESPONSE){

            ByteArray result = factory.getHttpResponseBody(input);

            if(result.length() == 0) {
                throw new IllegalArgumentException("HTTP response has no body.");
            }
            else {
                return result;
            }
        }
        else{
            return parseRawMessage(input);
        }
    }
}