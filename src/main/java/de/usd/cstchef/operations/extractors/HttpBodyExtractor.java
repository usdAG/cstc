package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "HTTP Body", category = OperationCategory.EXTRACTORS, description = "Extracts the body of a HTTP request.")
public class HttpBodyExtractor extends Operation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        try {
            // TODO: differentiate between Response and Request
            int bodyOffset = HttpResponse.httpResponse(input).bodyOffset();
            //TODO: Check for range errors
            return input.subArray(bodyOffset, input.length());
        } catch (Exception e) {
            throw new IllegalArgumentException("Provided input is not a valid http request.");
        }
    }
}