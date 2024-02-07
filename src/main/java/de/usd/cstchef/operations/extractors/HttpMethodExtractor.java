package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Method", category = OperationCategory.EXTRACTORS, description = "Extracts the method of a HTTP request.")
public class HttpMethodExtractor extends Operation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        try{
            return ByteArray.byteArray(HttpRequest.httpRequest(input).method());
        }
        catch(Exception e){
            throw new IllegalArgumentException("Input is not a valid request");
        }
    }
}
