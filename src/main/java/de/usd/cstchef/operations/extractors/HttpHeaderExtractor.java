package de.usd.cstchef.operations.extractors;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP Header", category = OperationCategory.EXTRACTORS, description = "Extracts a header of a HTTP message.")
public class HttpHeaderExtractor extends Operation {

    protected VariableTextField headerNameField;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String headerName = headerNameField.getText();
        if( headerName.length() == 0 )
            //return ByteArray.byteArray(0);
            return factory.createByteArray(0);
        if(messageType == MessageType.REQUEST){
            //return ByteArray.byteArray(checkNull(HttpRequest.httpRequest(input).headerValue(headerName)));
            return factory.createByteArray(checkNull(factory.createHttpRequest(input).headerValue(headerName)));
        }
        else if(messageType == MessageType.RESPONSE){
            //return ByteArray.byteArray(checkNull(HttpResponse.httpResponse(input).headerValue(headerName)));
            return factory.createByteArray(checkNull(factory.createHttpResponse(input).headerValue(headerName)));
        }
        else{
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.headerNameField = new VariableTextField();
        this.addUIElement("Name", this.headerNameField);
    }

}
