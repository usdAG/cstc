package de.usd.cstchef.operations.extractors;

import javax.swing.JTextField;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP JSON", category = OperationCategory.EXTRACTORS, description = "Get a JSON value from HTTP message.")
public class HttpJsonExtractor extends Operation {

    protected JTextField fieldTxt;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String keyName = fieldTxt.getText();
        if( keyName.equals("") )
            //return ByteArray.byteArray(0);
            return factory.createByteArray(0);

        JsonExtractor extractor = new JsonExtractor(keyName);
        if(messageType == MessageType.REQUEST){
            return checkNull(extractor.perform(factory.createHttpRequest(input).body(), messageType));
        }
        else if(messageType == MessageType.RESPONSE){
            return checkNull(extractor.perform(factory.createHttpResponse(input).body(), messageType));
        }
        else{
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.fieldTxt = new JTextField();
        this.addUIElement("Field", this.fieldTxt);
    }
}
