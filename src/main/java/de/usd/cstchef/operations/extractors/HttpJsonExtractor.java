package de.usd.cstchef.operations.extractors;

import javax.swing.JTextField;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Get HTTP JSON", category = OperationCategory.EXTRACTORS, description = "Get a JSON value from HTTP message.")
public class HttpJsonExtractor extends Operation {

    protected JTextField fieldTxt;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        String keyName = fieldTxt.getText();
        if( keyName.equals("") )
            return input;

        JsonExtractor extractor = new JsonExtractor(keyName);
        if(messageType == MessageType.REQUEST){
            return checkNull(extractor.perform(factory.createHttpRequest(input).body()));
        }
        else if(messageType == MessageType.RESPONSE){
            return checkNull(extractor.perform(factory.createHttpResponse(input).body()));
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
