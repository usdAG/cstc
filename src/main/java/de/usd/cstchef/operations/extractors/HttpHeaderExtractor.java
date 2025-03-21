package de.usd.cstchef.operations.extractors;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Get HTTP Header", category = OperationCategory.EXTRACTORS, description = "Extracts a header of a HTTP message.")
public class HttpHeaderExtractor extends Operation {

    protected VariableTextField headerNameField;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        String headerName = headerNameField.getText();
        if( headerName.length() == 0 ) {
            return input;
        }

        if(messageType == MessageType.REQUEST){
            try {
                return factory.createByteArray(checkNull(factory.createHttpRequest(input).headerValue(headerName)));
            }
            catch(Exception e) {
                throw new IllegalArgumentException("Header not found.");
            }
        }
        else if(messageType == MessageType.RESPONSE){
            try {
                return factory.createByteArray(checkNull(factory.createHttpResponse(input).headerValue(headerName)));
            }
            catch(Exception e) {
                throw new IllegalArgumentException("Header not found.");
            }
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
