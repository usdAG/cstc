package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Set HTTP Header", category = OperationCategory.SETTER, description = "Set a HTTP header to the specified value.")
public class HttpHeaderSetter extends SetterOperation {

    private JCheckBox addIfNotPresent;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        String newValue = getWhat();
        String headerName = getWhere();
        if( headerName.length() == 0 ) {
            return input;
        }

        if(messageType == MessageType.REQUEST){
            HttpRequest request = HttpRequest.httpRequest(input);
            if(request.hasHeader(headerName) || addIfNotPresent.isSelected()){
                return request.withHeader(HttpHeader.httpHeader(headerName, newValue)).toByteArray();
            }
            else{
                return input;
            }
        }
        else if(messageType == MessageType.RESPONSE){
            HttpResponse response = HttpResponse.httpResponse(input);
            if(response.hasHeader(headerName)) {
                return response.withUpdatedHeader(HttpHeader.httpHeader(headerName, newValue)).toByteArray();
            }
            else {
                if(addIfNotPresent.isSelected()) {
                    return response.withAddedHeader(HttpHeader.httpHeader(headerName, newValue)).toByteArray();
                }
                else {
                    return input;
                }
            }
        }
        else{
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        super.createUI();
        this.addIfNotPresent = new JCheckBox("Add if not present");
        this.addIfNotPresent.setSelected(true);
        this.addUIElement(null, this.addIfNotPresent, "checkbox1");
    }

}
