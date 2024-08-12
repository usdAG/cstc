package de.usd.cstchef.operations.setter;

import java.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.FormatTextField;

@OperationInfos(name = "Set HTTP Body", category = OperationCategory.SETTER, description = "Set the HTTP body to the specified value.")
public class HttpSetBody extends Operation {

    private FormatTextField replacementTxt;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        ByteArray replacementBody = replacementTxt.getText();
        if( replacementBody.toString().equals("") )
            return input;

        if(messageType == MessageType.REQUEST){
            return HttpRequest.httpRequest(input).withBody(replacementBody).toByteArray();
        }
        else if(messageType == MessageType.RESPONSE){
            return HttpResponse.httpResponse(input).withBody(replacementBody).toByteArray();
        }
        else{
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.replacementTxt = new FormatTextField();
        this.addUIElement("Body", this.replacementTxt);
    }

}
