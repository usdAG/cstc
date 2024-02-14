package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP Cookie", category = OperationCategory.EXTRACTORS, description = "Extracts a cookie from a HTTP request.")
public class HttpCookieExtractor extends Operation {

    private VariableTextField cookieNameField;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String cookieName = cookieNameField.getText();
        if( cookieName.length() == 0 )
            return ByteArray.byteArray(0);

        if(messageType == MessageType.REQUEST){
            HttpRequest request = HttpRequest.httpRequest(input);
            return Utils.httpRequestCookieExtractor(request, cookieName);
        }
        else if(messageType == MessageType.RESPONSE){
            HttpResponse response = HttpResponse.httpResponse(input);
            for(Cookie c : response.cookies()){
                if(c.name().equals(cookieName))
                    return ByteArray.byteArray(c.value());
            }
            return ByteArray.byteArray();
        }
        else{
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.cookieNameField = new VariableTextField();
        this.addUIElement("Name", this.cookieNameField);
    }
}
