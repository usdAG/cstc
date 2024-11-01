package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.objects.CstcByteArray;
import de.usd.cstchef.Utils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Get HTTP Cookie", category = OperationCategory.EXTRACTORS, description = "Extracts a cookie from a HTTP message.")
public class HttpCookieExtractor extends Operation {

    protected VariableTextField cookieNameField;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String cookieName = cookieNameField.getText();
        if( cookieName.length() == 0 )
            return factory.createByteArray(0);

        if(messageType == MessageType.REQUEST){
            HttpRequest request = factory.createHttpRequest(input);
            return checkNull(Utils.httpRequestCookieExtractor(request, cookieName));
        }
        else if(messageType == MessageType.RESPONSE){
            HttpResponse response = factory.createHttpResponse(input);
            for(Cookie c : response.cookies()){
                if(c.name().equals(cookieName))
                    return factory.createByteArray(checkNull(c.value()));
            }
            return factory.createByteArray(0);
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
