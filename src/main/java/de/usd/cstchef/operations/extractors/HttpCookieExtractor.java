package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
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
            return ByteArray.byteArray();

        if(messageType == MessageType.REQUEST){
            HttpRequest request = HttpRequest.httpRequest(input);
            String cookies = request.headerValue("Cookie");
            String[] splitCookies = cookies.split(";");
            for(String sC : splitCookies){
                String[] seperateCookie = sC.split("=");
                if(seperateCookie[0].equals(cookieName)){
                    return ByteArray.byteArray(seperateCookie[1]);
                }
            }
            return ByteArray.byteArray();
        }
        else if(messageType == MessageType.RESPONSE){
            HttpResponse response = HttpResponse.httpResponse(input);
            for(Cookie c : response.cookies()){
                if(c.name().equals(cookieName))
                    return ByteArray.byteArray(c.value());
            }
            return input;
        }
        else{
            //  try to parse to request and response, if not working, throw exception
            try{
                HttpRequest.httpRequest(input);
                return this.perform(input, MessageType.REQUEST);
            }
            catch(Exception e){
                
            }
            try{
                HttpResponse.httpResponse(input);
                return this.perform(input, MessageType.RESPONSE);
            }
            catch(Exception e){
                throw new IllegalArgumentException("Input could not be parsed to a request or a response.");
            }
        }
    }

    @Override
    public void createUI() {
        this.cookieNameField = new VariableTextField();
        this.addUIElement("Name", this.cookieNameField);
    }
}
