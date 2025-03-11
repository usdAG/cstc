package de.usd.cstchef.operations.extractors;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Get HTTP Cookie", category = OperationCategory.EXTRACTORS, description = "Extracts a cookie from a HTTP message.")
public class HttpCookieExtractor extends Operation {

    protected VariableTextField cookieNameField;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        String cookieName = cookieNameField.getText();

        if(input.toString().isEmpty() || cookieName.isEmpty()) return factory.createByteArray("");

        MessageType messageType = parseMessageType(input);

        if(messageType == MessageType.REQUEST) {
            HttpRequest request = factory.createHttpRequest(input);

            // has Cookie header
            if(request.hasHeader("Cookie")) {
                String cookieHeaderValue = request.headerValue("Cookie");
                // has this particular cookie set
                if(cookieHeaderValue.contains(cookieName + "=")) {
                    String[] cookies = cookieHeaderValue.split("; ");
                    cookieHeaderValue = "";
                    for(String cookie : cookies) {
                        String[] c = cookie.split("=");
                        if(c[0].equals(cookieName)) {
                            return factory.createByteArray(c[1]);
                        }
                    }
                }
                else {
                    throw new IllegalArgumentException("Parameter name not found.");
                }
            }

            throw new IllegalArgumentException("Parameter name not found.");
           
        }
        else if(messageType == MessageType.RESPONSE) {
            String cookie = factory.createHttpResponse(input).cookieValue(cookieName);
            
            if(cookie == null) {
                throw new IllegalArgumentException("Parameter name not found.");
            }
            else {
                return factory.createByteArray(cookie);
            }
        }
        else {
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.cookieNameField = new VariableTextField();
        this.addUIElement("Name", this.cookieNameField);
    }
}
