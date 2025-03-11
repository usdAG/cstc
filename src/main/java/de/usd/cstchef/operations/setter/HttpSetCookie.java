package de.usd.cstchef.operations.setter;

import java.util.List;

import javax.swing.JCheckBox;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Set HTTP Cookie", category = OperationCategory.SETTER, description = "Set a HTTP cookie to the specified value.")
public class HttpSetCookie extends SetterOperation {

    private JCheckBox addIfNotPresent;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        String cookieName = getWhere();
        String cookieValue = getWhat();
        if (getWhat().equals(""))
            return input;

        MessageType messageType = parseMessageType(input);
        
        if(messageType == MessageType.REQUEST) {
            HttpRequest request = HttpRequest.httpRequest(input);

            // has Cookie header
            if(request.hasHeader("Cookie")) {
                String cookies = request.header("Cookie").value();
                // has this particular cookie set
                if(cookies.contains(cookieName + "=")) {
                    String[] c = cookies.split("; ");
                    cookies = "";
                    for(String cookie : c) {
                        cookie = cookie.replaceAll(cookieName + "=\\S*", cookieName + "=" + cookieValue);
                        cookies = cookies.concat(cookie + "; ");
                    }
                    cookies = cookies.replaceAll(";\s$", "");
                    return request.withUpdatedHeader("Cookie", cookies).toByteArray();
                }
                // has this particular cookie not set
                else {
                    cookies = cookies.concat("; " + cookieName + "=" + cookieValue);
                        return addIfNotPresent.isSelected() ? request.withUpdatedHeader("Cookie", cookies).toByteArray() : input;
                }
            }
            // has no Cookie header
            else {
                return addIfNotPresent.isSelected() ? request.withAddedHeader("Cookie", cookieName + "=" + cookieValue).toByteArray() : input;
            }
        }

        else if (messageType == MessageType.RESPONSE) {
            HttpResponse response = HttpResponse.httpResponse(input);
            List<HttpHeader> httpHeader = response.headers();

            // has Set-Cookie header
            if(response.hasCookie(cookieName)) {
                response = response.withRemovedHeaders(httpHeader);
                for(int i = 0; i < httpHeader.size(); i++) {
                    if(httpHeader.get(i).name().equals("Set-Cookie")) {
                        // has this particular cookie set
                        if(httpHeader.get(i).value().contains(cookieName + "=")) {
                            response = response.withAddedHeader("Set-Cookie", cookieName + "=" + cookieValue);
                        }
                        else{
                            response = response.withAddedHeader(httpHeader.get(i));
                        }
                    }
                    else {
                        response = response.withAddedHeader(httpHeader.get(i));
                    }
                }

                return response.toByteArray();

            }
            // has no Set-Cookie header
            else {
                return addIfNotPresent.isSelected() ? response.withAddedHeader("Set-Cookie", cookieName + "=" + cookieValue).toByteArray(): input;
            }
        }
        
        else {
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
