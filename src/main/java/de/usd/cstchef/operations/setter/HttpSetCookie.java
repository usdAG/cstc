package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Cookie", category = OperationCategory.SETTER, description = "Set a HTTP cookie to the specified value.")
public class HttpSetCookie extends SetterOperation {

    private JCheckBox addIfNotPresent;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String cookieName = getWhere();
        String cookieValue = getWhat();
        if (getWhat().equals(""))
            return input;

        if (messageType == MessageType.REQUEST) {
            HttpRequest request = HttpRequest.httpRequest(input);
            if (!Utils.httpRequestCookieExtractor(request, cookieName).equals(ByteArray.byteArray(0))
                    || addIfNotPresent.isSelected()) {
                return Utils.addCookieToHttpRequest(request, new Utils.CSTCCookie(cookieName, cookieValue))
                        .toByteArray();
            }
            else{
                return input;
            }
        } else if (messageType == MessageType.RESPONSE) {
            HttpResponse response = HttpResponse.httpResponse(input);
            if (response.hasCookie(cookieName) || addIfNotPresent.isSelected()) {
                response.cookies().add(new Utils.CSTCCookie(cookieName, cookieValue));
                return response.toByteArray();
            } else {
                return input;
            }
        } else {
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
