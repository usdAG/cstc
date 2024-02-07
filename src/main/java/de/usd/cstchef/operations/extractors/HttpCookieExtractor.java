package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
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

        ByteArray cookieName = cookieNameField.getBytes();
        if( cookieName.length() == 0 )
            return input;

        ByteArray cookieSearch = cookieName.withAppended("=");

        MontoyaApi api = BurpUtils.getInstance().getApi();
        int length = input.length();

        boolean isRequest = (HttpResponse.httpResponse(input).statusCode() == 0);

        String cookieHeader = "\r\nSet-Cookie: ";
        if(isRequest)
            cookieHeader = "\r\nCookie: ";

        try {

            int offset = api.utilities().byteUtils().indexOf(input.getBytes(), cookieHeader.getBytes(), false, 0, length);
            int line_end = api.utilities().byteUtils().indexOf(input.getBytes(), "\r\n".getBytes(), false, offset + 2, length);
            int start = api.utilities().byteUtils().indexOf(input.getBytes(), cookieSearch.getBytes(), true, offset, line_end);
            int end = api.utilities().byteUtils().indexOf(input.getBytes(), ";".getBytes(), true, start, line_end);

            if( end < 0 )
                end = line_end;

            return BurpUtils.subArray(input, start+ cookieName.length() + 1, end);

        } catch( IllegalArgumentException e ) {
            throw new IllegalArgumentException("Cookie not found.");
        }
    }

    @Override
    public void createUI() {
        this.cookieNameField = new VariableTextField();
        this.addUIElement("Name", this.cookieNameField);
    }
}
