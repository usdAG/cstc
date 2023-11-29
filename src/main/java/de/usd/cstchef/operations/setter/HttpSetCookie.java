package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Cookie", category = OperationCategory.SETTER, description = "Set a HTTP cookie to the specified value.")
public class HttpSetCookie extends SetterOperation {

    private JCheckBox addIfNotPresent;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        ByteArray newValue = getWhatBytes();
        ByteArray cookieName = getWhereBytes();
        if( cookieName.length() == 0 )
            return input;

        MontoyaApi api = BurpUtils.getInstance().getApi();
        int length = input.length();

        ByteArray cookieSearch = cookieName.withAppended("=");

        HttpResponse resp = HttpResponse.httpResponse(input);
        boolean isRequest = (resp.statusCode() == 0);

        String cookieHeader = "\r\nSet-Cookie: ";
        if(isRequest)
            cookieHeader = "\r\nCookie: ";

        int offset = -1;
        int cookieHeaderLength = cookieHeader.length();

        try {

            offset = api.utilities().byteUtils().indexOf(input.getBytes(), cookieHeader.getBytes(), false, 0, length);
            int line_end = api.utilities().byteUtils().indexOf(input.getBytes(), "\r\n".getBytes(), false, offset + 2, length);
            int start = api.utilities().byteUtils().indexOf(input.getBytes(), cookieSearch.getBytes(), true, offset, line_end);
            int end = api.utilities().byteUtils().indexOf(input.getBytes(), ";".getBytes(), true, start, line_end);

            if( end < 0 )
                end = line_end;

            return Utils.insertAtOffset(input, start + cookieSearch.length(), end, newValue);

        } catch( IllegalArgumentException e ) {

            if( !addIfNotPresent.isSelected() )
                return input;

            if( (offset > 0) && isRequest ) {

                ByteArray value = cookieName.withAppended("=").withAppended(newValue).withAppended("; ");
                return Utils.insertAtOffset(input, offset + cookieHeaderLength, offset + cookieHeaderLength, value);

            } else {

                int bodyOffset = resp.bodyOffset() - 4;
                ByteArray value = factory.createByteArray(cookieHeader).withAppended(cookieName).withAppended("=").withAppended(newValue).withAppended(";");
                return Utils.insertAtOffset(input, bodyOffset, bodyOffset, value);
            }
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
