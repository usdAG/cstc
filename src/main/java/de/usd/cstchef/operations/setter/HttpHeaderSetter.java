package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Header", category = OperationCategory.SETTER, description = "Set a HTTP header to the specified value.")
public class HttpHeaderSetter extends SetterOperation {

    private JCheckBox addIfNotPresent;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        ByteArray newValue = getWhatBytes();
        ByteArray headerName = getWhereBytes();
        if( headerName.length() == 0 )
            return input;

        MontoyaApi api = BurpUtils.getInstance().getApi();
        int length = input.length();

        ByteArray headerSearch = headerName.withAppended(": ");

        try {

            int offset = api.utilities().byteUtils().indexOf(input.getBytes(), headerSearch.getBytes(), false, 0, length);
            int start = api.utilities().byteUtils().indexOf(input.getBytes(), ": ".getBytes(), false, offset, length) + 2;
            int end = api.utilities().byteUtils().indexOf(input.getBytes(), "\r\n".getBytes(), false, start, length);
            return Utils.insertAtOffset(input, start, end, newValue);

        } catch( IllegalArgumentException e ) {

            if( !addIfNotPresent.isSelected() )
                return input;

            int bodyOffset = HttpRequest.httpRequest(input).bodyOffset() - 2;

            ByteArray value = headerSearch.withAppended(newValue).withAppended("\r\n");
            return Utils.insertAtOffset(input, bodyOffset, bodyOffset, value);

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
