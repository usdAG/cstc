package de.usd.cstchef.operations.extractors;

import org.bouncycastle.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP Header", category = OperationCategory.EXTRACTORS, description = "Extracts a header of a HTTP request.")
public class HttpHeaderExtractor extends Operation {

    private VariableTextField headerNameField;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        ByteArray headerName = headerNameField.getBytes();
        if( headerName.length() == 0 )
            return input;

        ByteArray headerSearch = factory.createByteArray("\r\n").withAppended(headerName).withAppended(": ");

        MontoyaApi api = BurpUtils.getInstance().getApi();
        int length = input.length();

        int offset = api.utilities().byteUtils().indexOf(input.getBytes(), headerSearch.getBytes(), true, 0, length);

        if( offset < 0 )
            throw new IllegalArgumentException("Header not found.");

        int valueStart = api.utilities().byteUtils().indexOf(input.getBytes(), " ".getBytes(), false, offset, length);
        if( valueStart < 0 )
            throw new IllegalArgumentException("Invalid Header format.");
        int valueEnd = api.utilities().byteUtils().indexOf(input.getBytes(), "\r\n".getBytes(), false, valueStart, length);
        if( valueEnd < 0 )
            throw new IllegalArgumentException("Invalid Header format.");

        ByteArray result = BurpUtils.subArray(input, valueStart + 1, valueEnd);
        return result;
    }

    @Override
    public void createUI() {
        this.headerNameField = new VariableTextField();
        this.addUIElement("Name", this.headerNameField);
    }

}
