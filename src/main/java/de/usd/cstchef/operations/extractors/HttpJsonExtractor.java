package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import javax.swing.JTextField;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP JSON", category = OperationCategory.EXTRACTORS, description = "Get a JSON value from HTTP message.")
public class HttpJsonExtractor extends Operation {

    private JTextField fieldTxt;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String keyName = fieldTxt.getText();
        if( keyName.equals("") )
            return input;

        MontoyaApi api = BurpUtils.getInstance().getApi();

        ParsedHttpParameter param = HttpRequest.httpRequest(input).parameters().stream().filter(p -> p.name().equals(keyName)).findFirst().get();
        if( param == null)
            throw new IllegalArgumentException("Key not found.");
        if( param.type() != HttpParameterType.JSON )
            throw new IllegalArgumentException("Parameter type is not JSON");

            int start = param.valueOffsets().startIndexInclusive();
            int end = param.valueOffsets().endIndexExclusive();

            ByteArray result = BurpUtils.subArray(input, start, end);
            return result;
    }

    @Override
    public void createUI() {
        this.fieldTxt = new JTextField();
        this.addUIElement("Field", this.fieldTxt);
    }
}
