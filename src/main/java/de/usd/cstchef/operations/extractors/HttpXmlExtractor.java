package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import javax.swing.JTextField;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP XML", category = OperationCategory.EXTRACTORS, description = "Extract XML value from HTTP message.")
public class HttpXmlExtractor extends Operation {

    private JTextField fieldTxt;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String keyName = fieldTxt.getText();
        if (keyName.equals(""))
            return ByteArray.byteArray();

        try{
            return ByteArray.byteArray(HttpRequest.httpRequest(input).parameterValue(keyName, HttpParameterType.XML));
        }
        catch(Exception e){
            throw new IllegalArgumentException("Input is not a valid request");
        }
    }

    @Override
    public void createUI() {
        this.fieldTxt = new JTextField();
        this.addUIElement("Field", this.fieldTxt);
    }
}
