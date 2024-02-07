package de.usd.cstchef.operations.extractors;
import java.util.Arrays;

import burp.BurpExtender;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP GET Param", category = OperationCategory.EXTRACTORS, description = "Extracts a GET Parameter of a HTTP request.")
public class HttpGetExtractor extends Operation {

    protected VariableTextField parameter;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = parameter.getText();
        if( parameterName.equals("") )
            return ByteArray.byteArray();
        try{
            return ByteArray.byteArray(HttpRequest.httpRequest(input).parameterValue(parameterName, HttpParameterType.URL));
        }
        catch(Exception e){
            throw new IllegalArgumentException("Parameter name not found.");
        }

    }

    @Override
    public void createUI() {
        this.parameter = new VariableTextField();
        this.addUIElement("Parameter", this.parameter);
    }

}
