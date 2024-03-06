package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

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
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP POST Param", category = OperationCategory.EXTRACTORS, description = "Extracts a POST parameter of a HTTP request.")
public class HttpPostExtractor extends Operation {

    protected VariableTextField parameter;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = parameter.getText();
        if (parameterName.equals(""))
            return ByteArray.byteArray(0);

        if (messageType == MessageType.REQUEST) {
            try {
                return ByteArray.byteArray(
                        HttpRequest.httpRequest(input).parameterValue(parameterName, HttpParameterType.BODY));
            } catch (Exception e) {
                throw new IllegalArgumentException("Input is not a valid request");
            }
        } else if (messageType == MessageType.RESPONSE) {
            throw new IllegalArgumentException("Input is not a valid HTTP Request");
        } else {
            return parseRawMessage(input);
        }
    }

    @Override
    public void createUI() {
        this.parameter = new VariableTextField();
        this.addUIElement("Parameter", this.parameter);
    }
}
