package de.usd.cstchef.operations.extractors;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Get HTTP POST Param", category = OperationCategory.EXTRACTORS, description = "Extracts a POST parameter of a HTTP request.")
public class HttpPostExtractor extends Operation {

    protected VariableTextField parameter;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        String parameterName = parameter.getText();
        if (parameterName.equals(""))
            return input;

        if (messageType == MessageType.REQUEST) {
            try {
                return checkNull(factory.createByteArray(factory.createHttpRequest(input).parameterValue(parameterName, HttpParameterType.BODY)));
            } catch (Exception e) {
                throw new IllegalArgumentException("POST parameter not found.");
            }
        } else if (messageType == MessageType.RESPONSE) {
            throw new IllegalArgumentException("Input is not a valid HTTP request.");
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
