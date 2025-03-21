package de.usd.cstchef.operations.extractors;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Get HTTP GET Param", category = OperationCategory.EXTRACTORS, description = "Extracts a GET Parameter of a HTTP request.")
public class HttpGetExtractor extends Operation {

    protected VariableTextField parameter;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        MessageType messageType = parseMessageType(input);

        if(messageType == MessageType.RESPONSE) {
            throw new IllegalArgumentException("Input is not a valid HTTP request.");
        }

        String parameterName = parameter.getText();
        if (parameterName.equals("")) {
            return input;
        }

        if (messageType == MessageType.REQUEST) {
            try {
                return factory.createByteArray(checkNull(factory.createHttpRequest(input).parameterValue(parameterName, HttpParameterType.URL)));
            }
            catch(Exception e) {
                throw new IllegalArgumentException("GET parameter not found.");
            }
        }

        return input;

    }

    @Override
    public void createUI() {
        this.parameter = new VariableTextField();
        this.addUIElement("Parameter", this.parameter);
    }

}
