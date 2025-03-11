package de.usd.cstchef.operations.extractors;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Get HTTP Multipart Param", category = OperationCategory.EXTRACTORS, description = "Extracts a part of a multipart/form-data request.")
public class HttpMultipartExtractor extends Operation {

    protected VariableTextField parameter;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        String parameterName = parameter.getText();
        if (parameterName.equals(""))
            return factory.createByteArray(0);

        MessageType messageType = parseMessageType(input);

        if (messageType == MessageType.REQUEST) {
            try{
                return factory.createByteArray(checkNull(factory.createHttpRequest(input).parameterValue(parameterName, HttpParameterType.BODY)));
            }
            catch(Exception e){
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