package de.usd.cstchef.operations.setter;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Multipart Param", category = OperationCategory.SETTER, description = "Sets a part of a multipart/form-data request to the specified value.")
public class HttpMultipartSetter extends SetterOperation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = getWhere();
        if (parameterName.equals(""))
            return input;

        if (messageType == MessageType.REQUEST) {
            try {
                return HttpRequest.httpRequest(input)
                        .withParameter(HttpParameter.parameter(parameterName, getWhat(), HttpParameterType.BODY))
                        .toByteArray();
            } catch (Exception e) {
                throw new IllegalArgumentException("Input is not a valid request");
            }
        } else if (messageType == MessageType.RESPONSE) {
            throw new IllegalArgumentException("Input is not a valid HTTP Request");
        } else {
            return parseRawMessage(input);
        }

    }
}