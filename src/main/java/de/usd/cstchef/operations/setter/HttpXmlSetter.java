package de.usd.cstchef.operations.setter;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP XML", category = OperationCategory.SETTER, description = "Set a XML parameter to the specified value.")
public class HttpXmlSetter extends SetterOperation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = getWhere();
        if( parameterName.equals("") )
            return input;

        try{
            HttpRequest request = HttpRequest.httpRequest(input);
            if(request.hasParameter(parameterName, HttpParameterType.XML)){
                return request.withParameter(HttpParameter.parameter(parameterName, getWhat(), HttpParameterType.XML)).toByteArray();
            }
            else{
                return input;
            }
        }
        catch(Exception e){
            throw new IllegalArgumentException("Input is not a valid request");
        }
    }

}
