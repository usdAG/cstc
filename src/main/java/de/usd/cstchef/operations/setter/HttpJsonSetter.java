package de.usd.cstchef.operations.setter;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP JSON", category = OperationCategory.SETTER, description = "Set a JSON parameter to the specified value.")
public class HttpJsonSetter extends SetterOperation {

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {

        String parameterName = getWhere();
        if( parameterName.equals("") )
            return input;

        MontoyaApi api = BurpUtils.getInstance().getApi();

        ByteArray newValue = getWhatBytes();
        ParsedHttpParameter param = getParameter(input, parameterName, HttpParameterType.JSON, api);

        if( param == null )
            return input;

        ByteArray newRequest = replaceParam(input, param, newValue);
        return newRequest;
    }

}
