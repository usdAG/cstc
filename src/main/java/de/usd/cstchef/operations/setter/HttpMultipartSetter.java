package de.usd.cstchef.operations.setter;

import java.util.Iterator;
import java.util.List;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP Multipart Param", category = OperationCategory.SETTER, description = "Sets a part of a multipart/form-data request to the specified value.")
public class HttpMultipartSetter extends SetterOperation {

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        String parameterName = getWhere();
        if (parameterName.equals(""))
            return input;

        ByteArray newValue = getWhatBytes();

        ByteArray output;

        MontoyaApi api = BurpUtils.getInstance().getApi();

        List<ParsedHttpParameter> parameters = HttpRequest.httpRequest(input).parameters();
        Iterator iterator = parameters.iterator();
        while (iterator.hasNext()) {
            ParsedHttpParameter extractedParam = (ParsedHttpParameter) iterator.next();
            if (extractedParam.type() == HttpParameterType.BODY &&
                    extractedParam.name().equals(parameterName)) {
                int start = extractedParam.valueOffsets().startIndexInclusive();
                int end = extractedParam.valueOffsets().endIndexExclusive();

                int beforeChangeLength = start - 1;
                int changeLength = newValue.length();
                int afterChangeLength = input.length() - beforeChangeLength - (end - start) - 1;

                output = ByteArray.byteArray(beforeChangeLength + changeLength + afterChangeLength);

                for (int i = 0; i < beforeChangeLength; i++) {
                    output.setByte(i, input.getByte(i));
                }
                for (int i = 0; i < changeLength; i++) {
                    output.setByte(beforeChangeLength + i, input.getByte(i));
                }
                for (int i = 0; i < afterChangeLength; i++) {
                    output.setByte(beforeChangeLength + changeLength + i, input.getByte(end + i));
                }

                return output;

            }
        }
        throw new IllegalArgumentException("Parameter name not found.");
    }
}