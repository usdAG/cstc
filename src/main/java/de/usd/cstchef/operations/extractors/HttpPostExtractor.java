package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP POST Param", category = OperationCategory.EXTRACTORS, description = "Extracts a POST parameter of a HTTP request.")
public class HttpPostExtractor extends Operation {

    protected VariableTextField parameter;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        String parameterName = parameter.getText();
        if( parameterName.equals("") )
            return input;

        MontoyaApi api = BurpUtils.getInstance().getApi();

        ParsedHttpParameter param = HttpRequest.httpRequest(input).parameters().stream().filter(p -> p.name().equals(parameterName)).findFirst().get();
        if( param == null)
            throw new IllegalArgumentException("Parameter name not found.");
        if( param.type() != HttpParameterType.BODY )
            throw new IllegalArgumentException("Parameter type is not POST");

            int start = param.valueOffsets().startIndexInclusive();
            int end = param.valueOffsets().endIndexExclusive();

            ByteArray result = BurpUtils.subArray(input, start, end);
            return result;
    }

    @Override
    public void createUI() {
        this.parameter = new VariableTextField();
        this.addUIElement("Parameter", this.parameter);
    }
}
