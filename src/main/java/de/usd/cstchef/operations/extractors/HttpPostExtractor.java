package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP POST Param", category = OperationCategory.EXTRACTORS, description = "Extracts a POST parameter of a HTTP request.")
public class HttpPostExtractor extends Operation {

    protected VariableTextField parameter;

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        String parameterName = parameter.getText();
        if( parameterName.equals("") )
            return input;

        IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
        IExtensionHelpers helpers = callbacks.getHelpers();

        IParameter param = helpers.getRequestParameter(input, parameterName);
        if( param == null)
            throw new IllegalArgumentException("Parameter name not found.");
        if( param.getType() != IParameter.PARAM_BODY )
            throw new IllegalArgumentException("Parameter type is not POST");

        int start = param.getValueStart();
        int end = param.getValueEnd();

        byte[] result = Arrays.copyOfRange(input, start, end);
        return result;
    }

    @Override
    public void createUI() {
        this.parameter = new VariableTextField();
        this.addUIElement("Parameter", this.parameter);
    }
}
