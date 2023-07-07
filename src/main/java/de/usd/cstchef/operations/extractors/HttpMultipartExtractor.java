package de.usd.cstchef.operations.extractors;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP Multipart Param", category = OperationCategory.EXTRACTORS, description = "Extracts a parameter of a multipart request.")
public class HttpMultipartExtractor extends Operation {

    protected VariableTextField parameter;

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        String parameterName = parameter.getText();
        if (parameterName.equals(""))
            return input;

        String value = "";

        IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
        IExtensionHelpers helpers = callbacks.getHelpers();

        //TODO: Remove Header and fix encoding for getBytes and toString operations

        byte[] messageBody = Arrays.copyOfRange(input, helpers.analyzeRequest(input).getBodyOffset(), input.length);
        byte[] result = new byte[0];

        String bodyString = new String(messageBody);
        String[] formFields = bodyString.split("------");

        for (String form : formFields) {
            if(form.contains("name=\"" + parameterName)){
                return form.getBytes();
            }
        }

        throw new IllegalArgumentException("Parameter name not found.");

    }

    @Override
    public void createUI() {
        this.parameter = new VariableTextField();
        this.addUIElement("Parameter", this.parameter);
    }

}