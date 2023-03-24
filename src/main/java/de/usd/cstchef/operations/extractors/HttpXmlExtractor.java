package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import javax.swing.JTextField;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP XML", category = OperationCategory.EXTRACTORS, description = "Extract XML value from HTTP message.")
public class HttpXmlExtractor extends Operation {

    private JTextField fieldTxt;

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        String keyName = fieldTxt.getText();
        if( keyName.equals("") )
            return input;

        IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
        IExtensionHelpers helpers = callbacks.getHelpers();

        IParameter param = helpers.getRequestParameter(input, keyName);
        if( param == null)
            throw new IllegalArgumentException("Key not found.");
        if( param.getType() != IParameter.PARAM_XML )
            throw new IllegalArgumentException("Parameter type is not XML");

        int start = param.getValueStart();
        int end = param.getValueEnd();

        byte[] result = Arrays.copyOfRange(input, start, end);
        return result;
    }

    @Override
    public void createUI() {
        this.fieldTxt = new JTextField();
        this.addUIElement("Field", this.fieldTxt);
    }
}
