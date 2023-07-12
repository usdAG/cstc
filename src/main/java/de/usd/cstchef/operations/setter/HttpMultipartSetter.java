package de.usd.cstchef.operations.setter;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP Multipart Param", category = OperationCategory.SETTER, description = "Sets a parameter of a multipart request to the specified value.")
public class HttpMultipartSetter extends SetterOperation {

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        String parameterName = getWhere();
        if( parameterName.equals("") )
            return input;

        byte[] newValue = getWhatBytes();
        
        byte[] output;

        IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
        IExtensionHelpers helpers = callbacks.getHelpers();

        List<IParameter> parameters = helpers.analyzeRequest(input).getParameters();
        Iterator iterator = parameters.iterator();
        while (iterator.hasNext()) {
            IParameter extractedParam = (IParameter) iterator.next();
            if (extractedParam.getType() == IParameter.PARAM_BODY &&
                    extractedParam.getName().equals(parameterName)) {
                int start = extractedParam.getValueStart();
                int end = extractedParam.getValueEnd();

                int beforeChangeLength = start - 1;
                int changeLength = newValue.length;
                int afterChangeLength = input.length - beforeChangeLength - (end - start) - 1;

                output = new byte[beforeChangeLength + changeLength + afterChangeLength];

                for(int i = 0; i < beforeChangeLength; i++){
                    output[i] = input[i];
                }
                for(int i = 0; i < changeLength; i++){
                    output[beforeChangeLength + i] = newValue[i];
                }
                for(int i = 0; i < afterChangeLength; i++){
                    output[beforeChangeLength + changeLength + i] = input[end + i];
                }

                return output;
                
            }
        }
        throw new IllegalArgumentException("Parameter name not found.");
    }
}