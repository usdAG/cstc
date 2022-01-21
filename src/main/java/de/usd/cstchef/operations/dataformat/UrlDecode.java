package de.usd.cstchef.operations.dataformat;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Url Decode", category = OperationCategory.DATAFORMAT, description = "Url decoding")
public class UrlDecode extends Operation {

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        IBurpExtenderCallbacks cbs = BurpUtils.getInstance().getCallbacks();
        IExtensionHelpers helpers = cbs.getHelpers();

        byte[] result = helpers.urlDecode(input);
        return result;
    }

}
