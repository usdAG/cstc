package de.usd.cstchef.operations.networking;

import javax.swing.JCheckBox;
import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "HTTP Request", category = OperationCategory.NETWORKING, description = "Makes an http reqeust and returns the response.")
public class HTTPRequest extends Operation {

    private VariableTextField hostTxt;
    private VariableTextField portTxt;
    private JCheckBox sslEnabledBox;

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
        IExtensionHelpers helper = callbacks.getHelpers();
        String protocol = sslEnabledBox.isSelected() ? "https" : "http";
        IHttpService service = helper.buildHttpService(hostTxt.getText(), Integer.valueOf(portTxt.getText()), protocol);
        IHttpRequestResponse response = callbacks.makeHttpRequest(service, input);
        return response.getResponse();
    }

    @Override
    public void createUI() {
        this.hostTxt = new VariableTextField();
        this.addUIElement("Host", this.hostTxt);

        this.portTxt = new VariableTextField();
        this.addUIElement("Port", this.portTxt);

        this.sslEnabledBox = new JCheckBox();
        this.addUIElement("SSL", this.sslEnabledBox);
    }

}
