package de.usd.cstchef.operations.networking;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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

@OperationInfos(name = "Send Plain Request", category = OperationCategory.NETWORKING, description = "Makes an request and returns the response. You can use this operation in combination with e.g. \"Static String\" to perform more complex requests.")
public class PlainRequest extends Operation {

    private VariableTextField hostTxt;
    private VariableTextField portTxt;
    private JCheckBox sslEnabledBox;

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
        IExtensionHelpers helper = callbacks.getHelpers();
        String protocol = sslEnabledBox.isSelected() ? "https" : "http";
        IHttpService service = helper.buildHttpService(hostTxt.getText(), Integer.valueOf(portTxt.getText()), protocol);

        Callable<IHttpRequestResponse> runnable = new PlainRequestRunnable(input, service, callbacks);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<IHttpRequestResponse> future = executor.submit(runnable);
        IHttpRequestResponse result = future.get();
        return result == null ? null : result.getResponse();
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

    public class PlainRequestRunnable implements Callable<IHttpRequestResponse>{

        private byte[] data;
        private IHttpService service;
        private IBurpExtenderCallbacks callbacks;

        public PlainRequestRunnable(byte[] dataToSent, IHttpService service, IBurpExtenderCallbacks callbacks){
            this.data = dataToSent;
            this.callbacks = callbacks;
            this.service = service;
        }

        @Override
        public IHttpRequestResponse call() throws Exception {
            return callbacks.makeHttpRequest(this.service, this.data);
        }

    }

}