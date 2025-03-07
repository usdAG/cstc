package de.usd.cstchef.operations.networking;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.swing.JCheckBox;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;
import de.usd.cstchef.view.ui.VariableTextField;

import static burp.api.montoya.core.ToolType.EXTENSIONS;

@OperationInfos(name = "Send Plain Request", category = OperationCategory.NETWORKING, description = "Makes an request and returns the response. You can use this operation in combination with e.g. \"Static String\" to perform more complex requests.")
public class PlainRequest extends Operation {

    private VariableTextField hostTxt;
    private VariableTextField portTxt;
    private JCheckBox sslEnabledBox;

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        MontoyaApi api = BurpUtils.getInstance().getApi();
        HttpService service = HttpService.httpService(hostTxt.getText(), Integer.valueOf(portTxt.getText()), sslEnabledBox.isSelected());

        Callable<HttpRequestResponse> runnable = new PlainRequestRunnable(input, service, api);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<HttpRequestResponse> future = executor.submit(runnable);
        HttpRequestResponse result = future.get();
        return result == null ? null : result.response().toByteArray();
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

    public class PlainRequestRunnable implements Callable<HttpRequestResponse>{

        private ByteArray data;
        private HttpService service;
        private MontoyaApi api;

        public PlainRequestRunnable(ByteArray dataToSent, HttpService service, MontoyaApi api){
            this.data = dataToSent;
            this.service = service;
            this.api = api;
        }

        @Override
        public HttpRequestResponse call() throws Exception {
            if(BurpUtils.getInstance().getFilterState().shouldProcess(BurpOperation.OUTGOING, EXTENSIONS)) {
                HttpRequest requestWithCustomHeader = HttpRequest.httpRequest(service, data).withAddedHeader("X-CSTC-79301f837932346cb067c568e27369bf", "cstc");
                return api.http().sendRequest(requestWithCustomHeader);
            }

            return api.http().sendRequest(HttpRequest.httpRequest(service, data));
        }

    }

}