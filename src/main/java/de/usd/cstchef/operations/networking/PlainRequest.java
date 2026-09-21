package de.usd.cstchef.operations.networking;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.swing.JCheckBox;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;


@OperationInfos(name = "Send Plain Request", category = OperationCategory.NETWORKING, description = "Makes an request and returns the response. You can use this operation in combination with e.g. \"Static String\" to perform more complex requests.")
public class PlainRequest extends Operation {

    private VariableTextField hostTxt;
    private VariableTextField portTxt;
    private JCheckBox sslEnabledBox;
    private JSpinner timeoutSecondsSpinner;

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        MontoyaApi api = BurpUtils.getInstance().getApi();
        HttpService service = HttpService.httpService(hostTxt.getText(), Integer.valueOf(portTxt.getText()), sslEnabledBox.isSelected());
        int timeoutSeconds = (Integer) timeoutSecondsSpinner.getValue();

        Callable<HttpRequestResponse> runnable = new PlainRequestRunnable(input, service, api);
        ExecutorService executor = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "CSTC Plain Request");
            thread.setDaemon(true);
            return thread;
        });

        try {
            Future<HttpRequestResponse> future = executor.submit(runnable);
            HttpRequestResponse result = future.get(timeoutSeconds, TimeUnit.SECONDS);
            if (result == null || result.response() == null) {
                throw new IllegalStateException("No response received.");
            }

            return result.response().toByteArray();
        } catch (TimeoutException e) {
            throw new TimeoutException("Request timed out after " + timeoutSeconds + " seconds.");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Exception) {
                throw (Exception) cause;
            }
            throw e;
        } finally {
            executor.shutdownNow();
        }
    }

    @Override
    public void createUI() {
        this.hostTxt = new VariableTextField();
        this.addUIElement("Host", this.hostTxt);

        this.portTxt = new VariableTextField();
        this.addUIElement("Port", this.portTxt);

        this.sslEnabledBox = new JCheckBox();
        this.addUIElement("SSL", this.sslEnabledBox);

        this.timeoutSecondsSpinner = new JSpinner(new SpinnerNumberModel(30, 1, 900, 1));
        this.addUIElement("Timeout (s)", this.timeoutSecondsSpinner);
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
            HttpRequest requestWithCustomHeader = HttpRequest.httpRequest(service, data).withAddedHeader("X-CSTC-79301f837932346cb067c568e27369bf", "cstc");
            return api.http().sendRequest(requestWithCustomHeader);
        }

    }

}
