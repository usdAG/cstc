package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.FilterState;
import de.usd.cstchef.view.RequestFilterDialog;
import de.usd.cstchef.view.View;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class CstcHttpHandler implements HttpHandler {

    private MontoyaApi api;
    private View view;

    CstcHttpHandler(MontoyaApi api, View view) {
        this.api = api;
        this.view = view;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        RequestFilterDialog.getInstance().getFilterMask(null);
        if (view.getFilterState().shouldProcess(toolFlag, FilterState.BurpOperation.OUTGOING)) {
            byte[] request = requestToBeSent.toByteArray().getBytes();
            byte[] modifiedRequest = view.getOutgoingRecipePanel().bake(request);
            Logger.getInstance().log("modified request: \n" + new String(modifiedRequest));
            return continueWith(HttpRequest.httpRequest(ByteArray.byteArray(modifiedRequest)));
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (view.getFilterState().shouldProcess(toolFlag, FilterState.BurpOperation.INCOMING)) {
            byte[] response = responseReceived.toByteArray().getBytes();
            byte[] modifiedResponse = view.getIncomingRecipePanel().bake(response);
            Logger.getInstance().log("modified response: \n" + new String(modifiedResponse));
            return continueWith(HttpResponse.httpResponse(ByteArray.byteArray(modifiedResponse)));
        }
    }

}
