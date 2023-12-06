package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.FilterState;
import de.usd.cstchef.view.View;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class CstcHttpHandler implements HttpHandler {

    private View view;

    CstcHttpHandler(View view) {
        this.view = view;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (view.getFilterState().shouldProcess(FilterState.BurpOperation.OUTGOING)) {
            ByteArray request = requestToBeSent.toByteArray();
            ByteArray modifiedRequest = view.getOutgoingRecipePanel().bake(request);
            Logger.getInstance().log("modified request: \n" + new String(modifiedRequest.getBytes()));
            return continueWith(HttpRequest.httpRequest(modifiedRequest).withService(requestToBeSent.httpService()));
        }
        else{
            return continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (view.getFilterState().shouldProcess(FilterState.BurpOperation.INCOMING)) {
            ByteArray response = responseReceived.toByteArray();
            ByteArray modifiedResponse = view.getIncomingRecipePanel().bake(response);
            Logger.getInstance().log("modified response: \n" + new String(modifiedResponse.getBytes()));
            return continueWith(HttpResponse.httpResponse(modifiedResponse));
        }
        else{
            return continueWith(responseReceived);
        }
    }

}
