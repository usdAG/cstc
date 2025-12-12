package burp;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import static burp.api.montoya.core.ToolType.EXTENSIONS;
import static burp.api.montoya.core.ToolType.PROXY;

public class CstcHttpHandler implements HttpHandler {

    private View view;

    CstcHttpHandler(View view) {
        this.view = view;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {

        if(requestToBeSent.toolSource().isFromTool(PROXY)) {
            return continueWith(requestToBeSent);
        }

        if(requestToBeSent.toolSource().isFromTool(EXTENSIONS) && requestToBeSent.hasHeader("X-CSTC-79301f837932346cb067c568e27369bf")) {
            HttpRequest request = requestToBeSent.withRemovedHeader("X-CSTC-79301f837932346cb067c568e27369bf");
            return continueWith(request, Annotations.annotations("CSTC"));
        }

        if (BurpUtils.getInstance().getFilterState().shouldProcess(FilterState.BurpOperation.OUTGOING, requestToBeSent.toolSource().toolType())) {

            ByteArray request = requestToBeSent.toByteArray();
            ByteArray modifiedRequest = view.getOutgoingRecipePanel().bake(request, null);
            return continueWith(HttpRequest.httpRequest(modifiedRequest).withService(requestToBeSent.httpService()));
        }
        else{
            return continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (BurpUtils.getInstance().getFilterState().shouldProcess(FilterState.BurpOperation.INCOMING, responseReceived.toolSource().toolType())) {
            if(responseReceived.annotations().hasNotes() && responseReceived.annotations().notes().equals("CSTC")) {
                return continueWith(responseReceived);
            }
            ByteArray response = responseReceived.toByteArray();
            ByteArray modifiedResponse = view.getIncomingRecipePanel().bake(response, responseReceived.initiatingRequest().toByteArray());
            return continueWith(HttpResponse.httpResponse(modifiedResponse));
        }
        else{
            return continueWith(responseReceived);
        }
    }

}
