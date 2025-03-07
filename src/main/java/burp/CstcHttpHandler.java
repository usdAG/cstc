package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

import static burp.api.montoya.core.ToolType.EXTENSIONS;

public class CstcHttpHandler implements HttpHandler {

    private View view;

    CstcHttpHandler(View view) {
        this.view = view;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (BurpUtils.getInstance().getFilterState().shouldProcess(FilterState.BurpOperation.OUTGOING, requestToBeSent.toolSource().toolType())) {
            if(requestToBeSent.hasHeader("X-CSTC-79301f837932346cb067c568e27369bf") && requestToBeSent.toolSource().isFromTool(EXTENSIONS)) {
                ByteArray request = requestToBeSent.withRemovedHeader("X-CSTC-79301f837932346cb067c568e27369bf").toByteArray();
                return continueWith(HttpRequest.httpRequest(request).withService(requestToBeSent.httpService()));
            }

            ByteArray request = requestToBeSent.toByteArray();
            ByteArray modifiedRequest = view.getOutgoingRecipePanel().bake(request, MessageType.REQUEST);
            return continueWith(HttpRequest.httpRequest(modifiedRequest).withService(requestToBeSent.httpService()));
        }
        else{
            return continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (BurpUtils.getInstance().getFilterState().shouldProcess(FilterState.BurpOperation.INCOMING, responseReceived.toolSource().toolType())) {
            ByteArray response = responseReceived.toByteArray();
            ByteArray modifiedResponse = view.getIncomingRecipePanel().bake(response, MessageType.RESPONSE);
            return continueWith(HttpResponse.httpResponse(modifiedResponse));
        }
        else{
            return continueWith(responseReceived);
        }
    }

}
