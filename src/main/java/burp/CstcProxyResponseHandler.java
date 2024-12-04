package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;

import static burp.api.montoya.proxy.http.ProxyResponseToBeSentAction.continueWith;

public class CstcProxyResponseHandler implements ProxyResponseHandler {
    
    private View view;

    public CstcProxyResponseHandler(View view) {
        this.view = view;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        if (BurpUtils.getInstance().getFilterState().shouldProcess(FilterState.BurpOperation.INCOMING_HTTP_RESPONSE, ToolType.PROXY)) {
            ByteArray response = interceptedResponse.toByteArray();
            ByteArray modifiedResponse = view.getOutgoingProxyResponseRecipePanel().bake(response, MessageType.RESPONSE);
            return continueWith(HttpResponse.httpResponse(modifiedResponse));
        }
        else{
            return continueWith(interceptedResponse);
        }
    }
    
}