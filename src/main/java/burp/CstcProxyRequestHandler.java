package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;

import static burp.api.montoya.proxy.http.ProxyRequestReceivedAction.continueWith;

public class CstcProxyRequestHandler implements ProxyRequestHandler {
    
    private View view;

    public CstcProxyRequestHandler(View view) {
        this.view = view;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (BurpUtils.getInstance().getFilterState().shouldProcess(FilterState.BurpOperation.INCOMING_PROXY_REQUEST, ToolType.PROXY)) {
            ByteArray request = interceptedRequest.toByteArray();
            ByteArray modifiedRequest = view.getIncomingProxyRequestRecipePanel().bake(request, MessageType.REQUEST);
            return continueWith(HttpRequest.httpRequest(modifiedRequest).withService(interceptedRequest.httpService()));
        }
        else{
            return continueWith(interceptedRequest);
        }
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
    
}