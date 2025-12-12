package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState;

public class CstcProxyRequestHandler implements ProxyRequestHandler {

    private View view;

    CstcProxyRequestHandler(View view) {
        this.view = view;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {

        if (BurpUtils.getInstance().getFilterState().shouldProcess(FilterState.BurpOperation.OUTGOING, ToolType.PROXY)) {

            ByteArray request = interceptedRequest.toByteArray();
            ByteArray modifiedRequest = view.getOutgoingRecipePanel().bake(request, null);

            if(HttpRequest.httpRequest(modifiedRequest).hasHeader("X-CSTC-Drop-Request")) {
                return ProxyRequestReceivedAction.drop();
            }
            else {
                return ProxyRequestReceivedAction.continueWith(HttpRequest.httpRequest(modifiedRequest).withService(interceptedRequest.httpService()));
            }

        }
        else{
            return ProxyRequestReceivedAction.continueWith(interceptedRequest);
        }
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {

        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
        

    }
    
}
