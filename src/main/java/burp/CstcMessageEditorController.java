package burp;

import java.util.Optional;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

public class CstcMessageEditorController implements MessageEditorHttpRequestResponse{

    private HttpService httpService = null;
    private HttpRequest request = null;
    private HttpResponse response = null;
    private HttpRequestResponse requestResponse = null;

    public void setHttpRequestResponse(HttpRequestResponse requestResponse) {
        this.httpService = requestResponse.httpService();
        this.request = requestResponse.request();
        this.response = requestResponse.response();
    }

    public void setRequest(HttpRequest request) {
        this.request = request;
    }

    public void setResponse(HttpResponse response) {
        this.response = response;
    }

    // @Override
    // public HttpService getHttpService() {
    //     return httpService;
    // }

    // @Override
    // public HttpRequest getRequest() {
    //     return request;
    // }

    // @Override
    // public HttpResponse getResponse() {
    //     return response;
    // }

    @Override
    public SelectionContext selectionContext() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'selectionContext'");
    }

    @Override
    public Optional<Range> selectionOffsets() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'selectionOffsets'");
    }

    @Override
    public int caretPosition() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'caretPosition'");
    }

    @Override
    public HttpRequestResponse requestResponse() {
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

}
