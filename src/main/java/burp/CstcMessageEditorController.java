package burp;

public class CstcMessageEditorController implements IMessageEditorController {

    private IHttpService httpService = null;
    private byte[] request = null;
    private byte[] response = null;

    public void setHttpRequestResponse(IHttpRequestResponse requestResponse) {
        this.httpService = requestResponse.getHttpService();
        this.request = requestResponse.getRequest();
        this.response = requestResponse.getResponse();
    }

    public void setRequest(byte[] request) {
        this.request = request;
    }

    public void setResponse(byte[] response) {
        this.request = response;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public byte[] getResponse() {
        return response;
    }
}
