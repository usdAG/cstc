package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class BurpObjectFactory implements CstcObjectFactory{

    @Override
    public ByteArray createByteArray(String s) {
        return ByteArray.byteArray(s);
    }

    @Override
    public ByteArray createByteArray(byte[] bytes) {
        return ByteArray.byteArray(bytes);
    }

    @Override
    public ByteArray createByteArray(int i) {
        return ByteArray.byteArray(i);
    }

    @Override
    public ByteArray getHttpRequestBody(ByteArray request) {
        return HttpRequest.httpRequest(request).body();
    }

    @Override
    public ByteArray getHttpResponseBody(ByteArray response) {
        return HttpResponse.httpResponse(response).body();
    }

    @Override
    public HttpRequest createHttpRequest(ByteArray request) {
        return HttpRequest.httpRequest(request);
    }

    @Override
    public HttpResponse createHttpResponse(ByteArray response) {
        return HttpResponse.httpResponse(response);
    }
    
}
