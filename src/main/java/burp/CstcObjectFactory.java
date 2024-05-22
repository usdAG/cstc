package burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public interface CstcObjectFactory {
    public ByteArray createByteArray(String s);
    public ByteArray createByteArray(int i);
    public ByteArray createByteArray(byte[] bytes);
    public ByteArray getHttpRequestBody(ByteArray request);
    public ByteArray getHttpResponseBody(ByteArray response);
    public HttpRequest createHttpRequest(ByteArray request);
    public HttpResponse createHttpResponse(ByteArray response);
}
