package de.usd.cstchef.utils;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.objects.CstcByteArray;
import burp.objects.CstcHttpRequest;
import burp.objects.CstcHttpResponse;

public class UnitTestObjectFactory implements CstcObjectFactory{

    @Override
    public ByteArray createByteArray(String s) {
        return CstcByteArray.byteArray(s);
    }

    @Override
    public ByteArray createByteArray(byte[] bytes) {
        return CstcByteArray.byteArray(bytes);
    }

    @Override
    public ByteArray createByteArray(int i) {
        return CstcByteArray.byteArray(i);
    }

    @Override
    public ByteArray getHttpRequestBody(ByteArray request) {
        return new CstcHttpRequest(request).body();
    }

    @Override
    public ByteArray getHttpResponseBody(ByteArray response) {
        return new CstcHttpResponse(response).body();
    }

    @Override
    public HttpRequest createHttpRequest(ByteArray request) {
        return new CstcHttpRequest(request);
    }

    @Override
    public HttpResponse createHttpResponse(ByteArray response) {
        return new CstcHttpResponse(response);
    }
    
}
