package burp.objects;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.KeywordCount;

public class CstcHttpResponse implements HttpResponse {

    ByteArray httpResponse;

    public CstcHttpResponse(ByteArray httpResponse) {
        this.httpResponse = httpResponse;
    }

    @Override
    public ByteArray body() {
        int index = 0;
        byte[] response = this.httpResponse.getBytes();
        for(int i = 0; i < response.length - 1; i++) {
            if(response[i] == (byte)'\n' && response[i+1] == (byte)'\n') {
                index = i + 2;
            }
        }

        byte[] body = new byte[response.length - index];
        for(int i = index; i < response.length; i++) {
            body[i - index] = response[i];
        }

        return CstcByteArray.byteArray(body);
    }

    @Override
    public List<Cookie> cookies() {
        List<Cookie> cookieList = new ArrayList<>();
        String cookies = new String();

        byte[] responseBytes = this.httpResponse.getBytes();
        String response = new String(responseBytes);

        String[] responseLines = response.split("\n");
        for(String line : responseLines) {
            String[] header = line.split(": ");
            if(header[0].equals("Set-Cookie")) {
                cookies = header[1];
            }
        }

        for(String cookie : cookies.split("; ")) {
            String[] c = cookie.split("=");
            Cookie cc = new CstcCookie(c[0], c[1]);
            cookieList.add(cc);
        }

        return cookieList;
    }

    @Override
    public String headerValue(String name) {        
        byte[] responseBytes = this.httpResponse.getBytes();
        String response = new String(responseBytes);

        String[] responseLines = response.split("\n");
        for(String line : responseLines) {
            String[] header = line.split(": ");
            if(header[0].equals(name)) {
                return header[1];
            }
        }

        throw new IllegalArgumentException("Parameter name not found.");
    }

    @Override
    public String bodyToString() {
        byte[] responseBytes = this.httpResponse.getBytes();
        String response = new String(responseBytes);

        return response.split("\n\n")[1];
    }

    @Override
    public short statusCode() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'statusCode'");
    }

    @Override
    public String reasonPhrase() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'reasonPhrase'");
    }

    @Override
    public boolean isStatusCodeClass(StatusCodeClass statusCodeClass) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'isStatusCodeClass'");
    }

    @Override
    public Cookie cookie(String name) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'cookie'");
    }

    @Override
    public String cookieValue(String name) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'cookieValue'");
    }

    @Override
    public boolean hasCookie(String name) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasCookie'");
    }

    @Override
    public boolean hasCookie(Cookie cookie) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasCookie'");
    }

    @Override
    public MimeType mimeType() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'mimeType'");
    }

    @Override
    public MimeType statedMimeType() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'statedMimeType'");
    }

    @Override
    public MimeType inferredMimeType() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'inferredMimeType'");
    }

    @Override
    public List<KeywordCount> keywordCounts(String... keywords) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'keywordCounts'");
    }

    @Override
    public List<Attribute> attributes(AttributeType... types) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'attributes'");
    }

    @Override
    public boolean hasHeader(HttpHeader header) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasHeader'");
    }

    @Override
    public boolean hasHeader(String name) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasHeader'");
    }

    @Override
    public boolean hasHeader(String name, String value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasHeader'");
    }

    @Override
    public HttpHeader header(String name) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'header'");
    }

    @Override
    public List<HttpHeader> headers() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'headers'");
    }

    @Override
    public String httpVersion() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'httpVersion'");
    }

    @Override
    public int bodyOffset() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'bodyOffset'");
    }

    @Override
    public List<Marker> markers() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'markers'");
    }

    @Override
    public boolean contains(String searchTerm, boolean caseSensitive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'contains'");
    }

    @Override
    public boolean contains(Pattern pattern) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'contains'");
    }

    @Override
    public ByteArray toByteArray() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'toByteArray'");
    }

    @Override
    public HttpResponse copyToTempFile() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'copyToTempFile'");
    }

    @Override
    public HttpResponse withStatusCode(short statusCode) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withStatusCode'");
    }

    @Override
    public HttpResponse withReasonPhrase(String reasonPhrase) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withReasonPhrase'");
    }

    @Override
    public HttpResponse withHttpVersion(String httpVersion) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withHttpVersion'");
    }

    @Override
    public HttpResponse withBody(String body) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withBody'");
    }

    @Override
    public HttpResponse withBody(ByteArray body) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withBody'");
    }

    @Override
    public HttpResponse withAddedHeader(HttpHeader header) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAddedHeader'");
    }

    @Override
    public HttpResponse withAddedHeader(String name, String value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAddedHeader'");
    }

    @Override
    public HttpResponse withUpdatedHeader(HttpHeader header) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withUpdatedHeader'");
    }

    @Override
    public HttpResponse withUpdatedHeader(String name, String value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withUpdatedHeader'");
    }

    @Override
    public HttpResponse withRemovedHeader(HttpHeader header) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withRemovedHeader'");
    }

    @Override
    public HttpResponse withRemovedHeader(String name) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withRemovedHeader'");
    }

    @Override
    public HttpResponse withMarkers(List<Marker> markers) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withMarkers'");
    }

    @Override
    public HttpResponse withMarkers(Marker... markers) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withMarkers'");
    }
    
}
