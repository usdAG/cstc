package burp.objects;

import java.util.List;
import java.util.regex.Pattern;

import org.bouncycastle.util.Arrays;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.HttpTransformation;
import de.usd.cstchef.operations.extractors.JsonExtractor;

public class CstcHttpRequest implements HttpRequest {

    ByteArray httpRequest;

    public CstcHttpRequest(ByteArray httpRequest) {
        this.httpRequest = httpRequest;
    }

    @Override
    public ByteArray body() {
        int index = 0;
        byte[] request = this.httpRequest.getBytes();
        for(int i = 0; i < request.length - 1; i++) {
            if(request[i] == (byte)'\n' && request[i+1] == (byte)'\n') {
                index = i + 2;
            }
        }

        byte[] body = new byte[request.length - index];
        for(int i = index; i < request.length; i++) {
            body[i - index] = request[i];
        }

        return CstcByteArray.byteArray(body);
    }

    @Override
    public String headerValue(String name) {        
        byte[] requestBytes = this.httpRequest.getBytes();
        String request = new String(requestBytes);

        String[] requestLines = request.split("\n");
        for(String line : requestLines) {
            String[] header = line.split(": ");
            if(header[0].equals(name)) {
                return header[1];
            }
        }

        throw new IllegalArgumentException("Parameter name not found.");
    }

    @Override
    public String parameterValue(String name, HttpParameterType type) {
        byte[] requestBytes = this.httpRequest.getBytes();
        String request = new String(requestBytes);
        switch(type) {
            case URL:
                String query = request.split("\n")[0].split("\\?")[1].split("\\s")[0];
    
                for(String param : query.split("&")) {
                    String[] keyValue = param.split("=");
                    if(keyValue[0].equals(name)) {
                        return keyValue[1];
                    }
                }
    
                throw new IllegalArgumentException("Parameter name not found.");
            case BODY:
                // get Content-Type
                String contentType = headerValue("Content-Type").split(";|\n")[0];

                // multipart
                if(contentType.equals("multipart/form-data")) {
                    String boundary = headerValue("Content-Type").split("boundary=")[1];
                    String[] multipart = request.split(boundary + "\n\n")[1].split(boundary);
                    for(int i = 1; i < multipart.length; i++) {
                        String parameterName = multipart[i].split("name=\"")[1].split("\"")[0]; // throws ArrayIndexOutOfBoundsException in case param is not found
                        if(parameterName.equals(name)) {
                            String output = multipart[i].split("\n\n")[1];
                            if(output.endsWith("\n")) {
                                return output.trim();
                            }
                            else{
                                return output + "\n";
                            }
                        }
                    }
                
                    throw new IllegalArgumentException("Input is not a valid request");
                }

                // application/x-www-form-urlencoded
                else if(contentType.equals("application/x-www-form-urlencoded")) {
                    String postBody = request.split("\n\n")[1].trim();
                    String[] params = postBody.split("&");
                    for(String s : params) {
                        String[] keyValue = s.split("=");
                        if(keyValue[0].equals(name)) {
                            return keyValue[1];
                        }
                    }

                    throw new IllegalArgumentException("Input is not a vlaid request");
                }
            case XML:
                String postBody = request.split("\n\n")[1].trim();
                String fieldValue = postBody.split("<" + name + ">")[1].split("<")[0];
                return fieldValue;
                
            default:
                return null;
        }
    }

    @Override
    public String method() {
        byte[] requestBytes = this.httpRequest.getBytes();
        String request = new String(requestBytes);

        String method = request.split("\\s")[0];
        return method;
    }

    @Override
    public String url() {
        byte[] requestBytes = this.httpRequest.getBytes();
        String request = new String(requestBytes);

        String url = request.split("\\s")[1];
        return url;
    }

    @Override
    public ParsedHttpParameter parameter(String name, HttpParameterType type) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'parameter'");
    }

    @Override
    public boolean isInScope() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'isInScope'");
    }

    @Override
    public HttpService httpService() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'httpService'");
    }

    @Override
    public String path() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'path'");
    }

    @Override
    public String query() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'query'");
    }

    @Override
    public String pathWithoutQuery() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'pathWithoutQuery'");
    }

    @Override
    public String fileExtension() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'fileExtension'");
    }

    @Override
    public ContentType contentType() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'contentType'");
    }

    @Override
    public List<ParsedHttpParameter> parameters() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'parameters'");
    }

    @Override
    public List<ParsedHttpParameter> parameters(HttpParameterType type) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'parameters'");
    }

    @Override
    public boolean hasParameters() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasParameters'");
    }

    @Override
    public boolean hasParameters(HttpParameterType type) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasParameters'");
    }

    @Override
    public boolean hasParameter(String name, HttpParameterType type) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasParameter'");
    }

    @Override
    public boolean hasParameter(HttpParameter parameter) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'hasParameter'");
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
    public String bodyToString() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'bodyToString'");
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
    public HttpRequest copyToTempFile() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'copyToTempFile'");
    }

    @Override
    public HttpRequest withService(HttpService service) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withService'");
    }

    @Override
    public HttpRequest withPath(String path) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withPath'");
    }

    @Override
    public HttpRequest withMethod(String method) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withMethod'");
    }

    @Override
    public HttpRequest withHeader(HttpHeader header) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withHeader'");
    }

    @Override
    public HttpRequest withHeader(String name, String value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withHeader'");
    }

    @Override
    public HttpRequest withParameter(HttpParameter parameters) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withParameter'");
    }

    @Override
    public HttpRequest withAddedParameters(List<? extends HttpParameter> parameters) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAddedParameters'");
    }

    @Override
    public HttpRequest withAddedParameters(HttpParameter... parameters) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAddedParameters'");
    }

    @Override
    public HttpRequest withRemovedParameters(List<? extends HttpParameter> parameters) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withRemovedParameters'");
    }

    @Override
    public HttpRequest withRemovedParameters(HttpParameter... parameters) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withRemovedParameters'");
    }

    @Override
    public HttpRequest withUpdatedParameters(List<? extends HttpParameter> parameters) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withUpdatedParameters'");
    }

    @Override
    public HttpRequest withUpdatedParameters(HttpParameter... parameters) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withUpdatedParameters'");
    }

    @Override
    public HttpRequest withTransformationApplied(HttpTransformation transformation) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withTransformationApplied'");
    }

    @Override
    public HttpRequest withBody(String body) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withBody'");
    }

    @Override
    public HttpRequest withBody(ByteArray body) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withBody'");
    }

    @Override
    public HttpRequest withAddedHeader(String name, String value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAddedHeader'");
    }

    @Override
    public HttpRequest withAddedHeader(HttpHeader header) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAddedHeader'");
    }

    @Override
    public HttpRequest withUpdatedHeader(String name, String value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withUpdatedHeader'");
    }

    @Override
    public HttpRequest withUpdatedHeader(HttpHeader header) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withUpdatedHeader'");
    }

    @Override
    public HttpRequest withRemovedHeader(String name) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withRemovedHeader'");
    }

    @Override
    public HttpRequest withRemovedHeader(HttpHeader header) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withRemovedHeader'");
    }

    @Override
    public HttpRequest withMarkers(List<Marker> markers) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withMarkers'");
    }

    @Override
    public HttpRequest withMarkers(Marker... markers) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withMarkers'");
    }

    @Override
    public HttpRequest withDefaultHeaders() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withDefaultHeaders'");
    }
    
}
