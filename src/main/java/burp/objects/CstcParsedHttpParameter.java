package burp.objects;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

public class CstcParsedHttpParameter implements ParsedHttpParameter {

    private String value;

    public CstcParsedHttpParameter(String value) {
        this.value = value;
    }

    @Override
    public String value() {
        return this.value;
    }

    @Override
    public HttpParameterType type() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'type'");
    }

    @Override
    public String name() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'name'");
    }

    @Override
    public Range nameOffsets() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'nameOffsets'");
    }

    @Override
    public Range valueOffsets() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'valueOffsets'");
    }
    
}
