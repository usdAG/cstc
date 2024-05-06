package burp.objects;

import java.time.ZonedDateTime;
import java.util.Optional;

import burp.api.montoya.http.message.Cookie;

public class CstcCookie implements Cookie{

    private String name;
    private String value;

    public CstcCookie(String name, String value) {
        this.name = name;
        this.value = value;
    }

    @Override
    public String name() {
        return this.name;
    }

    @Override
    public String value() {
        return this.value;
    }

    @Override
    public String domain() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'domain'");
    }

    @Override
    public String path() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'path'");
    }

    @Override
    public Optional<ZonedDateTime> expiration() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'expiration'");
    }
    
}
