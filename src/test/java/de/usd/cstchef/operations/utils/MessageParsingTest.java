package de.usd.cstchef.operations.utils;

import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.utils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class MessageParsingTest extends Operation
{
    HashMap<String, MessageType> correctInputs = new HashMap<String, MessageType>();
    HashMap<String, MessageType> wrongInputs = new HashMap<String, MessageType>();

    @Test
    public void correctMessageTest() throws Exception
    {
        for(String s : correctInputs.keySet()){
            assert parseMessageType(factory.createByteArray(s)).equals(correctInputs.get(s));
        }
    }

    public void wrongMessageTest() throws Exception
    {
        for(String s : wrongInputs.keySet()){
            assert !parseMessageType(factory.createByteArray(s)).equals(wrongInputs.get(s));
        }
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        correctInputs.put("GET / HTTP/1.1", MessageType.REQUEST);
        correctInputs.put("POST /asd HTTP/2", MessageType.REQUEST);
        correctInputs.put("HEAD / HTTP/2", MessageType.REQUEST);
        correctInputs.put("PUT /new.html HTTP/2", MessageType.REQUEST);
        correctInputs.put("DELETE /old.html HTTP/2", MessageType.REQUEST);
        correctInputs.put("CONNECT /www.example.com HTTP/2", MessageType.REQUEST); // CONNECT requests without leading slash?
        correctInputs.put("OPTIONS /dir/index.html HTTP/2", MessageType.REQUEST);
        correctInputs.put("TRACE /reflect HTTP/2", MessageType.REQUEST);
        correctInputs.put("PATCH /file.txt HTTP/2", MessageType.REQUEST);

        correctInputs.put("HTTP/1.1 200 Ok", MessageType.RESPONSE);
        correctInputs.put("HTTP/2 301 Moved Permanently", MessageType.RESPONSE);

        wrongInputs.put("ABC / HTTP/2", MessageType.REQUEST);
        wrongInputs.put("GET abc HTTP/2", MessageType.REQUEST);
        wrongInputs.put("POST / HTT/2", MessageType.REQUEST);
        wrongInputs.put("OPTIONS / HTTP2", MessageType.REQUEST);
        wrongInputs.put("GET / HTTP/", MessageType.REQUEST);
        wrongInputs.put("GET / HTTP/1.", MessageType.REQUEST);
        wrongInputs.put("HTTP/2 200 Ok", MessageType.REQUEST);

        wrongInputs.put("HTTP/2", MessageType.RESPONSE);
        wrongInputs.put("HTT/2 301 Moved Permanently", MessageType.RESPONSE);
        wrongInputs.put("HTTP2 301 Moved Permanently", MessageType.RESPONSE);
        wrongInputs.put("HTTP/1. 301 Moved Permanently", MessageType.RESPONSE);
        wrongInputs.put("HTTP/ 301 Moved Permanently", MessageType.RESPONSE);
        wrongInputs.put("HTTP/2 30 Moved Permanently", MessageType.RESPONSE);
        wrongInputs.put("GET / HTTP/2", MessageType.RESPONSE);

    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'perform'");
    }
}