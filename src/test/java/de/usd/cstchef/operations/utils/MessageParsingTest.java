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
import de.usd.cstchef.testutils.UnitTestObjectFactory;

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

        correctInputs.put("GET / HTTP/2", MessageType.REQUEST);
        correctInputs.put("HTTP/2 301 Moved Permanently", MessageType.RESPONSE);

        wrongInputs.put("abcdefgh", MessageType.RESPONSE);
        wrongInputs.put("GET / HTTP/2", MessageType.RESPONSE);
        wrongInputs.put("HTTP/2 301 Moved Permanently", MessageType.REQUEST);
    }

    @Override
    protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'perform'");
    }
}