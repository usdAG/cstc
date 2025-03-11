package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertArrayEquals;

import java.util.HashMap;

import org.javatuples.Pair;
import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.utils.UnitTestObjectFactory;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.OperationCategory;


@OperationInfos(name = "HttpBodyExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpBodyExtractorTest extends HttpBodyExtractor {

    HashMap<String, Pair<String, Boolean>> inputs = new HashMap<String, Pair<String, Boolean>>();

    @Test
    public void extractionTest() throws Exception
    {
        for(String inp : inputs.keySet()){
            Pair<String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            MessageType messageType = parseMessageType(inputArray);
            if(res.getValue1()) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                assertEquals(messageType == MessageType.REQUEST ? "HTTP Request has no body." : "HTTP Response has no body.", exception.getMessage());
            }
            else {
                assertArrayEquals(factory.createByteArray(res.getValue0()).getBytes(), perform(inputArray).getBytes());
            }
        }
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        // param=value
        String reqIn1 = """
                POST / HTTP/2
                Header1: value1
                Header2: value2
            
                param=value
                """;
        String reqOut1 = """
                param=value
                """;
        Pair<String, Boolean> reqPair1 = new Pair<String, Boolean>(reqOut1, false);

        // empty body
        String reqIn2 = """
                GET / HTTP/2
                Header1: value1
                Header2: value2


                """;
        String reqOut2 = "";
        Pair<String, Boolean> reqPair2 = new Pair<String, Boolean>(reqOut2, true);

        // HTTP Response - html body
        String resIn1 = """
                HTTP/2 200 Ok
                Header1: value1
                Header2: value2
                
                <!doctype html>
                <html>
                    <h1>Example body</h1>
                </html>
                """; 
        String resOut1 = """
            <!doctype html>
            <html>
                <h1>Example body</h1>
            </html>
                """;
        Pair<String, Boolean> resPair1 = new Pair<String, Boolean>(resOut1, false);

        // HTTP Response - empty body
        String resIn2 = """
                HTTP/2 200 Ok
                Header1: value1


                """;
        String resOut2 = "";
        Pair<String, Boolean> resPair2 = new Pair<String, Boolean>(resOut2, true);
        

        inputs.put(reqIn1, reqPair1);
        inputs.put(reqIn2, reqPair2);
        inputs.put(resIn1, resPair1);
        inputs.put(resIn2, resPair2);
    }
}