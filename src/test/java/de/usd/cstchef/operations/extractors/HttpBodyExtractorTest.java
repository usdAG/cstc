package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;

import java.util.HashMap;

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

    HashMap<String, String> inputs = new HashMap<String, String>();

    @Test
    public void extractionTest() throws Exception
    {
        for(String res : inputs.keySet()){
            assertArrayEquals(factory.createByteArray(inputs.get(res)).getBytes(), perform(factory.createByteArray(res), MessageType.RESPONSE).getBytes());
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

        // empty body
        String reqIn2 = """
                GET / HTTP/2
                Header1: value1
                Header2: value2


                """;
        String reqOut2 = "";

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

        // HTTP Response - empty body
        String resIn2 = """
                HTTP/2 200 Ok
                Header1: value1


                """;
        String resOut2 = "";
        

        inputs.put(reqIn1, reqOut1);
        inputs.put(reqIn2, reqOut2);
        inputs.put(resIn1, resOut1);
        inputs.put(resIn2, resOut2);
    }
}