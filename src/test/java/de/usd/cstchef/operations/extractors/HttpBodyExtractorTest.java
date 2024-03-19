package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertEquals;

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
            assertEquals(perform(factory.createByteArray(res), MessageType.RESPONSE), inputs.get(res));
        }
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        String reqIn1 = "POST / HTTP/2\nHeader1: value1\nHeader2: value2\n\nparam=value\n\n";
        String reqOut1 = "param=value";
        String reqIn2 = "GET / HTTP/2\nHeader1: value1\nHeader2: value2\n\n";
        String reqOut2 = "";

        String resIn1 = "HTTP/2 200 Ok\nHeader1: value1\nHeader2: value2\n\n<!doctype html>\n<html>\n<h1>Example body</h1>\n</html>\n\n";
        String resOut1 = "<!doctype html>\n<html>\n<h1>Example body</h1>\n</html>";

        inputs.put(reqIn1, reqOut1);
        inputs.put(reqIn2, reqOut2);
        inputs.put(resIn1, resOut1);
    }
}
