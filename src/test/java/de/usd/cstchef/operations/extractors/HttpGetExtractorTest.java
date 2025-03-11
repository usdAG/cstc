package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.HashMap;

import org.javatuples.Triplet;
import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.utils.UnitTestObjectFactory;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.OperationCategory;


@OperationInfos(name = "HttpGetExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpGetExtractorTest extends HttpGetExtractor {

    // HashMap<Input, Pair<expectedOutput, paramToExtract, throwsException>>
    HashMap<String, Triplet<String, String, Boolean>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Triplet<String, String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            MessageType messageType = parseMessageType(inputArray);
            this.parameter.setText(res.getValue1());
            if (res.getValue2()) {
                if(messageType == MessageType.REQUEST) {
                    Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                    assertEquals("Parameter name not found.", exception.getMessage());
                }
                else{
                    Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                    assertEquals("Input is not a valid HTTP Request", exception.getMessage());
                }
            }
            else{
                assertArrayEquals(outputArray.getBytes(), perform(inputArray).getBytes());
            }
        }
    }

    @Before
    public void setup() {
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        // param1
        String reqIn1 = """
                GET /?param1=value1&param2=value2 HTTP/2
                Header1: a


                """;
        String reqOut1 = "value1";
        String reqParam1 = "param1";
        Triplet<String, String, Boolean> reqTriplet1 = new Triplet<String, String, Boolean>(reqOut1, reqParam1, false);

        // param2
        String reqIn2 = """
                GET /?param1=value1&param2=value2 HTTP/2
                Header1: b


                """;
        String reqOut2 = "value2";
        String reqParam2 = "param2";
        Triplet<String, String, Boolean> reqTriplet2 = new Triplet<String, String, Boolean>(reqOut2, reqParam2, false);

        // param3 - Exception
        String reqIn3 = """
                GET /?param1=value1&param2=value2 HTTP/2
                Header1: c


                """;
        String reqOut3 = "";
        String reqParam3 = "param3";
        Triplet<String, String, Boolean> reqTriplet3 = new Triplet<String, String, Boolean>(reqOut3, reqParam3, true);

        // empty paramName
        String reqIn4 = """
                GET /?param1=value1&param2=value2 HTTP/2
                Header1: d


                """;
        String reqOut4 = "";
        String reqParam4 = "";
        Triplet<String, String, Boolean> reqTriplet4 = new Triplet<String,String,Boolean>(reqOut4, reqParam4, false);

        // HTTP Response
        String resIn1 = """
                HTTP/2 200 Ok
                Header: value


                """;
        String resOut1 = "";
        String resParam1 = "param1";
        Triplet<String, String, Boolean> resTriplet1 = new Triplet<String,String,Boolean>(resOut1, resParam1, true);

        inputs.put(reqIn1, reqTriplet1);
        inputs.put(reqIn2, reqTriplet2);
        inputs.put(reqIn3, reqTriplet3);
        inputs.put(reqIn4, reqTriplet4);
        inputs.put(resIn1, resTriplet1);
        
    }
}
