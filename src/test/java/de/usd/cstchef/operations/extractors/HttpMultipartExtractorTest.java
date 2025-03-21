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

@OperationInfos(name = "HttpMultipartExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpMultipartExtractorTest extends HttpMultipartExtractor {

    // HashMap<Input, Triplet<expectedOutput, parameter, throwsException>>
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
                if(messageType == MessageType.RESPONSE) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                assertEquals("Input is not a valid HTTP request.", exception.getMessage());
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

        // default case
        String reqIn1 = """
            GET / HTTP/2
            Header1: a
            Content-Type: multipart/form-data; boundary=-----2a8ae6ad
            
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter1"; filename="file1"

            value1
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter2";

            value2

            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter3"; filename="file1"

            
            -----2a8ae6ad
                """;
        String reqOut1 = "value1";
        String reqParam1 = "parameter1";
        Triplet<String, String, Boolean> reqTriplet1 = new Triplet<String, String, Boolean>(reqOut1, reqParam1, false);

        // default case + newline
        String reqIn2 = """
            GET / HTTP/2
            Header1: a
            Content-Type: multipart/form-data; boundary=-----2a8ae6ad
            
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter1"; filename="file1"

            value1
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter2";

            value2

            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter3"; filename="file1"

            
            -----2a8ae6ad
                """;
        String reqOut2 = "value2\n";
        String reqParam2 = "parameter2";
        Triplet<String, String, Boolean> reqTriplet2 = new Triplet<String, String, Boolean>(reqOut2, reqParam2, false);

        // empty value
        String reqIn3 = """
            GET / HTTP/2
            Header1: c
            Content-Type: multipart/form-data; boundary=-----2a8ae6ad
            
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter1"; filename="file1"

            value1
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter2";

            value2

            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter3"; filename="file1"

            
            -----2a8ae6ad
                """;
        String reqOut3 = "";
        String reqParam3 = "parameter3";
        Triplet<String, String, Boolean> reqTriplet3 = new Triplet<String, String, Boolean>(reqOut3, reqParam3, false);

        // param not found
        String reqIn4 = """
            GET / HTTP/2
            Header1: d
            Content-Type: multipart/form-data; boundary=-----2a8ae6ad
            
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter1"; filename="file1"

            value1
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter2";

            value2

            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter3"; filename="file1"

            
            -----2a8ae6ad
                """;
        String reqOut4 = "";
        String reqParam4 = "parameter4";
        Triplet<String, String, Boolean> reqTriplet4 = new Triplet<String, String, Boolean>(reqOut4, reqParam4, true);

        // empty param
        String reqIn5 = """
            GET / HTTP/2
            Header1: e
            Content-Type: multipart/form-data; boundary=-----2a8ae6ad
            
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter1"; filename="file1"

            value1
            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter2";

            value2

            -----2a8ae6ad
            Content-Disposition: form-data; name="parameter3"; filename="file1"

            
            -----2a8ae6ad
                """;
        String reqParam5 = "";
        Triplet<String, String, Boolean> reqTriplet5 = new Triplet<String, String, Boolean>(reqIn5, reqParam5, false);

        // HTTP Response
        String resIn1 = """
            HTTP/2 200 Ok
            Header1: value1
            Header2: value2
                """;
        String resOut1 = "";
        String resParam1 = "abc";
        Triplet<String, String, Boolean> resTriplet1 = new Triplet<String,String,Boolean>(resOut1, resParam1, true);

        inputs.put(reqIn1, reqTriplet1);
        inputs.put(reqIn2, reqTriplet2);
        inputs.put(reqIn3, reqTriplet3);
        inputs.put(reqIn4, reqTriplet4);
        inputs.put(reqIn5, reqTriplet5);
        inputs.put(resIn1, resTriplet1);
    }
}
