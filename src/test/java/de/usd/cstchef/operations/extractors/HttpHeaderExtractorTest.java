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
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HttpHeaderExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpHeaderExtractorTest extends HttpHeaderExtractor {

    // HashMap<Input, Triplet<expectedOutput, headerName, throwsException>>
    HashMap<String, Triplet<String, String, Boolean>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Triplet<String, String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            this.headerNameField.setText(res.getValue1());
            if (res.getValue2()) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                assertEquals("Parameter name not found.", exception.getMessage());
            }
            else{
                //assertEquals(perform(inputArray, messageType), outputArray);
                assertArrayEquals(outputArray.getBytes(), perform(inputArray).getBytes());
            }
        }
    }

    @Before
    public void setup() {
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        // Header1
        String reqIn1 = """
                GET / HTTP/2
                Header1: value1
                Header2: value2

                a
                """;
        String reqOut1 = "value1";
        String reqHeader1 = "Header1";
        Triplet<String, String, Boolean> reqTriplet1 = new Triplet<String, String, Boolean>(reqOut1, reqHeader1, false);

        // Header2
        String reqIn2 = """
                GET / HTTP/2
                Header1: value1
                Header2: value2

                b
                """;
        String reqOut2 = "value2";
        String reqHeader2 = "Header2";
        Triplet<String, String, Boolean> reqTriplet2 = new Triplet<String, String, Boolean>(reqOut2, reqHeader2, false);

        // Header3 - Exception
        String reqIn3 = """
                GET / HTTP/2
                Header1: value1
                Header2: value2

                c
                """;
        String reqOut3 = "";
        String reqHeader3 = "Header3";
        Triplet<String, String, Boolean> reqTriplet3 = new Triplet<String, String, Boolean>(reqOut3, reqHeader3, true);

        // empty headerName
        String reqIn4 = """
                GET / HTTP/2
                Header1: value1
                Header2: value2

                d
                """;
        String reqOut4 = "";
        String reqHeader4 = "";
        Triplet<String, String, Boolean> reqTriplet4 = new Triplet<String,String,Boolean>(reqOut4, reqHeader4, false);

        // HTTP Response - Header2
        String resIn1 = """
                HTTP/2 200 Ok
                Header1: value1
                Header2: value2


                """;
        String resOut1 = "value2";
        String resHeader1 = "Header2";
        Triplet<String, String, Boolean> resTriplet1 = new Triplet<String,String,Boolean>(resOut1, resHeader1, false);

        inputs.put(reqIn1, reqTriplet1);
        inputs.put(reqIn2, reqTriplet2);
        inputs.put(reqIn3, reqTriplet3);
        inputs.put(reqIn4, reqTriplet4);
        inputs.put(resIn1, resTriplet1);
    }
}
