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


@OperationInfos(name = "HttpUriExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpUriExtractorTest extends HttpUriExtractor {

    // HashMap<Input, Triplet<expectedOutput, withOrWithoutParams, throwsException>>
    HashMap<String, Triplet<String, Boolean, Boolean>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Triplet<String, Boolean, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            MessageType messageType = parseMessageType(inputArray);
            this.checkbox.setSelected(res.getValue1());
            if (res.getValue2()) {
                if(messageType == MessageType.REQUEST) {
                    Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray, messageType));
                    assertEquals("Input is not a valid request", exception.getMessage());
                }
                if(messageType == MessageType.RESPONSE) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray, messageType));
                assertEquals("Input is not a valid HTTP Request", exception.getMessage());
                }
            }
            else{
                assertArrayEquals(outputArray.getBytes(), perform(inputArray, messageType).getBytes());
            }
        }
    }

    @Before
    public void setup() {
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        // with params
        String reqIn1 = """
                GET /uri?param=value HTTP/2
                Header1: a


                """;
        String reqOut1 = "/uri?param=value";
        Triplet<String, Boolean, Boolean> reqTriplet1 = new Triplet<String, Boolean, Boolean>(reqOut1, true, false);

        // without params
        String reqIn2 = """
                GET /uri?param=value HTTP/2
                Header1: b

                
                """;
        String reqOut2 = "/uri";
        Triplet<String, Boolean, Boolean> reqTriplet2 = new Triplet<String, Boolean, Boolean>(reqOut2, false, false);

        // HTTP Response
        String reqIn3 = """
                HTTP/2 200 Ok
                Header1: value1
                """;
        String reqOut3 = "";
        Triplet<String, Boolean, Boolean> reqTriplet3 = new Triplet<String, Boolean, Boolean>(reqOut3, false, true);


        inputs.put(reqIn1, reqTriplet1);
        inputs.put(reqIn2, reqTriplet2);
        inputs.put(reqIn3, reqTriplet3);
        
    }
}
