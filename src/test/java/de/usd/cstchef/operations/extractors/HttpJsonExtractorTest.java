package de.usd.cstchef.operations.extractors;

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

@OperationInfos(name = "HttpJsonExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpJsonExtractorTest extends HttpJsonExtractor {

    // HashMap<Input String, Pair<Output String, throwsException>>
    HashMap<String, Triplet<String, String, Boolean>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Triplet<String, String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            MessageType messageType = parseMessageType(inputArray);
            this.fieldTxt.setText(res.getValue1());
            if (res.getValue2()) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray, messageType));
                assertEquals("Parameter name not found.", exception.getMessage());
            }
            else{
                assertEquals(perform(inputArray, messageType), outputArray);
            }
        }
    }

    @Before
    public void setup() {
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        // param1
        String reqIn1 = "POST / HTTP/2\nHeader1: value1\nContent-Type: application/json\n\n{\"param1\": \"value1\", \"param2\": \"value2\"}\n\n";
        String reqOut1 = "value1";
        String reqParam1 = "param1";
        Triplet<String, String, Boolean> reqTriplet1 = new Triplet<String, String, Boolean>(reqOut1, reqParam1, false);

        // SESSION
        String reqIn2 = "POST / HTTP/2\nHeader1: value1\nContent-Type: application/json\n\n{\"param1\": \"value1\", \"param2\": \"value2\"}\n\n";
        String reqOut2 = "value2";
        String reqParam2 = "param2";
        Triplet<String, String, Boolean> reqTriplet2 = new Triplet<String, String, Boolean>(reqOut2, reqParam2, false);

        // param3 - Exception
        String reqIn3 = "POST / HTTP/2\nHeader1: value1\nContent-Type: application/json\n\n{\"param1\": \"value1\", \"param2\": \"value2\"}\n\n";
        String reqOut3 = "";
        String reqParam3 = "param3";
        Triplet<String, String, Boolean> reqTriplet3 = new Triplet<String, String, Boolean>(reqOut3, reqParam3, true);

        inputs.put(reqIn1, reqTriplet1);
        inputs.put(reqIn2, reqTriplet2);
        inputs.put(reqIn3, reqTriplet3);
    }
}
