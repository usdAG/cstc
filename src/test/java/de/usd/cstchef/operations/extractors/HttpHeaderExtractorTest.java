package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.HashMap;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.MutablePair; //
import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.utils.UnitTestObjectFactory;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HttpHeaderExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpHeaderExtractorTest extends HttpHeaderExtractor {

    // HashMap<Input String, Pair<Output String, throwsException>>
    HashMap<String, Pair<String, Boolean>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Pair<String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getLeft());
            MessageType messageType = parseMessageType(inputArray);
            if (res.getRight()) {
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

        // Header1
        String reqIn1 = "GET / HTTP/2\nHeader1: value1\nHeader2: value2\n\n";
        String reqOut1 = "value1";
        Pair <String, Boolean> reqPair1 = new MutablePair(reqOut1, false);

        // Header2
        String reqIn2 = "GET / HTTP/2\nHeader1: value1\nHeader2: value2\n\n";
        String reqOut2 = "value2";
        Pair <String, Boolean> reqPair2 = new MutablePair(reqOut2, false);

        // Header3 - Exception
        String reqIn3 = "GET / HTTP/2\nHeader1: value1\nHeader2: value2\n\n";
        String reqOut3 = "";
        Pair <String, Boolean> reqPair3 = new MutablePair(reqOut3, true);

        inputs.put(reqIn1, reqPair1);
        inputs.put(reqIn2, reqPair2);
        inputs.put(reqIn3, reqPair3);
    }
}
