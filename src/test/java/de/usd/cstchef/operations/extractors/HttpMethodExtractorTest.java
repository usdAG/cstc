package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.HashMap;

import org.javatuples.Pair;
import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.utils.UnitTestObjectFactory;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HttpMethodExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpMethodExtractorTest extends HttpMethodExtractor {

    // HashMap<Input, Pair<expectedOutput, throwsException>>
    HashMap<String, Pair<String, Boolean>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Pair<String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            if (res.getValue1()) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                assertEquals("Input is not a valid HTTP request.", exception.getMessage());
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

        // GET
        String reqIn1 = """
                GET / HTTP/2
                Header1: value1
                Header2: value2

                a
                """;
        String reqOut1 = "GET";
        Pair<String, Boolean> reqPair1 = new Pair<String, Boolean>(reqOut1, false);

        // HTTP Response - Exception
        String reqIn2 = """
                HTTP/2 200 Ok
                Header: value


                """;
        String reqOut2 = "";
        Pair<String, Boolean> reqPair2 = new Pair<String, Boolean>(reqOut2, true);

        inputs.put(reqIn1, reqPair1);
        inputs.put(reqIn2, reqPair2);
    }
}
