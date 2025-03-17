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
import de.usd.cstchef.Utils;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HttpCookieExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpCookieExtractorTest extends HttpCookieExtractor {

    // HashMap<Input, Pair<expectedOutput, cookieToExtract, throwsException>>
    HashMap<String, Triplet<String,String,Boolean>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Triplet<String, String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            this.cookieNameField.setText(res.getValue1());
            if (res.getValue2()) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                assertEquals("Cookie not found.", exception.getMessage());
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
        Utils.factory = new UnitTestObjectFactory();

        // cookie1
        String reqIn1 = """
                GET / HTTP/2
                Header1: a
                Cookie: cookie1=value1; cookie2=value2

                
                """;
        String reqOut1 = "value1";
        String reqCookie1 = "cookie1";
        Triplet<String, String, Boolean> reqTriplet1 = new Triplet<String,String,Boolean>(reqOut1, reqCookie1, false);

        // cookie2
        String reqIn2 = """
                GET / HTTP/2
                Header1: b
                Cookie: cookie1=value1; cookie2=value2

                
                """;
        String reqOut2 = "value2";
        String reqCookie2 = "cookie2";
        Triplet<String, String, Boolean> reqTriplet2 = new Triplet<String, String, Boolean>(reqOut2, reqCookie2, false);

        // Exception
        String reqIn3 = """
                GET / HTTP/2
                Header1: c
                Cookie: cookie1=value1; cookie2=value2

                
                """;
        String reqOut3 = "";
        String reqCookie3 = "cookie3";
        Triplet<String, String,  Boolean> reqTriplet3 = new Triplet<String, String, Boolean>(reqOut3, reqCookie3, true);

        // Empty cookieName
        String reqIn4 = """
                GET / HTTP/2
                Header1: d
                Cookie: cookie1=value1; cookie2=value2


                """;
        String reqCookie4 = "";
        Triplet<String, String, Boolean> reqTriplet4 = new Triplet<String, String, Boolean>(reqIn4, reqCookie4, false);

        // cookie1
        String resIn1 = """
                HTTP/2 200 Ok
                Header1: a
                Set-Cookie: cookie1=value1
                Set-Cookie: cookie2=value2

                """;
        String resOut1 = "value1";
        String resCookie1 = "cookie1";
        Triplet<String, String, Boolean> resTriplet1 = new Triplet<String,String,Boolean>(resOut1, resCookie1, false);

        // cookie2
        String resIn2 = """
                HTTP/2 200 Ok
                Header1: b
                Set-Cookie: cookie1=value1
                Set-Cookie: cookie2=value2

                """;
        String resOut2 = "value2";
        String resCookie2 = "cookie2";
        Triplet<String, String, Boolean> resTriplet2 = new Triplet<String,String,Boolean>(resOut2, resCookie2, false);

        // Exception
        String resIn3 = """
                HTTP/2 200 Ok
                Header1: c
                Set-Cookie: cookie1=value1
                Set-Cookie: cookie2=value2

                """;
        String resOut3 = "";
        String resCookie3 = "cookie3";
        Triplet<String, String, Boolean> resTriplet3 = new Triplet<String,String,Boolean>(resOut3, resCookie3, true);

        // empty cookieName
        String resIn4 = """
                HTTP/2 200 Ok
                Header1: d
                Set-Cookie: cookie1=value1
                Set-Cookie: cookie2=value2

                """;
        String resCookie4 = "";
        Triplet<String, String, Boolean> resTriplet4 = new Triplet<String,String,Boolean>(resIn4, resCookie4, false);

        inputs.put(reqIn1, reqTriplet1);
        inputs.put(reqIn2, reqTriplet2);
        inputs.put(reqIn3, reqTriplet3);
        inputs.put(reqIn4, reqTriplet4);
        inputs.put(resIn1, resTriplet1);
        inputs.put(resIn2, resTriplet2);
        inputs.put(resIn3, resTriplet3);
        inputs.put(resIn4, resTriplet4);
    }
}
