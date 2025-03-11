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


@OperationInfos(name = "HttpXmlExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpXmlExtractorTest extends HttpXmlExtractor {

    // HashMap<Input, Triplet<expectedOutput, keyName, throwsException>>
    HashMap<String, Triplet<String, String, Boolean>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Triplet<String, String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            this.fieldTxt.setText(res.getValue1());
            if (res.getValue2()) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                assertEquals("Input is not a valid request", exception.getMessage());
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

        // outer tag (HTTP Request && param correct)
        String reqIn1 = """
                GET / HTTP/2
                Header1: a
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String reqOut1 = "tag1";
        String reqTag1 = "Tag1";
        Triplet<String, String, Boolean> reqTriplet1 = new Triplet<String, String, Boolean>(reqOut1, reqTag1, false);

        // inner tag (HTTP Request && param correct)
        String reqIn2 = """
                GET / HTTP/2
                Header1: b
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String reqOut2 = "tag3";
        String reqTag2 = "Tag3";
        Triplet<String, String, Boolean> reqTriplet2 = new Triplet<String, String, Boolean>(reqOut2, reqTag2, false);


        // HTTP Request && param correct)
        String resIn1 = """
                POST /echo/post/xml HTTP/1.1
                Host: reqbin.com
                Content-Type: application/xml
                Accept: application/xml
                Content-Length: 118
            
                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String resOut1 = "tag1";
        String resTag1 = "Tag1";
        Triplet<String, String, Boolean> resTriplet1 = new Triplet<String, String, Boolean>(resOut1, resTag1, false);

        // HTTP Response && param correct
        String resIn2 = """
                HTTP/2 200 Ok
                Header1: b
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String resOut2 = "tag3";
        String resTag2 = "Tag3";
        Triplet<String, String, Boolean> resTriplet2 = new Triplet<String, String, Boolean>(resOut2, resTag2, false);
        
        
        // HTTP Request && param empty
        String reqIn3 = """
                GET / HTTP/2
                Header1: c
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String reqOut3 = "";
        String reqTag3 = "";
        Triplet<String, String,  Boolean> reqTriplet3 = new Triplet<String, String, Boolean>(reqOut3, reqTag3, false);

        // HTTP Response && param empty
        String resIn3 = """
                GET / HTTP/2
                Header1: c
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String resOut3 = "";
        String resTag3 = "";
        Triplet<String, String, Boolean> resTriplet3 = new Triplet<String, String, Boolean>(resOut3, resTag3, false);

        // HTTP Request && param incorrect
        String reqIn4 = """
                GET / HTTP/2
                Header1: a
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String reqOut4 = "";
        String reqTag4 = "ImaginaryTag";
        Triplet<String, String, Boolean> reqTriplet4 = new Triplet<String, String, Boolean>(reqOut4, reqTag4, true);

        // HTTP Response && param incorrect
        String resIn4 = """
                HTTP/2 200 Ok
                Header1: b
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String resOut4 = "";
        String resTag4 = "ImaginaryTag";
        Triplet<String, String, Boolean> resTriplet4 = new Triplet<String, String, Boolean>(resOut4, resTag4, true);

        inputs.put(reqIn1, reqTriplet1);
        inputs.put(reqIn2, reqTriplet2);
        inputs.put(resIn1, resTriplet1);
        inputs.put(resIn2, resTriplet2);
        inputs.put(reqIn3, reqTriplet3);
        inputs.put(resIn3, resTriplet3);
        inputs.put(reqIn4, reqTriplet4);
        inputs.put(resIn4, resTriplet4);
    }
}
