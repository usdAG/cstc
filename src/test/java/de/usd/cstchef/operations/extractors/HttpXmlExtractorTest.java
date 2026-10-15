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
    HashMap<String, Triplet<String, String, Integer>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Triplet<String, String, Integer> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            this.path.setText(res.getValue1());
            System.out.println(res.getValue1());
            if (res.getValue2() == 1) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                assertEquals("XML element not found.", exception.getMessage());
            }
            else if(res.getValue2() == 2) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray));
                assertEquals("Invalid XPath Syntax.", exception.getMessage());
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
                Host: a
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
        String reqPath1 = "/RootTag/Tag1";
        Triplet<String, String, Integer> reqTriplet1 = new Triplet<String, String, Integer>(reqOut1, reqPath1, 0);

        // inner tag (HTTP Request && param correct)
        String reqIn2 = """
                GET / HTTP/2
                Host: b
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
        String reqPath2 = "/RootTag/Tag2/Tag3";
        Triplet<String, String, Integer> reqTriplet2 = new Triplet<String, String, Integer>(reqOut2, reqPath2, 0);


        // HTTP Request && param correct)
        String resIn1 = """
                POST /echo/post/xml HTTP/1.1
                Host: c
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
        String resPath1 = "/RootTag/Tag1";
        Triplet<String, String, Integer> resTriplet1 = new Triplet<String, String, Integer>(resOut1, resPath1, 0);

        // HTTP Response && param correct
        String resIn2 = """
                HTTP/2 200 Ok
                Host: d
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
        String resPath2 = "/RootTag/Tag2/Tag3";
        Triplet<String, String, Integer> resTriplet2 = new Triplet<String, String, Integer>(resOut2, resPath2, 0);
        
        
        // HTTP Request && param empty
        String reqIn3 = """
                GET / HTTP/2
                Host: e
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String reqPath3 = "";
        Triplet<String, String,  Integer> reqTriplet3 = new Triplet<String, String, Integer>(reqIn3, reqPath3, 0);

        // HTTP Response && param empty
        String resIn3 = """
                GET / HTTP/2
                Host: f
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String resPath3 = "";
        Triplet<String, String, Integer> resTriplet3 = new Triplet<String, String, Integer>(resIn3, resPath3, 0);

        // HTTP Request && param incorrect
        String reqIn4 = """
                GET / HTTP/2
                Host: g
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
        String reqPath4 = "ElementDoesNotExist";
        Triplet<String, String, Integer> reqTriplet4 = new Triplet<String, String, Integer>(reqOut4, reqPath4, 1);

        // HTTP Response && param incorrect
        String resIn4 = """
                HTTP/2 200 Ok
                Host: h
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
        String resPath4 = "WrongSyntax";
        Triplet<String, String, Integer> resTriplet4 = new Triplet<String, String, Integer>(resOut4, resPath4, 1);


        // HTTP Request && invalid syntax
        String reqIn5 = """
                GET / HTTP/2
                Host: i
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String reqOut5 = "";
        String reqPath5 = "/invalidsyntax[";
        Triplet<String, String, Integer> reqTriplet5 = new Triplet<String, String, Integer>(reqOut5, reqPath5, 2);

        // HTTP Response && param incorrect
        String resIn5 = """
                HTTP/2 200 Ok
                Host: j
                Content-Type: application/xml

                <?xml version="1.0" encoding="utf-8"?>
                <RootTag>
                    <Tag1>tag1</Tag1>
                    <Tag2>
                        <Tag3>tag3</Tag3>
                    </Tag2>
                </RootTag>
                """;
        String resOut5 = "";
        String resPath5 = "/invalidsyntax[";
        Triplet<String, String, Integer> resTriplet5 = new Triplet<String, String, Integer>(resOut5, resPath5, 2);

        inputs.put(reqIn1, reqTriplet1);
        inputs.put(reqIn2, reqTriplet2);
        inputs.put(resIn1, resTriplet1);
        inputs.put(resIn2, resTriplet2);
        inputs.put(reqIn3, reqTriplet3);
        inputs.put(resIn3, resTriplet3);
        inputs.put(reqIn4, reqTriplet4);
        inputs.put(resIn4, resTriplet4);
        inputs.put(reqIn5, reqTriplet5);
        inputs.put(resIn5, resTriplet5);
    }
}
