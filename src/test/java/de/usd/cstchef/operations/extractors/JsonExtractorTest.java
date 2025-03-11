package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.util.HashMap;

import org.javatuples.Quartet;
import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.utils.UnitTestObjectFactory;
import de.usd.cstchef.operations.OperationCategory;


@OperationInfos(name = "JsonExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class JsonExtractorTest extends JsonExtractor {

    // HashMap<Input, Quartet<expectedOutput, key, throwsException, exceptionMessage>>
    HashMap<String, Quartet<String, String, Boolean, String>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Quartet<String, String, Boolean, String> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            this.fieldTxt.setText(res.getValue1());
            if (res.getValue2()) {
                Exception exception = assertThrows(com.jayway.jsonpath.PathNotFoundException.class, () -> perform(inputArray));
                assertEquals(res.getValue3(), exception.getMessage());
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

        // outer
        String in1 = """
            {
                "key1":"value1",
                "key2":{
                        "key3":"value3"
                }
            }
            """;
        String out1 = "value1";
        String key1 = "key1";
        Quartet<String, String, Boolean, String> quartet1 = new Quartet<String, String, Boolean, String>(out1, key1, false, null);

        // inner
        String in2 = """
            {
                "key1":"a",
                "key2":{
                        "key3":"value3"
                }
            }
            """;
        String out2 = "value3";
        String key2 ="key2.key3";
        Quartet<String, String, Boolean, String> quartet2 = new Quartet<String,String,Boolean,String>(out2, key2, false, null);

        // nested
        String in3 = """
            {
                "key1":"b",
                "key2":{
                        "key3":"value3"
                }
            }
            """;
        String out3 = "{key3=value3}";
        String key3 = "key2";
        Quartet<String, String, Boolean, String> quartet3 = new Quartet<String,String,Boolean,String>(out3, key3, false, null);

        // path not found exception
        String in4 = """
            {
                "key1":"c",
                "key2":{
                        "key3":"value3"
                }
            }
            """;
        String out4 = "";
        String key4 = "key3";
        String excMess4 = "No results for path: $['key3']";
        Quartet<String, String, Boolean, String> quartet4 = new Quartet<String,String,Boolean,String>(out4, key4, true, excMess4);

        inputs.put(in1, quartet1);
        inputs.put(in2, quartet2);
        inputs.put(in3, quartet3);
        inputs.put(in4, quartet4);
        
    }
}
