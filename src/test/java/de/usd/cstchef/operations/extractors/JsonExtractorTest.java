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

    // HashMap<Input String, Pair<Output String, throwsException>>
    HashMap<String, Quartet<String, String, Boolean, String>> inputs = new HashMap<>();

    @Test
    public void extractionTest() throws Exception {
        for (String inp : inputs.keySet()) {
            Quartet<String, String, Boolean, String> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            this.fieldTxt.setText(res.getValue1());
            if (res.getValue2()) {
                Exception exception = assertThrows(IllegalArgumentException.class, () -> perform(inputArray, null));
                assertEquals(res.getValue3(), exception.getMessage());
            }
            else{
                //assertEquals(perform(inputArray, null), outputArray);
                assertArrayEquals(outputArray.getBytes(), perform(inputArray, null).getBytes());
            }
        }
    }

    @Before
    public void setup() {
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        // outer
        String in = """
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
        String out2 = "value3";
        String key2 ="key2.key3";
        Quartet<String, String, Boolean, String> quartet2 = new Quartet<String,String,Boolean,String>(out2, key2, false, null);

        // exceptions

        inputs.put(in, quartet1);
        inputs.put(in, quartet2);
        
    }
}
