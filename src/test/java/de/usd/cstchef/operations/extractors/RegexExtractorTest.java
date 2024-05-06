package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertArrayEquals;

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


@OperationInfos(name = "RegexExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class RegexExtractorTest extends RegexExtractor {

    // HashMap<Input, Triplet<Output, regex, listMatchesOrCaptureGroups>>
    HashMap<String, Triplet<String, String, Boolean>> inputs = new HashMap<String, Triplet<String, String, Boolean>>();

    @Test
    public void extractionTest() throws Exception
    {
        for (String inp : inputs.keySet()) {
            Triplet<String, String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            assertArrayEquals(outputArray.getBytes(), perform(inputArray, null).getBytes());
        }
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        // param=value
        String input1 = """
                key=293845-432567-128974
                """;
        String output1 = """
                293845-432567-128974
                """;
        String regex1 = """
                [0-9\\-]*
                """;
        Triplet<String, String, Boolean> triplet1 = new Triplet<String, String, Boolean>(output1, regex1, false);

        inputs.put(input1, triplet1);
    }
}