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

    // HashMap<Input, Triplet<expectedOutput, regex, listMatchesOrCaptureGroups>>
    HashMap<String, Triplet<String, String, Boolean>> inputs = new HashMap<String, Triplet<String, String, Boolean>>();

    @Test
    public void extractionTest() throws Exception
    {
        for (String inp : inputs.keySet()) {
            Triplet<String, String, Boolean> res = inputs.get(inp);
            ByteArray inputArray = factory.createByteArray(inp);
            ByteArray outputArray = factory.createByteArray(res.getValue0());
            this.regexTxt.setText(res.getValue1());
            this.outputBox.setSelectedItem(res.getValue2() ? "List matches" : "List capture groups");
            assertArrayEquals(outputArray.getBytes(), perform(inputArray, null).getBytes());
        }
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;

        // list matches
        String input1 = "uuid=545687-147953-996348";
        String output1 = "545687-147953-996348";
        String regex1 = "[0-9\\-]{20}";
        Triplet<String, String, Boolean> triplet1 = new Triplet<String, String, Boolean>(output1, regex1, true);

        // list capture groups
        String input2 = "key=545687-147953-996348";
        String output2 = "545687\n147953\n996348";
        String regex2 = "([0-9]{6})-([0-9]{6})-([0-9]{6})";
        Triplet<String, String, Boolean> triplet2 = new Triplet<String,String,Boolean>(output2, regex2, false);

        inputs.put(input1, triplet1);
        inputs.put(input2, triplet2);
    }
}