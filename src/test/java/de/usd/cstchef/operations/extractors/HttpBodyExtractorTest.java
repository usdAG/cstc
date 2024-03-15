package de.usd.cstchef.operations.extractors;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.testutils.UnitTestObjectFactory;

@OperationInfos(name = "HttpBodyExtractorTest", category = OperationCategory.EXTRACTORS, description = "Test class")
public class HttpBodyExtractorTest extends HttpBodyExtractor {

    HashMap<String, String> inputs = new HashMap<String, String>();

    @Test
    public void extractionTest() throws Exception
    {
        for(String res : inputs.keySet()){
            assertEquals(perform(ByteArray.byteArray(res), MessageType.RESPONSE), inputs.get(res));
        }
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;
    }
}
