package de.usd.cstchef.operations.arithmetic;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Mean;
import de.usd.cstchef.testutils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class MeanTest extends Mean
{
    private String delimiter;
    private boolean isFloat;

    protected Delimiter getDelimiter() throws IllegalArgumentException
    {
        Delimiter delim = Delimiter.getByName(delimiter);

        if( delim == null )
            throw new IllegalArgumentException("Invalid delimiter.");

        return delim;
    }

    protected boolean isFloat()
    {
        return isFloat;
    }

    @Test
    public void CommaMeanTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = false;

        String testValue = "8,2,5";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("5");
    }

    @Test
    public void CommaMeanFloatTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = true;

        String testValue = "0.2,0.3,0.4,0.1";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("0.25");
    }

    @Test
    public void SpaceMeanTest() throws Exception
    {
        delimiter = "Space";
        isFloat = false;

        String testValue = "8 2 5";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("5");
    }

    @Test
    public void SpaceDivideFloatTest() throws Exception
    {
        delimiter = "Space";
        isFloat = true;

        String testValue = "0.2 0.3 0.4 0.1";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("0.25");
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;
    }
}