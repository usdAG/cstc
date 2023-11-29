package de.usd.cstchef.operations;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.DivideList;
import de.usd.cstchef.utils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class DivideListTest extends DivideList
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
    public void CommaDivideTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = false;

        String testValue = "8,2,4";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("1");
    }

    @Test
    public void CommaDivideFloatTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = true;

        String testValue = "8,2,4,2";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("0.5");
    }

    @Test
    public void SpaceDivideTest() throws Exception
    {
        delimiter = "Space";
        isFloat = false;

        String testValue = "8 2 4 0.5";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("2");
    }

    @Test
    public void SpaceDivideFloatTest() throws Exception
    {
        delimiter = "Space";
        isFloat = true;

        String testValue = "8 2 4 4 0.5";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("0.5");
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;
    }
}