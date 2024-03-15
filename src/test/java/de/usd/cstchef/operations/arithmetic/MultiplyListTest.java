package de.usd.cstchef.operations.arithmetic;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.MultiplyList;
import de.usd.cstchef.testutils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class MultiplyListTest extends MultiplyList
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
    public void CommaMultiplyTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = false;

        String testValue = "1,2,3,4,5,6";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("720");
    }

    @Test
    public void CommaMultiplyFloatTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = true;

        String testValue = "3,0.5,0.5";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("0.75");
    }

    @Test
    public void SpaceMultiplyTest() throws Exception
    {
        delimiter = "Space";
        isFloat = false;

        String testValue = "1 2 3 4 5 6";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        System.out.println(result.toString());
        assert result.toString().equals("720");
    }

    @Test
    public void SpaceMultiplyFloatTest() throws Exception
    {
        delimiter = "Space";
        isFloat = true;

        String testValue = "3 0.5 0.5";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("0.75");
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;
    }
}