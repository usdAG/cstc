package de.usd.cstchef.operations.arithmetic;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Median;
import de.usd.cstchef.utils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class MedianTest extends Median
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
    public void CommaMedianTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = false;

        String testValue = "1,2,3,4,5";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("3");
    }

    @Test
    public void CommaMedianFloatTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = true;

        String testValue = "1,2,3.5,4,5";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("3.5");
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;
    }
}