package de.usd.cstchef.operations.arithmetic;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Sum;
import de.usd.cstchef.utils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class SumTest extends Sum
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
    public void CommaSumTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = false;

        String testValue = "1,2,3,4,5,6";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("21");
    }

    @Test
    public void CommaSumFloatTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = true;

        String testValue = "1,2,3,4,5,6";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("21.0");
    }

    @Test
    public void SpacesumTest() throws Exception
    {
        delimiter = "Space";
        isFloat = false;

        String testValue = "1.0 2.1 3.2 4.3 5.4 6.5";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("23");
    }

    @Test
    public void SpacesumFloatTest() throws Exception
    {
        delimiter = "Space";
        isFloat = true;

        String testValue = "1.0 2.1 3.2 4.3 5.4 6.5";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("22.5");
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;
    }
}