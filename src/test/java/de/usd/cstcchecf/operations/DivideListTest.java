package de.usd.cstcchecf.operations;

import org.junit.Test;

import de.usd.cstchef.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.DivideList;

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
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("1");
    }

    @Test
    public void CommaDivideFloatTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = true;

        String testValue = "8,2,4,2";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("0.5");
    }

    @Test
    public void SpaceDivideTest() throws Exception
    {
        delimiter = "Space";
        isFloat = false;

        String testValue = "8 2 4 0.5";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("2");
    }

    @Test
    public void SpaceDivideFloatTest() throws Exception
    {
        delimiter = "Space";
        isFloat = true;

        String testValue = "8 2 4 4 0.5";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("0.5");
    }
}