package de.usd.cstcchecf.operations;

import org.junit.Test;

import de.usd.cstchef.Delimiter;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Median;

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
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("3");
    }

    @Test
    public void CommaMedianFloatTest() throws Exception
    {
        delimiter = "Comma";
        isFloat = true;

        String testValue = "1,2,3.5,4,5";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("3.5");
    }
}