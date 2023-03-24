package de.usd.cstcchecf.operations;

import org.junit.Test;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Addition;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class AdditionTest extends Addition
{
    private String number;
    private boolean isFloat;

    protected double getNumber()
    {
        return Double.valueOf(number);
    }

    protected boolean isFloat()
    {
        return isFloat;
    }

    @Test
    public void SimpleAdditionTest() throws Exception
    {
        number = "10";
        isFloat = false;

        String testValue = "22";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("32");
    }

    @Test
    public void AdditionFloatTest() throws Exception
    {
        number = "2.2";
        isFloat = true;

        String testValue = "2.2";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("4.4");
    }

    @Test
    public void AdditionFloatRoundTest() throws Exception
    {
        number = "2.2";
        isFloat = false;

        String testValue = "2.2";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("4");
    }
}