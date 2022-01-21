package de.usd.cstcchecf.operations;

import org.junit.Test;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Addition;
import de.usd.cstchef.operations.arithmetic.Subtraction;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class SubtractionTest extends Subtraction
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
    public void SimpleSubtraction() throws Exception
    {
        number = "10";
        isFloat = false;

        String testValue = "22";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("12");
    }

    @Test
    public void SubtractionFloatTest() throws Exception
    {
        number = "2.1";
        isFloat = true;

        String testValue = "2.2";
        byte[] result = perform(testValue.getBytes());

        System.out.println(new String(result));
        assert new String(result).startsWith("0.1");
    }

    @Test
    public void SubractionRoundTest() throws Exception
    {
        number = "2.2";
        isFloat = false;

        String testValue = "2.8";
        byte[] result = perform(testValue.getBytes());

        assert new String(result).equals("1");
    }
}