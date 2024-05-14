package de.usd.cstchef.operations.arithmetic;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Multiply;
import de.usd.cstchef.utils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class MultiplyTest extends Multiply
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
    public void SimpleMultiplyTest() throws Exception
    {
        number = "10";
        isFloat = false;

        String testValue = "22";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("220");
    }

    @Test
    public void MultiplyFloatTest() throws Exception
    {
        number = "2.2";
        isFloat = true;

        String testValue = "2.2";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().startsWith("4.84");
    }

    @Test
    public void MultiplyRoundTest() throws Exception
    {
        number = "2.2";
        isFloat = false;

        String testValue = "2.2";
        ByteArray result = perform(factory.createByteArray(testValue), null);

        assert result.toString().equals("5");
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;
    }
}