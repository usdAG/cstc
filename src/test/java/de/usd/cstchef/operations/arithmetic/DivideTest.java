package de.usd.cstchef.operations.arithmetic;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Divide;
import de.usd.cstchef.utils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class DivideTest extends Divide
{
    private String number;
    private boolean isFloat;
    private boolean isReverse;

    protected double getNumber()
    {
        return Double.valueOf(number);
    }

    protected boolean isFloat()
    {
        return isFloat;
    }

    protected boolean isReverse()
    {
        return isReverse;
    }

    @Test
    public void SimpleDivideTest() throws Exception
    {
        number = "2";
        isFloat = false;
        isReverse = false;

        String testValue = "4";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("2");
    }

    @Test
    public void ReverseDivideTest() throws Exception
    {
        number = "2";
        isFloat = true;
        isReverse = true;

        String testValue = "4";
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