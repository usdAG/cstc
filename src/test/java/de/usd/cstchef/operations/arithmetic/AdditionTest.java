package de.usd.cstchef.operations.arithmetic;

import org.junit.Before;
import org.junit.Test;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.arithmetic.Addition;
import de.usd.cstchef.utils.UnitTestObjectFactory;

@OperationInfos(name = "Test", category = OperationCategory.ARITHMETIC, description = "Test class")
public class AdditionTest extends Addition
{
    private String number;
    private boolean isFloat;
    private CstcObjectFactory factory;

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
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("32");
    }

    @Test
    public void AdditionFloatTest() throws Exception
    {
        number = "2.2";
        isFloat = true;

        String testValue = "2.2";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("4.4");
    }

    @Test
    public void AdditionFloatRoundTest() throws Exception
    {
        number = "2.2";
        isFloat = false;

        String testValue = "2.2";
        ByteArray result = perform(factory.createByteArray(testValue));

        assert result.toString().equals("4");
    }

    @Before
    public void setup(){
        CstcObjectFactory factory = new UnitTestObjectFactory();
        this.factory = factory;
        super.factory = factory;
    }
}