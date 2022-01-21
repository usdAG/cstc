package de.usd.cstchef.operations.arithmetic;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Single - Subtract", category = OperationCategory.ARITHMETIC, description = "Subtract from the input the given number.")
public class Subtraction extends ArithmeticOperation
{
    @Override
    protected double calculate(double input_number, double static_number)
    {
        return input_number - static_number;
    }
}