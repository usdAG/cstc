package de.usd.cstchef.operations.arithmetic;

import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Single - Multiply", category = OperationCategory.ARITHMETIC, description = "Multiply input with the given number")
public class Multiply extends ArithmeticOperation
{
    @Override
    protected double calculate(double input_number, double static_number)
    {
        return input_number * static_number;
    }
}