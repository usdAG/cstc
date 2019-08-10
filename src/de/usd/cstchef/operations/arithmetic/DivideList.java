package de.usd.cstchef.operations.arithmetic;

import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Divide", category = OperationCategory.ARITHMETIC, description = "Divides a list of numbers.")
public class DivideList extends ArithmeticDelimiterOperation {

	@Override
	protected double calculate(double a, double b) {
		return a / b;
	}

}
