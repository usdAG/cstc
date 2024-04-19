package de.usd.cstchef.operations.hashing;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;


@OperationInfos(name = "Luhn", category = OperationCategory.HASHING, description = "Calculate Luhn of a number")
public class Luhn extends Operation {

    @Override
    protected byte[] perform(byte[] input) throws Exception {

        for (int i = 0; i < input.length; i++){
            if ((input[i] < '0') || (input[i] > '9')) {
                throw new IllegalArgumentException("Luhn can only be applied to numerical values.");
            }
        }

        int check_digit = calculateLuhnCheckDigit(input);
        return new byte[]{ (byte) (check_digit + '0')};
    }

    private int calculateLuhnCheckDigit(byte[] input) {
        int sum = 0;
        boolean doubleDigit = true;

        for (int i = input.length - 1; i >= 0; i--) {



            int digit =  Integer.valueOf(Character.toString ((char) input[i]));

            if (doubleDigit) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            sum += digit;
            doubleDigit = !doubleDigit;
        }

        int mod = sum % 10;
        return mod == 0 ? 0 : 10 - mod;
    }
}
