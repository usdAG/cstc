package de.usd.cstchef.operations.utils;

import java.security.SecureRandom;
import java.text.NumberFormat;

import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "Random Number", category = OperationCategory.UTILS, description = "Generate a random number.")
public class RandomNumber extends Operation {

    // input fields for minimum/maximum
    private JTextField textFieldMinimum;
    private JTextField textFieldMaximum;

    // input fields for formatting
    private JTextField textFieldFormatMinIntDigits;
    private JTextField textFieldFormatMaxIntDigits;
    private JTextField textFieldFormatMinFracDigits;
    private JTextField textFieldFormatMaxFracDigits;

    private final static SecureRandom secRand = new SecureRandom();
    private static NumberFormat numberFormatter = NumberFormat.getInstance();

    /**
     * Helper to parse Integer from String and set default if it fails
     * @param numberStr A string representing a number
     * @param defaultValue default value if parsing fails
     * @return
     */
    private int parseInt(String numberStr, int defaultValue) {
        try {
            int intValue = Integer.valueOf(numberStr);
            return intValue;
        }catch (Exception e) {
            return defaultValue;
        }
    }

    @Override
    protected ByteArray perform(ByteArray input) throws Exception {

        // get Bounds from user input
        int boundMin = parseInt(this.textFieldMinimum.getText(), 0);
        int boundMax = parseInt(this.textFieldMaximum.getText(), Integer.MAX_VALUE);

        // prepare formatter
        int minIntDigits = parseInt(this.textFieldFormatMinIntDigits.getText(), 1);
        numberFormatter.setMinimumIntegerDigits(minIntDigits);

        int maxIntDigits = parseInt(this.textFieldFormatMaxIntDigits.getText(), 99);
        numberFormatter.setMaximumIntegerDigits(maxIntDigits);

        int minFracDigits = parseInt(this.textFieldFormatMinFracDigits.getText(), 0);
        numberFormatter.setMinimumFractionDigits(minFracDigits);

        int maxFracDigits = parseInt(this.textFieldFormatMaxFracDigits.getText(), 0);
        numberFormatter.setMaximumFractionDigits(maxFracDigits);

        numberFormatter.setGroupingUsed(false);

        // generate random numbers and format them
        if(maxFracDigits == 0) {
            // use int mode
            int randomValue = secRand.nextInt(boundMax - boundMin + 1) + boundMin;
            return factory.createByteArray(numberFormatter.format(randomValue));
        } else {
            // use double mode
            double randomValue = boundMin + (boundMax - boundMin) * secRand.nextDouble();
            return factory.createByteArray(numberFormatter.format(randomValue));
        }
    }

    public void createUI() {

        // fields for min/max
        this.textFieldMinimum = new JTextField();
        this.textFieldMinimum.setText("0");
        this.addUIElement("Minimum Number", this.textFieldMinimum);

        this.textFieldMaximum = new JTextField();
        this.textFieldMaximum.setText("9999");
        this.addUIElement("Maximum Number", this.textFieldMaximum);

        // use a separator
        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        this.addUIElement(null, separator);

        // fields for formatting: Integer digits
        this.textFieldFormatMinIntDigits = new JTextField();
        this.textFieldFormatMinIntDigits.setText("1");
        this.addUIElement("Min integer digits", this.textFieldFormatMinIntDigits);

        this.textFieldFormatMaxIntDigits = new JTextField();
        this.textFieldFormatMaxIntDigits.setText("99");
        this.addUIElement("Max integer digits", this.textFieldFormatMaxIntDigits);

        // fields for formatting: fraction digits
        this.textFieldFormatMinFracDigits = new JTextField();
        this.textFieldFormatMinFracDigits.setText("0");
        this.addUIElement("Min fraction digits", this.textFieldFormatMinFracDigits);

        this.textFieldFormatMaxFracDigits = new JTextField();
        this.textFieldFormatMaxFracDigits.setText("0");
        this.addUIElement("Max fraction digits", this.textFieldFormatMaxFracDigits);
    }
}
