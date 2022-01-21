package de.usd.cstchef.operations.extractors;

import java.util.Arrays;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.operations.OperationCategory;

@OperationInfos(name = "HTTP URI", category = OperationCategory.EXTRACTORS, description = "Extracts the URI of a HTTP request.")
public class HttpUriExtractor extends Operation {

    private JCheckBox checkbox;

    @Override
    public void createUI() {
        this.checkbox = new JCheckBox("With parameters");
        this.checkbox.setSelected(true);
        this.addUIElement(null, this.checkbox, "checkbox1");
    }

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        try {

            IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
            IExtensionHelpers helpers = callbacks.getHelpers();
            int length = input.length;

            int firstMark = helpers.indexOf(input, " ".getBytes(), false, 0, length);
            int lineMark = helpers.indexOf(input, " ".getBytes(), false, firstMark + 1, length);

            int secondMark = helpers.indexOf(input, "?".getBytes(), false, firstMark + 1, length);

            if( this.checkbox.isSelected() || secondMark < 0 || secondMark >= lineMark) {
                secondMark = lineMark;
            }

            byte[] result = Arrays.copyOfRange(input, firstMark + 1, secondMark);
            return result;

        } catch (Exception e) {
            throw new IllegalArgumentException("Provided input is not a valid http request.");
        }
    }
}
