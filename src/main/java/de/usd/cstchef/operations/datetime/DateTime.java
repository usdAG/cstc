package de.usd.cstchef.operations.datetime;

import java.text.SimpleDateFormat;
import java.util.Date;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Date Time", category = OperationCategory.DATES, description = "Returnes the current date time formatted with the provided date time pattern.")
public class DateTime extends Operation {

    private VariableTextField patternTxt;

    @Override
    protected byte[] perform(byte[] input) throws Exception {
        String pattern = this.patternTxt.getText().trim();
        SimpleDateFormat format = new SimpleDateFormat(pattern);
        return format.format(new Date()).getBytes();
    }

    public void createUI() {
        this.patternTxt = new VariableTextField();
        this.addUIElement("Pattern", this.patternTxt);
    }

}
