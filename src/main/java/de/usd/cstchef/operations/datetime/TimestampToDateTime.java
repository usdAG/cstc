package de.usd.cstchef.operations.datetime;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;

import javax.swing.JCheckBox;

import burp.Logger;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Epoch to DateTime", category = OperationCategory.DATES, description = "Returns a given Unix (Epoch) timestamp formatted with the provided date time pattern.")
public class TimestampToDateTime extends Operation {

    private VariableTextField patternTxt;    
    private JCheckBox milliseconds;
    
    
    @Override
    protected ByteArray perform(ByteArray input) throws Exception {
        String pattern = this.patternTxt.getText().trim();
        SimpleDateFormat format = new SimpleDateFormat(pattern);
        
        long timestamp = Long.parseLong(input.toString());        
        Instant instant = this.milliseconds.isSelected() ? Instant.ofEpochMilli(timestamp) : Instant.ofEpochSecond(timestamp);        
        Date date = Date.from(instant);        
        
        return factory.createByteArray(format.format(date));
    }

    public void createUI() {
        this.patternTxt = new VariableTextField();
        this.addUIElement("Pattern", this.patternTxt);
        
        this.milliseconds = new JCheckBox();
        milliseconds.setToolTipText("Check if a timestamp given is in milliseconds format. Otherwise seconds format is used.");
        this.milliseconds.setSelected(false);
        this.addUIElement("Input in milliseconds", this.milliseconds);
    }
}
