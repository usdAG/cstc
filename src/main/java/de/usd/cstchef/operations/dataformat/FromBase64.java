package de.usd.cstchef.operations.dataformat;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Base64;

import javax.swing.JCheckBox;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "From Base64", category = OperationCategory.DATAFORMAT, description = "Decode a base64 string.")
public class FromBase64 extends Operation implements ActionListener {

	private boolean urlSafe=false;
	private JCheckBox urlSafeCheckBox;
	
    @Override
    protected byte[] perform(byte[] input) {
    	if(!this.urlSafe) {
    		return Base64.getDecoder().decode(input);	
    	}
    	else {
    		return Base64.getUrlDecoder().decode(input);
    	}        
    }

    public void createUI() {
    	this.urlSafeCheckBox = new JCheckBox();
    	urlSafeCheckBox.setText("URL Safe");
    	urlSafeCheckBox.setToolTipText("The Base64 input string is using the URL safe character set where / and + are replaced with _ and -");
    	urlSafeCheckBox.setSelected(this.urlSafe);
    	urlSafeCheckBox.addActionListener(this);    	
    	this.addUIElement("", urlSafeCheckBox);
    }
    
	@Override
	public void actionPerformed(ActionEvent e) {
		this.urlSafe = this.urlSafeCheckBox.isSelected();		
	}
}
