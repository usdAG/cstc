package de.usd.cstchef.operations.dataformat;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Base64;

import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "To Base64", category = OperationCategory.DATAFORMAT, description = "Encodes a string to base64.")
public class ToBase64 extends Operation implements ActionListener {

	private boolean urlSafe=false;
	private JCheckBox urlSafeCheckBox;
	
    @Override
    protected byte[] perform(byte[] input) {
    	if(!this.urlSafe) {
    		return Base64.getEncoder().encode(input);	
    	}
    	else {
    		return Base64.getUrlEncoder().encode(input);
    	}        
    }

    public void createUI() {
    	this.urlSafeCheckBox = new JCheckBox();
    	urlSafeCheckBox.setText("URL Safe");
    	urlSafeCheckBox.setToolTipText("When activated Base64 encoding is done URL safe. / and + are replaced with _ and -");
    	urlSafeCheckBox.setSelected(this.urlSafe);
    	urlSafeCheckBox.addActionListener(this);    	
    	this.addUIElement("", urlSafeCheckBox);
    }
    
	@Override
	public void actionPerformed(ActionEvent e) {
		this.urlSafe = this.urlSafeCheckBox.isSelected();		
	}

}
