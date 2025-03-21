package de.usd.cstchef.operations.dataformat;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JCheckBox;

import burp.BurpUtils;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.utilities.Base64DecodingOptions;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "From Base64", category = OperationCategory.DATAFORMAT, description = "Decode a base64 string.")
public class FromBase64 extends Operation implements ActionListener {

	private boolean urlSafe=false;
	private JCheckBox urlSafeCheckBox;
	
    @Override
    protected ByteArray perform(ByteArray input) {
		MontoyaApi api = BurpUtils.getInstance().getApi();
		if(!this.urlSafe) {
			return api.utilities().base64Utils().decode(input);
    	}
    	else {
    		return api.utilities().base64Utils().decode(input, Base64DecodingOptions.URL);
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
