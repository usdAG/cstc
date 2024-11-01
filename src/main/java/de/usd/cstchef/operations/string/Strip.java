package de.usd.cstchef.operations.string;

import javax.swing.JComboBox;

import burp.BurpUtils;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Strip", category = OperationCategory.STRING, description = "Strip Whitespace at beginning, end or both")
public class Strip extends Operation {

	JComboBox<String> stripLocationSelection;

	@Override
	protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
		try {
			if(input != null) {
				String inputStr = input.toString();
				String selection = (String)this.stripLocationSelection.getSelectedItem();
				switch(selection){
					case "Start":
						inputStr = inputStr.stripLeading();
						break;
					case "End":
						inputStr = inputStr.stripTrailing();
						break;
					case "Both":
						inputStr = inputStr.stripLeading().stripTrailing();
						break;
					default:
						throw new IllegalArgumentException("Unkown location selection");
				}

				return factory.createByteArray(inputStr);	
			}
			else {
				return factory.createByteArray("");
			}
			 
		} catch (Exception e) {
			return input;
		}
	}
	
	@Override
    public void createUI() {
		this.stripLocationSelection = new JComboBox<>(new String[] { "Start", "End", "Both"});
		this.stripLocationSelection.setSelectedIndex(0);
		this.addUIElement("Strip at: ", this.stripLocationSelection);
	}
}
