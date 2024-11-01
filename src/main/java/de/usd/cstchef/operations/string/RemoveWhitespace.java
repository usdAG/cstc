package de.usd.cstchef.operations.string;

import javax.swing.JComboBox;

import burp.BurpUtils;
import burp.api.montoya.core.ByteArray;
import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;

@OperationInfos(name = "Remove Whitespace", category = OperationCategory.STRING, description = "Removes Spaces, Tabs or Newlines from input")
public class RemoveWhitespace extends Operation {

	JComboBox<String> whitespaceSelection;

	@Override
	protected ByteArray perform(ByteArray input, MessageType messageType) throws Exception {
		try {
			if(input != null) {
				String inputStr = input.toString();
				String selection = (String)this.whitespaceSelection.getSelectedItem();
				switch(selection){
					case "Space":
						inputStr = inputStr.replaceAll(" ", "");
						break;
					case "Newline":
						inputStr = inputStr.replaceAll("\n", "");
						break;
					case "Tab":
						inputStr = inputStr.replaceAll("\t", "");
						break;
					case "All":
						inputStr = inputStr.replaceAll("[\n\t\s]*", "");
						break;
					default:
						throw new IllegalArgumentException("Unkown whitespace type selection");
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
		this.whitespaceSelection = new JComboBox<>(new String[] { "Space", "Newline", "Tab", "All"});
		this.whitespaceSelection.setSelectedIndex(1);
		this.addUIElement("Type: ", this.whitespaceSelection);
	}
}
