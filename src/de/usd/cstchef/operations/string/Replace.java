package de.usd.cstchef.operations.string;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.OperationCategory;
import de.usd.cstchef.operations.Operation.OperationInfos;
import de.usd.cstchef.view.ui.VariableTextArea;
import de.usd.cstchef.view.ui.VariableTextField;

@OperationInfos(name = "Replace", category = OperationCategory.STRING, description = "Uses a regular expression to replace all occurences. Has side effect on binary content due to String Encoding.")
public class Replace extends Operation {

	private VariableTextField regexTxt;
	private VariableTextArea replacementTxt;

	@Override
	protected byte[] perform(byte[] input) throws Exception {
		String inputStr = new String(input);
		String result = inputStr.replaceAll(regexTxt.getText(), replacementTxt.getText());
		
		return result.getBytes();
	}

	@Override
	public void createUI() {
		this.regexTxt = new VariableTextField();
		this.addUIElement("Regex", this.regexTxt);

		this.replacementTxt = new VariableTextArea();
		this.addUIElement("Value", this.replacementTxt);
	}

}