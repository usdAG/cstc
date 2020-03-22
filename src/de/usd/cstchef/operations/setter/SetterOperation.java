package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.VariableTextField;

public abstract class SetterOperation extends Operation {
	
	private VariableTextField whereToSet;
	private VariableTextField whatToSet;
	private JCheckBox checkbox;
	
	@Override
	public void createUI() {
		this.whereToSet = new VariableTextField();
		this.whatToSet = new VariableTextField();
		this.addUIElement("Where to Set", this.whereToSet);
		this.addUIElement("What to Set", this.whatToSet);
		
		this.checkbox = new JCheckBox("URL encode");
	    this.checkbox.setSelected(false);
		this.addUIElement(null, this.checkbox);
	}
	
	protected String getWhere() {
		return whereToSet.getText();
	}
	
	protected byte[] getWhereBytes() {
		return whereToSet.getBytes();
	}
	
	protected String getWhat() {
		return whatToSet.getText();
	}

	protected byte[] getWhatBytes() {
		return whatToSet.getBytes();
	}
	
	protected boolean urlEncode() {
		return checkbox.isSelected();
	}
}
