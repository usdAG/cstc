package de.usd.cstchef.operations.setter;

import javax.swing.JCheckBox;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.VariableTextField;

public abstract class SetterOperation extends Operation {
	
	private VariableTextField whereToSet;
	private VariableTextField whatToSet;
	private JCheckBox urlEncode;
	private JCheckBox urlEncodeAll;
	private JCheckBox addIfNotPresent;
	
	@Override
	public void createUI() {
		this.whereToSet = new VariableTextField();
		this.whatToSet = new VariableTextField();
		this.addUIElement("Parameter name", this.whereToSet);
		this.addUIElement("Parameter value", this.whatToSet);
		
		this.urlEncode = new JCheckBox("URL encode");
	    this.urlEncode.setSelected(false);
		this.addUIElement(null, this.urlEncode);
		
		this.urlEncodeAll = new JCheckBox("URL encode all");
	    this.urlEncodeAll.setSelected(false);
		this.addUIElement(null, this.urlEncodeAll);
		
		this.addIfNotPresent = new JCheckBox("Add if not present");
	    this.addIfNotPresent.setSelected(true);
		this.addUIElement(null, this.addIfNotPresent);
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
		return urlEncode.isSelected();
	}
	
	protected boolean urlEncodeAll() {
		return urlEncodeAll.isSelected();
	}

	protected boolean addIfNotPresent() {
		return addIfNotPresent.isSelected();
	}
}
