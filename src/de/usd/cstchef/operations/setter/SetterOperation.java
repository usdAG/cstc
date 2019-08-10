package de.usd.cstchef.operations.setter;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.VariableTextField;

public abstract class SetterOperation extends Operation {
	
	private VariableTextField whereToSet;
	private VariableTextField whatToSet;
	
	@Override
	public void createUI() {
		this.whereToSet = new VariableTextField();
		this.whatToSet = new VariableTextField();
		this.addUIElement("Where to Set", this.whereToSet);
		this.addUIElement("What to Set", this.whatToSet);
	}
	
	protected String getWhere() {
		return whereToSet.getText();
	}
	
	protected String getWhat() {
		return whatToSet.getText();
	}

}
