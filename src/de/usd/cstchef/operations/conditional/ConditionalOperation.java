package de.usd.cstchef.operations.conditional;

import javax.swing.JTextField;

import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.view.ui.VariableTextField;

public abstract class ConditionalOperation extends Operation {

	protected VariableTextField expr;
	private JTextField operationSkipField;
	private JTextField laneSkipField;

	public void setOperationSkip() {
		
		try {
			int operationSkip = Integer.valueOf(operationSkipField.getText());
			this.setOperationSkip(operationSkip);
		} catch( Exception e ) {
			throw new IllegalArgumentException("Input is not a number.");
		}
	}
	
	public void setLaneSkip() {
		
		try {
			int laneSkip = Integer.valueOf(laneSkipField.getText());
			this.setLaneSkip(laneSkip);
		} catch( Exception e ) {
			throw new IllegalArgumentException("Input is not a number.");
		}
	}
	
	public void resetSkips() {
		this.setOperationSkip(0);
		this.setLaneSkip(0);
	}

	@Override
	public void createUI() {
		this.expr = new VariableTextField();
		this.addUIElement("Expr", this.expr);
		
		this.operationSkipField = new JTextField("0");
		this.addUIElement("Skip Operations", this.operationSkipField);
		
		this.laneSkipField = new JTextField("0");
		this.addUIElement("Skip Lanes", this.laneSkipField);

	}

}
