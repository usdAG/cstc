package de.usd.cstchef.view;

import java.awt.Component;
import java.awt.Container;

import de.usd.cstchef.operations.Operation;

public class MoveOperationMouseAdapter extends OperationMouseAdapter {

	public MoveOperationMouseAdapter(RecipeStepPanel source, Container target) {
		super(source.getOperationsPanel(), target);
	}

	@Override
	protected Operation getDraggedOperation(int x, int y) {
		Component comp = this.source.getComponentAt(x, y);
		comp.getParent().remove(comp);

		return comp instanceof Operation ? (Operation) comp : null;
	}
	
}
