package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.MatteBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import de.usd.cstchef.operations.*;

public class RecipeStepPanel extends JPanel {

	private JPanel operationsLine;
	private GridBagConstraints addContraints;
	private ChangeListener changeListener;

	public RecipeStepPanel(String title, ChangeListener changelistener) {
		this.changeListener = changelistener;
		this.setLayout(new BorderLayout());
		this.setPreferredSize(new Dimension(300, 0));

		// header
		Box headerBox = Box.createHorizontalBox();
		// add borders
		Border margin = BorderFactory.createEmptyBorder(10, 10, 10, 10);
		MatteBorder lineBorder = new MatteBorder(0, 0, 2, 0, Color.DARK_GRAY);
		CompoundBorder border = new CompoundBorder(lineBorder, margin);
		headerBox.setBorder(border);

		JTextField contentTextField = new JTextField();
		contentTextField.setBorder(null);
		contentTextField.setBackground(new Color(0, 0, 0, 0));
		contentTextField.setText(title);
		headerBox.add(contentTextField);

		this.add(headerBox, BorderLayout.NORTH);

		// body
		operationsLine = new JPanel(new GridBagLayout());

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.gridheight = GridBagConstraints.REMAINDER;
		gbc.weightx = 1;
		gbc.weighty = 1;
		gbc.fill = GridBagConstraints.BOTH;

		JPanel dummyPanel = new JPanel();
		operationsLine.add(dummyPanel, gbc);

		this.addContraints = new GridBagConstraints();
		this.addContraints.gridwidth = GridBagConstraints.REMAINDER;
		this.addContraints.weightx = 1;
		this.addContraints.fill = GridBagConstraints.HORIZONTAL;

		JScrollPane scrollPane = new JScrollPane(operationsLine);
		scrollPane.setBorder(new MatteBorder(0, 2, 0, 0, Color.DARK_GRAY));
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
		scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.getVerticalScrollBar().setUnitIncrement(16);

		this.add(scrollPane, BorderLayout.CENTER);
	}

	public void addComponent(Component comp, int index) {
		operationsLine.add(comp, addContraints, index);
		operationsLine.revalidate();
		operationsLine.repaint();
		if (comp instanceof Operation) {			
			((Operation) comp).setChangeListener(this.changeListener);
			this.changeListener.stateChanged(new ChangeEvent(this));
		}
	}

	public void removeComponent(Component comp) {
		operationsLine.remove(comp);
		operationsLine.revalidate();
		operationsLine.repaint();
		this.changeListener.stateChanged(new ChangeEvent(this));
	}
	
	public JPanel getOperationsPanel() {
		return this.operationsLine;
	}

	public List<Operation> getOperations() {
		List<Operation> result = new ArrayList<>();

		for (int i = 0; i < this.operationsLine.getComponentCount(); i++) {
			Component op = this.operationsLine.getComponent(i);
			if (!(op instanceof Operation)) {
				continue;
			}

			result.add((Operation) op);
		}
		return result;
	}

}
