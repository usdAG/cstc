package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.UIManager;

public class LayoutPanel extends JPanel {

	private Box headerBox;

	public LayoutPanel() {
		this("No tile");
	}

	public LayoutPanel(String title) {
		super();
		this.setLayout(new BorderLayout(0, 0));

		this.headerBox = Box.createHorizontalBox();
		this.headerBox.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		this.headerBox.setOpaque(true);
		this.headerBox.setBackground(UIManager.getColor("Panel.background"));

		JLabel titleLbl = new JLabel(title);
		titleLbl.setAlignmentX(Component.LEFT_ALIGNMENT);

		Font f = titleLbl.getFont();
		titleLbl.setFont(f.deriveFont(f.getStyle() | Font.BOLD));

		this.headerBox.add(titleLbl);
		this.headerBox.add(Box.createHorizontalGlue());

		this.add(headerBox, BorderLayout.PAGE_START);
	}

	public void addActionComponent(JComponent comp) {
		comp.setAlignmentX(Component.RIGHT_ALIGNMENT);
		this.headerBox.add(comp);
		this.headerBox.add(Box.createHorizontalStrut(10));
	}
}
