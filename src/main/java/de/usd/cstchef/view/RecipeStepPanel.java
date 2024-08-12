package de.usd.cstchef.view;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JOptionPane;
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
    private JTextField contentTextField;

    private String comment;
    private JButton commentBtn;

    private static ImageIcon commentIcon = new ImageIcon(Operation.class.getResource("/comment.png"));
    private static ImageIcon noCommentIcon = new ImageIcon(Operation.class.getResource("/no_comment.png"));

    public RecipeStepPanel(String title, ChangeListener changelistener) {
        this.changeListener = changelistener;
        this.setLayout(new BorderLayout());
        this.setPreferredSize(new Dimension(350, 0));

        // header
        Box headerBox = Box.createHorizontalBox();
        // add borders
        Border margin = BorderFactory.createEmptyBorder(10, 10, 10, 10);
        MatteBorder lineBorder = new MatteBorder(0, 0, 2, 0, Color.DARK_GRAY);
        CompoundBorder border = new CompoundBorder(lineBorder, margin);
        headerBox.setBorder(border);

        contentTextField = new JTextField();
        contentTextField.setBorder(null);
        contentTextField.setBackground(new Color(0, 0, 0, 0));
        contentTextField.setText(title);
        contentTextField.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                String newTitle = JOptionPane.showInputDialog("Edit title:", getTitle());
                contentTextField.setText(newTitle.length() <= 50 ? newTitle : getTitle());
                setTitle(newTitle.length() <= 50 ? newTitle : getTitle()); // lane name should be leq 50 chars
            }
        });
        headerBox.add(contentTextField);

        JPanel panel = new JPanel();
        panel.setBackground(new Color(0, 0, 0, 0)); // transparent

        commentBtn = createIconButton(noCommentIcon);

        commentBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                commentBtn.setToolTipText(getComment());
                String comment = JOptionPane.showInputDialog("Edit comment:", commentBtn.getToolTipText());
                commentBtn.setToolTipText(comment);
                setComment(comment);
                ImageIcon newIcon = comment.isEmpty() ? RecipeStepPanel.noCommentIcon : RecipeStepPanel.commentIcon;
                commentBtn.setIcon(newIcon);
            }
        });

        panel.add(commentBtn);
        headerBox.add(panel);

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

	public void clearOperations() {
		Component[] operations = this.operationsLine.getComponents();
		for (int i = 0; i < operations.length; i++) {
			Component op = operations[i];
			if (!(op instanceof Operation)) {
				continue;
			}
			operationsLine.remove(op);
		}
		operationsLine.revalidate();
		operationsLine.repaint();
		this.changeListener.stateChanged(new ChangeEvent(this));
	}

    public String getTitle() {
        return contentTextField.getText();
    }

    public void setTitle(String title) {
        contentTextField.setText(title);
    }

    private JButton createIconButton(ImageIcon icon) {
        JButton btn = new JButton();
        btn.setBorder(BorderFactory.createEmptyBorder());
        btn.setIcon(icon);
        btn.setContentAreaFilled(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setAlignmentX(Component.RIGHT_ALIGNMENT);

        return btn;
    }

    public String getComment() {
        return this.comment;
    }

    public void setComment(String comment) {
        if(comment != null) {
            this.comment = comment;
            commentBtn.setIcon(RecipeStepPanel.commentIcon);
            commentBtn.setToolTipText(comment);
        }
    }

    public void clearComment() {
        this.comment = "";
        commentBtn.setToolTipText("");
        commentBtn.setIcon(RecipeStepPanel.noCommentIcon);
    }
}
