package de.usd.cstchef.view.ui;

import javax.swing.*;
import javax.swing.plaf.basic.BasicButtonUI;

import de.usd.cstchef.Utils.MessageType;
import de.usd.cstchef.view.RecipePanel;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

import java.awt.*;
import java.awt.event.*;

/**
 * Component to be used as tabComponent;
 * Contains a JLabel to show the text 
 * JButtons to close the tab it belongs to or add one 
 */ 
public class ButtonTabComponent extends JPanel {
    private View view;
    private JTabbedPane pane;
    public static int indexOfLastComp = 2;

    private static JPopupMenu popup = new JPopupMenu();
    private static JMenuItem outgoingItem = new JMenuItem("Outgoing Requests");
    private static JMenuItem incomingItem = new JMenuItem("Incoming Responses");


    public ButtonTabComponent(View view, ButtonType buttonType, String title) {
        //unset default FlowLayout' gaps
        super(new FlowLayout(FlowLayout.LEFT, 0, 0));
        this.view = view;
        this.pane = this.view.getTabbedPane();
        setOpaque(false);

        JLabel label = new JLabel(title);
        label.addMouseListener(new TabMouseAdapter() {

            @Override
            public void mouseClicked(MouseEvent e) {
                super.mouseClicked(e);
                int index = pane.indexOfTabComponent(ButtonTabComponent.this);
                if(e.getClickCount() == 2) {
                    String newName = JOptionPane.showInputDialog("New name: ");
                    if(!newName.isBlank()) {
                        view.getRecipePanelAtIndex(index).setRecipeName(newName);
                        label.setText(newName);
                        view.saveRecipePanelChanges();
                    }
                }
            }
        });

        //add more space between the label and the button
        label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 15));

        add(label);

        switch(buttonType) {
            case NONE:
                break;
            case ADD:
                add(new AddButton());
                break;
            case CLOSE:
                add(new CloseButton());
                break;
            case CLOSEANDADD:
                add(new CloseButton());
                add(new AddButton());
                break;
        }

        //add more space to the top of the component
        setBorder(BorderFactory.createEmptyBorder(2, 0, 0, 0));
    }

    public static void updateIndexOfLastComp(int i) {
        indexOfLastComp = i;
    }

    public static void initPopUpMenu(View view, JTabbedPane tabbedPane) {
        AbstractAction outgoingListener = new AbstractAction() {

            @Override
            public void actionPerformed(ActionEvent e) {
                RecipePanel newRecipePanel = new RecipePanel(BurpOperation.OUTGOING, "Recipe " + (indexOfLastComp + 2));
                view.addRecipePanel(newRecipePanel);
                if(indexOfLastComp > 2) view.initTabButton(indexOfLastComp, ButtonType.CLOSE, view.getRecipePanelAtIndex(indexOfLastComp).getRecipeName());
                else view.initTabButton(indexOfLastComp, ButtonType.NONE, view.getRecipePanelAtIndex(indexOfLastComp).getRecipeName());
                indexOfLastComp += 1;
                tabbedPane.add(newRecipePanel.getRecipeName(), newRecipePanel);
                view.initTabButton(indexOfLastComp, ButtonType.CLOSEANDADD, view.getRecipePanelAtIndex(indexOfLastComp).getRecipeName());
                tabbedPane.setBackgroundAt(indexOfLastComp, view.getColor(BurpOperation.OUTGOING));
                view.saveRecipePanelChanges();
            }
            
        };

        AbstractAction incomingListener = new AbstractAction() {

            @Override
            public void actionPerformed(ActionEvent e) {
                RecipePanel newRecipePanel = new RecipePanel(BurpOperation.INCOMING, "Recipe " + (indexOfLastComp + 2));
                view.addRecipePanel(newRecipePanel);
                if(indexOfLastComp > 2) view.initTabButton(indexOfLastComp, ButtonType.CLOSE, view.getRecipePanelAtIndex(indexOfLastComp).getRecipeName());
                else view.initTabButton(indexOfLastComp, ButtonType.NONE, view.getRecipePanelAtIndex(indexOfLastComp).getRecipeName());
                indexOfLastComp += 1;
                tabbedPane.add(newRecipePanel.getRecipeName(), newRecipePanel);
                view.initTabButton(indexOfLastComp, ButtonType.CLOSEANDADD, view.getRecipePanelAtIndex(indexOfLastComp).getRecipeName());
                tabbedPane.setBackgroundAt(indexOfLastComp, view.getColor(BurpOperation.INCOMING));
                view.saveRecipePanelChanges();
            }
            
        };
        outgoingItem.addActionListener(outgoingListener);
        incomingItem.addActionListener(incomingListener);
        popup.add(outgoingItem);
        popup.add(incomingItem);
    }

    private class CloseButton extends JButton implements ActionListener {
        public CloseButton() {
            int size = 17;
            setPreferredSize(new Dimension(size, size));
            setToolTipText("Close this tab");
            setIcon(new ImageIcon(ButtonTabComponent.class.getResource("/closeRecipePanel.png")));
            setUI(new BasicButtonUI());
            setContentAreaFilled(false);
            setFocusable(false);
            setBorder(BorderFactory.createEtchedBorder());
            setBorderPainted(false);
            addMouseListener(closeButtonMouseListener);
            setRolloverEnabled(true);
            addActionListener(this);
        }

        public void actionPerformed(ActionEvent e) {
            int i = pane.indexOfTabComponent(ButtonTabComponent.this);
            
            if(i > 2) {
                if(i == indexOfLastComp) {
                    if(i > 3) view.initTabButton(indexOfLastComp - 1, ButtonType.CLOSEANDADD, view.getRecipePanelAtIndex(indexOfLastComp - 1).getRecipeName());
                    else view.initTabButton(indexOfLastComp - 1, ButtonType.ADD, view.getRecipePanelAtIndex(indexOfLastComp - 1).getRecipeName());
                }
                indexOfLastComp--;
                pane.remove(i);
                view.removeRecipePanel(i);
                view.saveRecipePanelChanges();
            }
        }

        //we don't want to update UI for this button
        public void updateUI() {
        }

    }

    private class AddButton extends JButton implements ActionListener {
        public AddButton() {
            int size = 17;
            setPreferredSize(new Dimension(size, size));
            setToolTipText("Add new tab");
            setIcon(new ImageIcon(ButtonTabComponent.class.getResource("/addRecipePanel.png")));
            setUI(new BasicButtonUI());
            setContentAreaFilled(false);
            setFocusable(false);
            setBorder(BorderFactory.createEtchedBorder());
            setBorderPainted(false);
            addMouseListener(addButtonMouseListener);
            setRolloverEnabled(true);
            addActionListener(this);
        }

            public void actionPerformed(ActionEvent e) {
        }

        //we don't want to update UI for this button
        public void updateUI() {
        }

    }

    private final static MouseListener closeButtonMouseListener = new MouseAdapter() {
        public void mouseEntered(MouseEvent e) {
            Component component = e.getComponent();
            if (component instanceof AbstractButton) {
                AbstractButton button = (AbstractButton) component;
                button.setBorderPainted(true);
            }
        }

        public void mouseExited(MouseEvent e) {
            Component component = e.getComponent();
            if (component instanceof AbstractButton) {
                AbstractButton button = (AbstractButton) component;
                button.setBorderPainted(false);
            }
        }
    };

    private final static MouseListener addButtonMouseListener = new MouseAdapter() {
        public void mouseEntered(MouseEvent e) {
            Component component = e.getComponent();
            if (component instanceof AbstractButton) {
                AbstractButton button = (AbstractButton) component;
                button.setBorderPainted(true);
            }
        }

        public void mouseExited(MouseEvent e) {
            Component component = e.getComponent();
            if (component instanceof AbstractButton) {
                AbstractButton button = (AbstractButton) component;
                button.setBorderPainted(false);
            }
        }

        public void mousePressed(MouseEvent e) {
            popup.show(e.getComponent(), e.getX(), e.getY());
        }
    };

    static class TabMouseAdapter implements MouseListener {
    
        @Override
        public void mouseClicked(MouseEvent e) {
            redispatch(e);
        }

        @Override
        public void mousePressed(MouseEvent e) {
            redispatch(e);
        }

        @Override
        public void mouseReleased(MouseEvent e) {
            redispatch(e);
        }

        @Override
        public void mouseEntered(MouseEvent e) {
            redispatch(e);
        }

        @Override
        public void mouseExited(MouseEvent e) {
            redispatch(e);
        }

        private void redispatch(MouseEvent e) {
        
            Component source = e.getComponent();
            Component target = source.getParent();
            while (true) {
            
                if (target == null) {
                
                    break;
                }
                if (target instanceof JTabbedPane) {
                
                    break;
                }
                target = target.getParent();
            }
            if (target != null) {
            
                MouseEvent targetEvent =
                    SwingUtilities.convertMouseEvent(source, e, target);
                target.dispatchEvent(targetEvent);
            }
        }
    }
}