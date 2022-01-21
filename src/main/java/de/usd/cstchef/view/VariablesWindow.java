package de.usd.cstchef.view;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagLayout;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.HashMap;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;

public class VariablesWindow extends JFrame {

    private static VariablesWindow instance;

    public static VariablesWindow getInstance() {
        if (VariablesWindow.instance == null) {
            VariablesWindow.instance = new VariablesWindow();
        }
        return VariablesWindow.instance;
    }

    private JLabel emptyLbl;
    private JTable table;

    private VariablesWindow() {
        super("Variables");
        this.setSize(new Dimension(600, 480));

        DefaultTableModel model = new DefaultTableModel(new String[] { "Variable Name", "Content" }, 0);
        this.table = new JTable(model) {
            public boolean isCellEditable(int row, int column) {
                return false;
            };
        };

        this.addComponentListener(new ComponentAdapter() {
            public void componentResized(ComponentEvent e) {
                if (table.getModel().getRowCount() == 0) {
                    setColumnWidth(new Dimension());
                }
            }
        });

        this.table.setLayout(new GridBagLayout());
        this.table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        this.table.getColumnModel().getColumn(0).setPreferredWidth(200);
        this.table.getColumnModel().getColumn(1).setCellRenderer(new WordWrapCellRenderer());
        this.table.getTableHeader().setReorderingAllowed(false);
        this.table.getTableHeader().setResizingAllowed(false);
        this.table.setFillsViewportHeight(true);
        ((DefaultTableCellRenderer)table.getTableHeader().getDefaultRenderer()).setHorizontalAlignment(JLabel.LEFT);

        this.emptyLbl = new JLabel("no variables defined");
        this.table.add(this.emptyLbl);

        JScrollPane scrollPane = new JScrollPane(this.table);
        this.add(scrollPane);
    }

    public void refresh(HashMap<String, byte[]> variables) {
        DefaultTableModel model = (DefaultTableModel) this.table.getModel();
        model.setRowCount(0);
        this.emptyLbl.setVisible(variables.isEmpty());
        SortedMap<String, byte[]> sortedMap = new TreeMap<String, byte[]>(variables);

        for (String key : sortedMap.keySet()) {
            model.addRow(new String[] { key, new String(sortedMap.get(key)) });
        }
    }

    private void setColumnWidth(Dimension preferredSize) {
        TableColumn contentColumn = this.table.getColumnModel().getColumn(1);
        int parentWidth = this.table.getParent().getWidth();
        int width = Integer.max(preferredSize.width + WordWrapCellRenderer.MARGIN, parentWidth - this.table.getColumnModel().getColumn(0).getWidth());
        contentColumn.setPreferredWidth(width);
    }

    class WordWrapCellRenderer extends JTextArea implements TableCellRenderer {
        private static final int MARGIN = 20;

        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Dimension preferredSize = getPreferredSize();
            setText(value.toString());
            setSize(preferredSize.width, getPreferredSize().height);
            if (table.getRowHeight(row) != getPreferredSize().height) {
                table.setRowHeight(row, getPreferredSize().height);
            }
            setColumnWidth(preferredSize);
            return this;
        }
    }
}
