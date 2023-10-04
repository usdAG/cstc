package de.usd.cstchef.view;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import de.usd.cstchef.FilterState;
import de.usd.cstchef.FilterState.BurpOperation;

public class RequestFilterDialog extends JPanel {
    FilterState filterState;

    private static RequestFilterDialog instance = null;

    public static RequestFilterDialog getInstance() {
        if (RequestFilterDialog.instance == null) {
            RequestFilterDialog.instance = new RequestFilterDialog();
        }
        return RequestFilterDialog.instance;
    }

    private RequestFilterDialog() {
        this(new FilterState());
    }

    private RequestFilterDialog(FilterState filterState) {
        this.setLayout(new GridLayout(0, 4));

        this.setFilterState(filterState);

        JPanel incomingPanel = createPanel(BurpOperation.INCOMING);
        JPanel outgoingPanel = createPanel(BurpOperation.OUTGOING);
        JPanel formatPanel = createPanel(BurpOperation.FORMAT);

        JPanel labelPanel = new JPanel();
        labelPanel.setLayout(new GridLayout(7, 0));
        labelPanel.add(new JLabel(""));
        List<String> labels = Arrays.asList("Proxy", "Repeater", "Scanner", "Intruder", "Extender");
        for (String label : labels) {
            labelPanel.add(new JLabel(label));
        }

        this.add(labelPanel);
        this.add("Incoming", incomingPanel);
        this.add("Outgoing", outgoingPanel);
        this.add("Format", formatPanel);

    }

    public void setFilterState(FilterState filterState) {
        this.filterState = filterState;
    }

    public FilterState getFilterState() {
        return filterState;
    }

    private JPanel createPanel(BurpOperation operation) {
        if (filterState.getFilterMask(operation).isEmpty()) {
            filterState.getFilterMask(operation).put(new Filter("Proxy", ToolType.PROXY.ordinal()), false);
            filterState.getFilterMask(operation).put(new Filter("Repeater", ToolType.REPEATER.ordinal()),
                    false);
            filterState.getFilterMask(operation).put(new Filter("Scanner", ToolType.SCANNER.ordinal()), false);
            filterState.getFilterMask(operation).put(new Filter("Intruder", ToolType.INTRUDER.ordinal()),
                    false);
            filterState.getFilterMask(operation).put(new Filter("Extender", ToolType.EXTENSIONS.ordinal()),
                    false);
        }

        JPanel panel = new JPanel();
        panel.add(new JLabel(FilterState.translateBurpOperation(operation)));
        for (Map.Entry<Filter, Boolean> entry : filterState.getFilterMask(operation).entrySet()) {
            Filter filter = entry.getKey();
            boolean selected = entry.getValue();

            JCheckBox box = new JCheckBox();
            box.setSelected(selected);
            box.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    filterState.getFilterMask(operation).put(filter, box.isSelected());
                }
            });
            panel.add(box);
        }

        panel.setLayout(new GridLayout(7, 0));
        return panel;
    }

    public LinkedHashMap<Filter, Boolean> getFilterMask(BurpOperation operation) {
        return filterState.getFilterMask(operation);
    }

    public class Filter {
        private String name;
        private int value;

        public Filter(String name, int value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public int getValue() {
            return value;
        }

        public void setValue(int value) {
            this.value = value;
        }
    }
}
