package de.usd.cstchef.view;

import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import burp.IBurpExtenderCallbacks;

public class RequestFilterDialog extends JPanel {
    private LinkedHashMap<Filter, Boolean> filterSettings;

    public RequestFilterDialog() {
        this.filterSettings = new LinkedHashMap<>();
        this.filterSettings.put(new Filter("Proxy", IBurpExtenderCallbacks.TOOL_PROXY), false);
        this.filterSettings.put(new Filter("Repeater", IBurpExtenderCallbacks.TOOL_REPEATER), false);
        this.filterSettings.put(new Filter("Spider", IBurpExtenderCallbacks.TOOL_SPIDER), false);
        this.filterSettings.put(new Filter("Scanner", IBurpExtenderCallbacks.TOOL_SCANNER), false);
        this.filterSettings.put(new Filter("Intruder", IBurpExtenderCallbacks.TOOL_INTRUDER), false);
        this.filterSettings.put(new Filter("Extender", IBurpExtenderCallbacks.TOOL_EXTENDER), false);

        this.setLayout(new GridLayout(0, 2));

        for (Map.Entry<Filter, Boolean> entry : this.filterSettings.entrySet()) {
            Filter filter = entry.getKey();
            boolean selected = entry.getValue();
            this.add(new JLabel(filter.getName() + ": "));

            JCheckBox box = new JCheckBox();
            box.setSelected(selected);
            box.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    filterSettings.put(filter, box.isSelected());
                }
            });
            this.add(box);
        }
    }

    public int getFilterMask() {
        int filterMask = 0;
        for (Map.Entry<Filter, Boolean> entry : this.filterSettings.entrySet()) {
            Filter filter = entry.getKey();
            boolean selected = entry.getValue();
            if (selected) {
                filterMask |= filter.getValue();
            }
        }
        return filterMask;
    }

    class Filter {
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
