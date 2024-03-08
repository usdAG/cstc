package de.usd.cstchef.view.filter;

import com.fasterxml.jackson.annotation.JsonValue;

import burp.Logger;
import burp.api.montoya.core.ToolType;

public class Filter {
        private ToolType toolType;
        private int value;

        public Filter(ToolType toolType, int value) {
            this.toolType = toolType;
            this.value = value;
        }

        public Filter(String s) {
            String[] pairs = s.split(":");
            this.toolType = ToolType.valueOf(pairs[0].trim().toUpperCase());
            this.value = Integer.parseInt(pairs[1].trim());
        }

        public ToolType getToolType() {
            return toolType;
        }

        public void setToolType(ToolType name) {
            this.toolType = name;
        }

        public int getValue() {
            return value;
        }

        public void setValue(int value) {
            this.value = value;
        }

        @Override
        @JsonValue
        public String toString() {
            return toolType.toString() + ": " + value;
        }
    }
