package de.usd.cstchef.view.filter;

import com.fasterxml.jackson.annotation.JsonValue;

import burp.Logger;

public class Filter {
        private String name;
        private int value;

        public Filter(String name, int value) {
            this.name = name;
            this.value = value;
        }

        public Filter(String s) {
            String[] pairs = s.split(":");
            this.name = pairs[0].trim();
            this.value = Integer.parseInt(pairs[1].trim());
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

        @Override
        @JsonValue
        public String toString() {
            return name + ": " + value;
        }
    }
