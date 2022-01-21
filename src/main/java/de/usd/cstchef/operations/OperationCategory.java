package de.usd.cstchef.operations;

public enum OperationCategory {
    ARITHMETIC("Arithmetic"),
    BYTEOPERATION("Byte Operations"),
    COMPRESSION("Compression"),
    CONDITIONALS("Conditionals"),
    DATAFORMAT("Data format"),
    DATES("Date / Time"),
    ENCRYPTION("Encryption / Encoding"),
    EXTRACTORS("Extractors"),
    HASHING("Hashing"),
    MISC("Misc"),
    NETWORKING("Networking"),
    SETTER("Setter"),
    SIGNATURE("Signature"),
    STRING("String"),
    UTILS("Utils");
//    LANGUAGE("Language"),
//    FLOWCONTROL("Flow control");

    private final String text;

    OperationCategory(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }
}
