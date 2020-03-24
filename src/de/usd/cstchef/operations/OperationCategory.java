package de.usd.cstchef.operations;

public enum OperationCategory {
	DATAFORMAT("Data format"),
	EXTRACTORS("Extractors"),
	SETTER("Setter"),
	STRING("String"),
	HASHING("Hashing"),
	BYTEOPERATION("Byte Operations"),
	ARITHMETIC("Arithmetic"),
	NETWORKING("Networking"),	
	UTILS("Utils"),
	DATES("Date / Time"),
	ENCRYPTION("Encryption / Encoding"),
	SIGNATURE("Signature"),	
	MISC("Misc"),
	COMPRESSION("Compression");
//	LANGUAGE("Language"),
//	FLOWCONTROL("Flow control");
	
    private final String text;

    OperationCategory(final String text) {
        this.text = text;
    }

    @Override
    public String toString() {
        return text;
    }

}
