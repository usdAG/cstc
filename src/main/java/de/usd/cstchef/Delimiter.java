package de.usd.cstchef;

public enum Delimiter
{
    COMMA("Comma", ","),
    SPACE("Space", " "),
    LINE_FEED("Line feed", "\n"),
    COLON("Colon", ":"),
    CLRF("CLRF", "\r\n"),
    SEMICOLON("Semicolon", ";");

    private String name;
    private String value;

    Delimiter(String name, String value)
    {
        this.name = name;
        this.value = value;
    }

    public String getValue()
    {
        return this.value;
    }

    public static Delimiter getByName(String name)
    {
        for(Delimiter delim : Delimiter.values() )

            if( delim.name.equals(name) )
                return delim;

        return null;
    }

    public static String[] getNames()
    {
        Delimiter[] delims = Delimiter.values();
        String[] names = new String[delims.length];

        for(int ctr = 0; ctr < delims.length; ctr++ )
            names[ctr] = delims[ctr].name;

        return names;
    }
}