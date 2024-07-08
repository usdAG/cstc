package de.usd.cstchef.wrapper;

import java.io.IOException;
import java.io.OutputStream;
import java.util.zip.GZIPOutputStream;

public class GZIPOutputStreamWrapper extends GZIPOutputStream {

    public GZIPOutputStreamWrapper(OutputStream out) throws IOException {
        super(out);
        //TODO Auto-generated constructor stub
    }

    public GZIPOutputStreamWrapper(OutputStream out, int size) throws IOException {
        super(out, size);
        //TODO Auto-generated constructor stub
    }

    public GZIPOutputStreamWrapper(OutputStream out, boolean syncFlush) throws IOException {
        super(out, syncFlush);
        //TODO Auto-generated constructor stub
    }

    public GZIPOutputStreamWrapper(OutputStream out, int size, boolean syncFlush) throws IOException {
        super(out, size, syncFlush);
        //TODO Auto-generated constructor stub
    }

    public void setCompressionLevel(int level) {
        def.setLevel(level);
    }
    
}
