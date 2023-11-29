package burp;

import burp.api.montoya.core.ByteArray;

public interface CstcObjectFactory {
    public ByteArray createByteArray(String s);
    public ByteArray createByteArray(byte[] bytes);
}
