package burp;

import burp.api.montoya.core.ByteArray;

public class BurpObjectFactory implements CstcObjectFactory{

    @Override
    public ByteArray createByteArray(String s) {
        return ByteArray.byteArray(s);
    }

    @Override
    public ByteArray createByteArray(byte[] bytes) {
        return ByteArray.byteArray(bytes);
    }

    @Override
    public ByteArray createByteArray(int i) {
        return ByteArray.byteArray(i);
    }
    
}
