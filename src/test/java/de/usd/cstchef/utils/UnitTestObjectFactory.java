package de.usd.cstchef.utils;

import burp.CstcObjectFactory;
import burp.api.montoya.core.ByteArray;
import burp.objects.CstcByteArray;

public class UnitTestObjectFactory implements CstcObjectFactory{

    @Override
    public ByteArray createByteArray(String s) {
        return CstcByteArray.byteArray(s);
    }

    @Override
    public ByteArray createByteArray(byte[] bytes) {
        return CstcByteArray.byteArray(bytes);
    }
    
}
