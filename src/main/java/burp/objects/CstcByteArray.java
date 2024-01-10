package burp.objects;

import java.util.Iterator;
import java.util.regex.Pattern;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;

public class CstcByteArray implements ByteArray{

    byte[] bytes;

    CstcByteArray(byte[] bytes){
        this.bytes = bytes;
    }

    public static ByteArray byteArray(String s){
        return new CstcByteArray(s.getBytes());
    }

    public static ByteArray byteArray(byte[] bytes){
        return new CstcByteArray(bytes);
    }

    public static ByteArray byteArray(){
        return new CstcByteArray(new byte[0]);
    }

    public static ByteArray byteArray(int i){
        return new CstcByteArray(new byte[i]);
    }

    public String toString(){
        return new String(bytes);
    }

    @Override
    public byte[] getBytes() {
        return bytes;
    }

    @Override
    public Iterator<Byte> iterator() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'iterator'");
    }

    @Override
    public byte getByte(int index) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'getByte'");
    }

    @Override
    public void setByte(int index, byte value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setByte'");
    }

    @Override
    public void setByte(int index, int value) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setByte'");
    }

    @Override
    public void setBytes(int index, byte... data) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setBytes'");
    }

    @Override
    public void setBytes(int index, int... data) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setBytes'");
    }

    @Override
    public void setBytes(int index, ByteArray byteArray) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'setBytes'");
    }

    @Override
    public int length() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'length'");
    }

    @Override
    public ByteArray subArray(int startIndexInclusive, int endIndexExclusive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'subArray'");
    }

    @Override
    public ByteArray subArray(Range range) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'subArray'");
    }

    @Override
    public ByteArray copy() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'copy'");
    }

    @Override
    public ByteArray copyToTempFile() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'copyToTempFile'");
    }

    @Override
    public int indexOf(ByteArray searchTerm) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'indexOf'");
    }

    @Override
    public int indexOf(String searchTerm) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'indexOf'");
    }

    @Override
    public int indexOf(ByteArray searchTerm, boolean caseSensitive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'indexOf'");
    }

    @Override
    public int indexOf(String searchTerm, boolean caseSensitive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'indexOf'");
    }

    @Override
    public int indexOf(ByteArray searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'indexOf'");
    }

    @Override
    public int indexOf(String searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'indexOf'");
    }

    @Override
    public int countMatches(ByteArray searchTerm) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'countMatches'");
    }

    @Override
    public int countMatches(String searchTerm) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'countMatches'");
    }

    @Override
    public int countMatches(ByteArray searchTerm, boolean caseSensitive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'countMatches'");
    }

    @Override
    public int countMatches(String searchTerm, boolean caseSensitive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'countMatches'");
    }

    @Override
    public int countMatches(ByteArray searchTerm, boolean caseSensitive, int startIndexInclusive,
            int endIndexExclusive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'countMatches'");
    }

    @Override
    public int countMatches(String searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'countMatches'");
    }

    @Override
    public ByteArray withAppended(byte... data) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAppended'");
    }

    @Override
    public ByteArray withAppended(int... data) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAppended'");
    }

    @Override
    public ByteArray withAppended(String text) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAppended'");
    }

    @Override
    public ByteArray withAppended(ByteArray byteArray) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'withAppended'");
    }

    @Override
    public int indexOf(Pattern pattern) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'indexOf'");
    }

    @Override
    public int indexOf(Pattern pattern, int startIndexInclusive, int endIndexExclusive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'indexOf'");
    }

    @Override
    public int countMatches(Pattern pattern) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'countMatches'");
    }

    @Override
    public int countMatches(Pattern pattern, int startIndexInclusive, int endIndexExclusive) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'countMatches'");
    }

}
