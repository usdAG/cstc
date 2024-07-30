package de.usd.cstchef;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URISyntaxException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

import burp.BurpUtils;
import burp.BurpObjectFactory;
import burp.CstcObjectFactory;
import burp.Logger;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.ResponseAction;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.arithmetic.Addition;
import de.usd.cstchef.operations.arithmetic.Divide;
import de.usd.cstchef.operations.arithmetic.DivideList;
import de.usd.cstchef.operations.arithmetic.Mean;
import de.usd.cstchef.operations.arithmetic.Median;
import de.usd.cstchef.operations.arithmetic.Multiply;
import de.usd.cstchef.operations.arithmetic.MultiplyList;
import de.usd.cstchef.operations.arithmetic.Subtraction;
import de.usd.cstchef.operations.arithmetic.Sum;
import de.usd.cstchef.operations.byteoperation.AddKey;
import de.usd.cstchef.operations.byteoperation.And;
import de.usd.cstchef.operations.byteoperation.Sub;
import de.usd.cstchef.operations.byteoperation.Xor;
import de.usd.cstchef.operations.compression.Deflate;
import de.usd.cstchef.operations.compression.GUnzip;
import de.usd.cstchef.operations.compression.Gzip;
import de.usd.cstchef.operations.compression.Inflate;
import de.usd.cstchef.operations.conditional.NumberCompare;
import de.usd.cstchef.operations.conditional.RegexMatch;
import de.usd.cstchef.operations.conditional.StringContains;
import de.usd.cstchef.operations.conditional.StringMatch;
import de.usd.cstchef.operations.dataformat.FromBase64;
import de.usd.cstchef.operations.dataformat.JsonBeautifier;
import de.usd.cstchef.operations.dataformat.FromHex;
import de.usd.cstchef.operations.dataformat.HtmlDecode;
import de.usd.cstchef.operations.dataformat.HtmlEncode;
import de.usd.cstchef.operations.dataformat.ToBase64;
import de.usd.cstchef.operations.dataformat.ToHex;
import de.usd.cstchef.operations.dataformat.UrlDecode;
import de.usd.cstchef.operations.dataformat.UrlEncode;
import de.usd.cstchef.operations.datetime.DateTime;
import de.usd.cstchef.operations.datetime.TimestampOffset;
import de.usd.cstchef.operations.datetime.TimestampToDateTime;
import de.usd.cstchef.operations.datetime.UnixTimestamp;
import de.usd.cstchef.operations.encryption.AesDecryption;
import de.usd.cstchef.operations.encryption.AesEncryption;
import de.usd.cstchef.operations.encryption.DesDecryption;
import de.usd.cstchef.operations.encryption.DesEncryption;
import de.usd.cstchef.operations.encryption.RsaDecryption;
import de.usd.cstchef.operations.encryption.RsaEncryption;
import de.usd.cstchef.operations.encryption.SM4Decryption;
import de.usd.cstchef.operations.encryption.SM4Encryption;
import de.usd.cstchef.operations.extractors.HttpBodyExtractor;
import de.usd.cstchef.operations.extractors.HttpCookieExtractor;
import de.usd.cstchef.operations.extractors.HttpGetExtractor;
import de.usd.cstchef.operations.extractors.HttpHeaderExtractor;
import de.usd.cstchef.operations.extractors.HttpJsonExtractor;
import de.usd.cstchef.operations.extractors.HttpMethodExtractor;
import de.usd.cstchef.operations.extractors.HttpMultipartExtractor;
import de.usd.cstchef.operations.extractors.HttpPostExtractor;
import de.usd.cstchef.operations.extractors.HttpUriExtractor;
import de.usd.cstchef.operations.extractors.HttpXmlExtractor;
import de.usd.cstchef.operations.extractors.JsonExtractor;
import de.usd.cstchef.operations.extractors.LineExtractor;
import de.usd.cstchef.operations.extractors.RegexExtractor;
import de.usd.cstchef.operations.hashing.Blake;
import de.usd.cstchef.operations.hashing.DSTU7564;
import de.usd.cstchef.operations.hashing.Gost;
import de.usd.cstchef.operations.hashing.Hmac;
import de.usd.cstchef.operations.hashing.MD2;
import de.usd.cstchef.operations.hashing.MD4;
import de.usd.cstchef.operations.hashing.MD5;
import de.usd.cstchef.operations.hashing.RIPEMD;
import de.usd.cstchef.operations.hashing.SHA1;
import de.usd.cstchef.operations.hashing.SHA2;
import de.usd.cstchef.operations.hashing.SHA3;
import de.usd.cstchef.operations.hashing.SM3;
import de.usd.cstchef.operations.hashing.Skein;
import de.usd.cstchef.operations.hashing.Tiger;
import de.usd.cstchef.operations.hashing.Luhn;
import de.usd.cstchef.operations.hashing.Whirlpool;
import de.usd.cstchef.operations.misc.GetRequestBuilder;
import de.usd.cstchef.operations.misc.ReadFile;
import de.usd.cstchef.operations.misc.WriteFile;
import de.usd.cstchef.operations.networking.PlainRequest;
import de.usd.cstchef.operations.setter.HttpGetSetter;
import de.usd.cstchef.operations.setter.HttpHeaderSetter;
import de.usd.cstchef.operations.setter.HttpJsonSetter;
import de.usd.cstchef.operations.setter.HttpMultipartSetter;
import de.usd.cstchef.operations.setter.HttpPostSetter;
import de.usd.cstchef.operations.setter.HttpSetBody;
import de.usd.cstchef.operations.setter.HttpSetCookie;
import de.usd.cstchef.operations.setter.HttpSetUri;
import de.usd.cstchef.operations.setter.HttpXmlSetter;
import de.usd.cstchef.operations.setter.JsonSetter;
import de.usd.cstchef.operations.setter.LineSetter;
import de.usd.cstchef.operations.signature.JWTDecode;
import de.usd.cstchef.operations.signature.JWTSign;
import de.usd.cstchef.operations.signature.RsaSignature;
import de.usd.cstchef.operations.signature.SM2Signature;
import de.usd.cstchef.operations.signature.SoapMultiSignature;
import de.usd.cstchef.operations.signature.XmlFullSignature;
import de.usd.cstchef.operations.signature.XmlMultiSignature;
import de.usd.cstchef.operations.string.Length;
import de.usd.cstchef.operations.string.Prefix;
import de.usd.cstchef.operations.string.Replace;
import de.usd.cstchef.operations.string.Reverse;
import de.usd.cstchef.operations.string.SplitAndSelect;
import de.usd.cstchef.operations.string.StaticString;
import de.usd.cstchef.operations.string.Substring;
import de.usd.cstchef.operations.string.Suffix;
import de.usd.cstchef.operations.string.Uppercase;
import de.usd.cstchef.operations.string.Lowercase;
import de.usd.cstchef.operations.string.Concatenate;
import de.usd.cstchef.operations.utils.Counter;
import de.usd.cstchef.operations.utils.GetVariable;
import de.usd.cstchef.operations.utils.NoOperation;
import de.usd.cstchef.operations.utils.RandomNumber;
import de.usd.cstchef.operations.utils.RandomUUID;
import de.usd.cstchef.operations.utils.SetIfEmpty;
import de.usd.cstchef.operations.utils.StoreVariable;
import de.usd.cstchef.view.View;
import de.usd.cstchef.view.filter.FilterState.BurpOperation;

public class Utils {

    public static CstcObjectFactory factory = new BurpObjectFactory();

    public static double parseNumber(String in) {
        // TODO hex values??
        return Double.valueOf(in);
    }

    public static String replaceVariables(String text) {
        HashMap<String, ByteArray> variables = VariableStore.getInstance().getVariables();
        for (Entry<String, ByteArray> entry : variables.entrySet()) {
            // TODO this is easy, but very bad, how to do this right?
            text = text.replace("$" + entry.getKey(), entry.getValue().toString());
        }

        return text;
    }

    public static ByteArray replaceVariablesByte(ByteArray bytes) {
        HashMap<String, ByteArray> variables = VariableStore.getInstance().getVariables();
        MontoyaApi api = BurpUtils.getInstance().getApi();

        ByteArray currentKey;
        for (Entry<String, ByteArray> entry : variables.entrySet()) {

            int offset = 0;
            currentKey = ByteArray.byteArray("$" + entry.getKey());

            while (offset >= 0) {
                offset = api.utilities().byteUtils().indexOf(bytes.getBytes(), currentKey.getBytes(), true, offset,
                        bytes.length());
                if (offset >= 0)
                    bytes = insertAtOffset(bytes, offset, offset + currentKey.length(), entry.getValue());
            }
        }
        return bytes;
    }

    public static ByteArray httpRequestCookieExtractor(HttpRequest request, String cookieName){
        String cookies = request.headerValue("Cookie");
        //return ByteArray.byteArray(cookieExtractor(cookies, cookieName));
        return factory.createByteArray(cookieExtractor(cookies, cookieName));
    }

    private static String cookieExtractor(String cookies, String cookieName) {
        String[] splitCookies = cookies.split("\\s*;\\s*");
        for(String sC : splitCookies){
            String[] separateCookie = sC.split("=");
            if(separateCookie[0].equals(cookieName)){
                return separateCookie[1];
            }
        }
        throw new IllegalArgumentException("Parameter name not found.");
    }

    public static HttpRequest addCookieToHttpRequest(HttpRequest request, Cookie cookie){
        String cookies = request.headerValue("Cookie");
        if(cookies.contains(cookie.name())){
            cookies = cookies.replace(cookie.name() + "=" + cookieExtractor(cookies, cookie.name()), cookie.toString());
        }
        else{
            cookies += "; " + cookie.toString();
        }
        return request.withUpdatedHeader(HttpHeader.httpHeader("Cookie", cookies));
    }

    public static ByteArray insertAtOffset(ByteArray input, int start, int end, ByteArray newValue) {
        ByteArray prefix = input.subArray(0, start);
        ByteArray rest = input.subArray(0, 0);
        if(end < input.length()) {
            rest = input.subArray(end, input.length());
        }
        
        ByteArray output = prefix.withAppended(newValue).withAppended(rest);
        return output;
    }

    public static ByteArray jsonSetter(ByteArray input, String key, String value, boolean addIfNotPresent, String path){
        DocumentContext document = JsonPath.parse(input.toString());

            try {
                document.read(key);
            } catch (Exception e) {

                if (!addIfNotPresent)
                    throw new IllegalArgumentException("Key not found.");

                String insertPath = path;
                if (insertPath.equals("Insert-Path") || insertPath.equals(""))
                    insertPath = "$";

                try {
                    document = document.put(insertPath, key, value);
                    return  ByteArray.byteArray(document.jsonString());
                } catch (Exception ex) {
                    throw new IllegalArgumentException("Could not parse JSON from input");
                }
            }

            document.set(key, value);
            return ByteArray.byteArray(document.jsonString());
    }

    public static Class<? extends Operation>[] getOperationsBurp() {
        ZipInputStream zip = null;
        List<Class<? extends Operation>> operations = new ArrayList<Class<? extends Operation>>();

        try {
            File f = new File(View.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            zip = new ZipInputStream(new FileInputStream(f.getAbsolutePath()));
            for (ZipEntry entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                if (entry.isDirectory() || !entry.getName().endsWith(".class")) {
                    continue;
                }

                String className = entry.getName().replace('/', '.');
                className = className.substring(0, className.length() - ".class".length());
                if (!className.contains("de.usd.operations")) {
                    continue;
                }

                Class cls = Class.forName(className);
                if (Operation.class.isAssignableFrom(cls)) {
                    Logger.getInstance().log(cls.toString());
                    operations.add(cls);
                }
            }
        } catch (URISyntaxException e) {
        } catch (ClassNotFoundException e) {
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        } finally {
            try {
                zip.close();
            } catch (IOException e) {
            }
        }

        return operations.toArray(new Class[operations.size()]);
    }

    // TODO reflection does not work in Burp Suite
    @SuppressWarnings("unchecked")
    public static Class<? extends Operation>[] getOperationsDevOutgoingFormatting() {
        return new Class[] {
                Addition.class, AddKey.class, AesDecryption.class, AesEncryption.class, And.class,
                Blake.class, Counter.class, DateTime.class, Deflate.class, DesDecryption.class, DesEncryption.class,
                Divide.class, DivideList.class, DSTU7564.class, FromBase64.class, FromHex.class,
                GetRequestBuilder.class,
                GetVariable.class, Gost.class, GUnzip.class, Gzip.class, Hmac.class,
                HttpBodyExtractor.class, HttpCookieExtractor.class, HttpGetExtractor.class,
                HttpGetSetter.class, HttpHeaderExtractor.class, HttpHeaderSetter.class,
                HttpJsonExtractor.class, HttpJsonSetter.class, HttpMethodExtractor.class, HttpMultipartExtractor.class,
                HttpMultipartSetter.class,
                HttpPostExtractor.class, HttpPostSetter.class, PlainRequest.class, HttpSetBody.class,
                HttpSetCookie.class, HttpSetUri.class, HttpUriExtractor.class, HttpXmlExtractor.class,
                HttpXmlSetter.class, HtmlEncode.class, HtmlDecode.class, Inflate.class,
                JsonExtractor.class, JsonSetter.class, JWTDecode.class, JWTSign.class, Length.class,
                LineExtractor.class,
                LineSetter.class, MD2.class, MD4.class, MD5.class, Mean.class, Median.class,
                Multiply.class, MultiplyList.class, NoOperation.class, NumberCompare.class, Prefix.class,
                RandomNumber.class, RandomUUID.class, ReadFile.class, RegexExtractor.class, Reverse.class,
                Replace.class,
                RIPEMD.class, RsaDecryption.class, RsaEncryption.class, RsaSignature.class, SM2Signature.class, SM3.class, SM4Encryption.class, SM4Decryption.class, RegexMatch.class,
                SetIfEmpty.class, SHA1.class, SHA2.class, SHA3.class, Skein.class, SplitAndSelect.class,
                StaticString.class, StoreVariable.class, Sub.class, Substring.class, Uppercase.class, Lowercase.class,
                Subtraction.class,
                Suffix.class, Sum.class, StringContains.class, StringMatch.class, Tiger.class,
                TimestampOffset.class, TimestampToDateTime.class, ToBase64.class, ToHex.class, UnixTimestamp.class,
                UrlDecode.class, UrlEncode.class,
                Whirlpool.class, WriteFile.class, XmlFullSignature.class, XmlMultiSignature.class,
                Xor.class, SoapMultiSignature.class, Luhn.class, Concatenate.class, JsonBeautifier.class
        };
    }

    // TODO reflection does not work in Burp Suite
    @SuppressWarnings("unchecked")
    public static Class<? extends Operation>[] getOperationsDevIncoming() {
        return new Class[] {
                Addition.class, AddKey.class, AesDecryption.class, AesEncryption.class, And.class,
                Blake.class, Counter.class, DateTime.class, Deflate.class, DesDecryption.class, DesEncryption.class,
                Divide.class, DivideList.class, DSTU7564.class, FromBase64.class, FromHex.class, GetRequestBuilder.class,
                GetVariable.class, Gost.class, GUnzip.class, Gzip.class, Hmac.class, HttpBodyExtractor.class, 
                HttpCookieExtractor.class, HttpHeaderExtractor.class, HttpHeaderSetter.class, HttpJsonExtractor.class,
                HttpJsonSetter.class, HttpMultipartExtractor.class, HttpMultipartSetter.class, PlainRequest.class,
                HttpSetBody.class, HttpSetCookie.class, HttpXmlExtractor.class, HttpXmlSetter.class, HtmlEncode.class,
                HtmlDecode.class, Inflate.class, JsonExtractor.class, JsonSetter.class, JWTDecode.class, JWTSign.class,
                Length.class, LineExtractor.class, LineSetter.class, MD2.class, MD4.class, MD5.class, Mean.class, Median.class,
                Multiply.class, MultiplyList.class, NoOperation.class, NumberCompare.class, Prefix.class, RandomNumber.class,
                RandomUUID.class, ReadFile.class, RegexExtractor.class, Reverse.class, Replace.class,
                RIPEMD.class, RsaDecryption.class, RsaEncryption.class, RsaSignature.class, SM2Signature.class, SM3.class,
                SM4Encryption.class, SM4Decryption.class, RegexMatch.class, SetIfEmpty.class, SHA1.class, SHA2.class,
                SHA3.class, Skein.class, SplitAndSelect.class, StaticString.class, StoreVariable.class, Sub.class, Substring.class,
                Uppercase.class, Lowercase.class, Subtraction.class, Suffix.class, Sum.class, StringContains.class,
                StringMatch.class, Tiger.class, TimestampOffset.class, TimestampToDateTime.class, ToBase64.class, ToHex.class,
                UnixTimestamp.class, UrlDecode.class, UrlEncode.class, Whirlpool.class, WriteFile.class, XmlFullSignature.class,
                XmlMultiSignature.class, Xor.class, SoapMultiSignature.class, Luhn.class, Concatenate.class, JsonBeautifier.class
        };
    }

    public static Class<? extends Operation>[] getOperations(BurpOperation operation) {
        //return BurpUtils.inBurp() ? Utils.getOperationsDev() : Utils.getOperationsDev();
        if(operation == BurpOperation.INCOMING) {
            return getOperationsDevIncoming();
        }
        else {
            return getOperationsDevOutgoingFormatting();
        }
    }

    public enum MessageType {
        REQUEST,
        RESPONSE,
        RAW
    }
    
    public static class CSTCCookie implements Cookie{
        private String name;
        private String value;

        public CSTCCookie(String cookieName, String cookieValue){
            this.name = cookieName;
            this.value = cookieValue;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public String value() {
            return value;
        }

        @Override
        public String domain() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'domain'");
        }

        @Override
        public String path() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'path'");
        }

        @Override
        public Optional<ZonedDateTime> expiration() {
            // TODO Auto-generated method stub
            throw new UnsupportedOperationException("Unimplemented method 'expiration'");
        }

        public String toString(){
            return name() + "=" + value();
        }
    }

}
