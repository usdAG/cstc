package de.usd.cstchef;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;

import burp.BurpUtils;
import burp.BurpObjectFactory;
import burp.CstcObjectFactory;
import burp.Logger;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.arithmetic.*;
import de.usd.cstchef.operations.byteoperation.*;
import de.usd.cstchef.operations.compression.*;
import de.usd.cstchef.operations.conditional.*;
import de.usd.cstchef.operations.dataformat.*;
import de.usd.cstchef.operations.datetime.*;
import de.usd.cstchef.operations.encryption.*;
import de.usd.cstchef.operations.extractors.*;
import de.usd.cstchef.operations.hashing.*;
import de.usd.cstchef.operations.misc.*;
import de.usd.cstchef.operations.networking.PlainRequest;
import de.usd.cstchef.operations.setter.*;
import de.usd.cstchef.operations.signature.*;
import de.usd.cstchef.operations.string.*;
import de.usd.cstchef.operations.utils.*;
import de.usd.cstchef.view.View;

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
        ByteArray prefix = BurpUtils.subArray(input, 0, start);
        ByteArray rest = BurpUtils.subArray(input, end, input.length());
        
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
    public static Class<? extends Operation>[] getOperationsDev() {
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
                Xor.class, SoapMultiSignature.class, Luhn.class, Concatenate.class, JsonFormating.class
        };
    }

    public static Class<? extends Operation>[] getOperations() {
        return BurpUtils.inBurp() ? Utils.getOperationsDev() : Utils.getOperationsDev();
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
