package de.usd.cstchef;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.StringWriter;
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

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

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
import de.usd.cstchef.operations.misc.RequestBuilder;
import de.usd.cstchef.operations.misc.ReadFile;
import de.usd.cstchef.operations.misc.WriteFile;
import de.usd.cstchef.operations.networking.PlainRequest;
import de.usd.cstchef.operations.setter.HttpHeaderRemove;
import de.usd.cstchef.operations.setter.HttpGetSetter;
import de.usd.cstchef.operations.setter.HttpHeaderSetter;
import de.usd.cstchef.operations.setter.HttpJsonSetter;
import de.usd.cstchef.operations.setter.HttpMultipartSetter;
import de.usd.cstchef.operations.setter.HttpPostSetter;
import de.usd.cstchef.operations.setter.HttpSetBody;
import de.usd.cstchef.operations.setter.HttpSetCookie;
import de.usd.cstchef.operations.setter.HttpSetUri;
import de.usd.cstchef.operations.setter.HttpXmlSetter;
import de.usd.cstchef.operations.setter.XmlSetter;
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
import de.usd.cstchef.operations.string.Strip;
import de.usd.cstchef.operations.string.RemoveWhitespace;
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

    public static ByteArray xmlSetter(ByteArray input, String path, String value, boolean addIfNotPresent) throws Exception {

        if(path.trim().isEmpty()) {
            return input;
        }

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // XXE prevention as per https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        Document doc = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(input.getBytes()));
        doc.getDocumentElement().normalize();

        Element toAdd;

        XPath xPath = XPathFactory.newInstance().newXPath();
        NodeList nodeList;

        Node disableEscaping = doc.createProcessingInstruction(StreamResult.PI_DISABLE_OUTPUT_ESCAPING, "&");
        // make sure disableEscaping is always the first child of the document element so the whole doc is escaped
        doc.getDocumentElement().getParentNode().insertBefore(disableEscaping, doc.getDocumentElement().getParentNode().getFirstChild());

        try {
            nodeList = (NodeList) xPath.compile(path).evaluate(doc, XPathConstants.NODESET);
        }
        catch(Exception e) {
            throw new IllegalArgumentException("Invalid XPath Syntax.");
        }

        for(int i = 0; i < nodeList.getLength(); i++) {
            nodeList.item(i).setTextContent(value);
        }

        if(nodeList.getLength() == 0 && addIfNotPresent) {
            if(path.matches(".*/@[a-zA-Z0-9-_.]*")) {
                nodeList = (NodeList) xPath.compile(path.replaceAll("/@[a-zA-Z0-9-_.]*$", "")).evaluate(doc, XPathConstants.NODESET);
                for(int i = 0; i < nodeList.getLength(); i++) {
                    ((Element) nodeList.item(i)).setAttribute(path.split("@")[path.split("@").length - 1], value);
                }
            }
            else {
                nodeList = (NodeList) xPath.compile(path.replaceAll("/[a-zA-Z0-9-_.]*$", "")).evaluate(doc, XPathConstants.NODESET);
                for(int i = 0; i < nodeList.getLength(); i++) {
                    toAdd = doc.createElement(path.split("/")[path.split("/").length - 1]);
                    toAdd.setTextContent(value);
                    nodeList.item(i).appendChild(toAdd);
                }
            }
        }

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        // XXE prevention
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");

        Transformer xformer = transformerFactory.newTransformer();
        xformer.setOutputProperty(OutputKeys.INDENT, "no");
        xformer.setOutputProperty(OutputKeys.DOCTYPE_PUBLIC, "yes");

        StringWriter output = new StringWriter();
        xformer.transform(new DOMSource(doc), new StreamResult(output));
        return ByteArray.byteArray(output.toString());
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
                RequestBuilder.class,
                GetVariable.class, Gost.class, GUnzip.class, Gzip.class, Hmac.class,
                HttpBodyExtractor.class, HttpCookieExtractor.class, HttpGetExtractor.class,
                HttpGetSetter.class, HttpHeaderExtractor.class, HttpHeaderSetter.class, HttpHeaderRemove.class,
                HttpJsonExtractor.class, HttpJsonSetter.class, HttpMethodExtractor.class, HttpMultipartExtractor.class,
                HttpMultipartSetter.class,
                HttpPostExtractor.class, HttpPostSetter.class, PlainRequest.class, HttpSetBody.class,
                HttpSetCookie.class, HttpSetUri.class, HttpUriExtractor.class, HttpXmlExtractor.class,
                HttpXmlSetter.class, XmlSetter.class, HtmlEncode.class, HtmlDecode.class, Inflate.class,
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
                Suffix.class, Sum.class, StringContains.class, StringMatch.class, Strip.class, RemoveWhitespace.class, Tiger.class,
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
                Divide.class, DivideList.class, DSTU7564.class, FromBase64.class, FromHex.class, RequestBuilder.class,
                GetVariable.class, Gost.class, GUnzip.class, Gzip.class, Hmac.class, HttpBodyExtractor.class, 
                HttpCookieExtractor.class, HttpHeaderExtractor.class, HttpHeaderSetter.class, HttpHeaderRemove.class, HttpJsonExtractor.class,
                HttpJsonSetter.class, HttpMultipartExtractor.class, HttpMultipartSetter.class, PlainRequest.class,
                HttpSetBody.class, HttpSetCookie.class, HttpXmlExtractor.class, HttpXmlSetter.class, XmlSetter.class, HtmlEncode.class,
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
