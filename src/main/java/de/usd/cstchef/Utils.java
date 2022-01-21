package de.usd.cstchef;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import burp.BurpUtils;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.Logger;
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
import de.usd.cstchef.operations.dataformat.FromHex;
import de.usd.cstchef.operations.dataformat.HtmlDecode;
import de.usd.cstchef.operations.dataformat.HtmlEncode;
import de.usd.cstchef.operations.dataformat.ToBase64;
import de.usd.cstchef.operations.dataformat.ToHex;
import de.usd.cstchef.operations.dataformat.UrlDecode;
import de.usd.cstchef.operations.dataformat.UrlEncode;
import de.usd.cstchef.operations.datetime.DateTime;
import de.usd.cstchef.operations.datetime.UnixTimestamp;
import de.usd.cstchef.operations.encryption.AesDecryption;
import de.usd.cstchef.operations.encryption.AesEncryption;
import de.usd.cstchef.operations.encryption.DesDecryption;
import de.usd.cstchef.operations.encryption.DesEncryption;
import de.usd.cstchef.operations.encryption.RsaDecryption;
import de.usd.cstchef.operations.encryption.RsaEncryption;
import de.usd.cstchef.operations.extractors.HttpBodyExtractor;
import de.usd.cstchef.operations.extractors.HttpCookieExtractor;
import de.usd.cstchef.operations.extractors.HttpGetExtractor;
import de.usd.cstchef.operations.extractors.HttpHeaderExtractor;
import de.usd.cstchef.operations.extractors.HttpJsonExtractor;
import de.usd.cstchef.operations.extractors.HttpMethodExtractor;
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
import de.usd.cstchef.operations.hashing.Skein;
import de.usd.cstchef.operations.hashing.Tiger;
import de.usd.cstchef.operations.hashing.Whirlpool;
import de.usd.cstchef.operations.misc.ReadFile;
import de.usd.cstchef.operations.misc.WriteFile;
import de.usd.cstchef.operations.networking.HTTPRequest;
import de.usd.cstchef.operations.setter.HttpGetSetter;
import de.usd.cstchef.operations.setter.HttpHeaderSetter;
import de.usd.cstchef.operations.setter.HttpJsonSetter;
import de.usd.cstchef.operations.setter.HttpPostSetter;
import de.usd.cstchef.operations.setter.HttpSetBody;
import de.usd.cstchef.operations.setter.HttpSetCookie;
import de.usd.cstchef.operations.setter.HttpSetUri;
import de.usd.cstchef.operations.setter.HttpXmlSetter;
import de.usd.cstchef.operations.setter.JsonSetter;
import de.usd.cstchef.operations.setter.LineSetter;
import de.usd.cstchef.operations.signature.RsaSignature;
import de.usd.cstchef.operations.signature.SoapMultiSignature;
import de.usd.cstchef.operations.signature.XmlFullSignature;
import de.usd.cstchef.operations.signature.XmlMultiSignature;
import de.usd.cstchef.operations.string.Length;
import de.usd.cstchef.operations.string.Prefix;
import de.usd.cstchef.operations.string.Replace;
import de.usd.cstchef.operations.string.SplitAndSelect;
import de.usd.cstchef.operations.string.StaticString;
import de.usd.cstchef.operations.string.Substring;
import de.usd.cstchef.operations.string.Suffix;
import de.usd.cstchef.operations.utils.GetVariable;
import de.usd.cstchef.operations.utils.NoOperation;
import de.usd.cstchef.operations.utils.RandomNumber;
import de.usd.cstchef.operations.utils.RandomUUID;
import de.usd.cstchef.operations.utils.SetIfEmpty;
import de.usd.cstchef.operations.utils.StoreVariable;
import de.usd.cstchef.view.View;

public class Utils {

    public static double parseNumber(String in) {
        // TODO hex values??
        return Double.valueOf(in);
    }

    public static String replaceVariables(String text) {
        HashMap<String, byte[]> variables = VariableStore.getInstance().getVariables();
        for (Entry<String, byte[]> entry : variables.entrySet()) {
            // TODO this is easy, but very bad, how to do this right?
            text = text.replace("$" + entry.getKey(), new String(entry.getValue()));
        }

        return text;
    }

    public static byte[] replaceVariablesByte(byte[] bytes) {
        HashMap<String, byte[]> variables = VariableStore.getInstance().getVariables();

        IBurpExtenderCallbacks callbacks = BurpUtils.getInstance().getCallbacks();
        IExtensionHelpers helpers = callbacks.getHelpers();

        byte[] currentKey;
        for (Entry<String, byte[]> entry : variables.entrySet()) {

            int offset = 0;
            currentKey = ("$" + entry.getKey()).getBytes();

            while( offset >= 0 ) {
                offset = helpers.indexOf(bytes, currentKey, true, offset, bytes.length);
                if( offset >= 0 )
                    bytes = insertAtOffset(bytes, offset, offset + currentKey.length, entry.getValue());
            }
        }
        return bytes;
    }

    public static byte[] insertAtOffset(byte[] input, int start, int end, byte[] newValue) {
        byte[] prefix = Arrays.copyOfRange(input, 0, start);
        byte[] rest = Arrays.copyOfRange(input, end, input.length);

        byte[] output = new byte[prefix.length + newValue.length + rest.length];
        System.arraycopy(prefix, 0, output, 0, prefix.length);
        System.arraycopy(newValue, 0, output, prefix.length, newValue.length);
        System.arraycopy(rest, 0, output, prefix.length + newValue.length, rest.length);

        return output;
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
            Blake.class, DateTime.class, Deflate.class, DesDecryption.class, DesEncryption.class,
            Divide.class, DivideList.class, DSTU7564.class, FromBase64.class, FromHex.class,
            GetVariable.class, Gost.class, GUnzip.class, Gzip.class, Hmac.class,
            HttpBodyExtractor.class, HttpCookieExtractor.class, HttpGetExtractor.class,
            HttpGetSetter.class, HttpHeaderExtractor.class, HttpHeaderSetter.class,
            HttpJsonExtractor.class, HttpJsonSetter.class, HttpMethodExtractor.class,
            HttpPostExtractor.class, HttpPostSetter.class, HTTPRequest.class, HttpSetBody.class,
            HttpSetCookie.class, HttpSetUri.class, HttpUriExtractor.class, HttpXmlExtractor.class,
            HttpXmlSetter.class, HtmlEncode.class, HtmlDecode.class, Inflate.class,
            JsonExtractor.class, JsonSetter.class, Length.class, LineExtractor.class,
            LineSetter.class, MD2.class, MD4.class, MD5.class, Mean.class, Median.class,
            Multiply.class, MultiplyList.class, NoOperation.class, NumberCompare.class, Prefix.class,
            RandomNumber.class, RandomUUID.class ,ReadFile.class, RegexExtractor.class, Replace.class,
            RIPEMD.class, RsaDecryption.class, RsaEncryption.class, RsaSignature.class, RegexMatch.class,
            SetIfEmpty.class, SHA1.class, SHA2.class, SHA3.class, Skein.class, SplitAndSelect.class,
            StaticString.class, StoreVariable.class, Sub.class, Substring.class, Subtraction.class,
            Suffix.class, Sum.class, StringContains.class, StringMatch.class, Tiger.class,
            ToBase64.class, ToHex.class, UnixTimestamp.class, UrlDecode.class, UrlEncode.class,
            Whirlpool.class, WriteFile.class, XmlFullSignature.class, XmlMultiSignature.class,
            Xor.class, SoapMultiSignature.class
        };
    }

    public static Class<? extends Operation>[] getOperations() {
        return BurpUtils.inBurp() ? Utils.getOperationsDev() : Utils.getOperationsDev();
    }

}
