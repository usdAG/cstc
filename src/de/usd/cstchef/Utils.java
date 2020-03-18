package de.usd.cstchef;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import burp.BurpUtils;
import burp.Logger;
import de.usd.cstchef.operations.Operation;
import de.usd.cstchef.operations.arithmetic.Addition;
import de.usd.cstchef.operations.arithmetic.DivideList;
import de.usd.cstchef.operations.arithmetic.Mean;
import de.usd.cstchef.operations.arithmetic.Median;
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
import de.usd.cstchef.operations.dataformat.FromBase64;
import de.usd.cstchef.operations.dataformat.FromHex;
import de.usd.cstchef.operations.dataformat.ToBase64;
import de.usd.cstchef.operations.dataformat.ToHex;
import de.usd.cstchef.operations.dataformat.UrlDecode;
import de.usd.cstchef.operations.dataformat.UrlEncode;
import de.usd.cstchef.operations.datetime.DateTime;
import de.usd.cstchef.operations.datetime.UnixTimestamp;
import de.usd.cstchef.operations.encrpytion.AesDecryption;
import de.usd.cstchef.operations.encrpytion.AesEncryption;
import de.usd.cstchef.operations.encrpytion.DesDecryption;
import de.usd.cstchef.operations.encrpytion.DesEncryption;
import de.usd.cstchef.operations.extractors.HttpBodyExtractor;
import de.usd.cstchef.operations.extractors.HttpGetExtractor;
import de.usd.cstchef.operations.extractors.HttpHeaderExtractor;
import de.usd.cstchef.operations.extractors.HttpMethodExtractor;
import de.usd.cstchef.operations.extractors.HttpPostExtractor;
import de.usd.cstchef.operations.extractors.HttpUriExtractor;
import de.usd.cstchef.operations.extractors.JsonExtractor;
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
import de.usd.cstchef.operations.setter.GetSetter;
import de.usd.cstchef.operations.setter.HttpSetUri;
import de.usd.cstchef.operations.setter.HttpSetBody;
import de.usd.cstchef.operations.signature.XmlFullSignature;
import de.usd.cstchef.operations.signature.XmlMultiSignature;
import de.usd.cstchef.operations.string.Length;
import de.usd.cstchef.operations.string.Prefix;
import de.usd.cstchef.operations.string.Replace;
import de.usd.cstchef.operations.string.StaticString;
import de.usd.cstchef.operations.string.Substring;
import de.usd.cstchef.operations.string.Suffix;
import de.usd.cstchef.operations.utils.GetVariable;
import de.usd.cstchef.operations.utils.StoreVariable;
import de.usd.cstchef.view.View;

public class Utils {

	// TODO find a better way to do this
	

	public static HashMap<String, String> delimiters = new HashMap<String, String>() {
		{
			put("Comma", ",");
			put("Space", " ");
			put("Line feed", "\n");
			put("Colon", ":");
			put("CLRF", "\r\n");
			put("Semi-colon", ";");
		}
	};

	public static double parseNumber(String in) {
		// TODO hex values??
		return Double.valueOf(in);
	}

	public static String replaceVariables(String text) {
		HashMap<String, byte[]> variables = VariableStore.getInstance().getVariables();
		for (Entry<String, byte[]> entry : variables.entrySet()) {
			// TODO this is easy, but very bad, how to do this right?
			text = text.replaceAll("§" + entry.getKey(), new String(entry.getValue()));
		}

		return text;
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
		return new Class[] { RegexExtractor.class, WriteFile.class, ReadFile.class, Length.class, UrlDecode.class, UrlEncode.class,
				HTTPRequest.class, SHA1.class, Hmac.class, Gost.class, Median.class, RIPEMD.class, DesDecryption.class,
				MultiplyList.class, Skein.class, StoreVariable.class, JsonExtractor.class, Sum.class, GetVariable.class,
				HttpUriExtractor.class, HttpBodyExtractor.class, HttpPostExtractor.class,
				HttpGetExtractor.class, Sub.class, Replace.class, DivideList.class, ToHex.class, FromHex.class, MD5.class,
				AesDecryption.class, Suffix.class, SHA2.class, Prefix.class, MD4.class, Whirlpool.class,
				StaticString.class, AddKey.class, FromBase64.class, DSTU7564.class, Substring.class, ToBase64.class,
				SHA3.class, HttpMethodExtractor.class, MD2.class, Blake.class, AesEncryption.class,
				Tiger.class, DesEncryption.class, HttpHeaderExtractor.class, And.class, Mean.class,
				XmlFullSignature.class, XmlMultiSignature.class, HttpSetBody.class,
				DateTime.class, Addition.class, Subtraction.class, GetSetter.class,
				Deflate.class, Inflate.class, Gzip.class, GUnzip.class, UnixTimestamp.class, Xor.class, HttpSetUri.class };
	}

	public static Class<? extends Operation>[] getOperations() {
		return BurpUtils.inBurp() ? Utils.getOperationsDev() : Utils.getOperationsDev();
	}

}
