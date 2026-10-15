package de.usd.cstchef.operations.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

public final class PgpUtils {

    public static final String PROVIDER = "BC";

    static {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private PgpUtils() {
    }

    public static int encryptionAlgorithmForName(String name) {
        if ("AES-128".equals(name)) {
            return PGPEncryptedData.AES_128;
        }
        if ("AES-192".equals(name)) {
            return PGPEncryptedData.AES_192;
        }
        return PGPEncryptedData.AES_256;
    }

    public static int hashAlgorithmForName(String name) {
        if ("SHA-1".equals(name)) {
            return HashAlgorithmTags.SHA1;
        }
        if ("SHA-224".equals(name)) {
            return HashAlgorithmTags.SHA224;
        }
        if ("SHA-384".equals(name)) {
            return HashAlgorithmTags.SHA384;
        }
        if ("SHA-512".equals(name)) {
            return HashAlgorithmTags.SHA512;
        }
        return HashAlgorithmTags.SHA256;
    }

    public static byte[] encrypt(byte[] input, String publicKeyText, int encryptionAlgorithm, boolean asciiArmor,
            boolean integrityPacket) throws Exception {
        PGPPublicKey publicKey = readEncryptionPublicKey(publicKeyText);
        byte[] literalData = toCompressedLiteralData(input);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        OutputStream finalOutput = asciiArmor ? new ArmoredOutputStream(output) : output;

        PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(encryptionAlgorithm)
                        .setWithIntegrityPacket(integrityPacket)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(PROVIDER));
        generator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider(PROVIDER));

        try (OutputStream encryptedStream = generator.open(finalOutput, literalData.length)) {
            encryptedStream.write(literalData);
        }

        finalOutput.close();
        return output.toByteArray();
    }

    public static byte[] decrypt(byte[] input, String privateKeyText, char[] passphrase) throws Exception {
        PGPSecretKeyRingCollection secretKeys = readSecretKeys(privateKeyText);

        InputStream decoderStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(input));
        PGPObjectFactory objectFactory = new JcaPGPObjectFactory(decoderStream);
        Object object = objectFactory.nextObject();
        PGPEncryptedDataList encryptedDataList;

        if (object instanceof PGPEncryptedDataList) {
            encryptedDataList = (PGPEncryptedDataList) object;
        } else {
            encryptedDataList = (PGPEncryptedDataList) objectFactory.nextObject();
        }

        if (encryptedDataList == null) {
            throw new IllegalArgumentException("Input is not a valid PGP encrypted message.");
        }

        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
        PGPPrivateKey privateKey = null;

        Iterator<?> encryptedData = encryptedDataList.getEncryptedDataObjects();
        while (encryptedData.hasNext()) {
            PGPPublicKeyEncryptedData current = (PGPPublicKeyEncryptedData) encryptedData.next();
            PGPSecretKey secretKey = secretKeys.getSecretKey(current.getKeyID());
            if (secretKey != null) {
                privateKey = extractPrivateKey(secretKey, passphrase);
                publicKeyEncryptedData = current;
                break;
            }
        }

        if (privateKey == null || publicKeyEncryptedData == null) {
            throw new IllegalArgumentException("No matching private PGP key found for the encrypted message.");
        }

        InputStream clear = publicKeyEncryptedData
                .getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(PROVIDER).build(privateKey));
        PGPObjectFactory plainFactory = new JcaPGPObjectFactory(clear);
        Object message = nextMeaningfulObject(plainFactory);

        byte[] result;
        if (message instanceof PGPLiteralData literalData) {
            result = readAll(literalData.getInputStream());
        } else {
            throw new IllegalArgumentException("Unsupported PGP message format.");
        }

        if (publicKeyEncryptedData.isIntegrityProtected() && !publicKeyEncryptedData.verify()) {
            throw new IllegalArgumentException("PGP integrity check failed.");
        }

        return result;
    }

    public static byte[] signDetached(byte[] input, String privateKeyText, char[] passphrase, int hashAlgorithm,
            boolean asciiArmor) throws Exception {
        PGPSecretKey secretKey = readSigningSecretKey(privateKeyText);
        PGPPrivateKey privateKey = extractPrivateKey(secretKey, passphrase);

        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), hashAlgorithm)
                        .setProvider(PROVIDER));
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        signatureGenerator.update(input);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        OutputStream finalOutput = asciiArmor ? new ArmoredOutputStream(output) : output;
        signatureGenerator.generate().encode(finalOutput);
        finalOutput.close();
        return output.toByteArray();
    }

    public static boolean verifyDetached(byte[] input, byte[] signatureBytes, String publicKeyText) throws Exception {
        PGPPublicKeyRingCollection publicKeys = readPublicKeys(publicKeyText);

        InputStream decoderStream = PGPUtil.getDecoderStream(new ByteArrayInputStream(signatureBytes));
        PGPObjectFactory objectFactory = new JcaPGPObjectFactory(decoderStream);
        Object object = nextMeaningfulObject(objectFactory);
        if (!(object instanceof PGPSignatureList signatureList) || signatureList.size() == 0) {
            throw new IllegalArgumentException("Input is not a valid detached PGP signature.");
        }

        PGPSignature signature = signatureList.get(0);
        PGPPublicKey publicKey = publicKeys.getPublicKey(signature.getKeyID());
        if (publicKey == null) {
            throw new IllegalArgumentException("No matching public PGP key found for the signature.");
        }

        signature.init(new JcaPGPContentVerifierBuilderProvider().setProvider(PROVIDER), publicKey);
        signature.update(input);
        return signature.verify();
    }

    public static PGPPublicKey readEncryptionPublicKey(String publicKeyText) throws Exception {
        PGPPublicKeyRingCollection publicKeys = readPublicKeys(publicKeyText);
        Iterator<PGPPublicKeyRing> keyRings = publicKeys.getKeyRings();
        while (keyRings.hasNext()) {
            Iterator<PGPPublicKey> keys = keyRings.next().getPublicKeys();
            while (keys.hasNext()) {
                PGPPublicKey key = keys.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("No PGP public encryption key found.");
    }

    public static PGPSecretKey readSigningSecretKey(String privateKeyText) throws Exception {
        PGPSecretKeyRingCollection secretKeys = readSecretKeys(privateKeyText);
        Iterator<PGPSecretKeyRing> keyRings = secretKeys.getKeyRings();
        while (keyRings.hasNext()) {
            Iterator<PGPSecretKey> keys = keyRings.next().getSecretKeys();
            while (keys.hasNext()) {
                PGPSecretKey key = keys.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("No PGP private signing key found.");
    }

    public static PGPPublicKeyRingCollection readPublicKeys(String publicKeyText) throws IOException, PGPException {
        return new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(publicKeyText.getBytes(StandardCharsets.UTF_8))),
                new JcaKeyFingerprintCalculator());
    }

    public static PGPSecretKeyRingCollection readSecretKeys(String privateKeyText) throws IOException, PGPException {
        return new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(new ByteArrayInputStream(privateKeyText.getBytes(StandardCharsets.UTF_8))),
                new JcaKeyFingerprintCalculator());
    }

    private static PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey, char[] passphrase) throws Exception {
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder().setProvider(PROVIDER)
                .build(passphrase == null ? new char[0] : passphrase);
        return secretKey.extractPrivateKey(decryptor);
    }

    private static byte[] toCompressedLiteralData(byte[] input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        try (OutputStream compressedOutput = compressedDataGenerator.open(output)) {
            PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
            try (OutputStream literalOutput = literalDataGenerator.open(compressedOutput, PGPLiteralData.BINARY,
                    PGPLiteralData.CONSOLE, input.length, new Date())) {
                literalOutput.write(input);
            }
        } finally {
            compressedDataGenerator.close();
        }
        return output.toByteArray();
    }

    private static Object nextMeaningfulObject(PGPObjectFactory objectFactory) throws IOException, PGPException {
        Object object = objectFactory.nextObject();
        while (object instanceof PGPCompressedData compressedData) {
            objectFactory = new JcaPGPObjectFactory(compressedData.getDataStream());
            object = objectFactory.nextObject();
        }
        return object;
    }

    private static byte[] readAll(InputStream inputStream) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = inputStream.read(buffer)) != -1) {
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }
}