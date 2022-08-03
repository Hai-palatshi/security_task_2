package il.ac.kinneret.mjmay.hls.hlsjava.model;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
/**
 * Class to perform encryption and decryption operations of messages and files
 * @authors Sasha Chernin & Hai Palatshi
 */
public class Encryption {

    public static SecretKey secretKey;
    public static SecretKey macKey;

    public static final int GCM_TAG_LENGTH = 16;

    static {
        try {
            secretKey = retrieveSecretKey();
            macKey = retrieveMACKey();
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Retrieves password from config file and transforms it into a sha256 digest to use as a key
     * @return SecretKeySpec object that is initialized with the sha256 version of the password
     */
    public static SecretKey retrieveSecretKey() throws NoSuchAlgorithmException, IOException {
        FileReader file = new FileReader("Config");
        BufferedReader buffer = new BufferedReader(file);
        //read the 1st line
        String keyText = buffer.readLine();
        System.out.println(keyText);

        // String to bytes array
        byte[] arr = keyText.getBytes(StandardCharsets.UTF_8);
        // bytes array to sha-256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return new SecretKeySpec(digest.digest(arr), 0, digest.digest(arr).length, "AES");
    }

    /**
     * Retrieves MAC password from config file and transforms it into a sha256 digest to use as a key
     * @return SecretKeySpec object that is initialized with the sha256 version of the password
     */
    public static SecretKey retrieveMACKey() throws NoSuchAlgorithmException, IOException {
        //read the 2nd line
        String macText = Files.readAllLines(Paths.get("Config")).get(1);
        System.out.println(macText);

        // String to bytes array
        byte[] arr = macText.getBytes(StandardCharsets.UTF_8);
        // bytes array to sha-256 hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return new SecretKeySpec(digest.digest(arr), 0, digest.digest(arr).length, "AES");
    }

    /**
     * Encrypts string in AES-CBC mode
     * @param value The string that is being encrypted
     * @return The encrypted string
     */
    public static String encryptMessage(String value) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

            // generate iv
            SecureRandom randomSecureRandom = new SecureRandom();
            byte[] iv = new byte[cipher.getBlockSize()];
            randomSecureRandom.nextBytes(iv);
            IvParameterSpec ivParams = new IvParameterSpec(iv);

            LoggerFile.getInstance().info("The random iv before encryption: "+bytesToHex(ivParams.getIV()));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

            // preform encryption in the message
            byte[] encrypted = cipher.doFinal(value.getBytes());

            // create output stream that will contain iv + enc data
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            // write iv to the first 16 bytes of output array
            output.write(ivParams.getIV());
            // write the encrypted message to the output array
            output.write(encrypted);

            // calc hmac
            byte[] macSignature = calcHMACSignature(output.toByteArray());
            LoggerFile.getInstance().info("calculated MAC: "+ bytesToHex(macSignature));


            // create new output that will contain mac signature, iv, enc data and write to it.
            ByteArrayOutputStream outputWithSignature = new ByteArrayOutputStream();
            outputWithSignature.write(macSignature);
            outputWithSignature.write(ivParams.getIV());
            outputWithSignature.write(encrypted);

            // convert output array to bytes array and return it
            byte[] out = outputWithSignature.toByteArray();

            return Base64.getEncoder().encodeToString(out);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    /**
     * Decrypts string in AES-CBC mode and check MAC signature
     * @param encrypted The string that is being decrypted
     * @return The decrypted string
     */
    public static String decryptMessage(String encrypted) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {

        byte[] StrToDecrypt = Base64.getDecoder().decode(encrypted);

        byte[] strToEnc = Arrays.copyOfRange(StrToDecrypt, 48, StrToDecrypt.length);

        // received string without mac
        byte[] checkMAC = Arrays.copyOfRange(StrToDecrypt, 32, StrToDecrypt.length);

        // received mac
        byte[] macSignature = Arrays.copyOfRange(StrToDecrypt, 0, 32);
        LoggerFile.getInstance().info("received MAC: "+ bytesToHex(macSignature));


        if (Arrays.equals(macSignature, calcHMACSignature(checkMAC))) {
            System.out.println("all is good! continue");
            LoggerFile.getInstance().info("HMAC value was correct!. proceeding decryption");
        }
        else {
            LoggerFile.getInstance().info("HMAC value is wrong. Can't decrypt");
            return "WRONGMAC";
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey,
                new IvParameterSpec(StrToDecrypt, 32, 16));

        LoggerFile.getInstance().info("The iv before decryption: " + bytesToHex(cipher.getIV()));

        byte[] original = cipher.doFinal(strToEnc);

        return new String(original);


    }

    /**
     * Encrypts file in AES-CTR mode
     * @param originalFile The full path of the file including the file name
     * @param fileName The full path of the target file including the file name
     */
    public static void encryptFile(String originalFile ,String fileName) throws NoSuchPaddingException, NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidAlgorithmParameterException {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        // generate iv
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        System.out.println("the iv is: "+ bytesToHex(ivParams.getIV()));

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivParams.getIV());
        LoggerFile.getInstance().info("The random iv before encryption: "+bytesToHex(ivParams.getIV()));

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] array = Files.readAllBytes(Paths.get(originalFile));

        try (FileOutputStream fileOut = new FileOutputStream(fileName);
             CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {
            fileOut.write(gcmParameterSpec.getIV());
            cipherOut.write(array);

        }
    }

    /**
     * Decrypts file in AES-CTR mode
     * @param fileName The full path of the file including the file name
     * @param decName The full path of the target file including the file name
     */
    public static void decryptFile(String fileName, String decName) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] array = Files.readAllBytes(Paths.get(fileName));
        byte[] withoutIV = Arrays.copyOfRange(array, 16, array.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        try (FileInputStream fileIn = new FileInputStream(fileName)) {
            byte[] fileIv = new byte[16];
            fileIn.read(fileIv);
            System.out.println("the iv is: "+ bytesToHex(fileIv));

            // Create GCMParameterSpec
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, fileIv);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);
            LoggerFile.getInstance().info("The iv before decryption: "+bytesToHex(cipher.getIV()));

            try (FileOutputStream fileOut = new FileOutputStream(decName);
                 CipherOutputStream cipherOut = new CipherOutputStream(fileOut, cipher)) {
                cipherOut.write(withoutIV);
            }

        } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
            LoggerFile.getInstance().info("Can't decrypt file: "+ decName);
        }
    }

    /**
     * Calculates MAC digest from a given bytes array
     * @param data The bytes array that should contain iv+encrypted message
     */
    public static byte[] calcHMACSignature(byte[] data)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        return mac.doFinal(data);
    }

    /**
     * Transforms bytes array to hex. returns string.
     * @param bytes The bytes array that is being transformed.
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte hashByte : bytes) {
            int intVal = 0xff & hashByte;
            if (intVal < 0x10) {
                sb.append('0');
            }
            sb.append(Integer.toHexString(intVal));
        }
        return sb.toString();
    }

}
