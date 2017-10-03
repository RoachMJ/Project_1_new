/**
 * Created by Roach + Miller.
 */
import java.io.*;
import java.util.*;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.spec.RSAPrivateKeySpec;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.math.BigInteger;


public class Sender {

    public static void main(String[] args) throws Exception{

        String symKey = readsymKey("symmetric.key");
        PrivateKey privateKeys = readPrivateKey("XPrivate.key");

        Scanner in = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String msg = in.next();
        in.close();

        byte[] PThash = messageDigest(msg);

        System.out.println("digit digest (hash value):");
        toHex(PThash);

        saveToFile("message.dd", PThash);

        byte[] CTHash = encryptRSA(privateKeys,PThash);

        System.out.println("CT Digital Signiture:");
        toHex(CTHash);
        System.out.println("");

        saveToFile("message.dd-msg",CTHash);
        append("message.dd-msg",msg);

        byte[] IV = randomIV();
        saveToFile("IV.byteArray",IV);
        //for debugging
        System.out.println("IV in Hex is :");
        toHex(IV);
        System.out.println("");

        encryptAES(symKey,"message.dd-msg" , "message.aescipher", IV);
    }

    //Start Methods
    public static byte[] encryptRSA(PrivateKey KXPrivate, byte[] hash) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        SecureRandom random = new SecureRandom();
        cipher.init(Cipher.ENCRYPT_MODE, KXPrivate, random);
        return cipher.doFinal(hash);
    }

    
    public static byte[] randomIV(){
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return bytes;
    }

    public static void toHex(byte [] in) {
        for (int k=0, j=0; k<in.length; k++, j++) {
            System.out.format("%2X ", new Byte(in[k])) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
    }

    public static  void encryptAES(String key, String inputFile, String outputFile,byte[] IV)
            throws Exception {
        aesCrypt(Cipher.ENCRYPT_MODE, key, inputFile, outputFile,IV);
    }

    
    public static void aesCrypt(int cipherMode, String key, String inputFile,
                                String outputFile,byte[] IV) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        cipher.init(cipherMode, secretKey, new IvParameterSpec(IV));
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream fileout = new FileOutputStream(outputFile);
        CipherOutputStream out = new CipherOutputStream(fileout , cipher);
        try {
            byte[] buffer = new byte[16*1024];
            int count;
            while ((count = inputStream.read(buffer)) > 0) {
                out.write(buffer, 0, count);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            out.close();
            inputStream.close();
        }
    }

    public static void append(String outputFile, String inputFile) throws Exception {
        System.out.println("append to " + outputFile + "\n");
        FileInputStream inputStream = new FileInputStream(inputFile);
        OutputStream outputStream = new FileOutputStream(new File(outputFile), true);
        try {
            byte[] buffer = new byte[16*1024];
            int count;
            while ((count = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, count);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                outputStream.close();
                inputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


    public static PrivateKey readPrivateKey(String keyFileName)
            throws IOException {
        InputStream in =
                Sender.class.getResourceAsStream(keyFileName);
        ObjectInputStream objectIn =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger e = (BigInteger) objectIn.readObject();
            BigInteger m = (BigInteger) objectIn.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException("error", e);
        } finally {
            objectIn.close();
        }
    }
    
    public static byte[] messageDigest(String f) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, messageDigest);
        int bufferSize = 32 * 1024;
        int i;
        byte[] buffer = new byte[bufferSize];
        do {
            i = in.read(buffer, 0, bufferSize);
        } while (i == bufferSize);
        messageDigest = in.getMessageDigest();
        in.close();
        byte[] hash = messageDigest.digest();
        System.out.println("");
        return hash;
    }

    
    public static String readsymKey(String keyFileName)
            throws IOException {
        InputStream in =
                Sender.class.getResourceAsStream(keyFileName);
        ObjectInputStream objectIn =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            String m = (String) objectIn.readObject();
            String key = m.toString();
            return key;
        } catch (Exception e) {
            throw new RuntimeException("error", e);
        } finally {
            objectIn.close();
        }
    }

    public static void saveToFile(String fileName, byte [] arr) throws Exception {
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        try {
            fileOutputStream.write(arr);
        }
        finally {
            fileOutputStream.close();
        }
    }
    
   
}
