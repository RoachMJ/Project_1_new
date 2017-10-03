

import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Scanner;
import javax.crypto.Cipher;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class Receiver {

    public static void main(String[] args) throws Exception{
        // decryption of file

        String KXY = readKXY("symmetric.key"); // read in symmetric key
        PublicKey KXPublic = readPubKey("XPublic.key"); // read in public key
        Scanner in = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String plainText = in.next();
        in.close();     // read in message.aescypher
        byte[] IV = getBytes("IV.byteArray"); // read in byte array iv
        System.out.println("\n");
        hexadecimalConversion(IV);
        AESDecryption(KXY, "message.aescipher", "message.ds-msg",IV);
        byte[] digSig = getMessage(plainText,"message.ds-msg");
        System.out.println("\n");
        System.out.println("Cipher Text of Digital Signature:");
        hexadecimalConversion(digSig);
        System.out.println();
        byte[] receivedHash = RSADecryption(KXPublic,digSig);
        createfile("message.dd",receivedHash);
        System.out.println();
        System.out.println("Received hash:");
        hexadecimalConversion(receivedHash);
        System.out.println();
        byte[] hash = messageDigest(plainText);
        System.out.println(compareHashes(receivedHash,hash));
    }

    public static  void AESDecryption(String Key, String inputFile, String outputFile, byte[] IV)
            throws Exception {
        aesCrypt(Cipher.DECRYPT_MODE, Key, inputFile, outputFile,IV);
    }


    public static void aesCrypt(int cipherMode, String key, String inputFile, String outputFile, byte[] IV) throws Exception {
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

    // Compares 2 byte []
    public static String compareHashes(byte [] received, byte[] text){
        if (Arrays.equals(received,text)){
            String yes = "Authentic";
            return yes;
        }
        else {
            String no = "Altered";
            return no;
        }
    }

    // Reads the ciphertext and splits the message from the
    // first 128 bytes.
    public static byte[] getMessage(String outputFile, String inputFile) throws Exception {
        //System.out.println("Write Digital signature to " + outputFile + "\n");
        FileInputStream inputStream = new FileInputStream(inputFile);
        OutputStream outputStream = new FileOutputStream(new File(outputFile), true);
        boolean flag = true;
        byte[] buffer = new byte[16*1024];
        byte[] offSet = new byte[128];
        int count;
        try {
            while (flag == true) {
                inputStream.read(offSet);
                flag = false;
            }
            while ((count = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, count);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            outputStream.close();
            inputStream.close();
            return offSet;
        }

    }
    public static byte[] RSADecryption(PublicKey KXPublic, byte[] hash) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, KXPublic);
        return cipher.doFinal(hash);
    }
    public static byte[] getBytes(String fileName) {       // reading iv.bytearray
        File file = new File(fileName);
        FileInputStream fileInputStream = null;
        byte[] RecievedFile = new byte[(int) file.length()];
        try{
            // convert file into array of bytes
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(RecievedFile);
            fileInputStream.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return RecievedFile;
    }
    public static void hexadecimalConversion(byte [] in) {
        for (int k=0, j=0; k<in.length; k++, j++) {
            System.out.format("%2X ", new Byte(in[k])) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
    }

    public static void createfile(String fileName, byte [] arr) throws Exception {
        System.out.println("Write to " + fileName + "\n");
        FileOutputStream fos = new FileOutputStream(fileName);
        try {
            fos.write(arr);
        }
        finally {
            fos.close();
        }
    }


    public static byte[] messageDigest(String f) throws Exception {
        BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(file, messageDigest);
        int BUFFER_SIZE = 32 * 1024;
        int i;
        byte[] buffer = new byte[BUFFER_SIZE];
        do {
            i = in.read(buffer, 0, BUFFER_SIZE);
        } while (i == BUFFER_SIZE);
        messageDigest = in.getMessageDigest();
        in.close();
        byte[] hash = messageDigest.digest();
        System.out.println("");
        return hash;
    }


    public static String readKXY(String keyFileName)
            throws IOException {
        InputStream in =
                Receiver.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            String m = (String) oin.readObject();
            System.out.println("Read from " + keyFileName + ": msg= " +
                    m.toString()  + "\n");
            String key = m.toString();
            return key;
        } catch (Exception e) {
            throw new RuntimeException("error", e);
        } finally {
            oin.close();
        }
    }


    public static PublicKey readPubKey(String keyFileName)
            throws IOException {
        InputStream in =
                Receiver.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);
            return key;
        } catch (Exception e) {
            throw new RuntimeException(" error", e);
        } finally {
            oin.close();
        }
    }
}