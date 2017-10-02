/**
 * Created by Roach on 10/2/17.
 */
import java.io.*;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.CipherOutputStream;


public class Reciever {

    public static void main(String[] args) throws Exception{

        // The Files
        //   symmetric.key
        //   XPrivate.key
        //   XPublic.key
        // are produced by running
        // the program in KeyGen/KeyGen
        //
        //   IV.byteArray is produced
        //   by Sender

        // symmetric.key and XPublic.key are read from files
        String KXY = readKXYFromFile("symmetric.key");
        PublicKey KXPublic = readPublicKeyFromFile("XPublic.key");

        // Get message file name from user System input
        Scanner in = new Scanner(System.in);
        System.out.print("Input the name of the message file: ");
        String plainText = in.next();
        in.close();

        // Read IV from IV.byteArray
        byte[] IV = readBytesFromFile("IV.byteArray");

        // Display IV
        System.out.println("\n");
        System.out.println("IV read from File:");
        toHexa(IV);

        decryptAES(KXY, "message.aescipher", "message.ds-msg",IV);

        byte[] digSig = getMessage(plainText,"message.ds-msg");


        System.out.println("\n");
        System.out.println("Cipher Text of Digital Signature:");
        toHexa(digSig);
        System.out.println();


        byte[] receivedHash = decryptRSA(KXPublic,digSig);
        saveToFile("message.dd",receivedHash);
        System.out.println();
        System.out.println("Received hash:");
        toHexa(receivedHash);
        System.out.println();

        byte[] hash = messageDigest(plainText);

        System.out.println(compareHashes(receivedHash,hash));
    }

    public static  void decryptAES(String Key, String inputFile, String outputFile,byte[] IV)
            throws Exception {
        aesCrypt(Cipher.DECRYPT_MODE, Key, inputFile, outputFile,IV);
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

    /*
     This encryptRSA method uses RSA encryption with a Private Key to
     encrypt the SHA256 hash of the message text.
    */
    public static byte[] decryptRSA(PublicKey KXPublic, byte[] hash) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, KXPublic);
        return cipher.doFinal(hash);
    }

    /*
     readBytesFromFile() is used here primarily to read the
     IV from the IV.bytearray file.
    */
    public static byte[] readBytesFromFile(String fileName) {
        File file = new File(fileName);
        FileInputStream fileInputStream = null;
        byte[] bFile = new byte[(int) file.length()];
        try{
            // convert file into array of bytes
            fileInputStream = new FileInputStream(file);
            fileInputStream.read(bFile);
            fileInputStream.close();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return bFile;

    }

    /**
     * toHexa() takes a byte array and outputs it to the console
     */
    public static void toHexa(byte [] in) {
        for (int k=0, j=0; k<in.length; k++, j++) {
            System.out.format("%2X ", new Byte(in[k])) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
    }

    /**
     * saveToFile() takes a fileName and a byte array, creates a file with that
     * filename and writes to it.
     */
    public static void saveToFile(String fileName, byte [] arr) throws Exception {
        System.out.println("Write to " + fileName + "\n");
        FileOutputStream fos = new FileOutputStream(fileName);
        try {
            fos.write(arr);
        }
        finally {
            fos.close();
        }
    }

    /**
     * md() stands for message digest. It is provided by Dr. Weiying Zhu.
     * It takes a String representing a filename, opens that corresponding file
     * and creates a SHA256 hash from the contents of the file.  It returns the
     * file's hash as a byte array.
     */
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

    /**
     * readKXYFromFile() takes a String representing the name
     * of the symmetric key and, prints and returns a String representing
     * the symmetric key.
     */
    public static String readKXYFromFile(String keyFileName)
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
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }

    /**
     * readPrivKeyFromFile takes a String representing the filename
     * of the File that contains the private key parameters generated by
     * KeyGen.  It creates and returns the PrivateKey
     */
    public static PublicKey readPublicKeyFromFile(String keyFileName)
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
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
}