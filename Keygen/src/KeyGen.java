/**
 * Created by Roach on 10/2/17.
 */
import java.math.BigInteger;
import java.io.*;
import java.security.Key;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Scanner;

public class KeyGen {
    public KeyGen() {
    }

    ;

    public static void main(String[] args) throws Exception {
        //Generate two pairs of keys (X and Y).
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        //1024: key size in bits
        generator.initialize(1024, random);
        KeyPair pairX = generator.generateKeyPair();
        Key kXpublic = pairX.getPublic();
        Key kXprivate = pairX.getPrivate();
        KeyPair pairY = generator.generateKeyPair();
        Key kYpublic = pairY.getPublic();
        Key kYprivate = pairY.getPrivate();
        //user input for symmetric key generation
        Scanner input = new Scanner(System.in);
        int counter = 0;
        String kXY = "";
        System.out.print("Enter 16 characters: ");
        while (kXY.length() < 16 || kXY.length() > 16) {
            kXY = input.nextLine();
            if (kXY.length() < 16 || kXY.length() > 16) {
                System.out.println("You must input 16 characters for the Key");
                System.out.print("Enter 16 characters: ");
            }
        }
        input.close();
        //get the parameters of the keys: modulus and exponet
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKXSpec = factory.getKeySpec(kXpublic,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKXSpec = factory.getKeySpec(kXprivate,
                RSAPrivateKeySpec.class);
        RSAPublicKeySpec pubKYSpec = factory.getKeySpec(kYpublic,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKYSpec = factory.getKeySpec(kYprivate,
                RSAPrivateKeySpec.class);
        //save the parameters of the keys to the files, and save symmetric key
        saveToFilePair("XPublic.key", pubKXSpec.getModulus(),
                pubKXSpec.getPublicExponent());
        saveToFilePair("XPrivate.key", privKXSpec.getModulus(),
                privKXSpec.getPrivateExponent());
        saveToFilePair("YPublic.key", pubKYSpec.getModulus(),
                pubKYSpec.getPublicExponent());
        saveToFilePair("YPrivate.key", privKYSpec.getModulus(),
                privKYSpec.getPrivateExponent());
        saveToFileKXY("symmetric.key", kXY);
    }

    public static void saveToFilePair(String fileName,
                                      BigInteger mod, BigInteger exp) throws IOException {
        System.out.println();
        System.out.println("Write to " + fileName + ": " +
                "\n---------------------------------\n" +
                "modulus = " + mod.toString() + ",\nexponent = "
                + exp.toString() + "\n");
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }

    public static void saveToFileKXY(String fileName,
                                     String msg) throws IOException {
        System.out.println("Write to " + fileName + ": "
                + "\n---------------------------------\n" + msg + "\n");
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(msg);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }
}