/**
 * Created by Roach + Miller on 10/2/17.
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

    public static void main(String[] args) throws Exception {
    	
        
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        SecureRandom secRandom = new SecureRandom();
        
        generator.initialize(1024, secRandom);
        
        
        KeyPair Y = generator.generateKeyPair();
        Key yPublicKey = Y.getPublic();
        Key yPrivateKey = Y.getPrivate();
        
        KeyPair X = generator.generateKeyPair();
        Key xPublicKey = X.getPublic();
        Key xPrivateKey = X.getPrivate();
        
        
        Scanner in = new Scanner(System.in);
        int counter = 0;
        String symKey = "";
        System.out.print("Please enter a 16 character string: ");
        while (symKey.length() < 16 || symKey.length() > 16) {
            symKey = in.nextLine();
            if (symKey.length() < 16 || symKey.length() > 16) {
                System.out.println("Key must be 16 characters long");
                System.out.print("Please enter a 16 character string: ");
            }
        }
        in.close();
        
        
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec XKeyPublicSpec = keyFactory.getKeySpec(xPublicKey,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec XKeyPrivateSpec = keyFactory.getKeySpec(xPrivateKey,
                RSAPrivateKeySpec.class);
        RSAPublicKeySpec YKeyPublicSpec = keyFactory.getKeySpec(yPublicKey,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec YKeyPrivateSpec = keyFactory.getKeySpec(yPrivateKey,
                RSAPrivateKeySpec.class);
        
        writeKeys("XPublic.key", XKeyPublicSpec.getModulus(),
                XKeyPublicSpec.getPublicExponent());
        writeKeys("XPrivate.key", XKeyPrivateSpec.getModulus(),
                XKeyPrivateSpec.getPrivateExponent());
        writeKeys("YPublic.key", YKeyPublicSpec.getModulus(),
                YKeyPublicSpec.getPublicExponent());
        writeKeys("YPrivate.key", YKeyPrivateSpec.getModulus(),
                YKeyPrivateSpec.getPrivateExponent());
        writeMessage("symmetric.key", symKey);
    }

    public static void writeMessage(String fileName,
            String message) throws IOException {
    			ObjectOutputStream outStream = new ObjectOutputStream(
    			new BufferedOutputStream(new FileOutputStream(fileName)));
    			try {
    				outStream.writeObject(message);
    			} catch (Exception e) {
    				throw new IOException("File writing error", e);
    			} finally {
    				outStream.close();
    				}
    }
    
    public static void writeKeys(String fileName,
                                      BigInteger modulus, BigInteger exponent) throws IOException {
    	
        ObjectOutputStream outStream = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            outStream.writeObject(modulus);
            outStream.writeObject(exponent);
        } catch (Exception e) {
            throw new IOException("File writing error", e);
        } finally {
            outStream.close();
        }
    }

}