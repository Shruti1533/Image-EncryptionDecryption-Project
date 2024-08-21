import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

public class ImageEncryption {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128;

    public static void main(String[] args) {
        try {
            // Generate a random key and initialization vector (IV)
            SecretKey secretKey = generateSecretKey();
            IvParameterSpec iv = generateIV();
    
            // Encrypt the image
            encryptImage("C:\\Users\\DELL\\Dropbox\\PC\\Desktop\\Image Encryption\\sample.jpg",
                        "C:\\Users\\DELL\\Dropbox\\PC\\Desktop\\Image Encryption\\encrypted.jpg", 
                        secretKey, iv);
    
            // Decrypt the image
            decryptImage("C:\\Users\\DELL\\Dropbox\\PC\\Desktop\\Image Encryption\\encrypted.jpg",
                        "C:\\Users\\DELL\\Dropbox\\PC\\Desktop\\Image Encryption\\decrypted.jpg", 
                        secretKey, iv);
    
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    private static IvParameterSpec generateIV() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static void encryptImage(String inputImagePath, String outputImagePath, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
    
        // Read the image into bytes
        byte[] inputBytes = ImageUtils.readImage(inputImagePath);
        System.out.println("Input bytes length: " + inputBytes.length);
    
        // Encrypt the image
        byte[] encryptedBytes = cipher.doFinal(inputBytes);
        System.out.println("Encrypted bytes length: " + encryptedBytes.length);
    
        // Save the encrypted bytes to a file
        ImageUtils.saveToFile(encryptedBytes, outputImagePath);
        System.out.println("Encrypted image saved to: " + outputImagePath);
    }

    private static void decryptImage(String encryptedImagePath, String outputImagePath, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
    
        // Read the encrypted image bytes
        byte[] encryptedBytes = Files.readAllBytes(Paths.get(encryptedImagePath));
    
        // Decrypt the image
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
    
        // Save the decrypted image
        ImageUtils.saveToFile(decryptedBytes, outputImagePath);
        System.out.println("Decrypted image saved to: " + outputImagePath);
    }
    
}