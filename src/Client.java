import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;

public class Client {
    VaultManager vaultManager;
    private String    user;
    private SecretKey secretKey;
    private String    hash;

    public Client(String user, String masterKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.user = user;
        vaultManager = new VaultManager();
        secretKey = getKeyFromPassword(masterKey, user);
        hash = hashMasterKey(masterKey);
    }

    /**
     * Creates a new empty vault for a user
     * Json Representation Example:
     * {"user":JohnSmith,authKey:"2jo4ijr284joifajfalkejf",passwords:{}}
     *
     * @param user
     * @param masterKey A user specified password
     */
    public void createNewVault(String user, String masterKey) {
        String authKey = hashMasterKey(masterKey);
        vaultManager.createVault(user, authKey, "{}");
    }

    /**
     * Deletes a user's entire vault
     *
     * @param user
     * @param masterKey A user specified password
     */
    public void deleteVault(String user, String masterKey) {
        String authKey = hashMasterKey(masterKey);
        vaultManager.deleteVault(user, authKey);
    }

    /**
     * Add a new password entry or multiple entries to a user's vault
     * <p>
     * All passwords are encrypted before adding to the vault
     *
     * @param identifier Name to identify saved password. e.g. site domain
     * @param password Password to encrypt and save
     */
    public void addVaultEntry(String identifier, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Vault v = retrieveVault();
        identifier = identifier.toLowerCase();
        String encryptedPassword = encrypt(password, secretKey);

        v.getPasswords()
         .put(identifier, encryptedPassword);
    }

    /**
     * Remove a password entry from a user's vault
     *
     * @param user
     * @param masterKey A user specified password
     */
    public void removeVaultEntry(String identifier) {
        Vault v = retrieveVault();
        Map<String, String> passwords = v.getPasswords();
        passwords.remove(identifier);
    }

    /**
     * Retrieves a users entire vault
     *
     * @param user
     * @param masterKey A user specified password
     * @return A Vault object
     */
    public Vault retrieveVault() {
        String vaultJson = vaultManager.retrieveVault(user, hash);
        Gson   gson      = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson().nullSafe()).create();
        return gson.fromJson(vaultJson, Vault.class);
    }

    /**
     * Hashes a given String using SHA-256
     *
     * @param masterKey A user specified password
     * @return A SHA-256 Hex String of the masterKey
     */
    public static String hashMasterKey(String masterKey) {
        try {
            String hash = masterKey;

            for (int i = 0; i < 256; i++) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(hash.getBytes());
                byte[]        digest  = md.digest();
                StringBuilder hexHash = new StringBuilder();

                for (byte b : digest) {
                    hexHash.append(Integer.toHexString(0xFF & b));
                }
                hash = hexHash.toString();
            }
            return hash;
        } catch (NoSuchAlgorithmException n) {
            System.out.println(n.getMessage());
        }

        return "";
    }

    public static String encrypt(String input, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());

        return Base64.getEncoder()
                     .encodeToString(cipherText);
    }

    public static String decrypt(String input, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherText = Base64.getDecoder().decode(input);
        byte[] decoded    = cipher.doFinal(cipherText);

        return new String(decoded);
    }

    public static SecretKey getKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec          spec    = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                                                    .getEncoded(), "AES");

        return secret;
    }
}
