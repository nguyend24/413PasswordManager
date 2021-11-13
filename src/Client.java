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
    private final VaultManager vaultManager;
    private final String       user;
    private final SecretKey    secretKey;
    private final String       hash;

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
     */
    public void createNewVault() {
        vaultManager.createVault(user, hash, "{}");
    }

    /**
     * Deletes a user's entire vault
     *
     * @param user User of Vault being deleted
     */
    public void deleteVault(String user) {
        vaultManager.deleteVault(user, hash);
    }

    /**
     * Add a new password entry or multiple entries to a user's vault
     * <p>
     * All passwords are encrypted before adding to the vault
     *
     * @param identifier Name to identify saved password. e.g. site domain
     * @param password   Password to encrypt and save
     */
    public void addVaultEntry(String identifier, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UserDoesNotExistException {
        Vault v = retrieveVault();
        identifier = identifier.toLowerCase();
        String encryptedPassword = encrypt(password, secretKey);

        v.getPasswords()
         .put(identifier, encryptedPassword);

        String passwordsJson = new Gson().toJson(v.getPasswords(), Map.class);
        vaultManager.updateVault(user, hash, passwordsJson);
    }

    /**
     * Remove a password entry from a user's vault
     *
     * @param identifier Name to identify saved password. e.g. site domain
     */
    public void removeVaultEntry(String identifier) throws UserDoesNotExistException {
        Vault               v         = retrieveVault();
        Map<String, String> passwords = v.getPasswords();
        passwords.remove(identifier);

        String passwordsJson = new Gson().toJson(v.getPasswords(), Map.class);
        vaultManager.updateVault(user, hash, passwordsJson);
    }

    /**
     * Retrieves a users entire vault
     *
     * @return A Vault object
     */
    public Vault retrieveVault() throws UserDoesNotExistException {
        String vaultJson = vaultManager.retrieveVault(user, hash);
        Gson   gson      = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson().nullSafe()).create();
        return gson.fromJson(vaultJson, Vault.class);
    }

    public void printPasswords() throws UserDoesNotExistException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Vault               v         = retrieveVault();
        Map<String, String> passwords = v.getPasswords();
        for (String key : passwords.keySet()) {
            System.out.println("key: " + decrypt(passwords.get(key), secretKey));
        }
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

    /**
     * Generates a ciphertext for a provided text and key using 256-bit AES.
     *
     * @param input A String to be encrypted
     * @param key   The key to use to perform encryption
     * @return AES encrypted and Base64 encoded version of the input text
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String encrypt(String input, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());

        return Base64.getEncoder()
                     .encodeToString(cipherText);
    }

    /**
     * Decrypts a ciphertext with the given key
     *
     * @param input
     * @param key
     * @return Decrypted ciphertext
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static String decrypt(String input, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] cipherText = Base64.getDecoder().decode(input);
        byte[] decoded    = cipher.doFinal(cipherText);

        return new String(decoded);
    }

    /**
     * Generates a Secret Key for use with AES encryption
     *
     * @param password A text to transform into a key
     * @param salt
     * @return A SecretKey for the provided password and salt
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static SecretKey getKeyFromPassword(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec          spec    = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);

        return new SecretKeySpec(factory.generateSecret(spec)
                                        .getEncoded(), "AES");
    }
}


