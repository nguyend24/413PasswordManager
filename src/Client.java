import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;

public class Client {
    private final VaultManager vaultManager;
    private final String       user;
    private final SecretKey    secretKey;
    private final String       hash;

    public Client(String user, String masterKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.user = user;
        secretKey = getKeyFromPassword(masterKey, user);
        vaultManager = new VaultManager(getSecretKey());
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
    public void deleteVault(String user) throws IOException {
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
    public void addVaultEntry(String identifier, String username, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UserDoesNotExistException, InvalidPasswordException {
        Vault v = retrieveVault();
        identifier = identifier.toLowerCase();

        String[] account = {username, password};

        if (checkPassword(password).equals("true")) {
            v.getAccounts()
             .put(identifier, account);
        } else {
            throw new InvalidPasswordException("Password does not meet requirements");
        }

        vaultManager.updateVault(user, hash, v);
    }

    /**
     * Remove a password entry from a user's vault
     *
     * @param identifier Name to identify saved password. e.g. site domain
     */
    public void removeVaultEntry(String identifier) throws UserDoesNotExistException, InvalidPasswordException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Vault               v         = retrieveVault();
        Map<String, String[]> accounts = v.getAccounts();
        accounts.remove(identifier);

        vaultManager.updateVault(user, hash, v);
    }

    /**
     * Retrieves a users entire vault
     *
     * @return A Vault object
     */
    public Vault retrieveVault() throws UserDoesNotExistException, InvalidPasswordException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String vaultJson = vaultManager.retrieveVault(user, hash);
        Gson   gson      = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson().nullSafe()).create();

        return gson.fromJson(vaultJson, Vault.class);
    }

    /***
     * Michael: Changed return type to ArrayList and returned an arrayList containing all passwords
     ***/
    public ArrayList<String> printPasswords() throws UserDoesNotExistException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidPasswordException {
        Vault               v            = retrieveVault();
        ArrayList<String>   passwordList = new ArrayList<>();
        Map<String, String[]> accounts    = v.getAccounts();
        for (String key : accounts.keySet()) {
            System.out.println("u: " + accounts.get(key)[0] + " p: " + accounts.get(key)[1]);
        }
        return passwordList;
    }

    public ArrayList<String> printKeys() throws UserDoesNotExistException, InvalidPasswordException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Vault               V       = retrieveVault();
        ArrayList<String>   keyList = new ArrayList<>();
//        Map<String, String> keys    = V.accounts;
//        for (String key : keys.keySet()) {
//            keyList.add(key);
//        }
        return keyList;
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

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public static String checkPassword(String password) {
        if (password.length() < 8) {
            return "short";
        } else if (!password.matches("[A-Za-z0-9]+")) {
            return "nAlphaNum";
        } else if (!checkNoConsecutive(password)) {
            return "cCon";
        } else if (password.toLowerCase().contains("password") || password.toLowerCase().contains("12345678")) {
            return "com";
        }

        return "true";
    }

    public static boolean checkNoConsecutive(String s) {
        int count = 0;
        char[] c = s.toCharArray();

        for (int i = 0; i < c.length; i++) {
            for (int j = i + 1; j < c.length; j++) {
                if (c[i] == c[j]) {
                    count += 1;
                }
            }
            if (count > 3) {
                return false;
            } else {
                count = 0;
            }
        }

        return true;
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


