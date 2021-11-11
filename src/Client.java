import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class Client {
    VaultManager vaultManager;

    public Client(VaultManager vaultManager) {
        this.vaultManager = vaultManager;
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
     *
     * All passwords are encrypted before adding to the vault
     * @param user
     * @param masterKey A user specified password
     * @param passwords A Map containing an identifier and a password for that identifier
     */
    public void addVaultEntry(String user, String masterKey, Map<String, String> passwords) {
//        String authKey = hashMasterKey(masterKey);
//        Vault  v       = retrieveVault(user, masterKey);
//        try {
//            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
//        } catch (NoSuchPaddingException | NoSuchAlgorithmException ignored) {
//        }

    }

    /**
     * Remove a password entry from a user's vault
     * @param user
     * @param masterKey A user specified password
     */
    public void removeVaultEntry(String user, String masterKey) {
        String authKey = hashMasterKey(masterKey);

    }

    /**
     * Retrieves a users entire vault
     *
     * @param user
     * @param masterKey A user specified password
     * @return A Vault object
     */
    public Vault retrieveVault(String user, String masterKey) {
        String authKey   = hashMasterKey(masterKey);
        String vaultJson = vaultManager.retrieveVault(user, authKey);
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
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(masterKey.getBytes());
            byte[]        digest  = md.digest();
            StringBuilder hexHash = new StringBuilder();

            for (byte b : digest) {
                hexHash.append(Integer.toHexString(0xFF & b));
            }

            return hexHash.toString();
        } catch (NoSuchAlgorithmException n) {
            System.out.println(n.getMessage());
        }

        return "";
    }
}
