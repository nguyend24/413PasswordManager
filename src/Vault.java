import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

public class Vault {
    private final String user;
    private final String                authKey;
    private final Map<String, String[]> accounts;
    private final String salt;

    public Vault(String user, String authKey, Map<String, String[]> accounts, String salt) {
        this.user = user;
        this.authKey = authKey;
        this.accounts = accounts;
        this.salt = salt;
    }

//    public Vault(String user, String authKey, String passwords) {
//        this.user = user;
//        this.authKey = authKey;
//
//        Type type = new TypeToken<Map<String, String>>() {
//        }.getType();
//        this.accounts = new Gson().fromJson(passwords, type);
//    }

    public String getUser() {
        return user;
    }

    public String getAuthKey() {
        return authKey;
    }

    public String getSalt() {
        return salt;
    }

    public Map<String, String[]> getAccounts() {
        return accounts;
    }

    @Override
    public String toString() {
        Gson gson = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson().nullSafe()).create();
        return gson.toJson(this);
    }

    public String toString(SecretKey secretKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Vault encryptedVault = new Vault(user, authKey, new LinkedHashMap<>(), salt);

        for (String k : accounts.keySet()) {
            String[] loginDetails = {k, Client.encrypt(accounts.get(k)[1], secretKey)};
            encryptedVault.getAccounts().put(k, loginDetails);
        }

        Gson gson = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson().nullSafe()).create();

        return gson.toJson(encryptedVault);
    }
}

