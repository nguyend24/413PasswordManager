import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.Map;

public class Vault {
    private final String user;
    private final String authKey;
    Map<String, String[]> accounts;

    public Vault(String user, String authKey, Map<String, String[]> accounts) {
        this.user = user;
        this.authKey = authKey;
        this.accounts = accounts;
    }

    public Vault(String user, String authKey, String passwords) {
        this.user = user;
        this.authKey = authKey;

        Type type = new TypeToken<Map<String, String>>() {
        }.getType();
        this.accounts = new Gson().fromJson(passwords, type);
    }

    public String getUser() {
        return user;
    }

    public String getAuthKey() {
        return authKey;
    }

    public Map<String, String[]> getAccounts() {
        return accounts;
    }

    @Override
    public String toString() {
        Gson gson = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson().nullSafe()).create();
        return gson.toJson(this);
    }
}

