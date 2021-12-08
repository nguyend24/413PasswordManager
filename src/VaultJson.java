import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;


public class VaultJson extends TypeAdapter<Vault> {
    @Override
    public void write(JsonWriter jsonWriter, Vault vault) throws IOException {
        jsonWriter.beginObject();

        jsonWriter.name("user").value(vault.getUser());
        jsonWriter.name("authKey").value(vault.getAuthKey());
        jsonWriter.name("salt").value(vault.getSalt());
//        jsonWriter.name("passwords").beginObject();
//        for (String p : vault.getPasswords().keySet()) {
//            jsonWriter.name(p).value(vault.getPasswords().get(p));
//        }

        jsonWriter.name("accounts").beginObject();
        for (String site : vault.getAccounts().keySet()) {
            jsonWriter.name(site).beginObject();
            String username = vault.getAccounts().get(site)[0];
            String password = vault.getAccounts().get(site)[1];
            jsonWriter.name("username").value(username);
            jsonWriter.name("password").value(password);
            jsonWriter.endObject();
        }
        jsonWriter.endObject();

        jsonWriter.endObject();
    }

    @Override
    public Vault read(JsonReader jsonReader) throws IOException {
        jsonReader.beginObject();

        jsonReader.nextName();
        String user = jsonReader.nextString();

        jsonReader.nextName();
        String authKey = jsonReader.nextString();

        jsonReader.nextName();
        String salt = jsonReader.nextString();

        jsonReader.nextName();
        jsonReader.beginObject();

        Map<String, String[]> accounts = new LinkedHashMap<>();
        while (jsonReader.peek() != JsonToken.END_OBJECT) {
            String site = jsonReader.nextName();
            jsonReader.beginObject();
            jsonReader.nextName();
            String username = jsonReader.nextString();
            jsonReader.nextName();
            String password = jsonReader.nextString();
            String[] account = {username, password};
            accounts.put(site, account);
            jsonReader.endObject();
        }
        jsonReader.endObject();

        jsonReader.endObject();

        return new Vault(user, authKey, accounts, salt);
    }
}
