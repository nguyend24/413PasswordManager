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

        jsonWriter.name("passwords").beginObject();
        for (String p : vault.getPasswords().keySet()) {
            jsonWriter.name(p).value(vault.getPasswords().get(p));
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
        jsonReader.beginObject();

        Map<String, String> passwords = new LinkedHashMap<>();
        while (jsonReader.peek() != JsonToken.END_OBJECT) {
            passwords.put(jsonReader.nextName(), jsonReader.nextString());
        }
        jsonReader.endObject();

        jsonReader.endObject();

        return new Vault(user, authKey, passwords);
    }
}
