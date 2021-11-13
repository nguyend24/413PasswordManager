import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class VaultManager {
    static final  String      VAULT_FILE = "encryptedStorage.txt";
    private final List<Vault> vaults;

    public VaultManager() {
        vaults = readVaultStorage(VAULT_FILE);
    }

    /**
     * Find and return
     *
     * @param user    The user for the vault to retrieve
     * @param authKey Key to authenticate proper person is attempting to retrieve a vault
     * @return Json representation of a Vault
     */
    public String retrieveVault(String user, String authKey) throws UserDoesNotExistException {
        if (userExists(user)) {
            Vault v = findUserVault(user);
            if (v.getAuthKey().equals(authKey)) {
                Gson gson = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson().nullSafe()).create();
                return gson.toJson(v);
            }
        } else {
            throw new UserDoesNotExistException("User not found");
        }

        return "{}";
    }

    /**
     * Creates a new Vault and stores it
     *
     * @param user      Identifier of the new vault
     * @param authKey   Key that will to used to authenticate the vault in the future
     * @param passwords The list of passwords in Json representation
     */
    public void createVault(String user, String authKey, String passwords) {
        if (userExists(user)) {
            //Error, can't create a new vault if a user exists
        } else {
            Map<String, String> passwordsMap = new Gson().fromJson(passwords, new TypeToken<Map<String, String>>() {
            }.getType());
            Vault v = new Vault(user, authKey, passwordsMap);
            vaults.add(v);
        }

        writeVaultStorage(VAULT_FILE, vaults);
    }

    /**
     * Overwrites the currently saved vault with a new modified list of passwords
     *
     * @param user      The user of the Vault to modify
     * @param authKey   Key to authenticate user attempting to update the Vault
     * @param passwords A new and modified list of passwords
     */
    public void updateVault(String user, String authKey, String passwords) {
        if (userExists(user)) {
            Vault v      = findUserVault(user);
            int   vIndex = findUserVaultIndex(user);
            if (v.getAuthKey().equals(authKey)) {
                Vault newVault = new Vault(user, authKey, passwords);
                vaults.set(vIndex, newVault);
            }
        }

        writeVaultStorage(VAULT_FILE, vaults);
    }

    /**
     * Deletes a Vault
     *
     * @param user    The user of the Vault to delete
     * @param authKey Key to authenticate user attempting to delete a Vault
     */
    public void deleteVault(String user, String authKey) {
        if (userExists(user)) {
            Vault v = findUserVault(user);

            if (v.getAuthKey().equals(authKey)) {
                vaults.remove(v);
            }
        } else {
            //User doesn't exist, no need to delete
        }

    }

    /**
     * Check if a Vault already exists for a user
     *
     * @param user The user to search for
     * @return true if the user exists, else otherwise
     */
    private boolean userExists(String user) {
        for (Vault v : vaults) {
            if (v.getUser().equals(user)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Finds the Vault corresponding to a specified user
     *
     * @param user The user to search for
     * @return The Vault if found, null otherwise
     */
    private Vault findUserVault(String user) {
        for (Vault v : vaults) {
            if (v.getUser().equals(user)) {
                return v;
            }
        }

        return null;
    }

    /**
     * Finds the index of the matching Vault for a corresponding user
     *
     * @param user The user to search for
     * @return The index of the Vault if found, -1 otherwise
     */
    private int findUserVaultIndex(String user) {
        for (int i = 0; i < vaults.size(); i++) {
            if (vaults.get(i).getUser().equals(user)) {
                return i;
            }
        }

        return - 1;
    }

    /**
     * Prints out every Vault that has been stored
     */
    public void printAllVaults() {
        for (Vault v : vaults) {
            System.out.println(v.toString());
        }
    }

    /**
     * Writes all Vaults to a file
     *
     * @param filename File to write to
     * @param vaults   List of Vaults to serialize
     */
    private static void writeVaultStorage(String filename, List<Vault> vaults) {
        File f = new File(filename);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(f))) {
            for (Vault v : vaults) {
                writer.write(v.toString());
                writer.write("\n");
            }
        } catch (IOException io) {
            io.printStackTrace();
            System.exit(- 1);
        }
    }

    /**
     * Reads a file and deseralize into a list of Vaults
     *
     * @param filename File to read
     * @return A list of Vault
     */
    private static List<Vault> readVaultStorage(String filename) {
        File        f      = new File(filename);
        List<Vault> vaults = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
            String line = reader.readLine();
            Gson   gson = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson()).create();
            Vault  v    = gson.fromJson(line, Vault.class);
            if (v != null) {
                vaults.add(v);
            }
        } catch (FileNotFoundException fileNotFoundException) {
            //Do nothing. There are no passwords currently stored.
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }

        return vaults;
    }
}
