import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class VaultManager {
    static final  String      VAULT_FILE = "passwords.txt";
    private final List<Vault> vaults;
    private final SecretKey   secretKey;

    public VaultManager(SecretKey secretKey, String salt) {
        this.secretKey = secretKey;
        vaults = readVaultStorage(VAULT_FILE, secretKey);
    }

    /**
     * Find and return
     *
     * @param user    The user for the vault to retrieve
     * @param authKey Key to authenticate proper person is attempting to retrieve a vault
     * @return Json representation of a Vault
     */
    public String retrieveVault(String user, String authKey) throws UserDoesNotExistException, InvalidPasswordException {
        if (userExists(user)) {
            Vault v = findUserVault(user);
            if (v.getAuthKey().equals(authKey)) {
                Gson gson = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson().nullSafe()).create();
                return gson.toJson(v);
            } else {
                throw new InvalidPasswordException("Invalid Password. Access Denied");
            }
        } else {
            throw new UserDoesNotExistException("User not found");
        }
    }

    /**
     * Creates a new Vault and stores it
     *
     * @param user      Identifier of the new vault
     * @param authKey   Key that will to used to authenticate the vault in the future
     * @param passwords The list of passwords in Json representation
     */
    public void createVault(String user, String authKey, String passwords, String salt) {
        if (userExists(user)) {
            //Error, can't create a new vault if a user exists
        } else {
            Map<String, String[]> accountsMap = new Gson().fromJson(passwords, new TypeToken<Map<String, String[]>>() {
            }.getType());

            Vault v = new Vault(user, authKey, accountsMap, salt);
            vaults.add(v);
        }

        writeVaultStorage(VAULT_FILE, vaults, secretKey);
    }

    /**
     * Overwrites the currently saved vault with a new modified list of passwords
     *
     * @param user    The user of the Vault to modify
     * @param authKey Key to authenticate user attempting to update the Vault
     * @param vault   A new and modified Vault
     */
    public void updateVault(String user, String authKey, Vault vault) {
        if (userExists(user)) {
            Vault v      = findUserVault(user);
            int   vIndex = findUserVaultIndex(user);
            if (v.getAuthKey().equals(authKey)) {
                vaults.set(vIndex, vault);
            }
        }

        writeVaultStorage(VAULT_FILE, vaults, secretKey);
    }

    /**
     * Deletes a Vault
     *
     * @param user    The user of the Vault to delete
     * @param authKey Key to authenticate user attempting to delete a Vault
     */
    public void deleteVault(String user, String authKey) throws IOException {
        if (userExists(user)) {
            Vault v = findUserVault(user);

            if (v.getAuthKey().equals(authKey)) {
                vaults.remove(v);
            }
        } else {
            //User doesn't exist, no need to delete
        }
        writeVaultStorage(VAULT_FILE, vaults, secretKey);
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
     * @param filename  File to write to
     * @param vaults    List of Vaults to serialize
     * @param secretKey Secret key to use to encrypt the vault
     */
    private static void writeVaultStorage(String filename, List<Vault> vaults, SecretKey secretKey) {
        File f = new File(filename);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(f))) {
            for (Vault v : vaults) {
                writer.write(v.getUser() + ',');
                writer.write(v.getSalt() + ",");
                writer.write(Client.encrypt(v.toString(secretKey), secretKey));
                writer.write("\n");
            }
        } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException io) {
            io.printStackTrace();
            System.exit(- 1);
        }
    }


    /**
     * Reads a file and deseralize into a list of Vaults
     *
     * @param filename  File to read
     * @param secretKey
     * @return A list of Vault
     * <p>
     * Michael: Created a while loop with line variable to iterate through entire file
     */
    private static List<Vault> readVaultStorage(String filename, SecretKey secretKey) {
        File        f      = new File(filename);
        List<Vault> vaults = new ArrayList<>();
        String      line;
        try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
            while ((line = reader.readLine()) != null) {
                String[] l = line.split(",");
                try {
                    Gson  gson = new GsonBuilder().registerTypeAdapter(Vault.class, new VaultJson()).create();
                    Vault v    = gson.fromJson(Client.decrypt(l[2], secretKey), Vault.class);
                    if (v != null) {

                        for (String k : v.getAccounts().keySet()) {
                            String[] loginDetails = {k, Client.decrypt(v.getAccounts().get(k)[1], secretKey)};
                            v.getAccounts().put(k, loginDetails);
                        }


                        vaults.add(v);
                    }
                } catch (JsonSyntaxException j) {}
            }
        } catch (FileNotFoundException fileNotFoundException) {
            //Do nothing. There are no passwords currently stored.
        } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException ioException) {
            ioException.printStackTrace();
        }

        return vaults;
    }
}
