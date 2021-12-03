import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, UserDoesNotExistException, InvalidPasswordException {
        Client c = new Client("denny", "secure password");
        c.createNewVault();
        c.addVaultEntry("google.com", "googleuser", "google password");
        c.addVaultEntry("microsoft.com", "microsoft user","microsoft password");
        c.addVaultEntry("facebook.com", "facebook user", "facebook password");
//        for (int i = 0; i < 10; i++) {
//            c.addVaultEntry(String.valueOf(Math.random()), String.valueOf(Math.random()));
//        }
//        c.printPasswords();
//
//        System.out.println("Remove microsoft");
//        c.removeVaultEntry("microsoft.com");
//        c.printPasswords();
//
//        System.out.println("Remove facebook");
//        c.removeVaultEntry("facebook.com");
//        c.printPasswords();

//        Client m = new Client("michael", "abc123");
//        m.createNewVault();
//        m.addVaultEntry("google.com", "password2021");
//        m.addVaultEntry("aol.com", "youGotMail");
        System.out.println("Hello world");
    }
}
