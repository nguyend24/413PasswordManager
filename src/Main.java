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
//        c.createNewVault();
//        c.addVaultEntry("google.com", "googleuser", "1google password");
//        c.addVaultEntry("microsoft.com", "microsoft user","1microsoft password");
//        c.addVaultEntry("facebook.com", "facebook user", "1facebook password");
        c.addVaultEntry("aoskdaokdw", "sokdoawkd", "aoskdoakw212312");
    }
}
