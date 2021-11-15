import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


public class PasswordVault {

    private final JFrame     frame;
    private LoginPanel loginPanel;

    public PasswordVault() throws UnsupportedLookAndFeelException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

        frame = new JFrame();
        frame.setTitle("Password Vault");
        frame.setSize(600, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        loginPanel = new LoginPanel(this);
    }

    public static void main(String[] args) throws UnsupportedLookAndFeelException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        PasswordVault vault = new PasswordVault();
        vault.start();
        System.out.println("new line");
    }

    public void start() {
        frame.setContentPane(loginPanel);
        frame.setVisible(true);
    }

    public void revalidate() {
        frame.revalidate();
    }

    public void login(String user, String password) {
        try {
            Client client = new Client(user, password);
            Vault vault = client.retrieveVault();
            VaultPanel vp = new VaultPanel(user, password, this);
            this.frame.setContentPane(vp);
            this.frame.revalidate();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
        } catch (UserDoesNotExistException | InvalidPasswordException il) {
            loginPanel.invalidLogin();
        }
    }

    public void logout() {
        loginPanel = new LoginPanel(this);
        frame.setContentPane(loginPanel);
        frame.revalidate();
    }
}

/**
 * LoginPanel is the initial view of the app frame.
 */
class LoginPanel extends JPanel {
    private final PasswordVault passwordVault;
    LoginPanel(PasswordVault passwordVault) {
        this.passwordVault = passwordVault;

        this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        addLoginFields();

        /*
        Ensures a constant spacing between the username, password, and login areas by adding invisible at the bottom of the window
         */
        this.add(new Box.Filler(
            new Dimension(0, 0),
            new Dimension(0, Short.MAX_VALUE),
            new Dimension(0, Short.MAX_VALUE)));

        passwordVault.revalidate();
    }

    public void invalidLogin() {
        this.removeAll();

        this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

        addLoginFields();

        /*
        Invalid login Text
         */
        JLabel invalidLogin = new JLabel("Invalid Login Attempt!");
        invalidLogin.setAlignmentX(Component.CENTER_ALIGNMENT);
        invalidLogin.setForeground(Color.RED);
        this.add(invalidLogin);

        /*
        Ensures a constant spacing between the username, password, and login areas by adding invisible at the bottom of the window
         */
        this.add(new Box.Filler(
            new Dimension(0, 0),
            new Dimension(0, Short.MAX_VALUE),
            new Dimension(0, Short.MAX_VALUE)));

        passwordVault.revalidate();
    }

    private void addLoginFields() {
        /*
        Username entry
         */
        JPanel username = new JPanel();
        username.add(new JLabel("Username"));
        JTextField usernameField = new JTextField(20);
        username.add(usernameField);
        username.grabFocus();
        this.add(username);

        this.add(Box.createRigidArea(new Dimension(0, 5)));

        /*
        Password entry
         */
        JPanel password = new JPanel();
        password.add(new JLabel("Password"));
        JPasswordField passwordField = new JPasswordField(20);
        passwordField.addActionListener(e -> passwordVault.login(usernameField.getText(), new String(passwordField.getPassword())));
        password.add(passwordField);

        this.add(password);

        this.add(Box.createRigidArea(new Dimension(0, 20)));

        /*
        Login button
         */
        JButton login = new JButton("Login");
        login.addActionListener(e -> passwordVault.login(usernameField.getText(), new String(passwordField.getPassword())));
        login.setAlignmentX(Component.CENTER_ALIGNMENT);
        this.add(login);
    }
}

class VaultPanel extends JPanel {
    VaultPanel(String user, String masterKey, PasswordVault frame) {
        this.add(new JLabel(user));
        this.add(new JLabel(masterKey));

        JButton logout = new JButton("Logout");
        logout.setAlignmentX(Component.CENTER_ALIGNMENT);
        logout.addActionListener(e -> frame.logout());
        this.add(logout);
    }
}