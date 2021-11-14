import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


public class PasswordVault {

    private final JFrame     frame;
    private LoginPanel loginPanel;
    private       JButton    addPasswordButton;
    private       JButton    viewPasswordsButton;
    private       JButton    deletePasswordButton;
    private       JTextField enterUsernameTextField;
    private       JTextField enterPasswordTextField;
    private       JTextField nameTextField;
    private       JTextField display;
    private       JLabel     msg1;
    private       JLabel     msg2;

    public PasswordVault() throws UnsupportedLookAndFeelException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());

        frame = new JFrame();
        frame.setTitle("Password Vault");
        frame.setSize(600, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        loginPanel = new LoginPanel(this);

//        vaultManager = new VaultManager();
//        client = new Client(vaultManager);
//        JPanel panel1 = new JPanel();
//        addPasswordButton = new JButton("Add Password");
//        deletePasswordButton = new JButton("Delete Password");
//        viewPasswordsButton = new JButton("View Passwords");
//        enterUsernameTextField = new JTextField(20);
//        enterPasswordTextField = new JTextField(20);
//        nameTextField = new JTextField(20);
//        display = new JTextField(20);
//        msg1 = new JLabel("Enter username: ");
//        msg2 = new JLabel("Enter password: ");
//
//
//
//        Listener listenForButton = new Listener();
//        addPasswordButton.addActionListener(listenForButton);
//        deletePasswordButton.addActionListener(listenForButton);
//        viewPasswordsButton.addActionListener(listenForButton);
//
//        panel1.add(msg1);
//        panel1.add(msg2);
//        /*msg1.setHorizontalAlignment(SwingConstants.LEFT);
//        msg2.setHorizontalAlignment(SwingConstants.LEFT);
//        msg2.setVerticalAlignment(SwingConstants.BOTTOM);*/
//
//        panel1.add(enterUsernameTextField);
//        panel1.add(enterPasswordTextField);
//        panel1.add(nameTextField);
//        panel1.add(display);
//
//        enterUsernameTextField.setHorizontalAlignment(SwingConstants.RIGHT);
//        enterPasswordTextField.setHorizontalAlignment(SwingConstants.RIGHT);
//
//        panel1.add(addPasswordButton);
//        panel1.add(deletePasswordButton);
//        panel1.add(viewPasswordsButton);
//        this.add(panel1);
    }

    public static void main(String[] args) throws UnsupportedLookAndFeelException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        PasswordVault vault = new PasswordVault();
        vault.start();
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

        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
        } catch (UserDoesNotExistException ue) {
            loginPanel.invalidLogin();
        }
    }

    public void logout() {
        loginPanel = new LoginPanel(this);
        frame.revalidate();
    }

    class Listener implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == addPasswordButton) {
                display.setText("Will add record");
            } else if (e.getSource() == deletePasswordButton) {
                display.setText("Will delete record");
            } else if (e.getSource() == viewPasswordsButton) {
                display.setText("Will display records");
            }
        }
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

//class VaultPanel extends JPanel {
//    VaultPanel(String user, String masterKey, Frame frame, Vault vault) {
//        this.add(new JLabel(user));
//        this.add(new JLabel(masterKey));
//
//        JButton logout = new JButton("Logout");
//        logout.setAlignmentX(Component.CENTER_ALIGNMENT);
//        logout.addActionListener(e -> {
//            frame.setContentPane(new LoginPanel(frame));
//            frame.revalidate();
//        });
//        this.add(logout);
//    }
//}