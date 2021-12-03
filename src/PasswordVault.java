import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.*;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;


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

    public static void main(String[] args) throws UnsupportedLookAndFeelException, ClassNotFoundException, InstantiationException, IllegalAccessException, FileNotFoundException {
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
            VaultPanel vp = new VaultPanel(user, password, this, client);
            this.frame.setContentPane(vp);
            this.frame.revalidate();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
        } catch (UserDoesNotExistException | InvalidPasswordException il) {
            loginPanel.invalidLogin();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public void logout() {
        loginPanel = new LoginPanel(this);
        frame.setContentPane(loginPanel);
        frame.revalidate();
    }

    public JFrame getFrame() {
        return frame;
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
        JPanel login1 = new JPanel();
        JButton login = new JButton("Login");
        login.addActionListener(e -> passwordVault.login(usernameField.getText(), new String(passwordField.getPassword())));
        login.setAlignmentX(Component.CENTER_ALIGNMENT);
        login1.add(login);

        /*
        New user button
         */
        JButton newUser = new JButton("New User");
        newUser.setAlignmentX(Component.RIGHT_ALIGNMENT);
        login1.add(newUser);

        this.add(login1);
    }
}

/***
 * Michael: Displays value and its respective password
 */
class VaultPanel extends JPanel {

    ArrayList<String> info;
    ArrayList<String> keyInfo;
    JLabel displayKey;
    JLabel displayPwd;

    private JList<String> sites;
    private JList<String> passwords;

    VaultPanel(String user, String masterKey, PasswordVault frame, Client client) throws InvalidPasswordException, UserDoesNotExistException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
//        client.retrieveVault();
//        this.add(new JLabel(user));
//        this.add(new JLabel(masterKey));
//        info = client.printPasswords();
//        keyInfo = client.printKeys();
//        for(int i = 0; i < info.size(); i++){
//            displayKey = new JLabel(keyInfo.get(i));
//            this.add(displayKey, BorderLayout.NORTH);
//            displayPwd = new JLabel(info.get(i));
//            this.add(displayPwd, BorderLayout.SOUTH);
//        }

        this.setLayout(new FlowLayout(FlowLayout.CENTER, 0, 10));
        Vault v = client.retrieveVault();

        sites = new JList<>(v.getAccounts().keySet().toArray(new String[0]));
        passwords = new JList<>(v.getAccounts().values().toArray(new String[0]));

        sites.addListSelectionListener(e -> synchronizeSelection(sites.getSelectedIndex()));
        passwords.addListSelectionListener(e -> synchronizeSelection(passwords.getSelectedIndex()));

        Dimension listDimension = new Dimension(200, frame.getFrame().getHeight());
        System.out.println(this.getHeight());

        JScrollPane siteScroller = new JScrollPane(sites);
        siteScroller.setPreferredSize(listDimension);
        JScrollBar siteScrollBar = siteScroller.getVerticalScrollBar();

        JScrollPane passwordScroller = new JScrollPane(passwords);
        passwordScroller.setPreferredSize(listDimension);
        passwordScroller.setVerticalScrollBar(siteScrollBar);

        this.add(siteScroller);
        this.add(passwordScroller);

        this.add(new Box.Filler(
            new Dimension(0, 0),
            new Dimension(25, this.getHeight()),
            new Dimension(25, this.getHeight())
        ));
        JButton logout = new JButton("Logout");
        logout.setAlignmentX(Component.CENTER_ALIGNMENT);
        logout.addActionListener(e -> frame.logout());
        this.add(logout);
    }

    private void synchronizeSelection(int index) {
        sites.setSelectedIndex(index);
        passwords.setSelectedIndex(index);
    }
}

class NewUserPanel extends JPanel{
    public NewUserPanel() {

    }
}