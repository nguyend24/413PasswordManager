import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;



public class PasswordVault {

    private final JFrame     frame;
    private LoginPanel loginPanel;


    public PasswordVault() throws UnsupportedLookAndFeelException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        frame = new JFrame();
        frame.setTitle("Password Vault");
        frame.setSize(800, 400);
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
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException ex) {
            ex.printStackTrace();
        } catch (UserDoesNotExistException | InvalidPasswordException il) {
            loginPanel.invalidLogin();
        }
    }
    public void createNewUser(){

        newUserPanel newUser = new newUserPanel(this);

        this.frame.setContentPane(newUser);
        this.frame.revalidate();
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
        newUser.addActionListener(e-> passwordVault.createNewUser());
        newUser.setAlignmentX(Component.RIGHT_ALIGNMENT);
        login1.add(newUser);

        this.add(login1);
    }
}

class newUserPanel extends JPanel{
    private final PasswordVault frame;
    newUserPanel(PasswordVault frame){
        this.frame = frame;
        this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        JPanel newUserDisplay = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 10));
        JPanel password = new JPanel();
        JPanel username = new JPanel();
        JPanel actionButtons = new JPanel();
        JButton create = new JButton("Create Vault");
        JLabel createUsername = new JLabel("Enter Username: ");
        JTextField userNameField = new JTextField(20);
        username.add(createUsername);
        username.add(userNameField);
        JLabel createMasterPassword = new JLabel("Enter Password: ");
        JPasswordField passWordField = new JPasswordField(20);
        password.add(createMasterPassword);
        password.add(passWordField);


        create.setAlignmentX(Component.CENTER_ALIGNMENT);
            create.addActionListener(e -> {
                try {
                    createNewUser(userNameField.getText(), new String(passWordField.getPassword()));
                } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                    ex.printStackTrace();
                }
            });
            create.addActionListener((e-> {
                try {
                    successfulNewUser(frame);
                } catch (InterruptedException ex) {
                    ex.printStackTrace();
                }
            }));
        actionButtons.add(create);




        JButton logout = new JButton("Back");
        logout.setAlignmentX(Component.CENTER_ALIGNMENT);
        logout.addActionListener(e -> frame.logout());
        actionButtons.add(logout);

        newUserDisplay.add(username);
        newUserDisplay.add(password);
        newUserDisplay.add(actionButtons);

        this.add(newUserDisplay, BorderLayout.WEST);
        newUserDisplay.revalidate();
    }

        //Message to be displayed if vault creation is successful
    void successfulNewUser(PasswordVault frame) throws InterruptedException {
        this.removeAll();

        this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        JPanel successfulUserDisplay = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 10));

        JLabel successfulCreation = new JLabel("Vault successfully created! Please go back and re-login");
        successfulCreation.setAlignmentX(Component.CENTER_ALIGNMENT);
        successfulCreation.setForeground(Color.GREEN);
        successfulUserDisplay.add(successfulCreation);

        JButton logout = new JButton("Back");
        logout.setAlignmentX(Component.CENTER_ALIGNMENT);
        logout.addActionListener(e -> frame.logout());
        successfulUserDisplay.add(logout);


        this.add(successfulUserDisplay, BorderLayout.WEST);
        successfulUserDisplay.revalidate();
    }


    void createNewUser(String username, String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        Client c = new Client(username, password);
        c.createNewVault();
    }

}

/***
 * Michael: Displays value and its respective password
 */
class VaultPanel extends JPanel {


    private final DefaultListModel<String> sitesListModel;
    private final JList<String> sitesList;

    private final DefaultListModel<String> usernamesListModel;
    private final JList<String> usernamesList;

    private DefaultListModel<String> passwordsListModel;
    private final JList<String> passwordsList;

    VaultPanel(String user, String masterKey, PasswordVault frame, Client client) throws InvalidPasswordException, UserDoesNotExistException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {

        this.setLayout(new BorderLayout());
        JPanel vaultDisplay = new JPanel(new FlowLayout(FlowLayout.CENTER, 0, 10));

        Vault v = client.retrieveVault();

        sitesListModel = new DefaultListModel<>();
        v.getAccounts().keySet().forEach(sitesListModel::addElement);
        sitesList = new JList<>(sitesListModel);

        usernamesListModel = new DefaultListModel<>();
        v.getAccounts().values().forEach(u -> usernamesListModel.addElement(u[0]));
        usernamesList = new JList<>(usernamesListModel);

        passwordsListModel = new DefaultListModel<>();
        v.getAccounts().values().forEach(u -> passwordsListModel.addElement(u[1]));
        passwordsList = new JList<>(passwordsListModel);

        sitesList.addListSelectionListener(e -> synchronizeSelection(sitesList.getSelectedIndex()));
        usernamesList.addListSelectionListener(e -> synchronizeSelection(usernamesList.getSelectedIndex()));
        passwordsList.addListSelectionListener(e -> synchronizeSelection(passwordsList.getSelectedIndex()));

        Dimension listDimension = new Dimension(200, frame.getFrame().getHeight());
        System.out.println(this.getHeight());

        JScrollPane siteScroller = new JScrollPane(sitesList);
        siteScroller.setPreferredSize(listDimension);
        JScrollBar siteScrollBar = siteScroller.getVerticalScrollBar();

        JScrollPane usernameScroller = new JScrollPane(usernamesList);
        usernameScroller.setPreferredSize(listDimension);
        usernameScroller.setVerticalScrollBar(siteScrollBar);

        JScrollPane passwordScroller = new JScrollPane(passwordsList);
        passwordScroller.setPreferredSize(listDimension);
        passwordScroller.setVerticalScrollBar(siteScrollBar);

        vaultDisplay.add(siteScroller);
        vaultDisplay.add(usernameScroller);
        vaultDisplay.add(passwordScroller);
        /**
        JLabel usernameColumn = new JLabel("Usernames");
        JLabel passwordColumn = new JLabel("Passwords");
        JLabel websiteColumn = new JLabel("Websites");
        vaultDisplay.add(usernameColumn);
        vaultDisplay.add(passwordColumn);
        vaultDisplay.add(websiteColumn);
        **/
        vaultDisplay.add(new Box.Filler(
            new Dimension(0, 0),
            new Dimension(25, this.getHeight()),
            new Dimension(25, this.getHeight())
        ));

        this.add(vaultDisplay, BorderLayout.CENTER);

        this.add(new Box.Filler(
            new Dimension(0, 0),
            new Dimension(1, 15),
            new Dimension(5, 15)),BorderLayout.PAGE_END);

        JPanel actionButtons = new JPanel();
        actionButtons.setLayout(new BoxLayout(actionButtons, BoxLayout.Y_AXIS));


        JButton logout = new JButton("Logout");
        logout.setAlignmentX(Component.CENTER_ALIGNMENT);
        logout.addActionListener(e -> frame.logout());
        actionButtons.add(logout);

        JButton addEntry = new JButton("Add Entry");
        addEntry.setAlignmentX(Component.CENTER_ALIGNMENT);
        addEntry.addActionListener(e -> {
            JTextField siteIdentifier = new JTextField(15);
            JTextField username = new JTextField(15);
            JTextField password = new JTextField(15);

            JPanel newEntryInfo = new JPanel();
            newEntryInfo.add(new JLabel("Site Indentifier"));
            newEntryInfo.add(siteIdentifier);
            newEntryInfo.add(new JLabel("Username"));
            newEntryInfo.add(username);
            newEntryInfo.add(new JLabel("Password"));
            newEntryInfo.add(password);

            int result = JOptionPane.showConfirmDialog(null, newEntryInfo, "Enter Account information", JOptionPane.OK_CANCEL_OPTION);
            if (result == JOptionPane.OK_OPTION) {
                try {
                    client.addVaultEntry(siteIdentifier.getText(), username.getText(), password.getText());
                    sitesListModel.addElement(siteIdentifier.getText());
                    usernamesListModel.addElement(username.getText());
                    passwordsListModel.addElement(password.getText());
                } catch (NoSuchPaddingException | UserDoesNotExistException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException ex) {
                    ex.printStackTrace();
                } catch (InvalidPasswordException ip) {
                    JOptionPane.showConfirmDialog(null, "Password does not meet requirements", "Password does not meet requirements", JOptionPane.DEFAULT_OPTION);
                    ip.printStackTrace();
                }
            }

            vaultDisplay.revalidate();
        });
        actionButtons.add(addEntry);

        JButton removeEntry = new JButton("Remove Entry");
        removeEntry.setAlignmentX(Component.CENTER_ALIGNMENT);
        removeEntry.addActionListener(e -> {
            try {
                client.removeVaultEntry(sitesList.getSelectedValue());
            } catch (UserDoesNotExistException | InvalidPasswordException | IllegalBlockSizeException | NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException ex) {
                ex.printStackTrace();
            }

            sitesListModel.removeElementAt(sitesList.getSelectedIndex());
            usernamesListModel.removeElementAt(usernamesList.getSelectedIndex());
            passwordsListModel.removeElementAt(passwordsList.getSelectedIndex());

            frame.revalidate();
        });
        actionButtons.add(removeEntry);

        //Button for copying the username for the selected entry to the clipboard
        JButton copyUsername = new JButton("Copy Username");
        copyUsername.setAlignmentX(Component.CENTER_ALIGNMENT);
        copyUsername.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(usernamesList.getSelectedValue()), null));
        actionButtons.add(copyUsername);

        //Button for copying the password for the selected entry to the clipboard
        JButton copyPassword = new JButton("Copy Password");
        copyPassword.setAlignmentX(Component.CENTER_ALIGNMENT);
        copyPassword.addActionListener(e -> Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(passwordsList.getSelectedValue()), null));
        actionButtons.add(copyPassword);

        this.add(actionButtons, BorderLayout.LINE_END);
        JButton deleteUser = new JButton("Delete User");
        deleteUser.setAlignmentX(Component.CENTER_ALIGNMENT);
        deleteUser.addActionListener(e-> {
            try {
                deleteUser(user, client, frame);
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        actionButtons.add(deleteUser);
    }

    private void synchronizeSelection(int index) {
        sitesList.setSelectedIndex(index);
        usernamesList.setSelectedIndex(index);
        passwordsList.setSelectedIndex(index);
    }

    private void deleteUser(String user, Client client, PasswordVault frame) throws IOException {
        client.deleteVault(user);
        frame.logout();
    }
}
