import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class PasswordVault extends JFrame {

    /**
     * LoginPanel is the initial view of the app frame.
     */
    static class LoginPanel extends JPanel {
        LoginPanel(PasswordVault frame) {
            this.setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

            /*
            Username entry
             */
            JPanel username = new JPanel();
            username.add(new JLabel("Username"));
            JTextField usernameField = new JTextField(20);
            username.add(usernameField);
            this.add(username);

            this.add(Box.createRigidArea(new Dimension(0, 5)));

            /*
            Password entry
             */
            JPanel password = new JPanel();
            password.add(new JLabel("Password"));
            JPasswordField passwordField = new JPasswordField(20);
            passwordField.addActionListener(e -> {
                login(usernameField.getText(), new String(passwordField.getPassword()), frame);
            });
            password.add(passwordField);

            this.add(password);

            this.add(Box.createRigidArea(new Dimension(0, 20)));

            /*
            Login button
             */
            JButton login = new JButton("Login");
            login.addActionListener(e -> {
                login(usernameField.getText(), new String(passwordField.getPassword()), frame);
            });
            login.setAlignmentX(Component.CENTER_ALIGNMENT);
            this.add(login);

            /*
            Ensures a constant spacing between the username, password, and login areas by adding invisible at the bottom of the window
             */
            this.add(new Box.Filler(
                new Dimension(0, 0),
                new Dimension(0, Short.MAX_VALUE),
                new Dimension(0, Short.MAX_VALUE)));

        }

        private void login(String user, String masterKey, PasswordVault frame) {
            Vault vault;
            try {
                vault = frame.client.retrieveVault(user, masterKey);
            } catch (Exception e) {

            }
            frame.setContentPane(new VaultPanel(user, masterKey, frame, null));
            frame.revalidate();
        }
    }

    static class VaultPanel extends JPanel {
        VaultPanel(String user, String masterKey, PasswordVault frame, Vault vault) {
            this.add(new JLabel(user));
            this.add(new JLabel(masterKey));

            JButton logout = new JButton("Logout");
            logout.setAlignmentX(Component.CENTER_ALIGNMENT);
            logout.addActionListener(e -> {
                frame.setContentPane(new LoginPanel(frame));
                frame.revalidate();
            });
            this.add(logout);
        }
    }

    private JButton    addPasswordButton;
    private JButton    viewPasswordsButton;
    private JButton    deletePasswordButton;
    private JTextField enterUsernameTextField;
    private JTextField enterPasswordTextField;
    private JTextField nameTextField;
    private JTextField display;
    private JLabel     msg1;
    private JLabel     msg2;
    JFrame       frame = new JFrame("My First Gui");

    VaultManager vaultManager;
    Client       client;

    public PasswordVault() {
        this.setContentPane(new LoginPanel(this));
        vaultManager = new VaultManager();
        client = new Client(vaultManager);
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

    public void start() {
        this.setTitle("Password Vault");
        this.setSize(600, 400);
        this.setVisible(true);
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }

    public static void main(String[] args) {
        PasswordVault vault = new PasswordVault();
        vault.start();
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
