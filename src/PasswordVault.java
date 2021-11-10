import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class PasswordVault extends JFrame{

    private JButton addPasswordButton;
    private JButton viewPasswordsButton;
    private JButton deletePasswordButton;
    private JTextField enterUsernameTextField;
    private JTextField enterPasswordTextField;
    private JTextField nameTextField;
    private JTextField display;
    private JLabel msg1;
    private JLabel msg2;
    JFrame frame = new JFrame("My First Gui");

    public PasswordVault() {
        JPanel panel1 = new JPanel();
        addPasswordButton = new JButton("Add Password");
        deletePasswordButton = new JButton("Delete Password");
        viewPasswordsButton = new JButton("View Passwords");
        enterUsernameTextField = new JTextField(20);
        enterPasswordTextField = new JTextField(20);
        nameTextField = new JTextField(20);
        display = new JTextField(20);
        msg1 = new JLabel("Enter username: ");
        msg2 = new JLabel("Enter password: ");



        Listener listenForButton = new Listener();
        addPasswordButton.addActionListener(listenForButton);
        deletePasswordButton.addActionListener(listenForButton);
        viewPasswordsButton.addActionListener(listenForButton);

        panel1.add(msg1);
        panel1.add(msg2);
        /*msg1.setHorizontalAlignment(SwingConstants.LEFT);
        msg2.setHorizontalAlignment(SwingConstants.LEFT);
        msg2.setVerticalAlignment(SwingConstants.BOTTOM);*/

        panel1.add(enterUsernameTextField);
        panel1.add(enterPasswordTextField);
        panel1.add(nameTextField);
        panel1.add(display);

        enterUsernameTextField.setHorizontalAlignment(SwingConstants.RIGHT);
        enterPasswordTextField.setHorizontalAlignment(SwingConstants.RIGHT);

        panel1.add(addPasswordButton);
        panel1.add(deletePasswordButton);
        panel1.add(viewPasswordsButton);
        this.add(panel1);

    }
    public static void main(String[] args){
        PasswordVault vault = new PasswordVault();

        vault.setTitle("Password Vault");
        vault.setSize(600,400);
        vault.setVisible(true);
        vault.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
    class Listener implements ActionListener{

        @Override
        public void actionPerformed(ActionEvent e) {
            if(e.getSource() == addPasswordButton){
                display.setText("Will add record");
            }
            else if(e.getSource() == deletePasswordButton){
                display.setText("Will delete record");
            }
            else if(e.getSource() == viewPasswordsButton){
                display.setText("Will display records");
            }
        }
    }
}
