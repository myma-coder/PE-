import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class CrackE3 {

    public static void main(String[] args) {
        JFrame frame = new JFrame("Cracker");

        frame.setSize(350, 200);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();
        frame.add(panel);

        placeComponents(panel);

        // 设置界面可见
        frame.setVisible(true);
    }

    private static void placeComponents(JPanel panel){
        panel.setLayout(null);
        JLabel userLabel = new JLabel("用户名:");
        userLabel.setBounds(10,20,80,25);
        panel.add(userLabel);

        JTextField userText = new JTextField(20);
        userText.setBounds(100,20,200,25);
        panel.add(userText);

        JLabel passwordLabel = new JLabel("注册码:");
        passwordLabel.setBounds(10,50,80,25);
        panel.add(passwordLabel);

        JTextField passwordText = new JTextField(20);
        passwordText.setBounds(100,50,200,25);
        passwordText.setEditable(false);
        panel.add(passwordText);

        JButton Button = new JButton("生成");
        Button.setBounds(10, 80, 80, 25);
        Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String UserName=userText.getText();
                int length=UserName.length()+5;
                String res="黑头Sun Bird"+String.valueOf(length)+"dseloffc-012-OK"+UserName;
                passwordText.setText(res);
            }
        });
        panel.add(Button);
        String s="Tips： 系统会检测键盘是否有输入，粘贴注册码后敲击键盘，之后双击，再单击";
        JTextArea Help=new JTextArea(s);
        Help.setBounds(10,110,280,40);
        Help.setLineWrap(true);
        Help.setEditable(false);
        Help.setForeground(Color.red);
        panel.add(Help);
    }

}
