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

        // ���ý���ɼ�
        frame.setVisible(true);
    }

    private static void placeComponents(JPanel panel){
        panel.setLayout(null);
        JLabel userLabel = new JLabel("�û���:");
        userLabel.setBounds(10,20,80,25);
        panel.add(userLabel);

        JTextField userText = new JTextField(20);
        userText.setBounds(100,20,200,25);
        panel.add(userText);

        JLabel passwordLabel = new JLabel("ע����:");
        passwordLabel.setBounds(10,50,80,25);
        panel.add(passwordLabel);

        JTextField passwordText = new JTextField(20);
        passwordText.setBounds(100,50,200,25);
        passwordText.setEditable(false);
        panel.add(passwordText);

        JButton Button = new JButton("����");
        Button.setBounds(10, 80, 80, 25);
        Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String UserName=userText.getText();
                int length=UserName.length()+5;
                String res="��ͷSun Bird"+String.valueOf(length)+"dseloffc-012-OK"+UserName;
                passwordText.setText(res);
            }
        });
        panel.add(Button);
        String s="Tips�� ϵͳ��������Ƿ������룬ճ��ע������û����̣�֮��˫�����ٵ���";
        JTextArea Help=new JTextArea(s);
        Help.setBounds(10,110,280,40);
        Help.setLineWrap(true);
        Help.setEditable(false);
        Help.setForeground(Color.red);
        panel.add(Help);
    }

}
