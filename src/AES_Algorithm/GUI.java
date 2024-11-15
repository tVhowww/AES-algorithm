package AES_Algorithm;

import javax.swing.*;
import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Base64;

public class GUI extends JFrame {
	private static final long serialVersionUID = 3778240298089605001L;
//	private static final char[] BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
	private static final String BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	private JTextField txtInputText, txtInputKey;
	private JLabel lblTextInput, lblKeyInput, lblEncrypt, lblDecrypt;
	private JButton btnEncrypt, btnDecrypt, btnReset;
	private JTextArea txtAEncypt, txtADecrypt;
	private static byte[] encrypt;
	private static byte[] decrypt;

	// Hàm main
	public static void main(String[] args) {
		new GUI().setVisible(true);
	}

	// Tạo giao diện
	public void CreateGUI() {

		// Tạo frame
		// Đường dẫn của icon
		String iconPath = "D:\\Nam_3_2024_2025\\Ki_I\\NMATTT\\code-tham-khao\\AES-RSA-Algorithm-main\\Nhom1_ATTT\\src\\IMG\\one.png";
		String iconPath2 = "D:\\Nam_3_2024_2025\\Ki_I\\NMATTT\\code-tham-khao\\AES-RSA-Algorithm-main\\Nhom1_ATTT\\src\\IMG\\data-encryption.png";
		String iconPath3 = "D:\\Nam_3_2024_2025\\Ki_I\\NMATTT\\code-tham-khao\\AES-RSA-Algorithm-main\\Nhom1_ATTT\\src\\IMG\\decrypt-data.png";
		String iconPath4 = "D:\\Nam_3_2024_2025\\Ki_I\\NMATTT\\code-tham-khao\\AES-RSA-Algorithm-main\\Nhom1_ATTT\\src\\IMG\\refresh.png";
		// Tạo một ImageIcon từ đường dẫn
		ImageIcon icon = new ImageIcon(iconPath);
		ImageIcon icon2 = new ImageIcon(iconPath2);
		ImageIcon icon3 = new ImageIcon(iconPath3);
		ImageIcon icon4 = new ImageIcon(iconPath4);
		// Thiết lập icon cho frame
		setIconImage(icon.getImage());
		setTitle("DEMO");
		setSize(800, 500);
		setLocationRelativeTo(null);
		setResizable(false);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		// Tạo các đối tượng trong frame
		Dimension dms = new Dimension(100, 30);
		lblTextInput = new JLabel("Plain text: ");
		lblTextInput.setFont(new Font("Arial", Font.BOLD, 15));
		txtInputText = new JTextField();
		txtInputText.setPreferredSize(dms);
		lblKeyInput = new JLabel("Key: ");
		lblKeyInput.setFont(new Font("Arial", Font.BOLD, 15));
		txtInputKey = new JTextField();
		txtInputKey.setPreferredSize(dms);
		lblEncrypt = new JLabel("Encrypted Text: ");
		lblEncrypt.setFont(new Font("Arial", Font.BOLD, 15));
		txtAEncypt = new JTextArea(10, 10);
		txtAEncypt.setBorder(BorderFactory.createLineBorder(Color.BLACK));
		txtAEncypt.setLineWrap(true);
		lblDecrypt = new JLabel("Decrypted Text: ");
		lblDecrypt.setFont(new Font("Arial", Font.BOLD, 15));
		txtADecrypt = new JTextArea(10, 18);
		txtADecrypt.setBorder(BorderFactory.createLineBorder(Color.BLACK));
		txtADecrypt.setLineWrap(true);
		btnEncrypt = new JButton("Encrypt", icon2);
		btnEncrypt.setFont(new Font("Arial", Font.BOLD, 15));
		btnDecrypt = new JButton("Decrypt", icon3);
		btnDecrypt.setFont(new Font("Arial", Font.BOLD, 15));
		btnReset = new JButton(icon4);
		btnReset.setFont(new Font("Arial", Font.BOLD, 15));

		// Title ( North )
		Label lblTitle = new Label("GROUP 4 - AES Algorithm");
		lblTitle.setFont(new Font("Arial", Font.BOLD, 25));
		lblTitle.setForeground(Color.decode("#191970"));
		lblTitle.setAlignment(Label.CENTER);
		lblTitle.setBackground(Color.decode("#B0E0E6"));
		this.add(lblTitle, BorderLayout.NORTH);

		// Content ( Center )
		// use set bounds
		JPanel panelCenter = new JPanel();
		panelCenter.setBackground(Color.decode("#F8F8FF"));
		panelCenter.setLayout(null);
		this.add(panelCenter, BorderLayout.CENTER);

		// text input and key input
		lblTextInput.setBounds(20, 50, 100, 30);
		txtInputText.setBounds(100, 50, 280, 30);
		lblKeyInput.setBounds(420, 50, 100, 30);
		txtInputKey.setBounds(500, 50, 280, 30);
		panelCenter.add(lblTextInput);
		panelCenter.add(txtInputText);
		panelCenter.add(lblKeyInput);
		panelCenter.add(txtInputKey);

		// encrypt and decrypt button
		btnEncrypt.setBounds(260, 100, 120, 30);
		btnEncrypt.setToolTipText("Button to encrypt text");
		btnDecrypt.setBounds(660, 100, 120, 30);
		btnDecrypt.setToolTipText("Button to decrypt text");
		panelCenter.add(btnEncrypt);
		panelCenter.add(btnDecrypt);

		// encrypt text
		lblEncrypt.setBounds(20, 150, 150, 30);
		txtAEncypt.setBounds(20, 180, 360, 180);
		panelCenter.add(lblEncrypt);
		panelCenter.add(txtAEncypt);

		// decrypt text
		lblDecrypt.setBounds(420, 150, 150, 30);
		txtADecrypt.setBounds(420, 180, 360, 180);
		panelCenter.add(lblDecrypt);
		panelCenter.add(txtADecrypt);

		// south
		Label lblFooter = new Label("© 2024 - Group 4 - Nhap mon An toan thong tin - IUH");
		lblFooter.setFont(new Font("Arial", Font.BOLD, 12));
		lblFooter.setForeground(Color.decode("#191970"));
		lblFooter.setAlignment(Label.CENTER);
		lblFooter.setBackground(Color.decode("#B0E0E6"));
		this.add(lblFooter, BorderLayout.SOUTH);

		// reload button
		btnReset.setBounds(750, 10, 30, 30);
		btnReset.setToolTipText("Reset all fields");
		btnReset.setBorder(null);
		panelCenter.add(btnReset);

	}

	// Hàm gọi các sự kiện
	public GUI() {
		CreateGUI();
		btnEncrypt.addActionListener(e -> xuLyMaHoa());
		btnDecrypt.addActionListener(e -> xuLyGiaiMa());
		btnReset.addActionListener(e -> xuLyReset());
	}

	private void xuLyReset() {
		txtInputText.setText("");
		txtInputKey.setText("");
		txtAEncypt.setText("");
		txtADecrypt.setText("");
		txtInputText.requestFocus();
	}

	// hàm xử lý khi nhấn nút mã hóa
	private void xuLyMaHoa() {
		// lấy văn bản rõ và khóa từ text field
		String explainText = txtInputText.getText();
		String k = new String(txtInputKey.getText());
		// kiểm tra khoa
		if (k.equals("")) {
			JOptionPane.showMessageDialog(null, "Vui lòng nhập khóa!");
			return;
		}
		if (k.length() != 16) {
			k = addKey(k);
		}
		encrypt = AES.encrypt(explainText.getBytes(), k.getBytes());
		String encryptedString = encode(encrypt);
		// cập nhật văn bản đã mã hóa
		txtAEncypt.setText(encryptedString);

	}

	// hàm xử lý khi nhấn nút giải mã
	private void xuLyGiaiMa() {
		// lấy văn bản đã mã hóa và khóa từ frame
		String encryptedString = txtAEncypt.getText();
		String k = new String(txtInputKey.getText());
		k = addKey(k);
		// giải mã văn bản đã mã hóa
		// sử dụng Base64 để giải mã chuỗi đã mã hóa thành mảng byte để giải mã
		byte[] encryptedBytes = decode(encryptedString);
		decrypt = AES.decrypt(encryptedBytes, k.getBytes());
		// cập nhật văn bản đã giải mã
		txtADecrypt.setText(String.valueOf(new String(decrypt, UTF8_CHARSET)));
	}

	public static String addKey(String key) {
		int length = key.length();
		if (length < 16) {
			for (int i = length; i < 16; i++) {
				key += "\0";
			}
		} else if (length > 16 && length < 24) {
			for (int i = length; i < 24; i++) {
				key += "\0";
			}
		} else if (length > 24 && length < 32) {
			for (int i = length; i < 32; i++) {
				key += "\0";
			}
		} else if (length > 32) {
			key = key.substring(0, 32);
		}
		return key;
	}

	// hàm Base64 để mã hóa và giải mã dữ liệu văn bản sang mảng byte và ngược lại
	public static String encode(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	public static byte[] decode(String base64) {
		return Base64.getDecoder().decode(base64);
	}

}
