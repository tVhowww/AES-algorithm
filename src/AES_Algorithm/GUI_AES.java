package AES_Algorithm;

import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

import java.awt.Font;
import javax.swing.SwingConstants;
import java.awt.SystemColor;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.Color;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.JButton;
import javax.swing.border.CompoundBorder;
import javax.swing.border.LineBorder;
import java.nio.charset.Charset;
import java.util.*;

public class GUI_AES extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	private JTextField txtKey;
	private JTextArea txtAPlaintxt, txtACiphertxt;
	private JButton btnEncrypt, btnDecrypt;
	private JLabel lblTitle, lblPlainText, lblKey, lblCipherText;
	private JButton btnRefresh;
	private JButton btnCopy1;
	private JButton btnCopy2;
	private static byte[] encrypt;
	private static byte[] decrypt;
	private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GUI_AES frame = new GUI_AES();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public GUI_AES() {
		setTitle("AES Algorithm");
		setResizable(false);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 917, 601);
		setLocationRelativeTo(null);
		contentPane = new JPanel();
		contentPane.setBackground(SystemColor.menu);
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));

		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		lblTitle = new JLabel("NHÓM 3 - AES ALGORITHM");
		lblTitle.setBounds(5, 5, 891, 80);
		lblTitle.setOpaque(true);
		lblTitle.setBorder(new EmptyBorder(24, 0, 24, 0));
		lblTitle.setBackground(new Color(19, 62, 135));
		lblTitle.setForeground(new Color(213, 213, 145));
		lblTitle.setHorizontalAlignment(SwingConstants.CENTER);
		lblTitle.setFont(new Font("MS Reference Sans Serif", Font.BOLD, 25));
		contentPane.add(lblTitle);
		
		btnRefresh = new JButton("Refresh");
		btnRefresh.setForeground(new Color(223, 223, 172));
		btnRefresh.setBackground(new Color(19, 62, 135));
		btnRefresh.setFont(new Font("Segoe UI", Font.PLAIN, 16));
		btnRefresh.setBounds(740, 95, 150, 36);
		btnRefresh.setFocusPainted(false);
		contentPane.add(btnRefresh);
		
		lblPlainText = new JLabel("Input");
		lblPlainText.setForeground(new Color(19, 62, 135));
		lblPlainText.setFont(new Font("Segoe UI", Font.BOLD, 18));
		lblPlainText.setBounds(96, 136, 91, 36);
		contentPane.add(lblPlainText);
		
		lblKey = new JLabel("Key");
		lblKey.setForeground(new Color(19, 62, 135));
		lblKey.setFont(new Font("Segoe UI", Font.BOLD, 18));
		lblKey.setBounds(96, 241, 91, 36);
		contentPane.add(lblKey);
		
		txtKey = new JTextField();
		txtKey.setBorder(new CompoundBorder(new LineBorder(new Color(160, 160, 160), 1, true), new EmptyBorder(0, 5, 0, 0)));
		txtKey.setColumns(10);
		txtKey.setBounds(212, 245, 512, 36);
		contentPane.add(txtKey);
		
		txtAPlaintxt = new JTextArea();
		txtAPlaintxt.setBorder(new CompoundBorder(new LineBorder(new Color(160, 160, 160), 1, true), new EmptyBorder(5, 5, 0, 0)));
		txtAPlaintxt.setBounds(212, 136, 512, 88);
		contentPane.add(txtAPlaintxt);
		
		btnCopy1 = new JButton("Copy");
		btnCopy1.setForeground(new Color(223, 223, 172));
		btnCopy1.setBackground(new Color(19, 62, 135));
		btnCopy1.setFont(new Font("Segoe UI", Font.PLAIN, 12));
		btnCopy1.setBounds(674+50, 136+88-30, 68, 30);
		btnCopy1.setFocusPainted(false);
		contentPane.add(btnCopy1);
		
		btnEncrypt = new JButton("Encrypt");
		btnEncrypt.setForeground(new Color(223, 223, 172));
		btnEncrypt.setBackground(new Color(19, 62, 135));
		btnEncrypt.setFont(new Font("Segoe UI", Font.PLAIN, 16));
		btnEncrypt.setBounds(212, 324, 181, 36);
		btnEncrypt.setFocusPainted(false);
		contentPane.add(btnEncrypt);
		
		btnDecrypt = new JButton("Decrypt");
		btnDecrypt.setForeground(new Color(223, 223, 172));
		btnDecrypt.setBackground(new Color(19, 62, 135));
		btnDecrypt.setFont(new Font("Segoe UI", Font.PLAIN, 16));
		btnDecrypt.setBounds(543, 324, 181, 36);
		btnDecrypt.setFocusPainted(false);
		contentPane.add(btnDecrypt);
		
		lblCipherText = new JLabel("Output");
		lblCipherText.setForeground(new Color(19, 62, 135));
		lblCipherText.setFont(new Font("Segoe UI", Font.BOLD, 18));
		lblCipherText.setBounds(96, 396, 99, 36);
		contentPane.add(lblCipherText);
		
		txtACiphertxt = new JTextArea();
		txtACiphertxt.setBorder(new CompoundBorder(new LineBorder(new Color(160, 160, 160), 1, true), new EmptyBorder(5, 5, 0, 0)));
		txtACiphertxt.setBounds(212, 396, 512, 133);
		contentPane.add(txtACiphertxt);
		
		btnCopy2 = new JButton("Copy");
		btnCopy2.setForeground(new Color(223, 223, 172));
		btnCopy2.setBackground(new Color(19, 62, 135));
		btnCopy2.setFont(new Font("Segoe UI", Font.PLAIN, 12));
		btnCopy2.setBounds(674+50, 396+133-30, 68, 30);
		btnCopy2.setFocusPainted(false);
		contentPane.add(btnCopy2);
		
		// xử lý sự kiện button
		btnEncrypt.addActionListener(e -> xuLyMaHoa());
		btnDecrypt.addActionListener(e -> xuLyGiaiMa());
		btnRefresh.addActionListener(e -> xuLyLamMoi());
		btnCopy1.addActionListener(e -> xuLyCopyInput());
		btnCopy2.addActionListener(e -> xuLyCopyOutput());
		
	}
	
	private Object xuLyCopyInput() {
		String input = txtAPlaintxt.getText();
        handleClipSave(input);
		return null;
	}
	
	private Object xuLyCopyOutput() {
		String output = txtACiphertxt.getText();
        handleClipSave(output);
		return null;
	}
	
	public void handleClipSave(String textToCopy) {
        StringSelection selection = new StringSelection(textToCopy);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, null);
    }

	private Object xuLyLamMoi() {
		txtACiphertxt.setText("");
        txtKey.setText("");
        txtAPlaintxt.setText("");
		return null;
	}

	// ma hoa mang byte sang chuoi ky tu theo base64
	public static String encode(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}
	
	// giai ma base64 ve du lieu goc
	public static byte[] decode(String base64) {
		return Base64.getDecoder().decode(base64);
	}
	
	// định dạng chiều dài khóa theo 16, 24 ,32 byte
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
	
	
	private void xuLyMaHoa() {
		// lấy bản rõ và khóa
		String plainText = txtAPlaintxt.getText();
		String k = new String(txtKey.getText());
		// kiểm tra khoa
		if (k.equals("")) {
			JOptionPane.showMessageDialog(null, "Chưa nhập khóa.");
			return;
		}
		if (k.length() != 16) {
			k = addKey(k);
		}
		encrypt = AES.encrypt(plainText.getBytes(), k.getBytes());
		String cipherText = encode(encrypt);
		// cập nhật chuoi đã mã hóa
		txtACiphertxt.setText(cipherText);

	}
	
	private void xuLyGiaiMa() {
		// lấy văn bản đã mã hóa 
		String encryptedString = txtAPlaintxt.getText();
		String k = new String(txtKey.getText());
		if (k.equals("")) {
			JOptionPane.showMessageDialog(null, "Chưa nhập khóa!");
			return;
		}
		k = addKey(k);
		// giải mã văn bản đã mã hóa
		try {
			// sử dụng Base64 để giải mã chuỗi đã mã hóa thành mảng byte để giải mã
			byte[] encryptedBytes = decode(encryptedString);
			decrypt = AES.decrypt(encryptedBytes, k.getBytes());			
			// cập nhật văn bản đã giải mã
			txtACiphertxt.setText(String.valueOf(new String(decrypt, UTF8_CHARSET)));
		} catch (Exception e) {
			JOptionPane.showMessageDialog(null, "Giải mã không thành công!");
		}
	}
	
}
