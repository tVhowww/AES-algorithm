package AES_Algorithm;

import java.util.Arrays;

public class AES {

	private static int Nb, Nk, Nr;
	private static byte[][] w;

	private static int[] sbox = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7,
			0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
			0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7,
			0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A,
			0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC,
			0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
			0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6,
			0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
			0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E,
			0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
			0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
			0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66,
			0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9,
			0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
			0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

	private static int[] inv_sbox = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81,
			0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9,
			0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08,
			0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6,
			0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD,
			0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3,
			0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1,
			0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF,
			0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C,
			0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE,
			0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F,
			0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F,
			0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE,
			0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6,
			0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

	private static final int[] Rcon = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

	public static final byte[][] galois = { { 0x02, 0x03, 0x01, 0x01 }, { 0x01, 0x02, 0x03, 0x01 },
			{ 0x01, 0x01, 0x02, 0x03 }, { 0x03, 0x01, 0x01, 0x02 } };

	public static final byte[][] invgalois = { { 0x0e, 0x0b, 0x0d, 0x09 }, { 0x09, 0x0e, 0x0b, 0x0d },
			{ 0x0d, 0x09, 0x0e, 0x0b }, { 0x0b, 0x0d, 0x09, 0x0e } };

	// Hàm generateKey để tạo khóa con từ khóa key
	private static byte[][] generateSubkeys(byte[] key) {
		byte[][] keyMatrix = new byte[Nb * (Nr + 1)][4];
		byte[] tmp = new byte[Nk];
		int index = 0;
		// Tạo khóa ban đầu từ khóa key
		for (int i = 0; i < Nk; i++) {
			keyMatrix[i][0] = key[index++];
			keyMatrix[i][1] = key[index++];
			keyMatrix[i][2] = key[index++];
			keyMatrix[i][3] = key[index++];
		}
		// Key expansion từ khóa ban đầu
		for (int i = Nk; i < Nb * (Nr + 1); i++) {
			for (int j = 0; j < 4; j++) {
				tmp[j] = keyMatrix[i - 1][j];
			}
			// Kiểm tra xem i có chia hết cho Nk không
			if (i % Nk == 0) {
				// Thực hiện gọi hàm rotWord ở trên
				tmp = rotWord(tmp);
				// Thực hiện gọi hàm subWord ở trên
				tmp = subWord(tmp);
				// Thực hiện XOR với Rcon[i/Nk]
				tmp[0] = (byte) (tmp[0] ^ (Rcon[i / Nk] & 0xff));
			}
			// XOR với subytes trước đó keyMatrix[i-Nk]
			for (int j = 0; j < Nb; j++) {
				keyMatrix[i][j] = (byte) (keyMatrix[i - Nk][j] ^ tmp[j]);
			}
		}
		// Trả về keyMatrix
		return keyMatrix;

	}

	// Hàm subWord để thay thế các byte trong một từ 4 byte bằng các giá trị tương
	// ứng từ bảng S-box
	private static byte[] subWord(byte[] input) {
		// Tạo một mảng mới để lưu kết quả
		byte[] output = new byte[input.length];

		for (int i = 0; i < output.length; i++) {
			// Lấy byte hiện tại
			byte currentByte = input[i];

			// Thay thế byte hiện tại bằng giá trị tương ứng từ bảng S-box
			byte substitutedByte = getSBoxValue(currentByte);
			// Lưu giá trị đã thay thế vào mảng kết quả
			output[i] = substitutedByte;
		}
		return output;
	}

	// Hàm getSBoxValue để lấy giá trị từ bảng S-box
	private static byte getSBoxValue(byte num) {
		// Trả về giá trị từ bảng S-box (dùng & 0xff để đảm bảo num là unsigned byte)
		return (byte) sbox[num & 0xff];
	}

	// Hàm rotateWord để dịch trái 1 byte
	private static byte[] rotWord(byte[] input) {
		byte[] tmp = new byte[input.length];
		tmp[0] = input[1];
		tmp[1] = input[2];
		tmp[2] = input[3];
		tmp[3] = input[0];
		return tmp;
	}

	// Tạo vòng key (input 4 biến 32 bit)
	private static byte[][] addRoundKey(byte[][] state, byte[][] subkeys, int round) {

		// subkeys là mảng chứa các khóa con
		// state là mảng sau khi thực hiện mixColumn
		// round là số vòng phải thực hiện
		byte[][] tmp = new byte[state.length][state[0].length]; // tạo mảng tmp có kích thước bằng state

		// Duyệt qua từng cột của state
		for (int c = 0; c < Nb; c++) {
			// Duyệt qua từng hàng của state
			for (int r = 0; r < 4; r++)
				// XOR từng byte trong state với từng byte trong khóa con
				tmp[r][c] = (byte) (state[r][c] ^ subkeys[round * Nb + c][r]);
		}

		return tmp;
	}

	// Hàm subByte để thay thế các byte trong state bằng các giá trị tương ứng từ
	// bảng sbox
	private static byte[][] subByte(byte[][] state) {
		byte[][] result = new byte[state.length][state[0].length];

		for (int row = 0; row < state.length; row++) {
			for (int col = 0; col < state[0].length; col++) {
				// Thay thế các byte trong state bằng các giá trị tương ứng từ bảng sbox
				result[row][col] = getSBoxValue(state[row][col]);
			}
		}

		return result;
	}

	// Hàm invSubByte để thay thế các byte trong state bằng các giá trị tương ứng
	// từ bảng inv_sbox
	private static byte[][] invSubByte(byte[][] state) {
		for (int row = 0; row < 4; row++)
			for (int col = 0; col < Nb; col++)
				// Thay thế các byte trong state bằng các giá trị tương ứng từ bảng inv_sbox
				state[row][col] = getInvSBoxValue(state[row][col]);
		return state;
	}

	// hàm getinvSubByte để lấy giá trị từ bảng inv_sbox
	private static byte getInvSBoxValue(byte value) {
		// Lấy chỉ mục trong bảng sbox
		int index = value & 0xFF; // Đảm bảo value là dạng unsigned byte

		// Trả về giá trị từ bảng sbox
		return (byte) inv_sbox[index];
	}

	// shiftRow
	private static byte[][] shiftRow(byte[][] state) {
		byte tmp;

		// Row 1: Shift left by 1 byte
		tmp = state[1][0];
		state[1][0] = state[1][1];
		state[1][1] = state[1][2];
		state[1][2] = state[1][3];
		state[1][3] = tmp;

		// Row 2: Shift left by 2 bytes
		tmp = state[2][0];
		state[2][0] = state[2][2];
		state[2][2] = tmp;
		tmp = state[2][1];
		state[2][1] = state[2][3];
		state[2][3] = tmp;

		// Row 3: Shift left by 3 bytes
		tmp = state[3][0];
		state[3][0] = state[3][3];
		state[3][3] = state[3][2];
		state[3][2] = state[3][1];
		state[3][1] = tmp;

		return state;
	}

	// invShiftRow
	private static byte[][] invShiftRow(byte[][] state) {
		byte tmp;

		// Row 1: Shift right by 1 byte
		tmp = state[1][3];
		state[1][3] = state[1][2];
		state[1][2] = state[1][1];
		state[1][1] = state[1][0];
		state[1][0] = tmp;

		// Row 2: Shift right by 2 bytes
		tmp = state[2][0];
		state[2][0] = state[2][2];
		state[2][2] = tmp;
		tmp = state[2][1];
		state[2][1] = state[2][3];
		state[2][3] = tmp;

		// Row 3: Shift right by 3 bytes
		tmp = state[3][0];
		state[3][0] = state[3][1];
		state[3][1] = state[3][2];
		state[3][2] = state[3][3];
		state[3][3] = tmp;

		return state;
	}

	// Hàm mixColumn để thực hiện phép nhân ma trận với ma trận galois
	private static byte[][] mixColumn(byte[][] state) {
		byte[][] result = new byte[state.length][state[0].length];

		for (int c = 0; c < Nb; c++) {
			for (int i = 0; i < 4; i++) {
				byte tmp = 0x00;
				for (int j = 0; j < 4; j++) {
					// Thực hiện phép nhân ma trận với ma trận galois và XOR các kết quả lại với
					// nhau để tạo ra ma trận kết quả mixColumn
					tmp ^= multiple(galois[i][j], state[j][c]);
				}
				result[i][c] = tmp;
			}
		}

		return result;
	}

	// Hàm invMixColumn để giải mã phép nhân ma trận với ma trận invgalois
	private static byte[][] invMixColumn(byte[][] state) {
		byte[][] result = new byte[state.length][state[0].length];
		// Thực hiện phép nhân ma trận với ma trận invgalois
		for (int c = 0; c < 4; c++) {
			for (int i = 0; i < 4; i++) {
				byte sp = 0x00;
				for (int j = 0; j < 4; j++) {
					// Thực hiện phép nhân ma trận với ma trận invgalois và XOR các kết quả lại với
					// nhau để tạo ra ma trận kết quả invMixColumn
					sp ^= multiple(invgalois[i][j], state[j][c]);
				}
				result[i][c] = sp;
			}
		}

		return result;
	}

	// Hàm encryptBlock để mã hóa một khối dữ liệu 128 bit
	public static byte[] encryptBlock(byte[] input) {

		// Khởi tạo mảng tạm thời để lưu kết quả
		byte[] tmp = new byte[input.length];

		// Chuyển đổi mảng byte đầu vào thành ma trận state
		byte[][] state = new byte[4][Nb];
		for (int i = 0; i < input.length; i++) {
			state[i % 4][i / 4] = input[i]; // state [i%4] là trí trị cột, [i/4] là trị trị hàng
		}

		// Thực hiện phép XOR giữa state và subkeys đầu tiên
		state = addRoundKey(state, w, 0);

		// Thực hiện các vòng lặp mã hóa
		for (int round = 1; round < Nr; round++) {
//			System.out.println(round);
			state = subByte(state);
			state = shiftRow(state);
			state = mixColumn(state);
			state = addRoundKey(state, w, round);
		}

		// Thực hiện vòng lặp cuối cùng của mã hóa
		state = subByte(state);
		state = shiftRow(state);
		state = addRoundKey(state, w, Nr);

		// Chuyển đổi ma trận state thành mảng byte kết quả
		for (int i = 0; i < tmp.length; i++) {
			tmp[i] = state[i % 4][i / 4]; // tmp[i] là giá trị của mảng byte kết quả tương ứng với state[i%4] là cột và
											// [i/4] là hàng
		}

		return tmp;
	}

	// Hàm Encrypt để mã hóa dữ liệu
	public static byte[] encrypt(byte[] in, byte[] key) {
//		System.out.println(key.length);
		Nb = 4; // số cột trong khối dữ liệu
		Nk = key.length / 4; // số cột trong khóa bằng độ dài khóa chia 4 ( ví dụ 128 bit = 16 byte = 4 cột)
		Nr = Nk + 6; // số vòng lặp mã hóa sẽ bằng số cột trong khóa + 6

		int length = 0;
		byte[] padding = new byte[1];
		int i;
		length = 16 - in.length % 16;
		padding = new byte[length];
		padding[0] = (byte) 0x80;

		for (i = 1; i < length; i++)
			padding[i] = 0;

		byte[] tmp = new byte[in.length + length];
		byte[] block = new byte[16];

		int count = 0; // khởi tạo biến count = 0
		w = generateSubkeys(key); // tạo khóa con từ khóa key

		for (i = 0; i < in.length + length; i++) {
			if (i > 0 && i % 16 == 0) {
				block = encryptBlock(block);
				System.arraycopy(block, 0, tmp, i - 16, block.length);
			}
			if (i < in.length)
				block[i % 16] = in[i];
			else {
				block[i % 16] = padding[count % 16];
				count++;
			}
		}
		if (block.length == 16) {
			block = encryptBlock(block);
			System.arraycopy(block, 0, tmp, i - 16, block.length);
		}

		return tmp;
	}

	// Hàm decryptBlock để giải mã một khối dữ liệu 128 bit
	public static byte[] decryptBlock(byte[] in) {
		byte[] tmp = new byte[in.length];

		byte[][] state = new byte[4][Nb];

		for (int i = 0; i < in.length; i++)
			state[i / 4][i % 4] = in[i % 4 * 4 + i / 4];

		state = addRoundKey(state, w, Nr);
		for (int round = Nr - 1; round >= 1; round--) {
			state = invSubByte(state);
			state = invShiftRow(state);
			state = addRoundKey(state, w, round);
			state = invMixColumn(state);
		}
		state = invSubByte(state);
		state = invShiftRow(state);
		state = addRoundKey(state, w, 0);

		for (int i = 0; i < tmp.length; i++)
			tmp[i % 4 * 4 + i / 4] = state[i / 4][i % 4];

		return tmp;
	}

	// Hàm decrypt để giải mã dữ liệu
	public static byte[] decrypt(byte[] in, byte[] key) {
		int i;
		byte[] tmp = new byte[in.length];
		byte[] block = new byte[16];

		Nb = 4;
		Nk = key.length / 4;
		Nr = Nk + 6;
		w = generateSubkeys(key);

		for (i = 0; i < in.length; i++) {
			if (i > 0 && i % 16 == 0) {
				block = decryptBlock(block);
				System.arraycopy(block, 0, tmp, i - 16, block.length);
			}
			if (i < in.length)
				block[i % 16] = in[i];
		}
		block = decryptBlock(block);
		System.arraycopy(block, 0, tmp, i - 16, block.length);

		tmp = dltPadding(tmp);

		return tmp;
	}

	// Hàm xóa padding, padding là các byte 0 được thêm vào cuối chuỗi, dùng để đảm
	// bảo độ dài của chuỗi là bội của 16 byte (block)
	private static byte[] dltPadding(byte[] input) {
		// Đếm số lượng byte padding có giá trị 0
		int paddingCount = 0;
		// Duyệt từ cuối mảng byte đầu vào
		int index = input.length - 1;
		// Kiểm tra các byte từ cuối mảng input ngược về phía trước
		while (input[index] == 0) {
			paddingCount++;
			index--;
		}

		byte[] result = new byte[input.length - paddingCount - 1];
		// Sao chép các phần tử từ mảng input vào mảng result, bỏ qua các byte padding
		System.arraycopy(input, 0, result, 0, result.length);
		return result;
	}

	// Hàm nhân 2 số trong trường hữu hạn GF(2^8), giá trị trả về là một byte
	public static byte multiple(byte a, byte b) {
		byte result = 0;
		for (int i = 0; i < 8; i++) {
			// Nếu bit thấp nhất của b là 1
			if ((b & 1) == 1) {
				result ^= a;
			}
			// Kiểm tra xem bit cao nhất của a trước khi dịch trái
			// 0x80 : 10000000
			boolean highBitSet = (a & 0x80) != 0;
			// Dịch trái a một bit
			a <<= 1;
			// Nếu bit cao nhất của a trước khi dịch trái là 1
			if (highBitSet) {
				// Thực hiện phép XOR với 0x1b
				// 0x1b : 00011011
				a ^= 0x1b;
			}
			// Dịch phải b một bit để xử lý bit tiếp theo
			b >>= 1;
		}
		// Trả về kết quả cuối cùng
		return result;
	}

//
//	public static void main(String[] args) {
//
//		// Test delete padding
////		byte[] input = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
////				0x00 };
////		byte[] result = dltPadding(input);
////		System.out.print("Test delete padding: ");
////		for (int i = 0; i < result.length; i++) {
////			System.out.print(Integer.toHexString(result[i] & 0xff) + " ");
////		}
////		System.out.println();
//
////		// Test multiple
////		byte a = (byte) 0x57; // (01010111)
////		byte b = (byte) 0x83; // (10000011)
////		System.out.println("a = " + Integer.toHexString(a & 0xff));
////		System.out.println("b = " + Integer.toHexString(b & 0xff));
////		byte result = multiple(a, b);
////		System.out.print("Test multiple: ");
//////		System.out.println(" =  " + Integer.toHexString(result & 0xff));
////		System.out.println(String.format("%02X", result));
//
//		// Test mixColumn
//		byte[][] state = new byte[4][4];
//
//		// ========================================Test shiftRow
////		byte[][] state = new byte[4][4];
//
//		// data test mixColumn
//		state[0][0] = (byte) 0x87;
//		state[0][1] = (byte) 0xF2;
//		state[0][2] = 0x4D;
//		state[0][3] = (byte) 0x97;
//		state[1][0] = 0x6E;
//		state[1][1] = 0x4C;
//		state[1][2] = (byte) 0x90;
//		state[1][3] = (byte) 0xEC;
//		state[2][0] = 0x46;
//		state[2][1] = (byte) 0xE7;
//		state[2][2] = 0x4A;
//		state[2][3] = (byte) 0xC3;
//		state[3][0] = (byte) 0xA6;
//		state[3][1] = (byte) 0x8C;
//		state[3][2] = (byte) 0xD8;
//		state[3][3] = (byte) 0x95;
//
//		System.out.println("Truoc khi mixColumn");
//		for (int i = 0; i < 4; i++) {
//			for (int j = 0; j < 4; j++) {
//				System.out.print(Integer.toHexString(state[i][j] & 0xff) + " ");
//			}
//			System.out.println();
//		}
//		System.out.println("Sau khi mixColumn");
//		state = mixColumn(state);
//		for (int i = 0; i < 4; i++) {
//			for (int j = 0; j < 4; j++) {
//				System.out.print(Integer.toHexString(state[i][j] & 0xff) + " ");
//			}
//			System.out.println();
//		}
//
////		System.out.println("Truoc khi invShiftRow");
////		for (int i = 0; i < 4; i++) {
////			for (int j = 0; j < 4; j++) {
////				System.out.print(Integer.toHexString(state[i][j] & 0xff) + " ");
////			}
////			System.out.println();
////		}
////		System.out.println("Sau khi invShiftRow");
////		state = invShiftRow(state);
////		for (int i = 0; i < 4; i++) {
////			for (int j = 0; j < 4; j++) {
////				System.out.print(Integer.toHexString(state[i][j] & 0xff) + " ");
////			}
////			System.out.println();
////		}
//
////		// ========================================Test roteteWord
////		byte[] input = new byte[4];
////		input[0] = 0x02;
////		input[1] = 0x05;
////		input[2] = 0x04;
////		input[3] = 0x08;
////		System.out.println("Truoc khi rotateWord");
////		for(int i = 0; i< 4; i++) {
////			System.out.print(Integer.toHexString(input[i] & 0xff)+ " ");
////		}
////		
////		System.out.println();
////		System.out.println("Sau khi rotateWord");
////		input = rotateWord(input); // gọi hàm rotetaWord cho input nhập vào
////		for(int i = 0; i< 4; i++) {
////			System.out.print(Integer.toHexString(input[i] & 0xff)+  " ");
////		}
////			
//	}
}
