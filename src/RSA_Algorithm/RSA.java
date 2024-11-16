/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package RSA_Algorithm;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.math.BigInteger;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 *
 * @author HP
 */
public class RSA {
    // Check if number is prime
    public boolean isPrime(long number) {
        if (number <= 1) {
            return false; // Numbers less than or equal to 1 are not prime
        }
        
        // Check from 2 to square root of number
        for (long i = 2; i <= Math.sqrt(number); i++) {
            if (number % i == 0) {
                return false; // If we find a divisor, number is not prime
            }
        }
        return true; // Number is prime
    }

    // Generate random prime number
    public long generateRandomPrime() {
        Random random = new Random();

        while (true) {
            // Generate random number between 100 and 1000
            // Using smaller range due to long limitations
            long lowerBound = 100000000;
            long upperBound = 1000000000;
            long randomNum = random.nextLong(upperBound - lowerBound) + lowerBound;
            
            // Check if prime
            if (isPrime(randomNum)) {
                return randomNum;
            }
        }
    }
    
    // Extended Euclidean Algorithm
    private long[] extendedGCD(long a, long b) {
        long x0 = 1, y0 = 0;
        long x1 = 0, y1 = 1;

        while (b != 0) {
            long q = a / b;
            long r = a % b;

            a = b;
            b = r;

            long newX = x0 - (q * x1);
            long newY = y0 - (q * y1);

            x0 = x1;
            y0 = y1;

            x1 = newX;
            y1 = newY;
        }

        return new long[] { a, x0, y0 };
    }

    // Calculate modular multiplicative inverse
    public Object[] modInverse(long a, long m) {
        long[] result = extendedGCD(a, m);
        long gcd = result[0];
        long x = result[1];

        if (gcd != 1) {
            return new Object[] {false, 0};
        } else {
            // Ensure positive result
            long d = ((x % m) + m) % m;
            return new Object[] {true, d};
        }
    }
    
    public long[] createKey(long p, long q) {
        long n = p * q;
        long m = (p - 1) * (q - 1);
        long e;
        long d = 0;
        boolean isSuccess = false;
        
        do {
            e = generateRandomPrime();
            Object[] result = modInverse(e, m);
            if((Boolean)result[0]) {
                d = (Long)result[1];
                isSuccess = true;
            }
        } while(!isSuccess); // Fixed the logic error in the original code
        return new long[] {n, e, d};
    }
    
    public BigInteger handleEncryption(BigInteger mess, BigInteger e, BigInteger n) {
        BigInteger code = mess.modPow(e, n);
        return code;
    }
    
//    public BigInteger handleEncryption(BigInteger mess, BigInteger e, BigInteger n) {
//        if (e.equals(BigInteger.ZERO)) {
//            return BigInteger.ONE;
//        }
//
//        BigInteger result = BigInteger.ONE;
//        BigInteger base = mess.mod(n);
//
//        // Convert exponent to binary representation
//        String binary = e.toString(2);
//
//        // Square and multiply algorithm for modular exponentiation
//        for (long i = 0; i < binary.length(); i++) {
//            // Square
//            result = result.multiply(result).mod(n);
//
//            // Multiply if current bit is 1
//            if (binary.charAt(i) == '1') {
//                result = result.multiply(base).mod(n);
//            }
//        }
//        return result;
//    }
    
    public BigInteger Decoding(BigInteger code, BigInteger d, BigInteger n) {
        BigInteger mess = code.modPow(d, n);
        return mess;
    }
    
//    public BigInteger Decoding(BigInteger code, BigInteger d, BigInteger n) {
//        if (d.equals(BigInteger.ZERO)) {
//            return BigInteger.ONE;
//        }
//
//        BigInteger result = BigInteger.ONE;
//        BigInteger base = code.mod(n);
//
//        // Convert exponent to binary representation
//        String binary = d.toString(2);
//
//        // Square and multiply algorithm
//        for (long i = 0; i < binary.length(); i++) {
//            // Square
//            result = result.multiply(result).mod(n);
//
//            // Multiply if current bit is 1
//            if (binary.charAt(i) == '1') {
//                result = result.multiply(base).mod(n);
//            }
//        }
//
//        return result;
//    }
    
    public String[] convertStringToASCII(String input) {
        List<String> result = new ArrayList<>();
        StringBuilder currentElement = new StringBuilder();

        for (char c : input.toCharArray()) {
            long ascii = (long) c;
            String asciiString = String.format("%03d", ascii);
            currentElement.append(asciiString);

            if (currentElement.length() == 15) {
                result.add(currentElement.toString());
                currentElement = new StringBuilder();
            }
        }

        // Add any remaining digits to the last element
        if (currentElement.length() > 0) {
            result.add(currentElement.toString());
        }

        return result.toArray(new String[0]);
    }
    
    public String[] handleEncryptionArr(String[] arr,  BigInteger e, BigInteger n) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < arr.length; i++) {
            BigInteger mess = new BigInteger(arr[i]);
            BigInteger code = handleEncryption(mess, e, n);
            result.add(code.toString());
        }
        return result.toArray(new String[0]);
    } 
    
    public String[] splitString(String input) {
        return input.split("/");
    }
    
    public String[] DecodingArr(String[] arr, BigInteger d, BigInteger n) {
        List<String> result = new ArrayList<>();
        for (int i = 0; i < arr.length; i++) {
            BigInteger code = new BigInteger(arr[i]);
            BigInteger mess = Decoding(code, d, n);
            String mess_str = mess.toString();
            if(mess_str.length() % 3 != 0) {
                mess_str = "0" + mess_str;
                result.add(mess_str);
            } else {
                result.add(mess_str);
            }
            
        }
        return result.toArray(new String[0]);
    }
    
    public String[] convertArrayToASCII(String[] input) {
        String[] result = new String[input.length];
        for (int i = 0; i < input.length; i++) {
            StringBuilder asciiString = new StringBuilder();
            for (int j = 0; j < input[i].length(); j += 3) {
                int end = Math.min(j + 3, input[i].length());
                String substring = input[i].substring(j, end);
                if (substring.length() == 3) {
                    int asciiValue = Integer.parseInt(substring);
                    asciiString.append((char) asciiValue);
                }
            }
            result[i] = asciiString.toString();
        }
        return result;
    }
    
    
    public void handleClipSave(String textToCopy) {
        StringSelection selection = new StringSelection(textToCopy);
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(selection, null);
    }
    
    public  String removeAccents(String x) {
        String s = x.trim();
        String temp = Normalizer.normalize(s, Normalizer.Form.NFD);
        String result = temp.replaceAll("\\p{InCombiningDiacriticalMarks}+", "");
        return result;
    }
    
    
}
