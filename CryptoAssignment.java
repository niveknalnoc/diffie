import java.math.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;
import java.io.*;

class CryptoAssignment {

	// p -> prime modulus p - 1024 bit prime
	final static BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc024184" +
											   "6de426e5dd8f6eddef00b465f38f509b2b18351064704fe7" +
											   "5f012fa346c5e2c442d7c99eac79b2bc8a202c98327b9681" +
											   "6cb8042698ed3734643c4c05164e739cb72fba24f6156b6f" +
											   "47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8" +
											   "dd3134745cdf7323", 16);
	
	// g -> generator g					
	final static BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a" +
						 					   "0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58" +
						 					   "eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec" +
						 					   "538088dcf5940b053c622e53bab0b4e84b1465f5738f5496" +
											   "64bd7430961d3e5a2e7bceb62418db747386a58ff267a993" +
											   "9833beefb7a6fd68", 16);
	
	// A -> public key A give by ga(mod p)						
	final static BigInteger key_A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6" +
												   "238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e79" +
												   "9485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee" +
												   "838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15" +
												   "171cb861b367732460e3a9842b532761c16218c4fea51be8" +
												   "ea0248385f6bac0d", 16);
							
	// 128 0 bits - block of zeros
	final static String plainTextBlock = "00000000000000000000000000000000000" +
								  		 "00000000000000000000000000000000000" +
					     		  		 "00000000000000000000000000000000000" +
								         "00000000000000000000000";
	
	// AES encryption (ECB mode) using 256 bit key k and plainText
	BigInteger AESencryption(String p, BigInteger s) {
		// cipherText will hold the cipherText result from AES encryption
		BigInteger cipherText = BigInteger.ZERO;
		
		try {
				// Byte array containing the key s
				byte [] key_s = s.toByteArray();
				// SHA-256 digest created from key s (1024 bit -> 256 bit)
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(key_s); 
				// Create the byte arrays to hold the key and plaintext
				byte [] key_k = md.digest();
				byte [] plainText = p.getBytes("UTF-8");
				// AES Encryption with ECB mode
				SecretKeySpec k = new SecretKeySpec(key_k, "AES");
				Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
				cipher.init(Cipher.ENCRYPT_MODE, k);
				// Byte array encryptedData to hold the cipherText
				byte[] encryptedData = cipher.doFinal(plainText);
				cipherText = new BigInteger(1,encryptedData);
				
		}catch (Exception e) {
			System.out.println("EXCEPTION!");
		}
		// return cipherText
		return cipherText;
	}
	
	// generatekey_s -> will generate the secret shared key s : A^b mod p
	BigInteger generateKey_s(BigInteger A, BigInteger b, BigInteger p) {
		
		BigInteger tmp = BigInteger.ZERO;
		BigInteger zero = BigInteger.ZERO;
		BigInteger ans_s = BigInteger.ONE;
		BigInteger two = new BigInteger("2");
		
		while(b.compareTo(zero) != 0) { // While the exponent not equal zero continue
			tmp = b.mod(two); // mod the exponent with 2
			if(tmp.compareTo(zero) != 0) { // If this result not equal 0 continue
				ans_s = ans_s.multiply(A); // ans_B * base
				ans_s = ans_s.mod(p); // mod result of last with the prime
			}
			A = A.multiply(A); // base * base
			A = A.mod(p); // result mod with prime
			b =  b.divide(two); // divide b by 2
		} 	
		return ans_s;
	}
	
	// generatekey_B -> will generate the key B : g^b mod p					
	BigInteger generateKey_B(BigInteger g, BigInteger b, BigInteger p) {
		
		BigInteger tmp = BigInteger.ZERO;
		BigInteger zero = BigInteger.ZERO;
		BigInteger ans_B = BigInteger.ONE;
		BigInteger two = new BigInteger("2");
		
		while(b.compareTo(zero) != 0) { // While the exponent not equal zero continue
			tmp = b.mod(two); // mod the exponent with 2
			if(tmp.compareTo(zero) != 0) { // If this result not equal 0 continue
				ans_B = ans_B.multiply(g); // ans_B * base
				ans_B = ans_B.mod(p); // mod result of last with the prime	
			}
			g = g.multiply(g); // base * base
			g = g.mod(p); // result mod with prime
			b =  b.divide(two); // divide b by 2
		} 	
		return ans_B;
	}
	
	
	public static void main(String [] args) throws Exception {
	
		// Generate a BigInteger of size 1023 bits - private key b
		BigInteger key_b = new BigInteger(1023, new Random());
		
		CryptoAssignment c = new CryptoAssignment();
		
		// Call d.generateKey_B and return key B
		BigInteger key_B = c.generateKey_B(g,key_b,p);
		
		// Call d.generateKey_s and return key s
		BigInteger key_s = c.generateKey_s(key_A,key_b,p);
		
		// Call AESencryption includes hashing of s to 256 bit lenght
		BigInteger cipherText = c.AESencryption(plainTextBlock, key_s);
		
		// Print out the keys and cipherText
		System.out.println("Private Key b = " + key_b);
		System.out.println("");
		System.out.println("Public Key B = " + key_B.toString(16)); // hex value 
		System.out.println("");
		System.out.println("Shared key s = "+ key_s);
		System.out.println("");
		System.out.println("CipherText = " + cipherText.toString(16)); // hex value
		
	}
}
