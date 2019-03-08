package anon_sys;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Semplificazione cifratura AES e generazione casuale chiavi
 * @author Tarasconi Davide - Andreozzi Dario
 *
 */

public class AES {
	
	/**
	 * algoritmo utilizzato
	 */
	private static String algo="AES";
	/**
	 * tipo di algoritmo
	 */
	private static String mode="ECB";
	/**
	 * tipo di padding
	 */
	private static String padding="PKCS5Padding";
	
	/**
	 * trasforma una stringa in un array di byte
	 * @param str stringa
	 * @return stringa trasformata in array di byte
	 */
	public static byte[] hexStringToBytes(String str) {
		byte[] buf=new byte[str.length()/2];
		for (int i=0; i<buf.length; i++) buf[i]=(byte)Integer.parseInt(str.substring(i*2,i*2+2),16);
		return buf;
	}
	
	/**
	 * 
	 */
	private static String algo_mode_padding=algo+'/'+mode+'/'+padding;
	
	/**
	 * chiave di forward
	 */
	private byte[] forwardKey;
	/**
	 * chiave di backward
	 */
	private byte[] backwardKey;
	
	/**
	 * cifratura
	 */
	private Cipher ciph;
	/**
	 * vettore di inizializzazione
	 */
	private IvParameterSpec iv_spec;
	/**
	 * chiave segreta
	 */
	private SecretKey sKey;
	
	/**
	 * costruttore con generazione casuale chiavi
	 */
	public AES()
	{	
		
		try {
			ciph = Cipher.getInstance(algo_mode_padding);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Algoritmo non trovato.");
		} catch (NoSuchPaddingException e) {
			System.err.println("Algoritmo padding non trovato.");
		}
		
		iv_spec = new IvParameterSpec("0000000000000000".getBytes());
		
		forwardKey = new byte[32];
		backwardKey = new byte[32];
		
		new SecureRandom().nextBytes(forwardKey);
		new SecureRandom().nextBytes(backwardKey);
	}
	
	/**
	 * costruttore
	 * @param fwk chiave di forward
	 * @param bwk chiave di backward
	 */
	public AES(byte[] fwk, byte[] bwk)
	{	
		
		try {
			ciph = Cipher.getInstance(algo_mode_padding);
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Algoritmo non trovato.");
		} catch (NoSuchPaddingException e) {
			System.err.println("Algoritmo padding non trovato.");
		}
		
		iv_spec = new IvParameterSpec("0000000000000000".getBytes());
		
		forwardKey = new byte[32];
		backwardKey = new byte[32];
		
		forwardKey = fwk;
		backwardKey = bwk;
	}
	
	
	/**
	 * cifratura
	 * @param key chiave
	 * @param text testo da cifrare in byte
	 * @return testo cifrato in byte
	 */
	public byte[] encrypt(byte[] key, byte[] text)
	{
		byte[] res = null;
		sKey = new SecretKeySpec(key, algo);
		try {
			ciph.init(Cipher.ENCRYPT_MODE, sKey);
			
			res = ciph.doFinal(text);
			
		} catch (InvalidKeyException e) {
			System.err.println("Chiave invalida.");
		} catch (IllegalBlockSizeException e) {
			System.err.println("Grandezza blocco non valida.");
		} catch (BadPaddingException e) {
			System.err.println("Padding non corretto.");
		}
		
		return res;
		
	}
	
	
	/**
	 * decifratura
	 * @param key chiave
	 * @param text testo da decifrare in byte
	 * @return testo decifrato
	 */
	public byte[] decrypt(byte[] key, byte[] text)
	{
		byte[] res = null;
		sKey = new SecretKeySpec(key, algo);
		try {
			ciph.init(Cipher.DECRYPT_MODE, sKey);
			
			res = ciph.doFinal(text);
			
		} catch (InvalidKeyException e) {
			System.err.println("Chiave invalida.");
		} catch (IllegalBlockSizeException e) {
			System.err.println("Grandezza blocco non valida.");
		} catch (BadPaddingException e) {
			System.err.println("Padding non corretto.");
		}
		
		return res;
		
	}
	
	/**
	 * 
	 * @return chiave di forward
	 */
	public byte[] getForward() {
		return forwardKey;
	}
	
	/**
	 * 
	 * @return chiave di backward
	 */
	public byte[] getBackWard() {
		return backwardKey;
	}
}
