package anon_sys;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;


/**
 * Semplificazione cifratura RSA
 * @author Tarasconi Davide - Andreozzi Dario
 *
 */


public class SendRSA {
	
	/**
	 * modulo
	 */
	private BigInteger n;
	/**
	 * esponente privato
	 */
	private BigInteger e;
	/**
	 * esponente pubblico
	 */
	private BigInteger d;
	
	/**
	 * gestore chiavi
	 */
	private KeyFactory kf;
	/**
	 * chiave pubblica
	 */
	private RSAPublicKeySpec rsa_pub_key;
	/**
	 * chiave privata
	 */
	private RSAPrivateKeySpec rsa_pri_key;
	
	/**
	 * generatore chiavi
	 */
	private KeyPairGenerator kpg;
	/**
	 * chiavi
	 */
	private KeyPair key_pair;
	/**
	 * chiave pubblica
	 */
	private PublicKey pub_key;
	/**
	 * chiave privata
	 */
	private PrivateKey pri_key;
	
	/**
	 * trasforma un array di byte in una stringa
	 * @param buf array di byte
	 * @return array di byte trasormato in stringa
	 */
	public static String bytesToHexString(byte[] buf) {
		StringBuffer sb=new StringBuffer();
		for (int i=0; i<buf.length; i++) sb.append(Integer.toHexString((buf[i]>>4)&0x0f)).append(Integer.toHexString(buf[i]&0x0f));
		return sb.toString();
	}
	
	/**
	 * trasforma un array di byte in una stringa, metodo alternativo
	 * @param bytes array di byte
	 * @return array di byte trasormato in stringa
	 */
    private static String toHex(byte[] bytes)
    {
        BigInteger bi = new BigInteger(1, bytes);
        return String.format("%0" + (bytes.length << 1) + "X", bi);
    }
	
    /**
     * costruttore vuoto
     */
	public SendRSA(){
		n = BigInteger.ZERO;
		e = BigInteger.ZERO;
		d = BigInteger.ZERO;
	}
	
	/**
	 * costruttore
	 * @param keyLen lunghezza chiave
	 */
	public SendRSA(int keyLen)
	{
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Algoritmo non trovato.");
		}
		kpg.initialize(keyLen);
		key_pair=kpg.genKeyPair();
		pub_key=key_pair.getPublic();
		pri_key=key_pair.getPrivate();	
		
		
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Algoritmo non trovato.");
		}
		
		
		try {
			rsa_pub_key = kf.getKeySpec(pub_key,RSAPublicKeySpec.class);
		} catch (InvalidKeySpecException e) {
			System.err.println("Chiave non valida.");
		}
		
		
		try {
			rsa_pri_key = kf.getKeySpec(pri_key,RSAPrivateKeySpec.class);
		} catch (InvalidKeySpecException e) {
			System.err.println("Chiave non valida.");
		}
		
		
		n = rsa_pub_key.getModulus();
		e = rsa_pub_key.getPublicExponent();
		d = rsa_pri_key.getPrivateExponent();
	}
	
	
	/**
	 * imposta la chiave pubblica
	 * @param mod modulo
	 * @param exp esponente pubblico
	 */
	public void setModExp(BigInteger mod, BigInteger exp){

		n = mod;
		d = exp;
	}
	
	/**
	 * cifratura con chiave privata
	 * @param plainText testo
	 * @return testo cifrato
	 */
    public String encrypt(String plainText)
    {
        BigInteger msg = new BigInteger(plainText.getBytes());
        return SendRSA.bytesToHexString(msg.modPow(e, n).toByteArray());
    }
    
    /**
     * decifra utilizzando la chiave privata
     * @param cipherText testo cifrato
     * @return testo in chiaro
     */
    public String decryptFrom(String cipherText)
    {
        BigInteger encrypted = new BigInteger(cipherText, 16);
        //System.out.println("SendRSA Class: "+encrypted.toString());
        return new String(encrypted.modPow(e, n).toByteArray());
    }

    /**
     * decifra utilizzando la chiave pubblica
     * @param cipherText testo cifrato
     * @return testo in chiaro
     */
    public String decrypt(String cipherText)
    {
        BigInteger encrypted = new BigInteger(cipherText, 16);
        //System.out.println("SendRSA Class: "+encrypted.toString());
        return new String(encrypted.modPow(d, n).toByteArray());
    }
    
	/**
	 * cifratura con chiave pubblica
	 * @param cipherText testo
	 * @return testo cifrato
	 */
    public String encryptTo(String cipherText)
    {
        BigInteger encrypted = new BigInteger(cipherText.getBytes());
        //System.out.println("SendRSA Class: "+encrypted.toString());
        return SendRSA.bytesToHexString(encrypted.modPow(d, n).toByteArray());
    }
    
    /**
     * 
     * @return modulo
     */
	public BigInteger getMod()
	{
		return n;
	}
	
	/**
	 * 
	 * @return esponente pubblico
	 */
	public BigInteger getExp()
	{
		return d;
	}
	
}
