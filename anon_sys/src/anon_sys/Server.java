package anon_sys;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;


public class Server {
	
	

	   public static void main(String args[]) throws Exception {
		   
		   BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
		   Communication cli = new Communication(9876,9862);
		   SendRSA srsa = new SendRSA(512);
		   SendRSA rsaB = new SendRSA();
		   SendRSA rsaN = new SendRSA();
		   AES myKeys = new AES();
		   AES NKeys = new AES();
		   AES BKeys = new AES();
		   MessageDigest digest = MessageDigest.getInstance("SHA-256");
		   byte[] hash;
		   String keyB;
		   String keyN;
		   String[] hkCtrl;
		   String comKeys;
		   String receiveMsg = "";
		   String sendMsg = "";
		   String msgTmp="";
		   
		   boolean exit = false;
		   
		   int portB = 9877;
		   
		   
		   //INVIO LA MIA CHIAVE
		   String myKeyConcat;
		   String keySend = srsa.getMod() + "-" + srsa.getExp();
		   
		   //utilizzo  l'hash per garantire integrità
		   hash = digest.digest(keySend.getBytes(StandardCharsets.UTF_8));
		   myKeyConcat = hash.toString()+"-"+keySend;
		   
		   System.out.println("Send: ");
		   sendMsg = inFromUser.readLine();
		   cli.send(myKeyConcat);
		   
		   
		   //RICEVO B
		   cli.receive();
		   
		   keyB = cli.getReceive();
			
		   hkCtrl = keyB.split("-");
			
		   //rimuovo la parte inutilizzata di buffer
		   hkCtrl[2] = hkCtrl[2].substring(0, hkCtrl[2].indexOf(0));
	
	
		   hash = digest.digest((hkCtrl[1]+"-"+hkCtrl[2]).getBytes(StandardCharsets.UTF_8));
		   if(hkCtrl[0].compareTo(hash.toString()) == 0){
			   rsaB.setModExp(new BigInteger(hkCtrl[1]), new BigInteger(hkCtrl[2]));
		   }
		   else {
			   System.err.println("Errore integrità chiave Client.");
		   }
		   
		   
		   
		   //SCAMBIO DELLA CHIAVE DEL NODO
		   
		   cli.send(" ");
		   
		   cli.receive();
		   
		   
		   keyN = cli.getReceive();
			
		   hkCtrl = keyN.split("-");
			
		   //rimuovo la parte inutilizzata di buffer
		   hkCtrl[2] = hkCtrl[2].substring(0, hkCtrl[2].indexOf(0));
	
	
		   hash = digest.digest((hkCtrl[1]+"-"+hkCtrl[2]).getBytes(StandardCharsets.UTF_8));
		   if(hkCtrl[0].compareTo(hash.toString()) == 0)
		   {
			   rsaN.setModExp(new BigInteger(hkCtrl[1]), new BigInteger(hkCtrl[2]));
		   }
		   else {
			   System.err.println("Errore integrità chiave Nodo.");
		   }
		   
		   // COMUNICAZIONE CHIAVI SEGRETE
		   String t;
		   
		   comKeys = SendRSA.bytesToHexString(myKeys.getBackWard());
		   
		   t = rsaN.encryptTo(SendRSA.bytesToHexString(myKeys.getForward()));
		   
		   cli.send(t);
		   cli.receive();
		   
		   t = rsaN.encryptTo(SendRSA.bytesToHexString(myKeys.getBackWard()));
		   cli.send(t);
		   
		   
		   //SCAMBIO MESSAGGI
		   
		   while(!exit){
			   
			   //impacchetto il messaggio da spedire e lo cripto
			   msgTmp = sendMsg;
			   sendMsg = portB+"-"+sendMsg;
			   sendMsg = SendRSA.bytesToHexString(myKeys.encrypt(myKeys.getForward(), sendMsg.getBytes()));
			   cli.send(sendMsg);
			   //controllo se è il messaggio di terminazione
			   if(msgTmp.compareTo("exit") == 0) {
				   exit = true;
				   break;
			   }
			   
			   //attendo un messaggio (in chiaro)
			   System.out.println("Waiting...");
			   cli.receive();
			   receiveMsg = cli.getReceive();
			   receiveMsg = receiveMsg.substring(0, receiveMsg.indexOf(0));
			   if(receiveMsg.compareTo("exit") == 0) {
				   exit = true;
				   break;
			   }
			   System.out.println("Receive: "+receiveMsg);
			   
			   //Scrivo nuovo messaggio
			   System.out.println("Send: ");
			   sendMsg = inFromUser.readLine();
		   }
		   
		   cli.closeSocket();
	   }
}