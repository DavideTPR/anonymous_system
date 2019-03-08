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
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Client {
	
	   public static void main(String args[]) throws Exception {

		   BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
		   Communication serv = new Communication(9877);
		   SendRSA srsa = new SendRSA(512);
		   SendRSA rsaA = new SendRSA();
		   SendRSA rsaN = new SendRSA();
		   AES com;
		   MessageDigest digest = MessageDigest.getInstance("SHA-256");
		   byte[] hash;
		   String keyA;
		   String keyN;
		   String[] hkCtrl;
		   
		   String myKeyConcat;
		   String keySend = srsa.getMod().toString() + "-" + srsa.getExp().toString();
		   
		   String recv;
		   
		   

		   String receiveMsg = "";
		   String sendMsg = "";
		   int portA = 9862;
		   
		   boolean exit = false;
		   
		   serv.receiveSetPort();
		   
		   //RICEVO CHIAVE PUBBLICA SERVER
		   
		   keyA = serv.getReceive();
			
		   hkCtrl = keyA.split("-");
			
		   //rimuovo la parte inutilizzata di buffer
		   hkCtrl[2] = hkCtrl[2].substring(0, hkCtrl[2].indexOf(0));
	
	
		   hash = digest.digest((hkCtrl[1]+"-"+hkCtrl[2]).getBytes(StandardCharsets.UTF_8));
		   if(hkCtrl[0].compareTo(hash.toString()) == 0)
		   {
			   rsaA.setModExp(new BigInteger(hkCtrl[1]), new BigInteger(hkCtrl[2]));
			   //serv.send(keyA,9862);
		   }
		   else {
			   System.err.println("Errore integrità chiave Server.");
		   }
		   
		   //MANDO LA MIA CHIAVE		   
		   hash = digest.digest(keySend.getBytes(StandardCharsets.UTF_8));
		   myKeyConcat = hash.toString()+"-"+keySend;
		   
		   
		   serv.send(myKeyConcat);

		   //CHIAVE NODO
		   
		   serv.receive();
		   
		   keyN = serv.getReceive();
			
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
		   
		   
		   
		   
		   //RICEZIONE CHIAVE BACKWARD
		   
		   serv.receive();
		   recv = serv.getReceive();
		   recv = recv.substring(0, recv.indexOf(0));

		   com = new AES(null, AES.hexStringToBytes(srsa.decryptFrom(recv)));
		   
		   
		   //SCAMBIO MESSAGGI
	
		   while(!exit){
			   System.out.println("Waiting...");
			   serv.receive();
			   receiveMsg = serv.getReceive();
			   receiveMsg = receiveMsg.substring(0, receiveMsg.indexOf(0));
			   if(receiveMsg.compareTo("exit") == 0) {
				   exit = true;
				   break;
			   }
			   System.out.println("Receive: "+receiveMsg);
			   
			   System.out.println("Send: ");
			   sendMsg = inFromUser.readLine();
			   if(sendMsg.compareTo("exit") == 0) {
				   exit = true;
			   }
			   sendMsg = portA+"-"+sendMsg;
			   sendMsg = SendRSA.bytesToHexString(com.encrypt(com.getBackWard(), sendMsg.getBytes()));
			   serv.send(sendMsg);
		   }
		   
		   
		   
		   
		   
		   serv.closeSocket();
		   
	      }
}