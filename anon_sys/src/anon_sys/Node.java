package anon_sys;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class Node {

	public static void main(String[] args) throws Exception{
		
		Communication socket = new Communication(9876);
		SendRSA srsa = new SendRSA(512);
		SendRSA rsaA = new SendRSA();
		SendRSA rsaB = new SendRSA();
		AES com;
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash;
		String keyA;
		String keyB;
		String[] hkCtrl;
		
		
		String myKeyConcat;
		String keySend = srsa.getMod().toString() + "-" + srsa.getExp().toString();
		
		
		String recv;
		
		String msg = "";
		int toSend;
		
		boolean exit = false;
		
		int portA = 9876;
		int portB = 9877;
		
		//CHIAVE PUBBLICA SERVER
		socket.receive();

		portA = socket.recFrom();
		keyA = socket.getReceive();
		
		hkCtrl = keyA.split("-");
		
		//rimuovo la parte inutilizzata di buffer
		hkCtrl[2] = hkCtrl[2].substring(0, hkCtrl[2].indexOf(0));
		
		//riproduco l'hash e controllo che sia uguale a quello ricevuto
		hash = digest.digest((hkCtrl[1]+"-"+hkCtrl[2]).getBytes(StandardCharsets.UTF_8));
		if(hkCtrl[0].compareTo(hash.toString()) == 0)
		{
			rsaA.setModExp(new BigInteger(hkCtrl[1]), new BigInteger(hkCtrl[2]));
			socket.send(keyA, portB);
		}
		else {
			System.err.println("Errore integrità chiave Server.");
		}
		
		//CHIAVE PUBBLICA CLIENT
		socket.receive();

		keyB = socket.getReceive();
		
		hkCtrl = keyB.split("-");
		
		//rimuovo la parte inutilizzata di buffer
		hkCtrl[2] = hkCtrl[2].substring(0, hkCtrl[2].indexOf(0));
		//riproduco l'hash e controllo che sia uguale a quello ricevuto
		hash = digest.digest((hkCtrl[1]+"-"+hkCtrl[2]).getBytes(StandardCharsets.UTF_8));
		if(hkCtrl[0].compareTo(hash.toString()) == 0)
		{
			rsaB.setModExp(new BigInteger(hkCtrl[1]), new BigInteger(hkCtrl[2]));
			socket.send(keyB, portA);
		}
		else {
			System.err.println("Errore integrità chiave Client.");
		}
		
		//INIZIO INVIO DELLA MIA CHIAVE A CLIENT E SERVER
		hash = digest.digest(keySend.getBytes(StandardCharsets.UTF_8));
		myKeyConcat = hash.toString()+"-"+keySend;
		
		//System.out.println("N: "+myKeyConcat);
		socket.send(myKeyConcat,portA);
		socket.send(myKeyConcat,portB);
		
		//SCAMBIO CHIAVI SEGRETE
		socket.receive();
		
		socket.receive();
		
		recv = socket.getReceive();
		recv = recv.substring(0, recv.indexOf(0));
		String fwk = srsa.decryptFrom(recv);
		
		socket.send("ok", portA);
		socket.receive();
		
		
		String bwk = srsa.decryptFrom(recv);
		com = new AES(AES.hexStringToBytes(fwk), AES.hexStringToBytes(bwk));
		socket.send(rsaB.encryptTo(bwk), portB);
		
		//SCAMBIO MESAGGI
		
		while(!exit) {
			//attendo che qualcuno mandi un messaggio
			socket.receive();
			msg = socket.getReceive();
			msg = msg.substring(0, msg.indexOf(0));
			//lo decifro e lo spedisco al nodo successivo
			msg = new String(com.decrypt(com.getForward(), AES.hexStringToBytes(msg)));
			hkCtrl = msg.split("-");
			toSend = Integer.parseInt(hkCtrl[0]);
			if(toSend == portB)
			{
				socket.send(hkCtrl[1], portB);
			}
			//controollo se è il messaggio di terminazione
			if(hkCtrl[1].compareTo("exit") == 0) {
				exit = true;
				break;
			}

			socket.receive();
			msg = socket.getReceive();
			msg = msg.substring(0, msg.indexOf(0));
			msg = new String(com.decrypt(com.getBackWard(),AES.hexStringToBytes(msg)));
			hkCtrl = msg.split("-");
			toSend = Integer.parseInt(hkCtrl[0]);
			if(toSend == portA)
			{
				socket.send(hkCtrl[1], portA);
			}
			if(hkCtrl[1].compareTo("exit") == 0) {
				exit = true;
			}
		}

		
		socket.closeSocket();
		
		 
	}

}
