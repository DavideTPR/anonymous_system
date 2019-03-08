package anon_sys;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
/**
 * 
 * Classe per semplificare la comunicazione socket UDP
 * 
 * @author Tarasconi Davide - Andreozzi Dario
 *
 */
public class Communication {
	
	/**
	 * dati da inviare
	 */
	public byte[] sendData;
	/**
	 * Dati ricevuti
	 */
	public byte[] receiveData;
	/**
	 * canale socket
	 */
	public  DatagramSocket socket;
	/**
	 * indirizzo host
	 */
	public InetAddress IPAddress;
	/**
	 * pacchetto da inviare
	 */
	public DatagramPacket sendPacket;
	/**
	 * pacchetto da ricevere
	 */
	public DatagramPacket receivePacket;
	/**
	 * porta a cui inviare
	 */
	private int sendPort;
	
	/**
	 * algoritmo cifratura
	 */
	public Cipher cip;
	
	/**
	 * costruttore base
	 */
	public Communication(){
		
		sendData = new byte[1024];
		receiveData = new byte[1024];
		sendPort = 0;
		//inFromUser = new BufferedReader(new InputStreamReader(System.in));
		try {
			IPAddress = InetAddress.getByName("localhost");
		} catch (UnknownHostException e1) {
			System.err.println("Host sconosciuto.");
		}
		
		try {
			socket = new DatagramSocket();
		} catch (SocketException e) {
			System.err.println("Errore creazione socket.");
		}
		
		try {
			cip = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Nessun algoritmo trovato.");
		} catch (NoSuchPaddingException e) {
			System.err.println("Padding non trovato.");
		}
	}
	
	
	/**
	 * costruttore
	 * @param sPort porta a cui inviare
	 * @param rPort porta in cui ricevere
	 */
	public Communication(int sPort, int rPort){
		
		sendData = new byte[1024];
		receiveData = new byte[1024];
		sendPort = sPort;
		//inFromUser = new BufferedReader(new InputStreamReader(System.in));
		try {
			IPAddress = InetAddress.getByName("localhost");
		} catch (UnknownHostException e1) {
			System.err.println("Host sconosciuto.");
		}
		
		try {
			socket = new DatagramSocket(rPort);
		} catch (SocketException e) {
			System.err.println("Errore creazione socket.");
		}
		
		try {
			cip = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Nessun algoritmo trovato.");
		} catch (NoSuchPaddingException e) {
			System.err.println("Padding non trovato.");
		}
	}
	
	/**
	 * costruttore
	 * @param port porta in cui ricevere
	 */
	public Communication(int port){
		
		sendData = new byte[1024];
		receiveData = new byte[1024];
		sendPort = 0;
		try {
			IPAddress = InetAddress.getByName("localhost");
		} catch (UnknownHostException e1) {
			System.err.println("Host sconosciuto.");
		}
		
		try {
			socket = new DatagramSocket(port);
		} catch (SocketException e) {
			System.err.println("Errore creazione socket.");
		}
		
		try {
			cip = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("Nessun algoritmo trovato.");
		} catch (NoSuchPaddingException e) {
			System.err.println("Padding non trovato.");
		}
	}
	
	/**
	 * Invio messaggio alla porta definita inizialmente
	 * @param s messaggio
	 */
	public void send(String s){
		sendData = new byte[s.getBytes().length];
		   sendData = s.getBytes();//sentence.getBytes(); 
		   sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, sendPort);
		   try {
			   socket.send(sendPacket);
		} catch (IOException e) {
			System.err.println("Send error");
		}
	}
	
	
	/**
	 * Invio messaggio alla porta scelta
	 * @param s messaggio
	 * @param port porta a cui inviare
	 */
	public void send(String s, int port){
		sendData = new byte[1024];
		   sendData = s.getBytes();//sentence.getBytes(); 
		   sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, port);
		   try {
			   socket.send(sendPacket);
		} catch (IOException e) {
			System.err.println("Send error");
		}
	}
	/**
	 * attesa ricezione messaggio
	 */
	public void receive(){
		receiveData = new byte[1024];
		receivePacket = new DatagramPacket(receiveData, receiveData.length);
		try {
			socket.receive(receivePacket);
		} catch (IOException e) {
			System.err.println("Receive error");
		}
	}
	
	/**
	 * attesa ricezione e imposta la porta a cui inviare in base a chi ha mandato iol messaggio
	 */
	public void receiveSetPort(){
		receiveData = new byte[1024];
		receivePacket = new DatagramPacket(receiveData, receiveData.length);
		try {
			socket.receive(receivePacket);
		} catch (IOException e) {
			System.err.println("Receive error");
		}
		if (sendPort != receivePacket.getPort()){
			sendPort = receivePacket.getPort();
		}
	}
	
	/**
	 * 
	 * @return messaggio ricevuto
	 */
	public String getReceive(){
		return  new String(receivePacket.getData());
	}
	
	
	/**
	 * chiude la socket
	 */
	public void closeSocket(){
		socket.close(); 
	}
	/**
	 * 
	 * @return porta di chi ha mandato il messaggio
	 */
	public int recFrom()
	{
		return receivePacket.getPort();
	}
}
