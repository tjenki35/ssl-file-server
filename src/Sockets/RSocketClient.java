package Sockets;

import Errors.SocketError;
import Cipher.CipherAES;
import static Cipher.CipherAES.DECRYPT_MODE;
import static Cipher.CipherAES.ENCRYPT_MODE;
import static Cipher.CipherAES.generateIV;
import Errors.CipherError;
import Msg.Nonces;
import Msg.Header;
import Errors.MessageError;
import Msg.Record;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RSocketClient implements AutoCloseable {

    private Socket self;
    private DataOutputStream out;
    private DataInputStream in;

    public static int HEADER_SIZE = Header.HEADER_SIZE;

    //generates a ClientSocket and connects it to the given IP address and port, originating from this localhost
    public RSocketClient(String ip, int port) throws SocketError {
        //generate a new underlying socket
        self = new Socket();
        InetSocketAddress address;
        try {
            address = new InetSocketAddress(InetAddress.getByName(ip), port);
            self.connect(address); // attempt to connect to given address
        } catch (UnknownHostException ex) {
            throw new SocketError("Cannot Connect to Host", ex);
        } catch (IOException ex) {
            throw new SocketError("Cannot Connect to Networking Interface", ex);
        }
    }

    // bind a java socket as the underlying API for the protocol socket
    public RSocketClient(Socket socket) {
        self = socket;
    }

    //public API to send a Record from this socket
    public void send_record(Record record, int type) throws SocketError, MessageError {
        if (record.data == null) {
            throw new MessageError("No Data to Send!");
        }
        byte[] data = record.data;
        send_bytes(new Header(type, Record.VERSION_NUMBER, data.length).encode());
        send_bytes(data);
    }

     //public API to send a protected Packet from this socket, uses integrity protection and encryptio
    public void send_record_protected(Record record, int type, byte[] ikey_write, SecretKeySpec ekey_write) throws SocketError, MessageError, CipherError {
        if (record.data == null) {
            throw new MessageError("No Data to Send!");
        }
        byte[] data = record.data;
        CipherAES aes = new CipherAES();
        IvParameterSpec IV = CipherAES.generateIV();
        data = aes.cipher_operation(data, ENCRYPT_MODE, ekey_write, IV);
        send_bytes(new Header(type, Record.VERSION_NUMBER, data.length).encode());
        send_bytes(IV.getIV());
        send_bytes(data);
        send_bytes(hashRecord(data, ikey_write)); //send 128 bit digest
    }

    
    public static int SHA_SIZE = 20;
    
    //public API to recieve a protected Packet from this socket, uses integrity protection and encryption
    public Record recv_record_protected(byte[] ikey_read, SecretKeySpec ekey_read) throws SocketError, MessageError, CipherError {
        Header header = new Header(recv_header());
        IvParameterSpec IV = new IvParameterSpec(recv_payload(CipherAES.KEY_SIZE));
        byte[] payload = recv_payload(header.getLength());
        byte[] hash = recv_payload(SHA_SIZE);
        if (!Arrays.equals(hashRecord(payload, ikey_read), hash)) {
            System.out.println(Arrays.toString(hashRecord(payload, ikey_read)));
            System.out.println(Arrays.toString(hash));
            throw new CipherError("Integrity Protected Failed");
        }
        CipherAES aes = new CipherAES();
        payload = aes.cipher_operation(payload, DECRYPT_MODE, ekey_read, IV);
        Record pkt = new Record(header, payload); //on receive we grab header info as well 
        pkt.parse();
        return pkt;
    }

    //public API to recieve a Packet from this socket
    public Record recv_record() throws SocketError, MessageError {
        Header header = new Header(recv_header());
        byte[] payload = recv_payload(header.getLength());
        Record pkt = new Record(header, payload); //on receive we grab header info as well 
        pkt.parse();
        return pkt;
    }

    //parses a header from the wire, (rudementary timeout code has been included)
    private byte[] recv_header() throws SocketError {
        byte[] buffer = new byte[HEADER_SIZE];
        int total_bytes = 0;
        int failsafe = 1024;
        try {
            while (total_bytes < HEADER_SIZE) {
                byte read = in.readByte();
                buffer[total_bytes] = read;
                total_bytes++;
                //read logic here
                failsafe--;
                if (failsafe < 0) {
                    throw new SocketError("No apparent data to read, (or too large of a response)");
                }
            }
        } catch (IOException ex) {
            throw new SocketError("Error Reading Header", ex);
        }
        return buffer;
    }

    private byte[] hashRecord(byte[] data, byte[] key) throws CipherError {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(key);
            byte[] di = digest.digest(data);
            digest.update(di);
            return digest.digest(key);
        } catch (NoSuchAlgorithmException ex) {
            throw new CipherError(ex.getMessage());
        }
    }

    //retrieves an arbitrary number of bytes from the wire, (rudementary timeout code has been included)
    private byte[] recv_payload(int len) throws SocketError {
        byte[] buffer = new byte[len];
        int total_bytes = 0;
        int failsafe = 65535;
        try {
            while (total_bytes < len) {
                byte read = in.readByte();
                buffer[total_bytes] = read;
                total_bytes++;
                //read logic here
                failsafe--;
                if (failsafe < 0) {
                    throw new SocketError("No apparent data to read, (or too large of a response)");
                }
            }
        } catch (IOException ex) {
            throw new SocketError("Error Reading Bytes", ex);
        }
        return buffer;
    }

    //private API to send arbitary bytes over this socket
    private void send_bytes(byte[] input) throws SocketError {
        try {
            out.write(input);
            out.flush();
        } catch (IOException ex) {
            throw new SocketError("Error Sending Bytes", ex);
        }
    }

    //attempts to open up input and output streams for this socket connection
    public void open() throws SocketError {
        try {
            out = new DataOutputStream(new BufferedOutputStream(self.getOutputStream()));
            in = new DataInputStream(self.getInputStream());

        } catch (IOException ex) {
            throw new SocketError("Error Opening Socket Streams", ex);
        }
    }

    //returns this particular socets InetAddress
    public InetAddress getAddress() {
        return self.getInetAddress();
    }

    @Override
    public void close() throws SocketError { // shutdown the socket, note the this class is not safe to use after this function is activated.
        try {
            out.close();
            in.close();
            self.close();
        } catch (IOException ex) {
            throw new SocketError("Error Closing Socket", ex);
        }

    }

    public byte[] generateSessionId() {
        SecureRandom random = new SecureRandom();
        byte[] temp = new byte[4];
        random.nextBytes(temp);
        return temp;
    }
    
    public int getPort(){
        return self.getLocalPort();
    }
}
