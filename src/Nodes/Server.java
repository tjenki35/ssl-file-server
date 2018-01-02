package Nodes;

import Errors.ResourceError;
import Errors.ProtocolError;
import static Cipher.CipherAES.KEY_SIZE;
import Errors.CipherError;
import Cipher.CipherRSA;
import Msg.Nonces;
import Msg.Certificate;
import Errors.CertificateError;
import Msg.Header;
import static Msg.Header.HANDSHAKE;
import Errors.MessageError;
import Msg.Record;
import static Msg.Record.ID.*;
import Msg.RecordGenerator;
import Sockets.RSocketClient;
import Sockets.RSocketServer;
import Errors.SocketError;
import static Msg.Header.encodeInt;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

public class Server {

    /*
       This is the class that drives the server functionality, a wrapper is needed to provide specific configuration parameters (i.e. AServer.java)
     */
    private BigInteger private_key;
    private Certificate self;
    private ArrayList<byte[]> messages;
    private String filename = "./resources/data";

    public Server(String prk, String pub_exponent, String pub_modulus, String identity) {

        private_key = new BigInteger(prk);
        self = new Certificate(identity, new BigInteger(pub_exponent), new BigInteger(pub_modulus));

        try {
            RSocketServer server = new RSocketServer(5050);
            System.out.println("Starting server @" + server.getHost() + ":" + server.getPort());

            while (true) {
                try {
                    RSocketClient client = server.listen();
                    client.open();

                    messages = new ArrayList<>(); // create a new array list for hashed messages

                    //recieving client hello record
                    Record client_hello = receiveRecord(client);

                    //verify cipher and compression parameters
                    if (!Arrays.equals(Record.SSL_RSA_WITH_AES_SHA, client_hello.getField(CIPHER_SUITE))) {
                        throw new ProtocolError("Invalid Cipher Suite Chosen");
                    }
                    if (!Arrays.equals(Record.NULL_COMPRESSION, client_hello.getField(COMPRESSION_METHOD))) {
                        throw new ProtocolError("Invalid Compression Method Chosen");
                    }

                    // We now send hello(random, ciphers, comp), certificate (pubkey), certificate_signed (signed), and cert_request
                    Record server_hello = RecordGenerator.generateServerHello(
                            client_hello.fields.get(CIPHER_SUITE),
                            client_hello.fields.get(COMPRESSION_METHOD),
                            client_hello.fields.get(SESSION_ID));

                    System.out.println("---------------------------------------------------------------------");
                    System.out.println("Cipher Suite Chosen : " + "RSA_WITH_AES_SHA-1");
                    System.out.println("Compression Method : " + "NULL");
                    System.out.println("Session_ID (not saved) : " + new BigInteger(1, client_hello.fields.get(SESSION_ID)).toString());
                    System.out.println("---------------------------------------------------------------------");

                    //send server_hello record
                    sendRecord(client, server_hello, HANDSHAKE);

                    System.out.println("Sending Self-Signed Certificate");
                    sendRecord(client, RecordGenerator.generateCertificate(self), HANDSHAKE);
                    sendRecord(client, RecordGenerator.generateCertificateVerify(self, private_key, self.getPubModulus()), HANDSHAKE);
                    sendRecord(client, RecordGenerator.generateCertificateRequest(), HANDSHAKE);

                    Record certificate_rec = receiveRecord(client);
                    Record signature_client = receiveRecord(client);

                    System.out.println("Received Certificate");
                    Certificate certificate = new Certificate(certificate_rec.getField(CERTIFICATE));

                    //verify certificate (see Certificate.java for certificate implementation)
                    System.out.println("Verfiying Certificate.......");
                    certificate.verifyCertificate(signature_client.getField(SIGNATURE));

                    System.out.println("Certificate Verified!");

                    String client_id = certificate.getIdentity();
                    BigInteger client_modulus = certificate.getPubModulus();
                    BigInteger client_exponent = certificate.getPubExponent();

                    System.out.println("");
                    System.out.println("---------------------------------------------------------------------");
                    System.out.println("<Certificate <e, N>>");
                    System.out.println("Client Public Information");
                    System.out.println("Identity: " + client_id);
                    System.out.println("Modulus: " + client_modulus.toString());
                    System.out.println("Exponent: " + client_exponent.toString());
                    System.out.println("");
                    System.out.println("---------------------------------------------------------------------");

                    byte[] R_B = Nonces.generateNonce();
                    byte[] R_B_copy = Arrays.copyOf(R_B, R_B.length);

                    //encrypt nonce and prepare to send
                    R_B = CipherRSA.encrypt(new BigInteger(1, R_B), client_exponent, client_modulus).toByteArray();

                    System.out.println("Sending Encrypted Challenge");
                    Record nonce_self = RecordGenerator.generateNonce(R_B);

                    sendRecord(client, nonce_self, HANDSHAKE);

                    //get challenge from the client
                    System.out.println("Received Encrypted Challenge");
                    Record nonce_client = receiveRecord(client);

                    byte[] R_A = new BigInteger(1, nonce_client.getField(RANDOM)).toByteArray();
                    R_A = CipherRSA.decrypt(new BigInteger(1, R_A), private_key, self.getPubModulus()).toByteArray();

                    //decrypt sent challenge and combine with the self generated challenge to create the master key (XOR as per assignment specifications)
                    BigInteger left = new BigInteger(1, R_A);
                    BigInteger right = new BigInteger(1, R_B_copy);
                    BigInteger key = left.xor(right);

                    System.out.println("Generated Master Key: " + key.toString());

                    byte[] key_bytes = key.toByteArray();

                    ByteBuffer key_buffer = ByteBuffer.allocate(128); //AES keysize
                    key_buffer.put(key_bytes);

                    SecretKeySpec master_key = new SecretKeySpec(key_buffer.array(), "AES"); //creates a 128 bit key for the handshake digest

                    //generate hash of all messages that have been exchanged. 
                    Record handshake_finished = RecordGenerator.generateHandshakeFinished(self.getIdentity(), messages, master_key);

                    client.send_record(handshake_finished, HANDSHAKE);

                    Record handshake_hash_client = client.recv_record();

                    //perform some checks here.
                    //generate keys, then transfer data. 
                    System.out.println("Validating Keyed Handshake Message Digest");

                    Record handshake_hash_verify = RecordGenerator.generateHandshakeFinished(client_id, messages, master_key);

                    //do the handshake hash verification using the identification field from the clients verfied certificate
                    if (!Arrays.equals(handshake_hash_client.data, handshake_hash_verify.data)) {
                        throw new ProtocolError("Verfication of Handshake Messages Failed");
                    }

                    System.out.println("Verification of handshake messages complete!");
                    System.out.println("Authentication Complete!");

                    byte[] master_key_bytes = key_buffer.array();

                    MessageDigest digest; // the function of the master key in this case is a hash chain
                    try {
                        digest = MessageDigest.getInstance("SHA-1");
                    } catch (NoSuchAlgorithmException ex) {
                        throw new CipherError("Incompatible Version of java, missing SHA", ex);
                    }

                    //generate our encryption write keys ( if we were to do any communication in the other direction we
                    //would create two more keys based off the master key, encrypt_read and integrity_read
                    System.out.println("Generating Keys...\n");

                    byte[] encrypt_write = new byte[KEY_SIZE];
                    byte[] integrity_write = new byte[KEY_SIZE];

                    byte[] temp = digest.digest(master_key_bytes);
                    System.arraycopy(temp, 0, encrypt_write, 0, KEY_SIZE);

                    temp = digest.digest(temp);
                    System.arraycopy(temp, 0, integrity_write, 0, KEY_SIZE);

                    SecretKeySpec crypt_write = new SecretKeySpec(encrypt_write, "AES");

                    //read in the file and prepare it to send
                    System.out.println("Loading File: " + filename);
                    File file = new File(filename);
                    byte[] datafile = new byte[(int) file.length()]; // won't work for large files...int.MAX is largest in bytes (multi-dimensional array?)
                    //we know the size ahead of time so this is kinda not as cool, but easy
                    try {
                        //now we need to touch the disk
                        InputStream in = new FileInputStream(file);
                        in.read(datafile);
                        in.close(); //close file
                    } catch (FileNotFoundException ex) {
                        throw new ResourceError("Resource file not found", ex);
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }

                    //some information to send out a variable amount of data
                    int pow = (int) (Math.pow(2, 14) - 1);
                    int quotient = datafile.length / pow;
                    int remainder = datafile.length % pow;

                    byte[] segment = new byte[pow];
                    int k = 0;

                    int how_many = quotient;
                    if (remainder > 0 && quotient != 0) {
                        how_many++;
                    }

                    //send info on how many packets are to come
                    Record next = new Record(encodeInt(how_many, 4));
                    client.send_record(next, Header.APPLICATION_DATA);

                    //start sending encrypted and integrity protected packets
                    System.out.println("Sending " + how_many + " protected packets @~" + pow + " bytes per packet");
                    for (int i = 0; i < quotient; i++) {
                        System.arraycopy(datafile, k, segment, 0, segment.length);
                        k += segment.length;
                        Record record = RecordGenerator.generateAppData(segment);
                        //see ClientSocketR.send_record_protected for implementation of encryption and integrity protection
                        //basically wraps over regular send and uses the generated keys to detect tampering
                        client.send_record_protected(record, Header.APPLICATION_DATA, integrity_write, crypt_write);
                        System.out.print("."); // each dot represents a packet that has been sent. 
                    }
                    if (remainder > 0) {  // send the tail end of the data if we need to (the remainder of data if you will :))
                        byte[] tail = new byte[remainder];
                        System.arraycopy(datafile, k, tail, 0, tail.length);
                        Record record = RecordGenerator.generateAppData(tail);
                        client.send_record_protected(record, Header.APPLICATION_DATA, integrity_write, crypt_write);
                        System.out.print("."); //send in protected mode (see ClientSocketS file)
                    }
                    System.out.println("\nTransfer completed successfully, waiting for next connection.\n");
                    //and the protocol has finished, the server will wait for another user connection

                } catch (MessageError | SocketError | NullPointerException | CertificateError | ResourceError | CipherError | ProtocolError ex) {
                    System.err.println(ex.getMessage());
                    System.err.println("\nDropping Client...\n");
                }  //catch errors here 
            }
        } catch (SocketError ex) { // if we can't start the server, then networking or the selected port must be wrong
            System.err.println("Cannot Start Server, Networking Error");
        }
    }

    private void sendRecord(RSocketClient network, Record rec, int type) throws SocketError, MessageError {
        try {
            if (network == null) {
                throw new SocketError("No sockets attached to process");
            }
            messages.add(rec.data);
            network.send_record(rec, type);
        } catch (NullPointerException ex) {
            throw new SocketError("Attached socket is not opened");
        }
    }

    private Record receiveRecord(RSocketClient network) throws SocketError, MessageError {
        try {
            if (network == null) {
                throw new SocketError("No sockets attached to process");
            }
            Record rec = network.recv_record();
            messages.add(rec.data);
            return rec;
        } catch (NullPointerException ex) {
            throw new SocketError("Attached socket is not opened");
        }
    }

}
