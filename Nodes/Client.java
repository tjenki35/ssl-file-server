package Nodes;

import Errors.ProtocolError;
import static Cipher.CipherAES.KEY_SIZE;
import Errors.CipherError;
import Cipher.CipherRSA;
import Msg.Nonces;
import Errors.CertificateError;
import Msg.Certificate;
import static Msg.Header.HANDSHAKE;
import Errors.MessageError;
import Errors.ResourceError;
import Msg.Record;
import static Msg.Record.ID.CERTIFICATE;
import static Msg.Record.ID.CIPHER_SUITE;
import static Msg.Record.ID.COMPRESSION_METHOD;
import static Msg.Record.ID.RANDOM;
import static Msg.Record.ID.SIGNATURE;
import Msg.RecordGenerator;
import Sockets.RSocketClient;
import Errors.SocketError;
import static Msg.Header.decodeInt;
import static Msg.Record.HandshakeMessage.CertificateRequest;
import static Msg.Record.ID.MESSAGE_TYPE;
import static Msg.Record.ID.SESSION_ID;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

public class Client {

    /*
       This is the class that drives the client functionality, a wrapper is needed to provide specific configuration parameters (i.e. AClient.java)
     */
    private BigInteger private_key;
    private Certificate self;
    private RSocketClient network;
    private ArrayList<byte[]> messages = new ArrayList<>();
    private boolean corrupt = false;
    private String filename = "./resources/out";

    public Client(String prk, String pub_exponent, String pub_modulus, String id, boolean corrupt_handshake) {
        try {

            //assignment specific parameter to corrupt one of the handshake messages to mess up the verification process, for educational purposes only
            corrupt = corrupt_handshake;

            private_key = new BigInteger(prk);
            self = new Certificate(id, new BigInteger(pub_exponent), new BigInteger(pub_modulus));
            network = new RSocketClient("localhost", 5050);

            System.out.println("Connecting to mySSL Server @" + network.getAddress().getHostName() + ":" + network.getPort());

            network.open();

            //send the hello record. (uses a useless R which we don't use) -- part of the SSL protocol...
            sendRecord(RecordGenerator.generateClientHello(Nonces.generateNonce()), HANDSHAKE);
            //this is the ServerHello record, we use it to verify the CipherSuite chosen (and compression)
            Record hello = receiveRecord();

            /*
                 This portion is to corrupt the very first message received from the server, this will result in a verification failure
                 Should only happen w/ the -c switch speficied when running the AClient.class (which triggers the class var corrupt (bool)
             */
            if (corrupt) {
                byte[] empty_mem = new byte[32];
                System.arraycopy(empty_mem, 0, hello.data, 5, empty_mem.length);
                messages.set(messages.size() - 1, hello.data);
            }

            /*
                  end assignment specific corruption
             */
            if (!Arrays.equals(Record.SSL_RSA_WITH_AES_SHA, hello.getField(CIPHER_SUITE))) {
                throw new ProtocolError("Invalid Cipher Suite Chosen");
            }
            if (!Arrays.equals(Record.NULL_COMPRESSION, hello.getField(COMPRESSION_METHOD))) {
                throw new ProtocolError("Invalid Compression Method Chosen");
            }

            //print out cipher suite information
            System.out.println("---------------------------------------------------------------------");
            System.out.println("Cipher Suite Chosen : " + "RSA_WITH_AES_SHA-1");
            System.out.println("Compression Method : " + "NULL");
            System.out.println("Session_ID (not saved) : " + new BigInteger(1, hello.fields.get(SESSION_ID)).toString());
            System.out.println("---------------------------------------------------------------------");

            //Now the server sends us it's certificate and signature
            Record rec_cert = receiveRecord();
            Record signature = receiveRecord();

            System.out.println("\n\n");
            System.out.println("Received Certificate");
            Certificate certificate_server = new Certificate(rec_cert.getField(CERTIFICATE));
            //verify the certificate using the signature (**note it is self-signed)

            System.out.println("Verfiying Certificate.......");
            certificate_server.verifyCertificate(signature.getField(SIGNATURE));

            System.out.println("Certificate Verified!");
            //pull the public info from the certificate
            BigInteger server_modulus = certificate_server.getPubModulus();
            BigInteger server_exponent = certificate_server.getPubExponent();
            String server_id = certificate_server.getIdentity();

            System.out.println("");
            System.out.println("---------------------------------------------------------------------");
            System.out.println("<Certificate <e, N>>");
            System.out.println("Client Public Information");
            System.out.println("Identity: " + server_id);
            System.out.println("Modulus: " + server_modulus.toString());
            System.out.println("Exponent: " + server_exponent.toString());
            System.out.println("---------------------------------------------------------------------");
            System.out.println("");

            Record certRequest = receiveRecord();
            if (decodeInt(certRequest.getField(MESSAGE_TYPE)) != CertificateRequest.getValue()) {
                throw new ProtocolError("Invalid Certificate Request");
            }

            System.out.println("Sending Self-Signed Certificate");
            Record certificate_self = RecordGenerator.generateCertificate(self);
            //this generation creates a signature given a certificate and a private key and puts it into a record
            Record signature_self = RecordGenerator.generateCertificateVerify(self, private_key, self.getPubModulus());
            //send the certificate and wait for the server to verify the self signed cert.
            sendRecord(certificate_self, HANDSHAKE);
            sendRecord(signature_self, HANDSHAKE);
            /*
            At this point the server should have enough information to encrypt a nonce and send it to use.
            Otherwise the verification process has failed (server-side).
             */
            //receive encrypted nonce from the server
            Record nonce_rec = receiveRecord();
            System.out.println("Received Encrypted Challenge");

            byte[] R_B = new BigInteger(1, nonce_rec.getField(RANDOM)).toByteArray();
            //decrypt the nonce using our private key
            R_B = CipherRSA.decrypt(new BigInteger(1, R_B), private_key, self.getPubModulus()).toByteArray();

            byte[] R_A = Nonces.generateNonce();
            //make a copy to use for the master key generation
            byte[] R_A_copy = Arrays.copyOf(R_A, R_A.length);

            //encrypt our nonce with the public key derived from the certificate
            System.out.println("Sending Encrypted Challenge");
            R_A = CipherRSA.encrypt(new BigInteger(1, R_A), server_exponent, server_modulus).toByteArray();
            //generate a nonce record
            Record n_self = RecordGenerator.generateNonce(R_A);
            sendRecord(n_self, HANDSHAKE);

            //now combine these two nonces to generate a key for the data exchange.
            BigInteger left = new BigInteger(1, R_A_copy);
            BigInteger right = new BigInteger(1, R_B);
            BigInteger key = right.xor(left);

            System.out.println("Generated Master Key: " + key.toString());

            //get the hash of the handshake from the server
            Record handshake_hash_s = network.recv_record();
            byte[] key_bytes = key.toByteArray();
            ByteBuffer key_buffer = ByteBuffer.allocate(128); //AES keysize
            key_buffer.put(key_bytes);
            SecretKeySpec master_key = new SecretKeySpec(key_buffer.array(), "AES");

            //generate hash of all messages that have been exchanged.
            Record handshake_finished = RecordGenerator.generateHandshakeFinished(self.getIdentity(), messages, master_key);
            network.send_record(handshake_finished, HANDSHAKE);

            //now we verify the other sides hash
            System.out.println("Validating Keyed Handshake Message Digest");
            Record handshake_hash_verify = RecordGenerator.generateHandshakeFinished(server_id, messages, master_key);
            if (!Arrays.equals(handshake_hash_s.data, handshake_hash_verify.data)) {
                throw new ProtocolError("Verfication of Handshake Messages Failed");
            }
            System.out.println("Verification of handshake messages complete!");
            System.out.println("Authentication Complete!");

            byte[] master_key_bytes = key_buffer.array();
            MessageDigest digest;  //the function of the master key in this case will just be a SHA-1 digest chain
            try {
                digest = MessageDigest.getInstance("SHA-1");
            } catch (NoSuchAlgorithmException ex) {
                throw new CipherError("Incompatible Version of java, missing SHA", ex);
            }

            //generate our encryption read keys ( if we were to do any communication in the other direction we
            //would create two more keys based off the master key, encrypt_write and integrity_write
            System.out.println("Generating keys...\n");
            byte[] encrypt_read = new byte[KEY_SIZE];
            byte[] integrity_read = new byte[KEY_SIZE];
            byte[] temp = digest.digest(master_key_bytes);
            System.arraycopy(temp, 0, encrypt_read, 0, KEY_SIZE);
            temp = digest.digest(temp);
            System.arraycopy(temp, 0, integrity_read, 0, KEY_SIZE);
            SecretKeySpec cyrpt_read = new SecretKeySpec(encrypt_read, "AES");
            //prepare to receive encrypted data from the server

            //find out how many packets we are going to receive
            Record how_many = network.recv_record();
            int hm = (decodeInt(how_many.data));

            //start receiving the encrypted file
            System.out.println("Receiving data and writing to file: " + filename);
            File file = new File(filename);
            try {
                OutputStream out = (new FileOutputStream(file));
                for (int i = 0; i < hm; i++) {
                    Record recv = network.recv_record_protected(integrity_read, cyrpt_read); // packets are decrypted in socket function (see ClientSocketR)
                    System.out.print("."); //each printed dot means a packet(record) has been sent. 
                    out.write(recv.data);
                }
            } catch (IOException ex) {
                throw new ResourceError("Could not write to resource file, retrieval failure!", ex);
            }
            System.out.println("\nFile has been retrieved SUCCESSFULLY!\n");

        } catch (SocketError | MessageError | CertificateError | ProtocolError | CipherError | ResourceError ex) {
            System.err.println(ex.getMessage());
        }

    }

    //Some wrappers on the ClientSocketS class to receive record and capture them for the hashshake hash
    private Record receiveRecord() throws SocketError, MessageError {
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

    //Some wrappers on the ClientSocketS class to receive record and capture them for the hashshake hash
    private void sendRecord(Record rec, int type) throws SocketError, MessageError {
        try {
            if (network == null) {
                throw new SocketError("No sockets attached to process");
            }
            network.send_record(rec, type);
            messages.add(rec.data);

        } catch (NullPointerException ex) {
            throw new SocketError("Attached socket is not opened");
        }
    }

}
