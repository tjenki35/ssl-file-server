package Msg;

import Cipher.CipherRSA;
import static Msg.Header.encodeInt;
import static Msg.Record.HandshakeMessage.Certificate;
import static Msg.Record.HandshakeMessage.CertificateRequest;
import static Msg.Record.NULL_COMPRESSION;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.SecretKeySpec;
import static Msg.Record.SSL_RSA_WITH_AES_SHA;

/**
 * Generates the handshake message packets.
 */
public class RecordGenerator {

    private static int SHS = 4; //secondary header size
    public static final String CLNT = "CLNT";
    public static final String SRVR = "SRVR";
    public static int CHALLENGE_SIZE = 32;

    public static Record generateClientHello(byte[] session_id) {

        SecureRandom ra = new SecureRandom();
        byte[] random = new byte[32];
        ra.nextBytes(random);

        int init_field_size = SHS + Record.VERSION_BYTES.length; // type(1) + length(3) + version(2) 
        int lens_fields_size = 4; //session_id len field
        int fields_size = SSL_RSA_WITH_AES_SHA.length + NULL_COMPRESSION.length; // cipher_list(2) + comp_methods(1)
        int total_size = random.length + session_id.length + init_field_size + lens_fields_size + fields_size;
        byte[] len = Header.encodeInt(total_size - SHS, 3);

        Record rec = new Record(total_size);
        rec.addBytes(encodeInt(1, 1));
        rec.addBytes(len);
        rec.addBytes(Record.VERSION_BYTES);
        rec.addBytes(random);
        rec.addWithLength(session_id, 1);
        rec.addBytes(encodeInt(1, 2));
        rec.addBytes(SSL_RSA_WITH_AES_SHA);
        rec.addBytes(encodeInt(1, 1));
        rec.addBytes(NULL_COMPRESSION);
        return rec;
    }

    public static byte[] generateChallenge() {
        SecureRandom random = new SecureRandom();
        byte[] challenge = new byte[CHALLENGE_SIZE];
        random.nextBytes(challenge);
        return challenge;
    }

    //just a wrapper for the data
    public static Record generateAppData(byte[] data) {
        return new Record(data);
    }

    public static Record generateServerHello(byte[] chosen_cipher, byte[] chosen_compression, byte[] session_id) {

        byte[] challenge = generateChallenge();

        int init_field_size = SHS + 2; // type(1) + length(3) + version(2) 
        int payload_size = init_field_size + challenge.length + session_id.length + chosen_cipher.length + chosen_compression.length + 1; // session_id_len(1)

        Record rec = new Record(payload_size);

        rec.addBytes(encodeInt(2, 1));
        rec.addBytes(encodeInt(payload_size - SHS, 3));
        rec.addBytes(Record.VERSION_BYTES);
        rec.addBytes(challenge);
        rec.addBytes(Header.encodeInt(session_id.length, 1));
        rec.addBytes(session_id);
        rec.addBytes(chosen_cipher);
        rec.addBytes(chosen_compression);
        return rec;
    }

    public static Record generateServerHelloDone() {
        Record rec = new Record(4);
        int k = 0;
        rec.data[k] = (byte) 14;
        rec.addBytes(encodeInt(Record.HandshakeMessage.ServerHelloDone.getValue(), 1));
        rec.addBytes(encodeInt(0, 3));
        return rec;
    }

    //encrypts and generates the record
    public static Record generateClientKeyExchange(byte[] pmk, BigInteger exponent, BigInteger modulus) {
        Record rec = new Record(SHS + pmk.length + 2); // 2 for the unused length field
        rec.addBytes(encodeInt(16, 1));
        rec.addBytes((encodeInt(rec.data.length - SHS, 3)));
        rec.addBytes(new byte[]{0, 0, 0});
        pmk = CipherRSA.encrypt(new BigInteger(pmk), exponent, modulus).toByteArray();
        rec.addBytes(pmk);
        return rec;
    }

    //this has to do w/ exporting
    public static Record generateServerKeyExchange() {
        throw new UnsupportedOperationException("");
    }

    //can't fully implement this one since we are not using real CA's 
    public static Record generateCertificateRequest() {
        Record rec = new Record(8);
        rec.addBytes(encodeInt(CertificateRequest.getValue(), 1)); // type
        rec.addBytes(encodeInt(4, 1)); // length
        rec.addBytes(encodeInt(1, 1)); // key type list length
        rec.addBytes(encodeInt(1, 1)); // RSA selection
        rec.addBytes(encodeInt(0, 2)); // CA name list
        return rec;
    }

    //this is for the RSA crypto 
    public static Record generateCertificate(Certificate certificate) {
        byte[] cert = certificate.getBytes();
        int total_size = cert.length + 10;
        Record rec = new Record(total_size); // type(1) + unused_length(3) + cert_length(3)
        rec.addBytes(encodeInt(Certificate.getValue(), 1));
        rec.addBytes(encodeInt(total_size - SHS, 3));
        rec.addBytes(new byte[]{0, 0, 0});
        rec.addBytes(encodeInt(cert.length, 3));
        rec.addBytes(cert);
        return rec;
    }

    //generates a record to request a certificate from the user
    public static Record generateCertificateVerify(Certificate cert, BigInteger pk_sign, BigInteger pub_mod) {
        BigInteger cipher = CipherRSA.encrypt(new BigInteger(1, cert.hash()), pk_sign, pub_mod);
        byte[] signature = cipher.toByteArray();
        Record rec = new Record(signature.length + 7);
        rec.addBytes(encodeInt(15, 1));
        rec.addBytes(encodeInt(signature.length + 2, 3));
        rec.addWithLength(signature, 3);
        return rec;
    }

    //generates a handshake finished message, also generates the needed hash for this record
    public static Record generateHandshakeFinished(String cons, ArrayList<byte[]> handshake_data, SecretKeySpec master_secret) {
        try {
            byte[] cs = cons.getBytes();
            byte[] ms = master_secret.getEncoded();

            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.update(cs);
            digest.update(ms);
            for (byte[] b : handshake_data) {
                digest.update(b);
            }
            byte[] hash = digest.digest();

            digest = MessageDigest.getInstance("SHA-1");
            digest.update(ms);
            digest.update(hash);
            hash = digest.digest();

            Record rec = new Record(4 + hash.length);

            rec.addBytes(encodeInt(20, 1));
            rec.addBytes(encodeInt(hash.length, 3));
            rec.addBytes(hash);

            return rec;
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            Logger.getLogger(RecordGenerator.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }

    }

    //generates a change cipher spec (not used for this assignment, but used in SSL)
    public static Record generateChangeCipherSpec() {
        Record rec = new Record(6);
        rec.addBytes(encodeInt(20, 1));
        rec.addBytes(Record.VERSION_BYTES);
        rec.addBytes(encodeInt(1, 2));
        rec.addBytes(encodeInt(1, 1));
        return rec;
    }

    //generates a record containing a challenge (specific to this assignment, SSL uses the hello messages to produce the challenges)
    public static Record generateNonce(byte[] nonce) {
        Record rec = new Record(1 + Record.VERSION_BYTES.length + 3 + nonce.length);
        rec.addBytes(encodeInt(99, 1));
        rec.addWithLength(nonce, 3);
        return rec;
    }

}
