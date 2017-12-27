package Msg;

import Errors.CertificateError;
import Cipher.CipherRSA;
import static Msg.Header.decodeInt;
import static Msg.Header.encodeInt;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Certificate {

    /*
       Note that this is a custom implementation of the Certificate, since we don't need a full x.509 certifiate for this assignment
       The format for this data structure is as follows:
       [id_len][id bytes (variable)][e_len][ e (pub exponent)][N_len][ N (pub modulus)]
    
       This certificate, along w/ additional RSA encryption/signature methods (found in this class and Server/Client classes) to verify the authenticity of a certificate
       Also note that these certificate verification uses self signing (using RSA) as per assignment instructions, there is no 3rd party auth in this protocol
     */
    private final byte[] data;
    private final String identity;
    private final BigInteger pub_modulus;
    private final BigInteger pub_exponent;

    private int read_position = 0;
    private int write_position = 0;

    //generates a certificate given an identity and a public key pair <e,N>
    public Certificate(String identity, BigInteger pub_exponent, BigInteger pub_modulus) {
        this.pub_exponent = pub_exponent;
        this.pub_modulus = pub_modulus;
        this.identity = identity;

        byte[] id = identity.getBytes();
        byte[] modulus = pub_modulus.toByteArray();
        byte[] exponent = pub_exponent.toByteArray();

        int cert_length = id.length + modulus.length + exponent.length;
        data = new byte[cert_length + 12];
        addWithLength(id, 4);;
        addWithLength(exponent, 4);
        addWithLength(modulus, 4);

    }

    //parses a Certificate from a byte array
    public Certificate(byte[] cert_data) {
        data = cert_data;
        identity = new String(parseNext(4, 1));
        pub_exponent = new BigInteger(1, parseNext(4, 1));
        pub_modulus = new BigInteger(1, parseNext(4, 1));

    }

    //gives a hash of this certificate
    public byte[] hash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            ByteBuffer buffer = ByteBuffer.allocate(identity.getBytes().length + pub_exponent.toByteArray().length + pub_modulus.toByteArray().length);
            buffer.put(identity.getBytes()).put(pub_exponent.toByteArray()).put(pub_modulus.toByteArray());
            return digest.digest(buffer.array());
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
            return null;
        }
    }

    //verifies a certificate given a signature of this cert and this certs public key pair <e,N>
    public void verifyCertificate(byte[] signature) throws CertificateError {
        BigInteger verify = new BigInteger(1, this.hash());
        BigInteger plain = CipherRSA.decrypt(new BigInteger(signature), pub_exponent, pub_modulus);
        if (verify.compareTo(plain) != 0) {
            throw new CertificateError("Certificates Do Not Match!");
        }
    }

    //some IO methods for the byte arrack backing
    private byte[] parseNext(int len_info_block_size, int block_size) {
        int i = decodeInt(nextBytes(len_info_block_size));
        return nextBytes(i * block_size);
    }

    private byte[] nextBytes(int len) {
        byte[] temp = new byte[len];
        System.arraycopy(data, read_position, temp, 0, len);
        read_position += len;
        return temp;
    }

    private void addWithLength(byte[] bytes, int block_size) {
        byte[] len = encodeInt(bytes.length, block_size);
        copy_from(len);
        copy_from(bytes);

    }

    private void copy_from(byte[] in) {
        System.arraycopy(in, 0, data, write_position, in.length);
        write_position += in.length;
    }

    public BigInteger getPubModulus() {
        return pub_modulus;
    }

    public BigInteger getPubExponent() {
        return pub_exponent;
    }

    public String getIdentity() {
        return identity;
    }

    public byte[] getBytes() {
        return this.data;
    }

}
