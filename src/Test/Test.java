package Test;

import Cipher.CipherAES;
import Errors.CipherError;
import Cipher.CipherRSA;
import Msg.Certificate;
import Msg.Header;
import Errors.MessageError;
import Errors.ResourceError;
import static Test.TestKeys.Server;
import Test.TestKeys.pub_info;
import java.math.BigInteger;
import java.util.Stack;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Test {

    /*
       TEST CLASS, do not run except for debugging internal functions
     */
    protected static String prk_c = "8879615993307052660307648829078020099353144832136172935648487317494389288824444680505952728536517945446240999417044084808446491226615888089088040899214501097256367428389307552729098750756742835285440002570756289634897513952207464873764945018642824512179375105440218921565649418290568635051089766032592336885418929622984259584571558628150623956884463552915404767223620709163082642207357962632161232774729465112889660601495523839152110439541645198617129338132932393947176455357880637225242845940664949864110090133649268367953830964250574992283860269723428798245365807723397224810718094024299522230194465761871726982187";

    public static void main(String[] args) throws ResourceError {
        test_AES();
        test_dencoding();
        test_Header();
        test_RSA();
        test_certificate_coding();

    }

    public static void test_certificate_coding() {
        try {
            TestKeys keys = new TestKeys();
            pub_info info = keys.get_info(Server);

            Certificate cert = new Certificate(info.id, info.public_exponent_sign, info.public_modulus_sign);
            Certificate cert2 = new Certificate(cert.getBytes());

            if (!cert.getIdentity().equals(cert2.getIdentity())) {
                System.err.println("Error w/ certificate dencoding");
            } else if (cert.getPubExponent().compareTo(cert2.getPubExponent()) != 0) {
                System.err.println("Error w/ certificate dencoding");
            } else if (cert.getPubModulus().compareTo(cert2.getPubModulus()) != 0) {
                System.err.println("Error w/ certificate dencoding");
            }
        } catch (ResourceError ex) {
            System.err.println("Error w/ Resource");
        }

    }

    public static void test_RSA() {
        try {
            TestKeys keys = new TestKeys();

            pub_info info = keys.get_info(Server);

            Certificate cert = new Certificate(info.id, info.public_exponent_sign, info.public_modulus_sign);

            BigInteger verify = new BigInteger(1, cert.hash());
            BigInteger cipher = CipherRSA.encrypt(verify, new BigInteger(prk_c), info.public_modulus_sign);
            BigInteger plain = CipherRSA.decrypt(cipher, info.public_exponent_sign, info.public_modulus_sign);

            if (verify.compareTo(plain) != 0) {
                System.err.println("Error w/ RSA crypto");
            }
        } catch (ResourceError ex) {
            System.err.println("Error w/ RSA crypto");
        }
    }

    public static void test_Header() {

        for (int i = 0; i < Math.pow(2, 16); i++) {
            try {
                Header header = new Header(i, i, i);
                byte[] send = header.encode();
                Header recv = new Header(send);

                if ((header.getLength() != recv.getLength())
                        || (header.getType() != header.getType())
                        || (header.getVersion() != recv.getVersion())) {
                    System.err.println("There's an issue w/ the headers");
                }
            } catch (MessageError ex) {
                System.err.println("There's an issue w/ the headers");
            }
        }
    }

    public static void test_AES() {
        try {
            String test = "rawrrawrs9asjllakfj;slk";
            String other = new String(test);
            CipherAES aes = new CipherAES();
            byte[] testb = test.getBytes();
            SecretKeySpec key = CipherAES.generateKey();
            IvParameterSpec iv = CipherAES.generateIV();
            testb = aes.cipher_operation(testb, CipherAES.ENCRYPT_MODE, key, iv);
            String crypto = new String(testb);
            testb = aes.cipher_operation(testb, CipherAES.DECRYPT_MODE, key, iv);

            test = new String(testb);
            if (!other.equals(test)) {
                System.err.println("Error w/ encryption");
            }
            if (crypto.equals(other)) {
                System.err.println("Error w/ encryption");
            }

        } catch (CipherError ex) {
            System.err.println("test_AES: " + ex.getMessage());
        }
    }

    public static void test_dencoding() {
        int max = Integer.MAX_VALUE;
        Stack<Integer> stacked = new Stack<>();
        for (int i = 0; i < Header.INT_SIZE; i++) {
            int f = max;
            f = Header.decodeInt(Header.encodeInt(f, i + 1));
            stacked.push(f);
        }
        int[] arr = new int[4];
        int set_size = 8;
        for (int i = arr.length - 1; i >= 0; i--) {
            arr[i] = (int) Math.pow(2, set_size * (i + 1)) - 1;
        }
        int k = arr.length - 1;
        arr[k] = max;
        while (!stacked.empty()) {
            if (arr[k] != stacked.pop()) {
                System.err.println("error w/ dencoding");
            }
            k--;
        }
    }
}
