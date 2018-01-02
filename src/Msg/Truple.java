package Msg;

import java.math.BigInteger;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

//Generic truple class to hold various useful objects
public class Truple<T> {

    public T first;
    public T second;
    public T third;

    public Truple() {
    }

    public Truple(T k1, T k2, T k3) {
        this.first = k1;
        this.second = k2;
        this.third = k3;
    }

    //this function has only been implemented for the parsing of SecretKeys from byte arrays
    public static Truple<SecretKey> parseTruple(byte[] a, byte[] b, byte[] c) {
        SecretKeySpec key1 = new SecretKeySpec(a, 0, a.length, "DES");
        SecretKeySpec key2 = new SecretKeySpec(b, 0, b.length, "DES");
        SecretKeySpec key3 = new SecretKeySpec(c, 0, c.length, "DES");
        return new Truple(key1, key2, key3);
    }

    //this to string override only changes the output for BigInteger and SecretKeys (mainly for testing)
    @Override
    public String toString() {
        StringBuilder output = new StringBuilder();
        if (first instanceof SecretKey) {
            output.append(new BigInteger(1, ((SecretKey) first).getEncoded())).append("\n");
            output.append(new BigInteger(1, ((SecretKey) second).getEncoded())).append("\n");
            output.append(new BigInteger(1, ((SecretKey) third).getEncoded())).append("\n");
        } else if (first instanceof BigInteger) {
            output.append((BigInteger) first);
            output.append((BigInteger) second);
            output.append((BigInteger) third);
        } else { // else just use the normal toString() for that object
            output.append(first);
            output.append(second);
            output.append(third);
        }
        return output.toString();
    }

}
