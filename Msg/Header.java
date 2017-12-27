package Msg;

import Errors.MessageError;
import java.nio.ByteBuffer;

public class Header {

    /*
        Follows the SSL record Header format 
        [type (1 byte)][version (2 bytes)][record length (2 bytes)]    
     */
    //some static identifiers
    public static final int ALERT = 21;
    public static final int HANDSHAKE = 22;
    public static final int APPLICATION_DATA = 23;
    public static final int HEADER_SIZE = 5;

    //private data for encoding
    private byte[] header; //internal backing for the whole header
    private int type;
    private int version;
    private int length;
    public static final int INT_SIZE = 4;

    //parses a header from a byte array
    public Header(byte[] header) throws MessageError {
        if (header.length != HEADER_SIZE) {
            throw new MessageError("Invalid Header Length");
        }

        this.header = header;

        int k = 0;
        byte type = header[k];
        this.type = (int) type;
        k++;

        byte[] temp = new byte[2];
        System.arraycopy(header, k, temp, 0, temp.length);
        k += 2;

        version = Header.decodeInt(temp);
        temp = new byte[2];
        System.arraycopy(header, k, temp, 0, temp.length);
        length = Header.decodeInt(temp);

    }

    //generates a header given the following parameters
    //type, version, length
    public Header(int type, int version, int len) {
        this.type = type;
        this.version = version;
        this.length = len;

        byte typeb = (byte) type;
        byte[] verb = Header.encodeInt(this.version, 2);
        byte[] lengthb = Header.encodeInt(this.length, 2);

        this.header = new byte[5];

        int k = 0;
        header[k] = typeb;
        k++;
        System.arraycopy(verb, 0, header, k, verb.length);
        k += 2;
        System.arraycopy(lengthb, 0, header, k, lengthb.length);

    }

    //encodes an integer into a variable byte array (up to four bytes)
    public static byte[] encodeInt(int e, int bytes_num) {
        byte[] buffer = ByteBuffer.allocate(INT_SIZE).putInt(e).array();
        byte[] out = new byte[bytes_num];

        int k = out.length - 1;
        for (int i = buffer.length - 1; i >= INT_SIZE - bytes_num; i--) {
            out[k] = buffer[i];
            k--;
        }
        return out;
    }

    //decodes an integer from a variable byte array (up to four bytes)
    public static int decodeInt(byte[] d) {
        byte[] pad = new byte[INT_SIZE - d.length];
        for (int i = 0; i < pad.length; i++) {
            pad[i] = 0;
        }
        ByteBuffer buffer = ByteBuffer.allocate(4).put(pad).put(d);
        return buffer.getInt(0);
    }

    //public getters
    public int getVersion() {
        return version;
    }

    public int getType() {
        return type;
    }

    public int getLength() {
        return length;
    }

    public byte[] encode() {
        return header;
    }

}
