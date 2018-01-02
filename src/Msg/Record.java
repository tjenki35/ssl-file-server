package Msg;

import Errors.MessageError;
import static Msg.Header.ALERT;
import static Msg.Header.APPLICATION_DATA;
import static Msg.Header.decodeInt;
import static Msg.Header.encodeInt;
import static Msg.Record.HandshakeMessage.*;
import static Msg.Record.ID.*;
import java.util.Arrays;
import java.util.HashMap;

/*
    Record/Header message format for this program:

    Message Format Header [record_type][version_number][payload_length]
    Message Format Packet [total_fields]......

    The Record class attempts to provide functionality similar to that of the Records in SSL. 
    Since only of fraction of these messages are useful for the assignment there is a bit of unused code in this class, mainly in parse_packet and additionaly in the class RecordGenerator.java
   
    The ClientSocketR implementation supports the recieving and sending of the Packet class format
    Mainly this class is so we don't have to deal with byte operations manually
 */
public class Record {

    //different types of header information
    public static byte[] SSL_RSA_WITH_AES_SHA = new byte[]{(byte) 0x34, (byte) 0x34}; // some random code
    public static byte[] NULL_COMPRESSION = new byte[]{(byte) 0x00};

    //SSLv3
    public static final byte[] VERSION_BYTES = new byte[]{(byte) 0x03, (byte) 0x00};
    public static int VERSION_NUMBER = ((int) Math.pow(2, 8)) * Record.VERSION_BYTES[0];

    //Fields (specified by the pre-defined IDs enum) 
    public HashMap<ID, byte[]> fields = new HashMap<>();

    //backing for this record
    public byte[] data; //parse data (**note: may not be filled until generate_data is called)

    //some io pointers
    private int write_position = 0;
    private int read_position = 0;

    private Header header = null;

    //create an empty packet
    public Record() {

    }

    //create a packet with the given input as the data field
    public Record(byte[] input) {
        this();
        data = input;
    }

    //create a packet with the given header and input (chains to normal contructor)
    public Record(Header header, byte[] input) {
        this(input);
        this.header = header;
    }

    //creates a packet w/ the given buffer backing
    public Record(int payload_size) {
        data = new byte[payload_size]; // allocate space for the data.
        for (int i = 0; i < data.length; i++) {
            data[0] = 0; // 
        }
    }

    //parses a packet dependant on its type
    public void parse() throws MessageError {
        try {
            if (header != null && header.getType() == ALERT) {
                System.err.println("Alerts not supported");
                System.err.println("data: ");
                System.err.println(Arrays.toString(data));
            } else if (header != null && header.getType() == APPLICATION_DATA) {
                fields.put(DATA, data);
            } else {
                int message_type = data[0];
                fields.put(MESSAGE_TYPE, encodeInt(message_type, 1));
                // System.out.println(HandshakeMessage.get(message_type));
                if (message_type == ClientHello.getValue()) {
                    parse_hello(ClientHello);
                } else if (message_type == ServerHello.getValue()) {
                    parse_hello(ServerHello);
                } else if (message_type == ChangeCipherSpec.getValue()) {
                    parse_specs();
                } else {
                    parse_packet(HandshakeMessage.get(message_type));
                }
            }
        } catch (ArrayIndexOutOfBoundsException ex) {
            throw new MessageError("Error parsing packet", ex);
        }
    }

    //parses a client_hello or a server_hello record
    public void parse_hello(HandshakeMessage type) throws MessageError {
        read_position = 0;
        fields.put(MESSAGE_TYPE, nextBytes(1));
        fields.put(LENGTH, nextBytes(3));
        fields.put(VERSION, nextBytes(Record.SSL_RSA_WITH_AES_SHA.length));
        fields.put(RANDOM, nextBytes(32));
        fields.put(SESSION_ID_LENGTH, nextBytes(1));
        fields.put(SESSION_ID, nextBytes(fields.get(SESSION_ID_LENGTH)[0]));
        if (type == ClientHello) {
            fields.put(CIPHER_SUITE, parseNext(2, 2));
            fields.put(COMPRESSION_METHOD, parseNext(1, 1));
        } else {
            fields.put(CIPHER_SUITE, nextBytes(2));
            fields.put(COMPRESSION_METHOD, nextBytes(1));
        }
    }

    //prints out a record to the standard output (in byte format)
    public void print_record() {
        fields.forEach((s, bytes) -> {
            System.out.println(s.toString());
            System.out.println(Arrays.toString(bytes));
        });
    }

    //parses a change cipher specs record (not used in this assignment)
    private void parse_specs() {
        fields.put(MESSAGE_TYPE, nextBytes(1));
        fields.put(VERSION, nextBytes(2));
        fields.put(LENGTH, nextBytes(2));
        fields.put(CHANGE_CIPHER_SPEC, nextBytes(1));
    }

    //This method parses a packet dependant on its type (mainly, if not all, Handshake messages)
    //**Note:only a handful of these bindings are actually used ( the rest come from the record specifications in the book )
    public void parse_packet(HandshakeMessage type) {
        //System.out.println("Packet Received: " + type.toString());
        read_position = 1;
        int length = decodeInt(nextBytes(3));
        fields.put(LENGTH, encodeInt(length, 4));
        if (null == type) {
            throw new UnsupportedOperationException(); // todo protocol exception
        } else {
            switch (type) { // some of these fields aren't used, but are a part of SSLv3
                case ClientKeyExchange:
                    //skip over other data
                    nextBytes(2); // (unusedlen(2)
                    fields.put(KEY, nextBytes(length));
                    break;
                case ServerKeyExchange:
                    throw new UnsupportedOperationException();
                case CertificateRequest:
                    nextBytes(1);
                    fields.put(CIPHER_SUITE, parseNext(1, 1));
                    fields.put(CAS, parseNext(2, 2));
                    break;
                case Certificate:
                    nextBytes(3);
                    fields.put(CERTIFICATE, parseNext(3, 1));
                    //only accepts one certificate at this point
                    break;
                case CertificateVerify:
                    fields.put(SIGNATURE, parseNext(3, 1));
                    break;
                case HandshakeFinished:
                    fields.put(DIGEST, nextBytes(length));
                    break;
                case ServerHelloDone:
                    fields.put(HELLO_DONE, encodeInt(1, 1));
                    break;
                case Nonce:
                    fields.put(RANDOM, nextBytes(length));
                    break;
                default:
                    throw new UnsupportedOperationException(); // todo protocol exception
            }
        }

    }

    //parses the next field based a length block (of varying size) prepended to the item in the buffer. 
    public byte[] parseNext(int len_size, int multiplier) {
        int i = decodeInt(nextBytes(len_size)); //get length information
        return nextBytes(i * multiplier); //proceed to get a number of items == to multiplier, of length i
    }

    //shorthand for retrieving a field
    public byte[] getField(ID name) throws MessageError {
        if (!fields.containsKey(name)) {
            throw new MessageError("Non existance field selected");
        } else {
            return fields.get(name);
        }

    }

    //Some IO methods
    public void addWithLength(byte[] bytes, int block_size) {
        byte[] len = encodeInt(bytes.length, block_size);
        copy_from(len);
        copy_from(bytes);

    }

    //just some (simple) bytebuffer like logic
    private void copy_from(byte[] in) {
        System.arraycopy(in, 0, data, write_position, in.length);
        write_position += in.length;
    }

    //returns the current position
    public void addBytes(byte[] bytes) {
        copy_from(bytes);
    }

    //reads the next len bytes
    private byte[] nextBytes(int len) {
        byte[] temp = new byte[len];
        System.arraycopy(data, read_position, temp, 0, len);
        read_position += len;
        return temp;
    }

    //some enums for field names
    public static enum ID {
        MESSAGE_TYPE, LENGTH, RANDOM, SESSION_ID_LENGTH, SESSION_ID, CIPHER_SUITE, COMPRESSION_METHOD, VERSION,
        KEY, DIGEST, CAS, CERTIFICATE, SIGNATURE, CHANGE_CIPHER_SPEC, HELLO_DONE, DATA;
    }

    //some enums for handshake types
    public static enum HandshakeMessage {
        ClientHello(1), ServerHello(2), ServerHelloDone(14), ClientKeyExchange(16),
        ServerKeyExchange(12), CertificateRequest(13), Certificate(11), CertificateVerify(15),
        HandshakeFinished(20), ChangeCipherSpec(20), Nonce(99);

        private final int value;

        HandshakeMessage(int v) {
            value = v;
        }

        public static HandshakeMessage get(int v) {
            for (HandshakeMessage k : HandshakeMessage.values()) {
                if (k.equals(v)) {
                    return k;
                }
            }
            return null;
        }

        public int getValue() {
            return value;
        }

        public boolean equals(int v) {
            return v == value;
        }

    }

}
