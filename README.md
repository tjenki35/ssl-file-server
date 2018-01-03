### Running the project in the IDE

The netbeans configuration file is being maintained for this project. 
-Simply run the server as a single java process
-Then run the client as a separate process.

### Building from the command line

The makefile provided does some generic java compilation since dependencies are light. 

Run </br>
` make ` </br>
in the source directory to compile all java source files in ./src.

Run </br>
` make clean ` </br>
to delete all class files and output *(files in ./src/resources/out).


should compile all of the java files underneath this directory

For the simulation:
1.run (in separate terminals)

- ` java Simulation.AServer `

This server will be listening for incoming connections on the default port (5050) for clients that implement the following protocol:

## Handshake and Data Transfer Model

Client                          Server
   ------------------------------>   1. Client node initiates connection with Server

   ------------------------------>   2. The Client sends hello record to inform the server of the cipher/compression parameters. 

   <------------------------------   3. The server verifies the parameters and generated session id (*session id is disregarded in this current state of implementation)

   <------------------------------   4. The server sends a self-signed certificate (<N,e>) to the client.

   ------------------------------>   5. After verifying the self-signed certificate the client sends a certificate as well. 

   <----------------------------->   6. Using this gained public key information both the server and client send encrypted nonces. 
                                        These nonces are then xored to create a master key. From this master key four additional keys
                                        are generated for encryption and integerity protection (for one-way communication from server to client). 
      
   <------------------------------   7. The Server then delivers the encrypted payload to the client.    


- ` java Simulation.AClient #starts the client and connects to port 5050 `

#this should trigger the protocol, which will authenticate per assignment
#requirements and then proceed to send the file from server to client
#in a cryptographically secure manner. (details are in the code)

The input file for the program is src/resources/data, which is a randomly generated file using urandom
The output file (after the program has been run) is src/resources/out. This file should be overwritten by the program each time the client grabs a file

To verify these files are infact the same run (in the resources directory)
$diff data out

For the corruption simulation:
1. run (in separate terminals)

$java Simulation.AServer
$java Simulation.AClient -c #note the -c switch

#this should trigger the same process, but intentially corrupts
#the first message sent on the client side.
#this should produce verification errors during the handshake verification process

#Note: the certificate model I am using is simply the encoding of
#<e, N> (e - public exponent, N - public modulus)

and the signature of this certificate consists of:
# hash(<e,N>)^d mod N. 

#**where d denotes the private RSA key

#the symmetric key scheme used is AES (using the java Cipher library)
#the hash scheme used is SHA-1 as per assignment requirement

