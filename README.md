#to build this project run
make
#the default recipe should run and it should compile all of the java files underneath this directory

#to clean this project run
make clean
#this will remove all class files and the src/resources/out file (if present, will error out if not after cleaning up the class files)

For the simulation:
1.run (in separate terminals)

$java Simulation.AServer #starts the server on port 5050
$java Simulation.AClient #starts the client and connects to port 5050

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

