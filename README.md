### Running the project in the IDE

The netbeans configuration file is being maintained for this project. 
- Simply run the server as a single java process
- Then run the client as a separate process.

### Building from the command line

The makefile provided does some generic java compilation since dependencies are light. 

Run </br>
` make ` </br>
in the source directory to compile all java source files in ./src.

Run </br>
` make clean ` </br>
to delete all class files and output *(files in ./src/resources/out).

#### To run the simulation:
run (in separate terminals) </br>
` java Simulation.AServer ` </br>
and </br>
` java Simulation.AClient `

## Handshake and Data Transfer Model

This server will be listening for incoming connections on the default port (5050) for clients that implement the following protocol:

![screenshot](https://github.com/tjenki35/ssl-file-server/blob/master/resources/SSL-file-server-diagram.jpg?raw=true)

## Sidenotes: 

- The input file for the program is src/resources/data, which is a randomly generated file using urandom
- The output file (after the program has been run) is src/resources/out. This file should be overwritten by the program each time the client grabs a file
- To verify that the file is transported securly use a tool such a diff (linux)
` diff data out `
- The symmetric key scheme used is AES (using the java Cipher library)
- The hash scheme used is SHA-1 
