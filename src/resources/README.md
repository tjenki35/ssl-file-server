#generates an (around) 2MB file for use
#this is what I used to generate my files for testing
head -c 2097152 < /dev/urandom/ > data 

#the program will take it's file input from ./data (the file named data in this directory)
#the output (after the transfer) will be put into ./out (the file name out in this directory)

#to check the difference of the files run
diff data out
#after the program has been run (each program run should overwrite the last out, but maybe delete the old out just to be sure before testing any new files besides the provided data file)
