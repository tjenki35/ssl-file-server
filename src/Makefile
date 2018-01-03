#note this is for compiling the project within the source folder
default:
	find -name "*.java" > sources.txt
	javac @sources.txt
clean:
	find . -name "*.class" -type f -delete
	rm ./resources/out