LIB = bcprov-jdk15on-160.jar
JAVA_SOURCE = *.java
JAVAC = javac
JVM = java
JAR = jar
MAIN = BrickChain

.java: $(JAVA_SOURCE)
	$(JAVAC) -cp "$(LIB):." $?

.jar: .java
	$(JAR) -cf $(MAIN).jar *.class

all: .jar
	java -cp "$(LIB):$(MAIN).jar:." $(MAIN)

test:
	java -cp "$(LIB):$(MAIN).jar:." $(MAIN)

clean:
	rm -f  *.class $(MAIN).jar
