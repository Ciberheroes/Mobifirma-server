#!/bin/bash

javac server/MsgSSLServerSocket.java

java -Djavax.net.ssl.keyStore=$HOME/SSLStore/keystore.jks -Djavax.net.ssl.keyStorePassword=ciberheroes -classpath ".:lib/*" server.MsgSSLServerSocket