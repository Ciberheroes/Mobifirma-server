@echo off

javac server/MsgSSLServerSocket.java -classpath ".;./lib/*"

java "-Djavax.net.ssl.keyStore=C:\SSLStore\keystore.jks" "-Djavax.net.ssl.keyStorePassword=ciberheroes" -classpath ".;./lib/*" server/MsgSSLServerSocket
