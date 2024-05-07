#!/bin/bash

mkdir ~/SSLStore && Keytool -genkey -keystore ~/SSLStore/keystore.jks -alias SSLCertificate -keyalg RSA