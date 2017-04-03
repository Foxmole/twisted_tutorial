#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os

from OpenSSL import SSL
from twisted.web import server
from twisted.internet import reactor
from twisted.internet import ssl
from RPC_functions import JSONRPCServer


# Show dedailed information for invalid certificates
def verifyCallback(connection, x509, errnum, errdepth, ok):
    try:
        if not ok:
            print('\033[91mInvalid client certificate\033[0m')
            if(x509.has_expired()):
                print("\033[91mCertificate has expired\033[0m")
                return False
            print(str(x509.get_subject()))
            print("Issuer: " + str(x509.get_issuer()))
            print("Version: " + str(x509.get_version()))
            return False
        else:
            return True
    except Exception as e:
        print("error in verifyCallback" + str(e))
        return False


def main():
    port = 12345
    # Servers private Key
    privKey = "<PATH TO YOUR PRIVATE KEY>"
    # Server's certificate
    certificate = "<PATH TO YOUR CERTIFICATE>"
    # Accepted client Certificate Authority, accepts only
    # clients with signed certificates as authentication method
    accepted_ca = "<PATH TO YOUR ACCEPTED CERTIFICATE AUTHORITY>"
    # Used SSL/TLS method using OpenSSL
    sslMethod = SSL.TLSv1_2_METHOD

    # Our RPC Server which is imported from RPC_functions.py
    r = JSONRPCServer()

    # SSL context used for encryption
    sslContext = ssl.DefaultOpenSSLContextFactory(privKey, certificate,
                                                  sslmethod=sslMethod)
    ctx = sslContext.getContext()
    # Ensure, that we verify clients's certificate, use our verifyCallback
    # for detailed information if the offered certificate is invalid
    ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                   verifyCallback)
    # Only accept our trusted CA/Certificate
    ctx.load_verify_locations(accepted_ca)

    # Use our RPC server with encryption as well as client certificate
    # authentication
    reactor.listenSSL(port,
                      server.Site(r),
                      contextFactory=sslContext)
    print("\033[94mJSON-RPC server started at port: \033[0m" + str(port))
    # start our server
    reactor.run()


if __name__ == '__main__':
    # Disallow root to execute our client
    if os.geteuid() == 0:
        exit('\033[91mSorry, server cannot run as root user!\n\033[0m')
    main()
