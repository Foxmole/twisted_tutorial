#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import signal
import sys
from OpenSSL import SSL
from twisted.internet import reactor, ssl, task
from txjsonrpc.web.jsonrpc import Proxy
import os
import getpass

# Stores password if needed to decrypt keyfile
# Password can be hardcoded if needed,
# but than you can use unecrypted keyfiles as well.
# Best security practise is to enter password during runtime to avoid storing
# the password as cleartext
keypw = ""


# Show dedailed information for invalid certificates
def verifyCallback(connection, x509, errnum, errdepth, ok):
    try:
        if not ok:
            print('\033[91mInvalid server certificate\033[0m')
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


# Use our own password callback  method to get Keyfiles password
# This ensures, that we only have to enter it once
def password_cb(maxLength, promptTwice, data=None):
    global keypw
    if(not keypw):
        while(not keypw):
            keypw = getpass.getpass("Enter PEM pass phrase:",
                                    stream=None)
            if(not keypw):
                print("Nothing entered, try it again.")
    return str(keypw).encode("utf-8")


# Use our own context factory to use our Certificate to authenticate
# against the server and ensure that we are using a throng SSL/TLS
# encryption method
class AltCtxFactory(ssl.ClientContextFactory):
    def getContext(self):
        # Used TLS/SSL encryption method
        sslMethod = SSL.TLSv1_2_METHOD
        # Clients private Key, used for authentication
        privKey = "<PATH TO YOUR PRIVATE KEY>"
        # Clients certificate, used for authentication
        certificate = "<PATH TO YOUR CERTIFICATE>"
        # Our trusted Certificate Authority for server connections
        accepted_ca = "<PATH TO YOUR ACCEPTED CERTIFICATE AUTHORITY>"

        self.method = sslMethod
        ctx = ssl.ClientContextFactory.getContext(self)
        # Ensure that we verify server's certificate and use our own
        # verifyCallback method to get further details of invalid certificates
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
                       verifyCallback)
        # Ensure that we only trust our CA
        ctx.load_verify_locations(accepted_ca)
        # Use our own Callback mehtod if a password is needed to decrypt our
        # private key
        ctx.set_passwd_cb(password_cb)
        # Use our certificate for authentication against server
        ctx.use_certificate_file(certificate)
        # Use our private key for authentication against server
        ctx.use_privatekey_file(privKey)
        return ctx


# timeout function wich terminates calls if they take more time than specified
# seconds in $timeout_duration
def timeout(func, args=(), kwargs={}, timeout_duration=3, default=None):
    class TimeoutError(Exception):
        pass

    def handler(signum, frame):
        raise TimeoutError()

    # set the timeout handler
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout_duration)
    try:
        result = func(*args, **kwargs)
    except TimeoutError:
        result = default
    finally:
        signal.alarm(0)

    return result


# Calls a JSON-RPC Remopte function named as $function, on given $proxy
# It uses callbackOK as callback function and $callbackError if there are any
# errors. *args takes all arguments to be used for the remote $function
def callRemote(proxy, function, callbackOK, callbackError, *args):
    proceed = True
    while proceed:
        try:
            # get arround missing python function for python version < 3.5
            li = []
            li.append(function)
            for ar in args:
                li.append(ar)
            # call the timeout function with our arguments, which executes our
            # function on JSONRPC Server and cacels the call if it takes longer
            # than the specified seconds in $timeout_duration
            handle = timeout(proxy.callRemote,
                             args=(tuple(li)),
                             kwargs={},
                             timeout_duration=60,
                             default=None)
            if(handle):
                # adds callback methods which are called from JSONRPC server.
                # $callbackOK gets called if there was no error
                # $callbackError gets called if there was an error like
                # a lost connection
                handle.addCallbacks(callbackOK, callbackError)
            else:
                print("Can not connect to " + function +
                      " please check cacert settings")
            # If we were able to execute our command, there was noi issue with
            # a missing/wrong decryption Key for our private key and we can
            # go further.
            proceed = False
        except SSL.Error as ex:
            # handle worn password or decrypt error,
            # raise it again if it was something else
            if('bad password read' in str(ex) or 'bad decrypt' in str(ex)):
                print("Wrong PEM decryption password entered, " +
                      "wasn't able to decrypt keyfile")
                exit()
            else:
                raise SSL.Error(ex)


# JSONRPC echo callback function, called if everythign went fine
def printValue(value):
    print("Received value: " + str(value))


# JSONRPC multiply callback function, called if everythign went fine
def printMultiplyResult(value):
    print("Received multiplication value: " + str(value))
    # Calls reactor.stop() after 0.1 seconds to stop reactor
    task.deferLater(reactor, 0.1, reactor.stop)


# JSONRPC callback function, called if something went wrong
def printError(error):
    print("Received error in printError: " + str(error))


def main():
    print("\033[94mJSON-RPC client started\033[0m")

    # Server connection data we want to connect
    serverIP = "localhost"
    port = "12345"
    # Enables the Twisted debug mode, if needed
    debugmode = False

    # Creates the JSONRPC Connection with our context factory to
    # authenticate us against the server with our private key and ensure a
    # strong encryption method as well as setting our trusted CA for our
    # server connection.
    proxy = Proxy('https://%s:%s' % (serverIP,
                                     port),
                  ssl_ctx_factory=AltCtxFactory)

    # Calling function "echo" at server "proxy", using printValue if
    # everything went fine, using printError if somethging went wrong
    # as callback function.
    # Passing the message "Servertest passed" to the RPC Server, which returns
    # that value if erverything went fine.
    callRemote(proxy, "echo", printValue, printError, "Servertest passed")
    # Calling function "multiply" at server "proxy", using printValue if
    # everything went fine, using printError if somethging went wrong
    # as callback function.
    # Passing the integers to the RPC Server, which returns
    # the result 42 if erverything went fine.
    callRemote(proxy, "multiply", printMultiplyResult, printError, 6, 7)
    # Enable the Twisted logging module if defined
    if(debugmode):
        from twisted.python import log
        log.startLogging(sys.stdout)
    # Starting our Client jobs
    reactor.run()


if __name__ == "__main__":
    # Disallow root to execute our client
    if os.geteuid() == 0:
        exit('\033[91mSorry, client cannot run as root user!\n\033[0m')
    main()
