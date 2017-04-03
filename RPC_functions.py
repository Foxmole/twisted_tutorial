#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from txjsonrpc.web import jsonrpc


class JSONRPCServer(jsonrpc.JSONRPC):
    """
    JSONRPC server offers the following functions to be executed by clients

    functions can be called with:
    d = proxy.callRemote('echo', 'test')
    d.addCallbacks(printValue, printError)

    further examples:
    https://github.com/oubiwann/txjsonrpc/tree/master/examples
    """

    def jsonrpc_echo(self, *args):
        """
        Return all passed args.
        """
        return args

    def jsonrpc_multiply(self, a, b):
        """
        Multiply a with b.
        """
        # we can define subfunctions for our calculations
        def multiply(a, b):
            return (a * b)

        result = multiply(a, b)
        return result
