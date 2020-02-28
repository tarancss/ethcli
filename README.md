# ethcli
Ethereum node client implementing basic interface to RPC-JSON API

Package ethcli implements a simple client interface to an Ethereum node using RPC-JSON API calls as described in https://github.com/ethereum/wiki/wiki/JSON-RPC.

The client simplifies using the Ethereum RPC interface by providing simple methods to call the most used functionality, such as asking for the balance of an address, getting name or decimals of an ERC20 token and sending and getting transactions. The client connects to the node's endpoint (often http://localhost:8545) or you can use third party providers such as infura.io. To connect to infura.io ethereum infrastructure, you need to provide your infura endpoint and a secret password if you are using Infura API v3.

When calling methods, input arguments like addresses, tokens, hashes and amounts need to be "0x"-prefixed strings in hexadecimal (see the tests for reference).