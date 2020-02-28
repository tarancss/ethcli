// Package ethcli implements a simple client interface to an Ethereum node using RPC-JSON API calls as described in https://github.com/ethereum/wiki/wiki/JSON-RPC.
//
// The client simplifies using the Ethereum RPC interface by providing simple methods to call the most used functionality, such as asking for the balance of an address, getting name or decimals of an ERC20 token and sending and getting transactions. The client connects to the node's endpoint (often http://localhost:8545) or you can use third party providers such as infura.io. To connect to infura.io ethereum infrastructure, you need to provide your infura endpoint and a secret password if you are using Infura API v3.
//
// When calling methods, input arguments like addresses, tokens, hashes and amounts need to be "0x"-prefixed strings in hexadecimal (see the tests for reference).
package ethcli

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/powerman/rpc-codec/jsonrpc2"
)

// Ethereum ERC20 token methodID (keccak-256 of the function name and arguments)
const (
	ERC20transfer256     = "a9059cbb" // transfer(address,uint256)
	ERC20transferFrom256 = "23b872dd" // transferFrom(address,address,uint256)
	ERC20transfer        = "6cb927d8" // transfer(address,uint)
	ERC20transferFrom    = "a978501e" // transferFrom(address,address,uint)
)

const (
	// gas needed for an ether transfer
	GasTransferEther uint64 = 21000
	// gas needed for an ERC20 token transfer
	GasTransferToken uint64 = 100000
)

// Transaction status constants
const (
	TrxPending uint8 = 0
	TrxFailed  uint8 = 1
	TrxSuccess uint8 = 2
)

// Error codes defined
var (
	ErrBadKey         = errors.New("Bad format key")
	ErrBadTo          = errors.New("Bad format to address")
	ErrBadToken       = errors.New("Bad format token address")
	ErrBadFrom        = errors.New("Bad format from address")
	ErrBadAmt         = errors.New("Error converting value returned by node")
	ErrNoBlock        = errors.New("Block not available yet")
	ErrNoTrx          = errors.New("Transaction receipt not available yet")
	ErrNoToken        = errors.New("Address has no valid token defined")
	ErrWrongAmt       = errors.New("Bad amount format or amount cannot be over 32 bytes!")
	ErrWrongHash      = errors.New("Hash of transaction does not match with requested hash")
	ErrInvalidTrxData = errors.New("Transaction data received from node is invalid")
	ErrSendTokenData  = errors.New("Cannot send token and data at same time")
)

// ropsten configuration variables used to generate transactions
var ropstenConfig *params.ChainConfig = params.TestnetChainConfig
var ropstenBlock *big.Int = big.NewInt(2756944) // this is the latest block in ropsten as of 2018/03/02 19:56

// Compose EthCli as JSON RPC client
type EthCli struct {
	*jsonrpc2.Client
}

// Init initializes the client connecting to the ethereum node url.
// A secret password is optional. "secret" is needed for Infura's v3 API.
func Init(nodeUrl, secret string) *EthCli {
	if secret == "" {
		return &EthCli{jsonrpc2.NewHTTPClient(nodeUrl)}
	}
	return &EthCli{jsonrpc2.NewCustomHTTPClient(nodeUrl,
		jsonrpc2.DoerFunc(func(req *http.Request) (*http.Response, error) {
			// Setup custom HTTP client.
			client := &http.Client{}
			// Modify request as needed.
			req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(secret)))
			return client.Do(req)
		}))}
}

// End closes the client
func (c *EthCli) End() {
	c.Close()
}

// GetBalance makes an RPC call to get the balance of an address.
// Returns the balance in ether, and if a token has been specified, it returns the balance of the token too using the ERC20 function balanceOf(address).
// To check balance (ether):
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x357dd3856d856197c1a000bbAb4aBCB97Dfc92c4","latest"],"id":1}' http://localhost:8545
// To check balance (ERC20):
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"data":"0x70a08231000000000000000000000000cba75F167B03e34B8a572c50273C082401b073Ed","to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f"},"latest"],"id":1}' http://localhost:8545
func (c *EthCli) GetBalance(address, token string, ethBal, tokBal *big.Int) (err error) {
	var response interface{}
	var ok bool
	// get ether
	if err = c.Call("eth_getBalance", []interface{}{address, "latest"}, &response); err != nil {
		return
	}
	if ethBal, ok = ethBal.SetString(response.(string), 0); !ok {
		err = ErrBadAmt
	}
	// get token
	if token != "" {
		var data string
		data = "0x70a08231" + "000000000000000000000000" + address[2:] // balanceOf(address) + 12 zeroes padded + address
		if err = c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": data}, "latest"}, &response); err != nil {
			return
		}
		if tokBal, ok = tokBal.SetString(response.(string), 0); !ok {
			err = ErrBadAmt
		}
	}
	return
}

// GetTransactionCountAtBlock makes an RPC call to get the number of transactions ("nonce") sent from an account ("address") at the block number ("block"). Possible values for block are a hexadecimal number, "earliest", "latest" or "pending".
func (c *EthCli) GetTransactionCount(address, block string) (nonce uint64, err error) {
	var response interface{}
	if err = c.Call("eth_getTransactionCount", []interface{}{address, block}, &response); err != nil {
		return
	}
	return strconv.ParseUint(response.(string), 0, 64)
}

// GasPrice makes an RPC call to get the current gasPrice.
// To get gasPrice execute in a terminal:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":1}' http://localhost:8545
// There are gasPrice providers for mainNet, for instance:
//  curl -X POST https://www.ethgasstation.info/json/ethgasAPI.json
func (c *EthCli) GasPrice() (price uint64, err error) {
	var response interface{}
	if err = c.Call("eth_gasPrice", []interface{}{}, &response); err != nil {
		return 0, err
	}
	return strconv.ParseUint(response.(string), 0, 64)
}

// EstimateGas makes an RPC call to get the estimated gas needed for a transaction that sends "value" to address "to". Optionally, data may be filled and it is also taken into account.
// To get gasLimit execute in a terminal:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_estimateGas","params":[{"to":"0x1CD434711fBAe1f2d9C70001409Fd82d71fDCCAa", "value":"0xb1a2bc2ec50000", "data":"0xfffe3031"}],"id":1}' -u <user:secret> https://ropsten.infura.io/v3/projectId
func (c *EthCli) EstimateGas(to, value, data string) (gas uint64, err error) {
	// if an ERC token transfer, just return enough gas
	if len(data) == 2+68*2 && (data[2:10] == ERC20transfer || data[2:10] == ERC20transfer256) ||
		len(data) == 2+100*2 && (data[2:10] == ERC20transferFrom || data[2:10] == ERC20transferFrom256) {
		return GasTransferToken, nil
	}

	// geth nodes have problems unmarshaling values with leading zeroes (ie. 0x04fc), so we remove them. Parity does not have this problem
	var response interface{}
	var tmp string = ""
	if len(value) > 2 {
		tmp = "0x" + strings.TrimLeft(value[2:], "0")
		if tmp == "0x" {
			tmp = ""
		}
	}
	// call the node
	if err = c.Call("eth_estimateGas", []interface{}{map[string]interface{}{"to": to, "value": tmp, "data": data}}, &response); err != nil {
		return
	}
	return strconv.ParseUint(response.(string), 0, 64)
}

// sendRawTransaction makes an RPC call to send a signed tx to the blockchain and returns the transaction hash.
// "0x"+raw has to be inserted in a curl command to send the transaction via Infura.io eth_sendRawTransaction RPC
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86b0285012a05f20082ffff941cd434711fbae1f2d9c70001409fd82d71fdccaa87b1a2bc2ec50000802aa0727841e5f55e5a8315a83ee1341405f05ba68ca8667db13fa694b5e680f41e31a07e291bc489aefb24ee2217900cddbd533966cc456799032fea6632896f100b64"],"id":4}' http://localhost:8545
// Example response from Infura:
//  {"jsonrpc":"2.0","id":4,"result":"0xfdd2beb06580944421f4e0ea8e408d9cb51dace689d5835288bf934500931e5d"}
func (c *EthCli) sendRawTransaction(raw []byte) (hash string, err error) {
	var response interface{}
	if err = c.Call("eth_sendRawTransaction", []interface{}{"0x" + hex.EncodeToString(raw)}, &response); err != nil {
		return hash, err
	}
	return response.(string), nil
}

// GetTransactionByHash makes an RPC call to get a transaction detail. Arguments:
//  hash: hash of the transaction to get
//  response: pointer to the receipt received from the node
func (c *EthCli) GetTransactionByHash(hash string, response *map[string]interface{}) (err error) {
	err = c.Call("eth_getTransactionByHash", []interface{}{hash}, response)
	if err == nil && *response == nil {
		return ErrNoTrx
	}
	return err
}

// GetTransactionReceipt makes an RPC call to get a transaction receipt (status). Arguments:
//  hash: hash of the transaction to get
//  response: pointer to the receipt received from the node
func (c *EthCli) GetTransactionReceipt(hash string, response *map[string]interface{}) (err error) {
	err = c.Call("eth_getTransactionReceipt", []interface{}{hash}, response)
	if err == nil && *response == nil {
		return ErrNoTrx
	}
	return err
}

// GetBlockByNumber makes an RPC call to get block data from the node. Arguments:
//  block: number of the block to get
//  full: true (gets full data for each transaction in the block), false (only the block hash is provided)
//  response: pointer to the blockData received from the node
func (c *EthCli) GetBlockByNumber(block uint64, full bool, response *map[string]interface{}) (err error) {
	blk := strconv.FormatUint(block, 16)
	err = c.Call("eth_getBlockByNumber", []interface{}{("0x" + blk), full}, response)
	if err == nil && *response == nil {
		return ErrNoBlock
	}
	return err
}

// GetLatestBlock makes an RPC call to get the number of the latest block mined.
func (c *EthCli) GetLatestBlock() (num uint64, err error) {
	var response map[string]interface{}
	if c != nil {
		err = c.Call("eth_getBlockByNumber", []interface{}{"latest", false}, &response)
		if err == nil {
			number, ok := response["number"]
			if ok {
				return strconv.ParseUint(number.(string), 0, 64)
			}
		}
	}
	return num, err
}

// GetTokenDecimals makes an RPC call to get a token (identified by contract address) decimals.
// token: address of the contract that defines the token. It must be ERC20 compliant
// Executes:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f","data":"0x313ce567"},"latest"],"id":4}' http://localhost:8545
func (c *EthCli) GetTokenDecimals(token string) (dec uint64, err error) {
	var response interface{}
	if token == "" { // ether
		return 18, nil
	}
	if len(token) != 42 {
		return 0, ErrBadToken
	}
	if err = c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": "0x313ce567"}, "latest"}, &response); err != nil {
		return 0, err
	}
	return strconv.ParseUint(response.(string), 0, 64)
}

// GetTokenName makes an RPC call to get a token (identified by contract address) name.
// token: address of the contract that defines the token. It must be ERC20 compliant
// Executes:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f","data":"0x06fdde03"},"latest"],"id":4}' http://localhost:8545
func (c *EthCli) GetTokenName(token string) (name string, err error) {
	var response interface{}
	var result string
	var tmp []byte
	var length int64

	if token == "" {
		return "Ether", nil
	}
	if len(token) != 42 {
		return name, ErrBadToken
	}
	if err = c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": "0x06fdde03"}, "latest"}, &response); err != nil {
		return "", err
	}
	result = response.(string)
	if result == "0x" {
		return "", ErrNoToken
	}
	if len(result) >= 2+64*2 {
		length, err = strconv.ParseInt(result[2+64:2+64*2], 16, 64)
		if len(result) >= 2+64*2+int(length*2) {
			tmp, err = hex.DecodeString(result[2+64*2 : 2+64*2+int(length*2)])
		} else {
			err = ErrNoToken
		}
	} else {
		err = ErrNoToken
	}
	return string(tmp), err
}

// GetTokenSymbol makes an RPC call to get a token (identified by contract address) symbol.
// token: address of the contract that defines the token. It must be ERC20 compliant
// Executes:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f","data":"0x95d89b41"},"latest"],"id":4}' http://localhost:8545
func (c *EthCli) GetTokenSymbol(token string) (name string, err error) {
	var response interface{}
	var result string
	var tmp []byte
	var length int64

	if token == "" {
		return "ETH", nil
	}
	if len(token) != 42 {
		return name, ErrBadToken
	}
	if err = c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": "0x95d89b41"}, "latest"}, &response); err != nil {
		return "", err
	}
	result = response.(string)
	if result == "0x" {
		return "", ErrNoToken
	}
	if len(result) >= 2+64*2 {
		length, err = strconv.ParseInt(result[2+64:2+64*2], 16, 64)
		if len(result) >= 2+64*2+int(length*2) {
			tmp, err = hex.DecodeString(result[2+64*2 : 2+64*2+int(length*2)])
		} else {
			err = ErrNoToken
		}
	} else {
		err = ErrNoToken
	}
	return string(tmp), nil
}

// GetTokenIcoOffer makes an RPC call to get a token (identified by contract address) unitsOneEthCanBuy.
// token: address of the contract that defines the token. It must be ERC20 compliant
// Executes:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f","data":"0x65f2bc2e"},"latest"],"id":4}' http://localhost:8545
func (c *EthCli) GetTokenIcoOffer(token string) (ico uint64, err error) {
	var response interface{}
	if token == "" {
		return 0, nil
	}
	if len(token) != 42 {
		return 0, ErrBadToken
	}
	if err = c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": "0x65f2bc2e"}, "latest"}, &response); err != nil || response.(string) == "0x" {
		return 0, err
	}
	return strconv.ParseUint(response.(string), 0, 64)
}

// Sends a transaction to the blockchain.
// If sending an ERC20 token, the argument token must be a valid 20-byte address
// If priceIn is 0, a suggested gas price will be sought from the blockchain.
// Use dryRun = true for testing (it will not send the transaction to the blockchain but provide a valid hash)
func (c *EthCli) SendTrx(fromAddress, toAddress, token, amount string, data []byte, key string, priceIn uint64, dryRun bool) (priceOut, gasLimit uint64, hash []byte, err error) {
	var nonce uint64
	var ok bool
	var to common.Address
	var fromKey *ecdsa.PrivateKey
	var amt *big.Int = new(big.Int)
	var raw, tmp, tmpAmt []byte

	// check arguments
	if fromAddress[:2] != "0x" || len(fromAddress) != 42 {
		err = ErrBadFrom
	}
	if toAddress[:2] != "0x" || len(toAddress) != 42 {
		err = ErrBadTo
	}
	if token != "" && (token[:2] != "0x" || len(token) != 42) {
		err = ErrBadToken
	}
	if amount[:2] != "0x" {
		err = ErrWrongAmt
	}
	if len(key) != 64 {
		err = ErrBadKey
	}
	// from
	if fromKey, err = crypto.HexToECDSA(key); err != nil {
		return
	}
	// check amount and get amt for signTrx
	amt, ok = amt.SetString(amount, 0)
	if !ok || len(amt.Bytes()) > 32 {
		return priceOut, gasLimit, hash, ErrWrongAmt
	}
	// get nonce
	if nonce, err = c.GetTransactionCount(fromAddress, "latest"); err != nil {
		return
	}
	// get to, data
	if token == "" {
		to = common.HexToAddress(toAddress)
	} else {
		// make sure data comes empty!
		if data != nil {
			return priceOut, gasLimit, hash, ErrSendTokenData
		}
		to = common.HexToAddress(token)
		var toAddr []byte
		toAddr, err = hex.DecodeString(toAddress[2:])
		tmpAmt = make([]byte, 32)
		copy(tmpAmt[32-len(amt.Bytes()):32], amt.Bytes()[:])
		amt.Sub(amt, amt) // amt = 0 as we do not send ether!!
		// build data for token transaction: methodId (4), to address (32), amount (32)
		tmp = make([]byte, 0, 4+32+32)
		tmp = append(tmp, 0xa9, 0x05, 0x9c, 0xbb)                                                 // transfer = 0xa9059cbb
		tmp = append(tmp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // pad 12 zeroes
		tmp = append(tmp, toAddr[:]...)                                                           // to
		tmp = append(tmp, tmpAmt[:]...)                                                           // amount
		data = tmp
	}
	// get gasPrice
	if priceIn == 0 {
		priceOut, err = c.GasPrice()
		if err != nil {
			return
		}
	} else {
		priceOut = priceIn
	}
	// gasPrice and gasLimit
	gasPrice := new(big.Int).SetUint64(priceOut)
	if token == "" {
		gasLimit, err = c.EstimateGas(toAddress, amount, "0x"+hex.EncodeToString(data))
	} else {
		gasLimit, err = c.EstimateGas(token, "0x00", "0x"+hex.EncodeToString(tmp))
	}
	if err != nil {
		return
	}
	// generate transaction, get hash and raw signed transaction
	if hash, raw, err = signTrx(nonce, to, amt, gasLimit, gasPrice, data, fromKey); err != nil {
		return
	}
	// send transaction to blockchain
	if !dryRun {
		_, err = c.sendRawTransaction(raw)
	}
	return
}

// signTrx returns the hash and raw signed transaction ready to be sent to node
// "0x"+raw has to be inserted in a curl command to send the transaction via Infura.io eth_sendRawTransaction RPC
// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86b0285012a05f20082ffff941cd434711fbae1f2d9c70001409fd82d71fdccaa87b1a2bc2ec50000802aa0727841e5f55e5a8315a83ee1341405f05ba68ca8667db13fa694b5e680f41e31a07e291bc489aefb24ee2217900cddbd533966cc456799032fea6632896f100b64"],"id":4}' http://localhost:8545
// response from Infura: {"jsonrpc":"2.0","id":4,"result":"0xfdd2beb06580944421f4e0ea8e408d9cb51dace689d5835288bf934500931e5d"}
func signTrx(nonce uint64, to common.Address, amt *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, prv *ecdsa.PrivateKey) (hash, raw []byte, err error) {
	var s types.Signer = types.MakeSigner(ropstenConfig, ropstenBlock)
	// generate a transaction
	var tx *types.Transaction = types.NewTransaction(nonce, to, amt, gasLimit, gasPrice, data)
	// sign transaction
	if tx, err = types.SignTx(tx, s, prv); err != nil {
		return
	}
	hash = tx.Hash().Bytes()
	// serialize signed transaction
	raw, err = rlp.EncodeToBytes(tx)
	return
}

// GetTrx returns the transaction data for the given hash.
func (c *EthCli) GetTrx(hash string) (blk uint64, ts int32, price, gas uint64, status uint8, fee uint64, token, data []byte, to, from, amount string, err error) {
	var response map[string]interface{}
	var tmp string
	var ok bool
	var i int
	var ts64 int64

	// get tx by Hash
	err = c.GetTransactionByHash(hash, &response)
	if err != nil && err != ErrNoTrx {
		return
	} else if response != nil {
		// check hash
		if tmp, ok = response["hash"].(string); !ok || hash != tmp {
			err = ErrWrongHash
			return
		}
		// block number
		tmp, ok = response["blockNumber"].(string)
		if ok {
			blk, err = strconv.ParseUint(tmp, 0, 64)
			if err != nil {
				err = ErrInvalidTrxData
				return
			}
		} // else blk will be 0 as tx may be pending and has not been included in a mined block

		// gasPrice
		tmp, ok = response["gasPrice"].(string)
		if !ok {
			err = ErrInvalidTrxData
			return
		}
		price, err = strconv.ParseUint(tmp, 0, 64)
		if err != nil {
			err = ErrInvalidTrxData
			return
		}

		// input (data sent to the tx)
		tmp, ok := response["input"].(string)
		if !ok {
			err = ErrInvalidTrxData
			return
		}
		data, err = hex.DecodeString(tmp[2:])
		if err != nil {
			err = ErrInvalidTrxData
			return
		}

		// if data[0:4]=methodId, get token from "to" address
		if len(data) >= 4 && (bytes.Compare(data[0:4], []byte{0xa9, 0x05, 0x9c, 0xbb}) == 0 || bytes.Compare(data[0:4], []byte{0xa9, 0x78, 0x50, 0x1c}) == 0) {
			// this is a ERC20 token transfer
			tmp, ok = response["to"].(string)
			if !ok {
				err = ErrInvalidTrxData
				return
			}
			token, err = hex.DecodeString(tmp[2:])
			if err != nil {
				err = ErrInvalidTrxData
				return
			}
			// to address
			if len(data) >= 4+32 {
				to = "0x" + hex.EncodeToString(data[16:36])
			}
			if bytes.Compare(data[0:4], []byte{0xa9, 0x78, 0x50, 0x1c}) == 0 {
				// transferFrom method, get from address first, then amount (without any leading zero)
				if len(data) == 100 {
					from = "0x" + hex.EncodeToString(data[36+12:36+32])
					for i = 0; i < 32 && data[68+i] == 0x00; i++ {
					}
					amount = "0x" + hex.EncodeToString(data[68+i:68+32])
				}
			} else {
				// transfer method, get amount. "from" address taken from response map.
				if len(data) == 68 {
					for i = 0; i < 32 && data[36+i] == 0x00; i++ {
					}
					amount = "0x" + hex.EncodeToString(data[36+i:36+32])
				}
				// from address
				if from, ok = response["from"].(string); !ok {
					err = ErrInvalidTrxData
					return
				}
			}
		} else {
			// this is a normal ether transaction, so get from, to and amount from the response map
			if from, ok = response["from"].(string); !ok {
				err = ErrInvalidTrxData
				return
			}
			if to, ok = response["to"].(string); !ok {
				err = ErrInvalidTrxData
				return
			}
			if amount, ok = response["value"].(string); !ok {
				err = ErrInvalidTrxData
				return
			}
		}
	} else {
		fmt.Printf("GetTrx in eth_getTransactionByHash: No transaction\n")
		err = ErrNoTrx
		return
	}

	err = c.GetTransactionReceipt(hash, &response)
	if err != nil && err != ErrNoTrx {
		return
	} else if response != nil {
		// check hash
		if tmp, ok = response["hash"].(string); !ok || hash != tmp {
			err = ErrWrongHash
			return
		}
		blkno, ok := response["blockNumber"].(string)
		if ok {
			blk, _ = strconv.ParseUint(blkno, 0, 64)
		}
		// if tx in block, get the status. If not in block tx is pending mining, so status=0
		if blk != 0 {
			tmp, ok := response["status"].(string)
			if ok {
				statu64, _ := strconv.ParseUint(tmp, 0, 8)
				status = uint8(statu64)
				status++ // for Ethereum 0=failed 1=success, so we just add 1
			}
		}
		gasUsed, ok := response["gasUsed"].(string)
		if ok {
			gas, _ = strconv.ParseUint(gasUsed, 0, 64)
		}
		fee = gas * price
	} else {
		fmt.Printf("GetTrx in eth_getTransactionReceipt: No transaction\n")
		err = ErrNoTrx
		return
	}

	if blk > 0 {
		err = c.GetBlockByNumber(blk, false, &response)
		if err != nil && err != ErrNoBlock {
			return
		} else if response != nil {
			// get block timestamp
			tmp, ok = response["timestamp"].(string)
			if !ok {
				err = ErrWrongHash
				return
			}
			ts64, err = strconv.ParseInt(tmp, 0, 32)
			ts = int32(ts64)
		} else {
			err = ErrNoBlock
			return
		}
	}

	return
}
