// Package ethcli implements a simple client interface to an Ethereum node using RPC-JSON API calls.
//
// The client simplifies using the Ethereum RPC interface by providing simple methods to call the most used
// functionality, such as asking for the balance of an address, getting name or decimals of an ERC20 token and sending
// and getting transactions. The client connects to the node's endpoint (often http://localhost:8545) or you can use
// third party providers such as infura.io. To connect to infura.io ethereum infrastructure, you need to provide your
// infura endpoint and a secret password if you are using Infura API v3.
//
// When calling methods, input arguments like addresses, tokens, hashes and amounts need to be "0x"-prefixed strings in
// hexadecimal (see the tests for reference).
//
// Ethereum's RPC-JSON API is described in https://github.com/ethereum/wiki/wiki/JSON-RPC.
package ethcli

import (
	"bytes"
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

// Ethereum ERC20 token methodID (keccak-256 of the function name and arguments).
const (
	ERC20transfer256     = "a9059cbb" // transfer(address,uint256)
	ERC20transferFrom256 = "23b872dd" // transferFrom(address,address,uint256)
	ERC20transfer        = "6cb927d8" // transfer(address,uint)
	ERC20transferFrom    = "a978501e" // transferFrom(address,address,uint)
)

//nolint:gochecknoglobals // slice representation of above
var (
	erc20transfer256B  = []byte{0xa9, 0x05, 0x9c, 0xbb}
	erc20transferFromB = []byte{0xa9, 0x78, 0x50, 0x1e}
)

const (
	// Gas needed for an ether transfer.
	GasTransferEther uint64 = 21000
	// Gas needed for an ERC20 token transfer.
	GasTransferToken uint64 = 100000
)

// Transaction status constants.
const (
	TrxPending uint8 = 0
	TrxFailed  uint8 = 1
	TrxSuccess uint8 = 2
)

// Error codes defined.
var (
	ErrBadKey         = errors.New("bad format key")
	ErrBadTo          = errors.New("bad format to address")
	ErrBadToken       = errors.New("bad format token address")
	ErrBadFrom        = errors.New("bad format from address")
	ErrBadAmt         = errors.New("error converting value returned by node")
	ErrNoBlock        = errors.New("block not available yet")
	ErrNoTrx          = errors.New("transaction receipt not available yet")
	ErrNoToken        = errors.New("address has no valid token defined")
	ErrWrongAmt       = errors.New("bad amount format or amount cannot be over 32 bytes")
	ErrWrongHash      = errors.New("hash of transaction does not match with requested hash")
	ErrInvalidTrxData = errors.New("transaction data received from node is invalid")
	ErrSendTokenData  = errors.New("cannot send token and data at same time")
)

//nolint:gochecknoglobals // Refer to go-ethereum/params/config.go for this variables
// Ropsten configuration variables used to generate transactions.
var (
	ropstenConfig *params.ChainConfig = params.TestnetChainConfig

	//nolint:gomnd // this is the latest block in ropsten as of 2018/03/02 19:56
	ropstenBlock *big.Int = big.NewInt(2756944)
)

// Trx is an ethereum transaction.
type Trx struct {
	Hash                 string
	To, From             string
	Amount               string
	Token, Data          []byte
	Status               uint8
	TS                   int32
	Blk, Price, Gas, Fee uint64
}

// EthCli is a JSON RPC client.
type EthCli struct {
	*jsonrpc2.Client
}

// Init initializes the client connecting to the ethereum node url.
// A secret password is optional. "secret" is needed for Infura's v3 API.
func Init(nodeURL, secret string) *EthCli {
	if secret == "" {
		return &EthCli{Client: jsonrpc2.NewHTTPClient(nodeURL)}
	}

	return &EthCli{Client: jsonrpc2.NewCustomHTTPClient(nodeURL,
		jsonrpc2.DoerFunc(func(req *http.Request) (*http.Response, error) {
			// Setup custom HTTP client.
			client := &http.Client{}
			// Modify request as needed.
			req.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(secret)))

			return client.Do(req)
		}))}
}

// End closes the client.
func (c *EthCli) End() error {
	return c.Close()
}

// GetBalance makes an RPC call to get the balance of an address.
// Returns the balance in ether, and if a token has been specified, it returns the balance of the token too using the
// ERC20 function balanceOf(address).
// To check balance (ether):
//  curl -X POST --data '{"jsonrpc":"2.0", "method":"eth_getBalance", "params": ["0x357dd3856d856197c1a000bbAb4aBCB97Dfc92c4", "latest"], "id":1}' http://localhost:8545
// To check balance (ERC20):
//  curl -X POST --data '{"jsonrpc":"2.0", "method":"eth_call", "params": [{"data":"0x70a08231000000000000000000000000cba75F167B03e34B8a572c50273C082401b073Ed", "to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f"},"latest"], "id":1}' http://localhost:8545
func (c *EthCli) GetBalance(address, token string) (*big.Int, *big.Int, error) {
	var ok bool

	// get ether balance
	var response interface{}
	if err := c.Call("eth_getBalance", []interface{}{address, "latest"}, &response); err != nil {
		return nil, nil, fmt.Errorf("ethcli error getting balance for addr:%s: %w", address, err)
	}

	ethBal, tokBal := new(big.Int), new(big.Int)

	if ethBal, ok = ethBal.SetString(response.(string), 0); !ok {
		return nil, nil, ErrBadAmt
	}

	if token != "" {
		// get token
		data := "0x70a08231" + "000000000000000000000000" + address[2:] // balanceOf(address) + 12 zeroes + address

		err := c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": data}, "latest"}, &response)
		if err != nil {
			return nil, nil, fmt.Errorf("ethcli error getting token balance for addr:%s: %w", address, err)
		}

		if tokBal, ok = tokBal.SetString(response.(string), 0); !ok {
			return nil, nil, ErrBadAmt
		}
	}

	return ethBal, tokBal, nil
}

// GetTransactionCount makes an RPC call to get the number of transactions ("nonce") sent from an account ("address") at the block number ("block").
// Possible values for block are a hexadecimal number, "earliest", "latest" or "pending".
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
		return 0, fmt.Errorf("ethcli error getting gas price: %w", err)
	}

	return strconv.ParseUint(response.(string), 0, 64)
}

// EstimateGas makes an RPC call to get the estimated gas needed for a transaction that sends "value" to address "to".
// Optionally, data may be filled and it is also taken into account.
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
	}

	if tmp == "0x" {
		tmp = ""
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
		return hash, fmt.Errorf("ethcli error sending transaction: %w", err)
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

	if err != nil {
		return fmt.Errorf("ethcli error getting transaction by hash:%s: %w", hash, err)
	}

	return nil
}

// GetTransactionReceipt makes an RPC call to get a transaction receipt (status). Arguments:
//  hash: hash of the transaction to get
//  response: pointer to the receipt received from the node
func (c *EthCli) GetTransactionReceipt(hash string, response *map[string]interface{}) (err error) {
	err = c.Call("eth_getTransactionReceipt", []interface{}{hash}, response)
	if err == nil && *response == nil {
		return ErrNoTrx
	}

	if err != nil {
		return fmt.Errorf("ethcli error getting transaction receipt for hash:%s: %w", hash, err)
	}

	return nil
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

	if err != nil {
		return fmt.Errorf("ethcli error getting block by number:%d: %w", block, err)
	}

	return nil
}

// GetLatestBlock makes an RPC call to get the number of the latest block mined.
func (c *EthCli) GetLatestBlock() (uint64, error) {
	var response map[string]interface{}

	err := c.Call("eth_getBlockByNumber", []interface{}{"latest", false}, &response)
	if err != nil {
		return 0, fmt.Errorf("ethcli error getting latest block: %w", err)
	}

	number, ok := response["number"]
	if !ok {
		return 0, ErrNoBlock
	}

	return strconv.ParseUint(number.(string), 0, 64)
}

// GetTokenDecimals makes an RPC call to get a token (identified by contract address) decimals.
// token: address of the contract that defines the token. It must be ERC20 compliant
// Executes:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f","data":"0x313ce567"},"latest"],"id":4}' http://localhost:8545
func (c *EthCli) GetTokenDecimals(token string) (dec uint64, err error) {
	if token == "" {
		return 18, nil //nolint:gomnd // 18 is ether decimals
	}

	if len(token) != 42 {
		return 0, ErrBadToken
	}

	var response interface{}
	if err = c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": "0x313ce567"}, "latest"}, &response); err != nil {
		return 0, fmt.Errorf("ethcli error getting token decimals: %w", err)
	}

	return strconv.ParseUint(response.(string), 0, 64)
}

// GetTokenName makes an RPC call to get a token (identified by contract address) name.
// token: address of the contract that defines the token. It must be ERC20 compliant
// Executes:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f","data":"0x06fdde03"},"latest"],"id":4}' http://localhost:8545
func (c *EthCli) GetTokenName(token string) (string, error) { //nolint:dupl // similar code to other token function
	if token == "" {
		return "Ether", nil
	}

	if len(token) != 42 {
		return "", ErrBadToken
	}

	var response interface{}
	if err := c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": "0x06fdde03"}, "latest"}, &response); err != nil {
		return "", fmt.Errorf("ethcli error getting token name: %w", err)
	}

	result := response.(string)
	if result == "0x" {
		return "", ErrNoToken
	}

	if len(result) < 2+64*2 {
		return "", ErrNoToken
	}

	length, err := strconv.ParseInt(result[2+64:2+64*2], 16, 64)
	if err != nil {
		return "", fmt.Errorf("ethcli error parsing token name: %w", err)
	}

	if len(result) < 2+64*2+int(length*2) {
		return "", ErrNoToken
	}

	tmp, err := hex.DecodeString(result[2+64*2 : 2+64*2+int(length*2)])
	if err != nil {
		return "", fmt.Errorf("ethcli error getting token name: %w", err)
	}

	return string(tmp), nil
}

// GetTokenSymbol makes an RPC call to get a token (identified by contract address) symbol.
// token: address of the contract that defines the token. It must be ERC20 compliant
// Executes:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f","data":"0x95d89b41"},"latest"],"id":4}' http://localhost:8545
func (c *EthCli) GetTokenSymbol(token string) (sym string, err error) { //nolint:dupl // similar code to other token function
	if token == "" {
		return "ETH", nil
	}

	if len(token) != 42 {
		return "", ErrBadToken
	}

	var response interface{}
	if err = c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": "0x95d89b41"}, "latest"}, &response); err != nil {
		return "", fmt.Errorf("ethcli error getting token symbol: %w", err)
	}

	result := response.(string)
	if result == "0x" {
		return "", ErrNoToken
	}

	if len(result) < 2+64*2 {
		return "", ErrNoToken
	}

	length, err := strconv.ParseInt(result[2+64:2+64*2], 16, 64)
	if err != nil {
		return "", fmt.Errorf("ethcli error getting token symbol: %w", err)
	}

	if len(result) < 2+64*2+int(length*2) {
		return "", ErrNoToken
	}

	tmp, err := hex.DecodeString(result[2+64*2 : 2+64*2+int(length*2)])
	if err != nil {
		return "", fmt.Errorf("ethcli error getting token symbol: %w", err)
	}

	return string(tmp), nil
}

// GetTokenIcoOffer makes an RPC call to get a token (identified by contract address) unitsOneEthCanBuy.
// token: address of the contract that defines the token. It must be ERC20 compliant
// Executes:
//  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f","data":"0x65f2bc2e"},"latest"],"id":4}' http://localhost:8545
func (c *EthCli) GetTokenIcoOffer(token string) (ico uint64, err error) {
	if token == "" {
		return 0, nil
	}

	if len(token) != 42 {
		return 0, ErrBadToken
	}

	var response interface{}
	if err = c.Call("eth_call", []interface{}{map[string]interface{}{"to": token, "data": "0x65f2bc2e"}, "latest"}, &response); err != nil {
		return 0, fmt.Errorf("ethcli error getting token ico offer: %w", err)
	}

	if response.(string) == "0x" {
		return 0, ErrNoToken
	}

	return strconv.ParseUint(response.(string), 0, 64)
}

// SendTrx sends a transaction to the blockchain returning the gas price and limit and the tx hash or an error.
// If sending an ERC20 token, the argument token must be a valid 20-byte address and data empty.
// If priceRequested is 0, a suggested gas price will be sought from the blockchain.
// Use dryRun = true for testing (it will not send the transaction to the blockchain but still provide a valid hash).
func (c *EthCli) SendTrx(fromAddress, toAddress, token, amount string, data []byte, key string, priceRequested uint64,
	dryRun bool) (uint64, uint64, []byte, error) {
	if err := validateSendTrx(fromAddress, toAddress, token, amount, key, data); err != nil {
		return 0, 0, nil, err
	}

	nonce, err := c.GetTransactionCount(fromAddress, "latest")
	if err != nil {
		return 0, 0, nil, err
	}

	to, amt, dataEther, dataToken, err := getToAmountAndData(toAddress, token, amount, data)
	if err != nil {
		return 0, 0, nil, err
	}

	gasLimit, priceSet, gasPrice, err := c.getGasLimitAndPrice(priceRequested, token, toAddress, amount, dataEther,
		dataToken)
	if err != nil {
		return 0, 0, nil, err
	}

	// generate transaction, get hash and raw signed transaction
	hash, raw, err := signTrx(nonce, to, amt, gasLimit, gasPrice, data, key)
	if err != nil {
		return 0, 0, nil, err
	}

	// send transaction to blockchain
	if !dryRun {
		_, err = c.sendRawTransaction(raw)
	}

	return priceSet, gasLimit, hash, err
}

func validateSendTrx(fromAddress, toAddress, token, amount, key string, data []byte) error {
	if fromAddress[:2] != "0x" || len(fromAddress) != 42 {
		return ErrBadFrom
	}

	if toAddress[:2] != "0x" || len(toAddress) != 42 {
		return ErrBadTo
	}

	if token != "" {
		if token[:2] != "0x" || len(token) != 42 {
			return ErrBadToken
		}

		if data != nil {
			return ErrSendTokenData
		}
	}

	if amount[:2] != "0x" {
		return ErrWrongAmt
	}

	if len(key) != 64 { //nolint:gomnd // length of private key
		return ErrBadKey
	}

	return nil
}

func getToAmountAndData(toAddress, token, amount string, data []byte) (to common.Address, amt *big.Int, dataEther, dataToken []byte, err error) {
	var ok bool

	amt = new(big.Int)

	amt, ok = amt.SetString(amount, 0)
	if !ok || len(amt.Bytes()) > 32 {
		return common.Address{}, nil, nil, nil, ErrWrongAmt
	}

	if token == "" {
		to = common.HexToAddress(toAddress)
		dataEther = data
	} else {
		to = common.HexToAddress(token)

		toAddr, err := hex.DecodeString(toAddress[2:])
		if err != nil {
			return common.Address{}, nil, nil, nil, fmt.Errorf("ethcli error getting to address: %w", err)
		}

		tmpAmt := make([]byte, 32)
		copy(tmpAmt[32-len(amt.Bytes()):32], amt.Bytes())

		amt.Sub(amt, amt) // amt = 0 as we do not send ether!!

		// build data for token transaction: methodId (4), to address (32), amount (32)
		dataToken = make([]byte, 0, 4+32+32)
		dataToken = append(dataToken, 0xa9, 0x05, 0x9c, 0xbb)                                                 // transfer = 0xa9059cbb
		dataToken = append(dataToken, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // pad 12 zeroes
		dataToken = append(dataToken, toAddr...)                                                              // to
		dataToken = append(dataToken, tmpAmt...)                                                              // amount
	}

	return to, amt, dataEther, dataToken, nil
}

func (c *EthCli) getGasLimitAndPrice(priceRequested uint64, token, toAddress, amount string,
	data, tmp []byte) (gasLimit, priceSet uint64, gasPrice *big.Int, err error) {
	if priceRequested == 0 {
		if priceSet, err = c.GasPrice(); err != nil {
			return
		}
	} else {
		priceSet = priceRequested
	}

	gasPrice = new(big.Int).SetUint64(priceSet)

	if token == "" {
		gasLimit, err = c.EstimateGas(toAddress, amount, "0x"+hex.EncodeToString(data))
	} else {
		gasLimit, err = c.EstimateGas(token, "0x00", "0x"+hex.EncodeToString(tmp))
	}

	return
}

// signTrx returns the hash and raw signed transaction ready to be sent to node
// "0x"+raw has to be inserted in a curl command to send the transaction via Infura.io eth_sendRawTransaction RPC
// curl -X POST --data '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0xf86b0285012a05f20082ffff941cd434711fbae1f2d9c70001409fd82d71fdccaa87b1a2bc2ec50000802aa0727841e5f55e5a8315a83ee1341405f05ba68ca8667db13fa694b5e680f41e31a07e291bc489aefb24ee2217900cddbd533966cc456799032fea6632896f100b64"],"id":4}' http://localhost:8545
// response from Infura: {"jsonrpc":"2.0","id":4,"result":"0xfdd2beb06580944421f4e0ea8e408d9cb51dace689d5835288bf934500931e5d"}.
func signTrx(nonce uint64, to common.Address, amt *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, key string) ([]byte, []byte, error) {
	privateKey, err := crypto.HexToECDSA(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ethcli error getting private key: %w", err)
	}

	signer := types.MakeSigner(ropstenConfig, ropstenBlock)

	// generate a transaction
	tx := types.NewTransaction(nonce, to, amt, gasLimit, gasPrice, data)

	// sign transaction
	if tx, err = types.SignTx(tx, signer, privateKey); err != nil {
		return nil, nil, fmt.Errorf("ethcli error signing transaction: %w", err)
	}

	hash := tx.Hash().Bytes()

	raw, err := rlp.EncodeToBytes(tx) // serialize signed transaction
	if err != nil {
		return nil, nil, fmt.Errorf("ethcli error encoding transaction: %w", err)
	}

	return hash, raw, nil
}

// GetTrx returns the transaction data for the given hash.
func (c *EthCli) GetTrx(hash string) (*Trx, error) {
	var response map[string]interface{}

	err := c.GetTransactionByHash(hash, &response)
	if err != nil {
		return nil, err
	}

	var t *Trx = &Trx{}

	t.Blk, t.Price, t.Data, t.Token, t.To, t.From, t.Amount, err = c.DecodeGetTransactionResponse(hash, response)
	if err != nil {
		return nil, err
	}

	err = c.GetTransactionReceipt(hash, &response)
	if err != nil {
		return nil, err
	}

	t.Gas, t.Status, t.TS, err = c.decodeTransactionReceipt(hash, response)
	if err != nil {
		return nil, err
	}

	t.Fee = t.Gas * t.Price
	t.Hash = hash

	return t, nil
}

func decodeBlockNumber(response map[string]interface{}) (uint64, error) {
	tmp, ok := response["blockNumber"].(string)
	if !ok {
		return 0, nil
	}

	return strconv.ParseUint(tmp, 0, 64)
}

// DecodeGetTransactionResponse returns the block number, gas price and data of the transaction.
// If the transaction has not been mined block number is 0.
func (c *EthCli) DecodeGetTransactionResponse(hash string,
	response map[string]interface{}) (uint64, uint64, []byte, []byte, string, string, string, error) {
	// check hash
	if tmp, ok := response["hash"].(string); !ok || hash != tmp {
		return 0, 0, nil, nil, "", "", "", ErrWrongHash
	}

	blk, err := decodeBlockNumber(response)
	if err != nil {
		return 0, 0, nil, nil, "", "", "", fmt.Errorf("%s: %w", ErrInvalidTrxData, err)
	}

	// gasPrice
	tmp, ok := response["gasPrice"].(string)
	if !ok {
		return 0, 0, nil, nil, "", "", "", ErrInvalidTrxData
	}

	price, err := strconv.ParseUint(tmp, 0, 64)
	if err != nil {
		return 0, 0, nil, nil, "", "", "", fmt.Errorf("%s: %w", ErrInvalidTrxData, err)
	}

	// input (data sent to the tx)
	tmp, ok = response["input"].(string)
	if !ok {
		return 0, 0, nil, nil, "", "", "", ErrInvalidTrxData
	}

	data, err := hex.DecodeString(tmp[2:])
	if err != nil {
		return 0, 0, nil, nil, "", "", "", fmt.Errorf("%s: %w", ErrInvalidTrxData, err)
	}

	// if data[0:4]=methodId, get token from "to" address
	if len(data) >= 4 && (bytes.Equal(data[0:4], erc20transfer256B) || bytes.Equal(data[0:4], erc20transferFromB)) {
		token, to, from, amount, err := decodeTokenTransfer(response, data) //nolint:govet // redeclare err
		if err != nil {
			return 0, 0, nil, nil, "", "", "", err
		}

		return blk, price, data, token, to, from, amount, nil
	}

	to, from, amount, err := decodeEtherTransfer(response)
	if err != nil {
		return 0, 0, nil, nil, "", "", "", err
	}

	return blk, price, data, nil, to, from, amount, nil
}

func decodeTokenTransfer(response map[string]interface{}, data []byte) (token []byte, to, from, amount string,
	err error) {
	tmp, ok := response["to"].(string)
	if !ok {
		return nil, "", "", "", ErrInvalidTrxData
	}

	token, err = hex.DecodeString(tmp[2:])
	if err != nil {
		return nil, "", "", "", fmt.Errorf("%s: %w", ErrInvalidTrxData, err)
	}

	// to address
	if len(data) >= 4+32 {
		to = "0x" + hex.EncodeToString(data[16:36])
	}

	if bytes.Equal(data[0:4], erc20transferFromB) {
		// transferFrom method, get from address first, then amount (without any leading zero)
		if len(data) == 68+32 {
			from = "0x" + hex.EncodeToString(data[36+12:36+32])
			amount = "0x" + hex.EncodeToString(bytes.TrimLeftFunc(data[68:68+32], func(r rune) bool { return r == 0x00 }))
		}

		return
	}

	// transfer method, get amount. "from" address taken from response map.
	if len(data) == 68 {
		amount = "0x" + hex.EncodeToString(bytes.TrimLeftFunc(data[36:36+32], func(r rune) bool { return r == 0x00 }))
	}
	// from address
	if from, ok = response["from"].(string); !ok {
		return nil, "", "", "", ErrInvalidTrxData
	}

	return token, to, from, amount, nil
}

func decodeEtherTransfer(response map[string]interface{}) (to, from, amount string, err error) {
	var ok bool

	if from, ok = response["from"].(string); !ok {
		return "", "", "", ErrInvalidTrxData
	}

	if to, ok = response["to"].(string); !ok {
		return "", "", "", ErrInvalidTrxData
	}

	if amount, ok = response["value"].(string); !ok {
		return "", "", "", ErrInvalidTrxData
	}

	return
}

func (c *EthCli) decodeTransactionReceipt(hash string, response map[string]interface{}) (gas uint64, status uint8, ts int32, err error) {
	if tmp, ok := response["hash"].(string); !ok || hash != tmp {
		return 0, 0, 0, ErrWrongHash
	}

	blk, err := decodeBlockNumber(response)
	if err != nil {
		return 0, 0, 0, ErrWrongHash
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
		gas, err = strconv.ParseUint(gasUsed, 0, 64)
		if err != nil {
			return 0, 0, 0, ErrWrongHash
		}
	}

	if blk > 0 {
		if err = c.GetBlockByNumber(blk, false, &response); err != nil {
			return 0, 0, 0, ErrWrongHash
		}

		// get block timestamp
		tmp, ok := response["timestamp"].(string)
		if !ok {
			return 0, 0, 0, ErrWrongHash
		}

		ts64, err := strconv.ParseInt(tmp, 0, 32)
		if err != nil {
			return 0, 0, 0, ErrWrongHash
		}

		ts = int32(ts64)
	}

	return gas, status, ts, nil
}
