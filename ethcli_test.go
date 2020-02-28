package ethcli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
)

var nodeUrl string = ""    // write the url of your node here!! If left empty, the test uses a mock HTTP JSONRPC2.0 server to provide responses from slice "expected".
var nodeSecret string = "" // ie. for Infura v3 node, use ":<your secret here>"
var c *EthCli

// type mockRequest for JSONRPC 2.0
type mockRequest struct {
	Version string           `json:"jsonrpc"`
	Method  string           `json:"method"`
	Params  *json.RawMessage `json:"params"`
	ID      *json.RawMessage `json:"id"`
}

// type mockResponse for JSONRPC 2.0
type mockResponse struct {
	Version string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id"`
	Result  interface{}      `json:"result,omitempty"`
	Error   interface{}      `json:"error,omitempty"`
}

func TestMain(m *testing.M) {
	// define handler for mock HTTP server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mockRequest
		var res mockResponse
		var err error
		// make sure we reply to request either with error or the response
		defer func() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			res.Version = "2.0"
			if err = json.NewEncoder(w).Encode(res); err != nil {
				fmt.Printf("[Mock server] Error encoding response:%e\n", err)
			}
		}()
		// read request body
		var body []byte = make([]byte, int(r.ContentLength))
		var n int
		n, err = r.Body.Read(body)
		if err == nil || (err == io.EOF && n == int(r.ContentLength)) {
			// fmt.Printf("[Mock server] Request Body:%s", body)
		} else {
			res.Error = errors.New(fmt.Sprintf("n:%d error:%e\n", n, err))
			return
		}
		// unmarshal JSON body
		if err = json.Unmarshal(body, &req); err != nil {
			res.Error = errors.New(fmt.Sprintf("Error unmarshaling Body:%e\n", err))
			return
		}
		res.ID = req.ID

		// check basic auth details
		user, pass, ok := r.BasicAuth()
		if ok || nodeSecret != "" {
			if user+":"+pass != nodeSecret {
				res.Error = errors.New(fmt.Sprintf("Error with basic auth: %s:$%s", user, pass))
				return
			}
		}

		// reply with expected value
		var i int
		var buf []byte = []byte(*res.ID)
		for j := 0; j < len(buf); j++ {
			i = i*10 + int(buf[j]-0x30)
		}
		res.Result = mock[i]
		return
	})

	// start a mock node server if nodeUrl is not defined
	if nodeUrl == "" {
		mock := httptest.NewServer(handler)
		nodeUrl = mock.URL
		println("Warning: running tests against mock node in:", nodeUrl)
		defer mock.Close()
	}

	// connect to ethereum node
	if c = Init(nodeUrl, nodeSecret); c == nil {
		println("error connecting to %s: %s", nodeUrl)
		os.Exit(-1)
	}
	defer c.End()

	// run tests & exit
	os.Exit(m.Run())
}

func TestCases(t *testing.T) {
	var err error

	// Test balances: request the ether and ERC token balances for 3 addresses and compare to that of expected.
	var ethBal, tokBal, ethExp, tokExp *big.Int = new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	var acc []string = []string{
		"0xcba75F167B03e34B8a572c50273C082401b073Ed",
		"0x357dd3856d856197c1a000bbAb4aBCB97Dfc92c4",
		"0x1CD434711fBAe1f2d9C70001409Fd82d71fDCCAa",
	}
	var tok string = "0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f" // ERC20 token
	for i := 0; i < 3; i++ {
		err = c.GetBalance(acc[i], tok, ethBal, tokBal)
		if err != nil {
			t.Errorf("error getting balance for %s: %s", acc[i], err)
		}
		ethExp, _ = ethExp.SetString(expected[i*2].(string), 0)
		tokExp, _ = tokExp.SetString(expected[i*2+1].(string), 0)
		if ethBal.Cmp(ethExp) != 0 || tokBal.Cmp(tokExp) != 0 {
			t.Errorf("error balance for %s (%d,%d) does not match expected: %d %d", acc[i], ethBal, tokBal, ethExp, tokExp)
		}
	}

	// test a direct jsonrpc call using EthCli
	var res string
	err = c.Call("web3_clientVersion", []string{}, &res)
	if err != nil {
		t.Errorf("ClientVersion error in Call to %s: %s", nodeUrl, err)
	} else if res != expected[6].(string) {
		t.Logf("web3_clientVersion method reply:%+v does not match %s\n", res, expected[6].(string)) // just log issue
	}

	// test nonce using GetTransactionCount
	var num, numExp uint64
	numExp, _ = strconv.ParseUint(expected[7].(string), 0, 64)
	if num, err = c.GetTransactionCount(acc[1], "latest"); err != nil {
		t.Errorf("[GetTransactionCount] error in Call to %s: %s", nodeUrl, err)
	} else if num != numExp {
		t.Errorf("GetTransaction count, value %d is not the expected %d", num, numExp)
	}
	numExp, _ = strconv.ParseUint(expected[8].(string), 0, 64)
	if num, err = c.GetTransactionCount(acc[1], "pending"); err != nil {
		t.Errorf("[GetTransactionCount] error in Call to %s: %s", nodeUrl, err)
	} else if num != numExp {
		t.Errorf("GetTransaction count, value %d is not the expected %d", num, numExp)
	}

	// get gasPrice
	numExp, _ = strconv.ParseUint(expected[9].(string), 0, 64)
	if num, err = c.GasPrice(); err != nil {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else if num != numExp {
		t.Logf("INFO: GasPrice, value %d is not the expected %d", num, numExp) // we log this instead of Error as it is likely this may change overtime, just like LatestBlock
	}

	// test estimate gas, tests sending ether only and sending ether and data
	numExp = GasTransferEther
	if num, err = c.EstimateGas(acc[1], "0x2000", ""); err != nil {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else if num != expected[10].(uint64) {
		t.Errorf("EstimateGas, value %d is not the expected %d", num, numExp)
	}
	if num, err = c.EstimateGas(acc[1], "0x2000", "0x3020a0ffe7343536"); err != nil {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else if num != expected[11].(uint64) {
		t.Errorf("EstimateGas, value %d is not the expected %d", num, numExp)
	}

	// get latest block number
	num, err = c.GetLatestBlock()
	if err != nil {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else if num != expected[12].(uint64) {
		// we just log this
		t.Logf("INFO: GetLatestBlock, value %d is not the expected %d", num, numExp)
	}

	// get tx by Hash
	var response map[string]interface{}
	var hash string = "0xdbd3184b2f947dab243071000df22cf5acc6efdce90a04aaf057521b1ee5bf60"
	err = c.GetTransactionByHash(hash, &response)
	if err != nil && err != ErrNoTrx {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else if response != nil {
		if response["hash"] != expected[13].(string) { // we could compare other fields too...
			t.Errorf("GetTransactionByHash got %+v which is not expected %v", response["hash"], expected[13].(string))
		}
	} else {
		t.Error("eth_getTransactionByHash method tested: No transaction")
	}

	// get tx receipt, we test 2 cases, right hash and wrong hash (no transaction found)
	err = c.GetTransactionReceipt(hash, &response)
	if err != nil && err != ErrNoTrx {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else if response != nil {
		if response["hash"] != expected[14].(string) {
			t.Errorf("GetTransactionReceipt got %+v which is not expected %s", response["hash"], expected[14].(string))
		}
	} else {
		t.Errorf("eth_getTransactionReceipt method tested: No transaction")
	}
	hash = "0xdbd3184b2f947dab243071000df22cf5acc6efdce90a04aaf057521b1ee5bf61" // same as above but 1 digit changed!
	err = c.GetTransactionReceipt(hash, &response)
	if err != nil && err != ErrNoTrx {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else if response == nil {
		t.Logf("INFO: GetTransactionReceipt: No transaction for hash:%s which is the expected result.\n", hash)
	} else {
		t.Errorf("GetTransactionReceipt found a tx for hash:%s which is not expected. Tx details %+v\n", hash, response)
	}

	// test get block by Hash direct call
	err = c.Call("eth_getBlockByHash", []interface{}{"0xd44a255e40eee23bd90a54a792f7a35c175400958de22a9bbfe08a7b2c244ed6", true}, &response)
	if err != nil {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else {
		if response == nil {
			t.Errorf("eth_getBlockByHash: block not found")
		} else {
			if response["hash"] != expected[16].([]string)[0] || response["logsBloom"] != expected[16].([]string)[1] {
				t.Errorf("GetBlockByHash got %+v and %+v which is not expected %+v %+v", response["hash"], response["logsBloom"], expected[16].([]string)[0], expected[16].([]string)[1])
			}
		}
	}

	// get token name and symbol, test 3 tokens
	var token [3]string = [3]string{
		"", // ether!!
		"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732e", // wrong token address!!
		"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f", // right token address!!
	}
	for j := 0; j < 3; j++ {
		res, err = c.GetTokenName(token[j])
		if err != nil && (j != 1 && err != ErrNoToken) {
			t.Errorf("error in Call to %s: j=%d %s", nodeUrl, j, err)
		} else if strings.Compare(res, expected[17+j*3].(string)) != 0 {
			t.Errorf("GetTokenName error:%s\n", res)
		}
		res, err = c.GetTokenSymbol(token[j])
		if err != nil && (j != 1 && err != ErrNoToken) {
			t.Errorf("error in Call to %s: j=%d %s", nodeUrl, j, err)
		} else if strings.Compare(res, expected[18+j*3].(string)) != 0 {
			t.Errorf("GetTokenName error:%s\n", res)
		}
		num, err = c.GetTokenIcoOffer(token[j])
		if err != nil && (j != 1 && err != ErrNoToken) {
			t.Errorf("error in Call to %s: j=%d %s", nodeUrl, j, err)
		} else if num != expected[19+j*3].(uint64) {
			t.Errorf("GetTokenIcoOffer error:%d\n", num)
		}
	}

	// test ERC20 token transfer estimate gas
	tmp := make([]byte, 0, 4+32+32)
	tmp = append(tmp, 0xa9, 0x05, 0x9c, 0xbb)                                                 // transfer = 0xa9059cbb
	tmp = append(tmp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // pad 12 zeroes
	tmpAddr, _ := hex.DecodeString(acc[1][2:])
	tmp = append(tmp, tmpAddr[:]...) // to
	tmpAmt := make([]byte, 32)
	tmpAmt[31] = 0x5f
	tmpAmt[30] = 0x2a
	tmp = append(tmp, tmpAmt[:]...) // transfer of 0x2a5f (10847)
	var gas uint64
	gas, err = c.EstimateGas(token[2], "0x00", "0x"+hex.EncodeToString(tmp))
	if err != nil {
		t.Errorf("error in Call to %s: %s", nodeUrl, err)
	} else if gas != expected[26].(uint64) {
		t.Errorf("Got wrong gas %d (expected %d)\n", gas, GasTransferToken)
	}
}

func TestGet(t *testing.T) {
	// Test 1, ether transfer
	var hash string = "0x3f3f895f532d7aab86a0a25f6df799f673d35e27dd48ecb73c76e824fb63d302"
	blk, ts, price, gas, status, fee, _, _, from, to, amount, err := c.GetTrx(hash)
	if err != nil {
		t.Errorf("Error getting transaction %e\n", err)
	} else if blk != 7009599 || ts != 1576970931 || price != 10000000 || gas != 21000 || status != TrxSuccess || fee != 210000000000 || from != "0x357dd3856d856197c1a000bbab4abcb97dfc92c4" || to != "0xcba75f167b03e34b8a572c50273c082401b073ed" || amount != "0x500000" {
		t.Errorf("Error data gotten is not the expected!!")
	}

	// Test 2, token transfer
	hash = "0x9626a3677e30331fc29a6e24d4e2c1693cd287c3588031ca43e18a27cedf3a6d"
	blk, ts, price, gas, status, fee, _, _, from, to, amount, err = c.GetTrx(hash)
	if err != nil {
		t.Errorf("Error getting transaction %e\n", err)
	} else if blk != 7024699 || ts != 1577201600 || price != 1000000 || gas != 36772 || status != TrxSuccess || fee != 36772000000 || from != "0x357dd3856d856197c1a000bbab4abcb97dfc92c4" || to != "0xcba75f167b03e34b8a572c50273c082401b073ed" || amount != "0x038d7ea4c68000" {
		t.Errorf("Error data gotten is not the expected!!")
	}

}
