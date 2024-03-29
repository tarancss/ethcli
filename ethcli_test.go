package ethcli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/require"
)

type nodeConfig struct {
	URL    string `envconfig:"ETHCLI_NODE_URL"`    // if empty, the test uses a mock HTTP JSONRPC2.0 server to provide responses from slice "expected".
	Secret string `envconfig:"ETHCLI_NODE_SECRET"` // ie. for Infura v3 node, use ":<secret>".
}

func getNodeConfig() (*nodeConfig, error) {
	c := &nodeConfig{}

	err := envconfig.Process("ETHCLI", c)
	if err != nil {
		return nil, err
	}

	if c.URL == "" {
		c.URL = mockURL
	}

	return c, nil
}

//nolint:gochecknoglobals // used for mock http server
var (
	mock    *[]interface{}
	mockURL string
)

// type mockRequest for JSONRPC 2.0.
type mockRequest struct {
	Version string           `json:"jsonrpc"`
	Method  string           `json:"method"`
	Params  *json.RawMessage `json:"params"`
	ID      *json.RawMessage `json:"id"`
}

// type mockResponse for JSONRPC 2.0.
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
		var (
			body = make([]byte, int(r.ContentLength))
			n    int
		)

		n, err = r.Body.Read(body)
		if err != nil && (err != io.EOF || n != int(r.ContentLength)) { //nolint:errorlint // io.EOF is not wrapped
			res.Error = fmt.Errorf("[Mock server] n:%d error:%w", n, err)

			return
		}

		// unmarshal JSON body
		if err = json.Unmarshal(body, &req); err != nil {
			res.Error = fmt.Errorf("[Mock server] Error unmarshaling Body:%w", err)

			return
		}
		res.ID = req.ID

		// reply with expected value
		n, err = strconv.Atoi(string(*req.ID))
		if err != nil {
			res.Error = fmt.Errorf("[Mock server] Error bad ID in JSONRPC request:%w", err)

			return
		}

		res.Result = (*mock)[n]
	})

	cfg, err := getNodeConfig()
	if err != nil {
		log.Fatalf("error loading config: %s", err)
	}

	// start a mock node server if node URL is not defined
	if cfg.URL == "" {
		mock := httptest.NewServer(handler)
		mockURL = mock.URL
		println("Warning: running tests against mock node in:", mockURL)
	}

	os.Exit(m.Run())
}

func connectToEthereum() (*EthCli, error) {
	cfg, err := getNodeConfig()
	if err != nil {
		return nil, err
	}

	c := Init(cfg.URL, cfg.Secret)
	if c == nil {
		return nil, fmt.Errorf("error connecting to: %s", cfg.URL) //nolint:goerr113 // test error.
	}

	return c, nil
}

func TestJSONRPCCalls(t *testing.T) {
	c, err := connectToEthereum()
	require.NoError(t, err)

	defer c.End()

	mock = &[]interface{}{
		// clientVersion
		"Geth/v1.11.4-omnibus-8c089133/linux-amd64/go1.19.7",
		// getBlockbyHash (omitted all but 1 transaction)
		map[string]interface{}{
			"difficulty": "0x0",
			"extraData":  "0xd883010b04846765746888676f312e32302e32856c696e7578",
			"gasLimit":   "0x1c9c380", "gasUsed": "0x6cc526",
			"hash":      "0xb20319b3d93034bafa8bfda3616691e3f1e347e1d2360733a321c26909270496",
			"logsBloom": "0x006c008000a400481019089084800921420800043d410810114c20009821581102a20000810700812412a0005064008c02041840034452b11282120d80b6a1020a0050049c3020404800010a028012e0204d00008c4c150000788ba0c0808000a00422000222024040201c800810090000c000a024304591a1800819c0014058180201000880204228000000a29000824000080b0c16062c00000041558201802209108005020018080824907400031404040233a894030080d2605539204203c4304862000002080052101000abd414800010000008001e4049418248006082001031880022ac403002014062001806801004520998c2c2010228080a080001",
			"miner":     "0xc6e2459991bfe27cca6d86722f35da23a1e4cb97",
			"mixHash":   "0x5b078b9f78fb4bc3095d78f8eee2836e854532f1bda1173a537bd0332d9c8d48",
			"nonce":     "0x0000000000000000", "number": "0x84552a",
			"parentHash":   "0xdea6834254ad6d12c0e970b66da9b4d944b8bc24170c69213dca54cb074f28c7",
			"receiptsRoot": "0x6f7151a9dccc9af76a9296a0bf834f75d520bd80452c32a8e483f4d61eff0e7c",
			"sha3Uncles":   "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
			"size":         "0x10227", "stateRoot": "0xb7a70da82f4c9ca9d2bcf0b98f798d2b9b0716e65acb908599099cb10bd431ad",
			"timestamp": "0x6414db18", "totalDifficulty": "0xa4a470",
			"transactions": []map[string]interface{}{
				{"blockHash": "0xb20319b3d93034bafa8bfda3616691e3f1e347e1d2360733a321c26909270496", "blockNumber": "0x84552a", "chainId": "0x5", "from": "0x1b7aa44088a0ea95bdc65fef6e5071e946bf7d8f", "gas": "0x5208", "gasPrice": "0x174876e800", "hash": "0xe5a071e84c0278f0ae3466bc4d9559de17b633255b8f368bb99270424ff06866", "input": "0x", "nonce": "0x29f7a", "r": "0x7ac2c88f2bc9f93b75e51ecea6188ad63c2bc8c0944028790236bb78a2b1dae", "s": "0x523f544e4388de90dd3ad13d74ee6511b4102178371df7a6eba37f78b80925ff", "to": "0xdd04e587427506ebbc67e0ae9f6d2c69c132b29a", "transactionIndex": "0x0", "type": "0x0", "v": "0x2d", "value": "0x3782dace9d90000"},
			},
			"transactionsRoot": "0xea55d940e7a60656e7c660795bba71d3456c612746957ec41e2693584e70b4bd",
			"uncles":           []string{},
		},
	}

	hash := "0xb20319b3d93034bafa8bfda3616691e3f1e347e1d2360733a321c26909270496"
	expectedVersionPrefix := "Geth"
	expectedLogsBloom := "0x006c008000a400481019089084800921420800043d410810114c20009821581102a20000810700812412a0005064008c02041840034452b11282120d80b6a1020a0050049c3020404800010a028012e0204d00008c4c150000788ba0c0808000a00422000222024040201c800810090000c000a024304591a1800819c0014058180201000880204228000000a29000824000080b0c16062c00000041558201802209108005020018080824907400031404040233a894030080d2605539204203c4304862000002080052101000abd414800010000008001e4049418248006082001031880022ac403002014062001806801004520998c2c2010228080a080001"

	// test a direct jsonrpc call using EthCli
	var res string

	err = c.Call("web3_clientVersion", []string{}, &res)
	require.NoError(t, err)
	require.Contains(t, res, expectedVersionPrefix)

	// test get block by Hash direct call
	var response map[string]interface{}

	err = c.Call("eth_getBlockByHash", []interface{}{hash, true}, &response)
	require.NoError(t, err)
	require.NotNil(t, response, "eth_getBlockByHash: block not found")
	require.Equal(t, hash, response["hash"])
	require.Equal(t, expectedLogsBloom, response["logsBloom"])
}

// TestGetGasAndGetLatestBlock tests the methods GasPrice and GetLatestBlock. This test is better run against the mock server
// as a real node will return the values for the given time the test is run.
func TestGetGasAndGetLatestBlock(t *testing.T) {
	c, err := connectToEthereum()
	require.NoError(t, err)

	defer c.End()

	mock = &[]interface{}{
		"0x44b",
		// GetLatestBlock
		map[string]interface{}{"difficulty": "0xe1bd4", "extraData": "0xd783010502846765746887676f312e362e33856c696e7578", "gasLimit": "0xa739b8", "gasUsed": "0x0", "hash": "0x4a89e885e0a6cc17b78d790320833299b550d47c36287b0d8d4fda97684a777a", "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "miner": "0xc2fa6dcef5a1fbf70028c5636e7f64cd46e7cfd4", "mixHash": "0x9ea5c067c1c19a170b349ae3c9f41285fb2c0a7cef92b117f25ed7ca6da86314", "nonce": "0x6188497bd6f143d9", "number": "0x1b4", "parentHash": "0x3a2e26193bf74178717951b6696e937607b62615bbf91dd6ae192001006bdb4a", "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", "size": "0x219", "stateRoot": "0xba9f4d1af1371ab66551526776697af24d9df3492ac67bec3b913534fe85d95a", "timestamp": "0x5831c32b", "totalDifficulty": "0x16ae78d0", "transactions": []string{}, "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", "uncles": []string{}},
	}

	expected := []uint64{
		0x44b,
		0x1b4,
	}

	// get gasPrice
	num, err := c.GasPrice()
	require.NoError(t, err)
	require.GreaterOrEqual(t, num, expected[0])

	// test GetLatestBlock
	num, err = c.GetLatestBlock()
	require.NoError(t, err)
	require.GreaterOrEqual(t, num, expected[1])
}

func TestBalance(t *testing.T) {
	c, err := connectToEthereum()
	require.NoError(t, err)

	defer c.End()

	mock = &[]interface{}{
		"0x10a741a462780000", // balance of ether
		"0x0000000000000000000000000000000000000000000000000000000000000000", // balance of token
	}

	var (
		expected = []interface{}{
			"0x10a741a462780000", // balance of ether
			"0x0000000000000000000000000000000000000000000000000000000000000000", // balance of token
		}

		// Test balances: request the ether and ERC token balances for address and compare to that of expected.
		acc = "0x357dd3856d856197c1a000bbAb4aBCB97Dfc92c4" // account to test
		tok = "0x5AB6F31B29Fc2021436B3Be57dE83Ead3286fdc7" // ERC20 token

		ethExp, tokExp = new(big.Int), new(big.Int)
	)

	ethBal, tokBal, err := c.GetBalance(acc, tok)
	require.NoError(t, err)

	ethExp, _ = ethExp.SetString(expected[0].(string), 0)
	require.Equal(t, ethExp, ethBal)

	tokExp, _ = tokExp.SetString(expected[1].(string), 0)
	require.Equal(t, tokExp, tokBal)
}

func TestNonceAndEstimageGas(t *testing.T) {
	c, err := connectToEthereum()
	require.NoError(t, err)

	defer c.End()

	mock = &[]interface{}{
		// test transaction count
		"0x0",
		"0x0",
		// EstimateGas
		"21000",
		"21128",
	}

	var (
		acc      = "0x357dd3856d856197c1a000bbAb4aBCB97Dfc92c4"
		expected = []interface{}{
			// test transaction count
			"0x0",
			"0x0",
			// EstimateGas
			GasTransferEther,
			uint64(21128),
		}
	)

	// test nonce using GetTransactionCount
	numExp, _ := strconv.ParseUint(expected[0].(string), 0, 64)

	num, err := c.GetTransactionCount(acc, "latest")
	require.NoError(t, err)
	require.Equal(t, numExp, num)

	numExp, _ = strconv.ParseUint(expected[1].(string), 0, 64)

	num, err = c.GetTransactionCount(acc, "pending")
	require.NoError(t, err)
	require.Equal(t, numExp, num)

	// test estimate gas, tests sending ether only and sending ether and data
	num, err = c.EstimateGas(acc, "0x2000", "")
	require.NoError(t, err)
	require.Equal(t, expected[2].(uint64), num)

	num, err = c.EstimateGas(acc, "0x2000", "0x3020a0ffe7343536")
	require.NoError(t, err)
	require.Equal(t, expected[3].(uint64), num)
}

func TestTransactions(t *testing.T) {
	c, err := connectToEthereum()
	require.NoError(t, err)

	defer c.End()

	mock = &[]interface{}{
		// GetTransactionByHash
		map[string]interface{}{
			"blockHash": "0xb20319b3d93034bafa8bfda3616691e3f1e347e1d2360733a321c26909270496", "blockNumber": "0x84552a",
			"chainId": "0x5", "from": "0x1b7aa44088a0ea95bdc65fef6e5071e946bf7d8f", "gas": "0x5208", "gasPrice": "0x174876e800",
			"hash": "0xe5a071e84c0278f0ae3466bc4d9559de17b633255b8f368bb99270424ff06866", "input": "0x", "nonce": "0x29f7a",
			"to": "0xdd04e587427506ebbc67e0ae9f6d2c69c132b29a", "transactionIndex": "0x0", "type": "0x0", "v": "0x2d",
			"value": "0x3782dace9d90000",
		},
		// GetTransactionReceipt
		map[string]interface{}{
			"blockHash": "0xd44a255e40eee23bd90a54a792f7a35c175400958de22a9bbfe08a7b2c244ed6", "blockNumber": "0x29bf9b",
			"contractAddress": nil, "cumulativeGasUsed": "0x4fa3d", "from": "0x1cd434711fbae1f2d9c70001409fd82d71fdccaa",
			"gas": "0xff59", "gasPrice": "0x98bca5a00", "gasUsed": "0xf67f",
			"hash": "0xe5a071e84c0278f0ae3466bc4d9559de17b633255b8f368bb99270424ff06866", "input": "0x",
			"nonce": "0x0", "status": "0x1", "to": "0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f",
			"transactionHash":  "0xdbd3184b2f947dab243071000df22cf5acc6efdce90a04aaf057521b1ee5bf60",
			"transactionIndex": "0x1", "v": "0x29", "value": "0x16345785d8a0000",
		},
		map[string]interface{}(nil),
	}

	var (
		expected = []interface{}{
			// GetTransactionByHash
			"0xe5a071e84c0278f0ae3466bc4d9559de17b633255b8f368bb99270424ff06866",
			// GetTransactionReceipt
			"0xe5a071e84c0278f0ae3466bc4d9559de17b633255b8f368bb99270424ff06866",
			nil, // map[string]interface{}(nil),
		}

		hash     = "0xe5a071e84c0278f0ae3466bc4d9559de17b633255b8f368bb99270424ff06866"
		response map[string]interface{}
	)

	// get tx by Hash
	err = c.GetTransactionByHash(hash, &response)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, expected[0].(string), response["hash"]) // we could compare other fields too...

	// get tx receipt, we test 2 cases, right hash and wrong hash (no transaction found)
	err = c.GetTransactionReceipt(hash, &response)
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, expected[1].(string), response["hash"])

	hash = "0xdbd3184b2f947dab243071000df22cf5acc6efdce90a04aaf057521b1ee5bf61" // wrong hash

	err = c.GetTransactionReceipt(hash, &response)
	require.Error(t, err)
	require.Equal(t, ErrNoTrx, err)
	require.Nil(t, response)
}

func TestTokens(t *testing.T) {
	c, err := connectToEthereum()
	require.NoError(t, err)

	defer c.End()

	mock = &[]interface{}{
		// GetToken for no token - server is not getting request for these test, so we ignore them
		// GetToken for VTCN
		"0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d76696b617374657374636f696e00000000000000000000000000000000000000",
		"0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000045654434e00000000000000000000000000000000000000000000000000000000",
		"10",
		// GetToken for wrong token
		"0x", "0x", "0x",
	}

	var (
		expected = []interface{}{
			"Ether", "ETH", uint64(0), // GetToken for no token - server is not getting request for these, so we ignore them
			"vikastestcoin", "VTCN", uint64(10), // GetToken for VTCN
		}

		token = []string{
			"", // test ether
			"0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f", // Test a real token address!!
		}
	)

	for i := 0; i < len(token); i++ {
		res, errGet := c.GetTokenName(token[i])
		require.NoError(t, errGet)
		require.Equal(t, expected[i*3].(string), res)

		res, errGet = c.GetTokenSymbol(token[i])
		require.NoError(t, errGet)
		require.Equal(t, expected[i*3+1].(string), res)

		num, errGet := c.GetTokenIcoOffer(token[i])
		require.NoError(t, errGet)
		require.Equal(t, expected[i*3+2].(uint64), num)
	}

	badToken := "0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732e"

	_, err = c.GetTokenName(badToken)
	require.Error(t, err)
	require.Equal(t, ErrNoToken, err)

	_, err = c.GetTokenSymbol(badToken)
	require.Error(t, err)
	require.Equal(t, ErrNoToken, err)

	_, err = c.GetTokenIcoOffer(badToken)
	require.Error(t, err)
	require.Equal(t, ErrNoToken, err)
}

func TestTokenGas(t *testing.T) {
	c, err := connectToEthereum()
	require.NoError(t, err)

	defer c.End()

	token := "0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f"

	// test ERC20 token transfer estimate gas
	tmp := make([]byte, 0, 4+32+32)
	tmp = append(tmp, 0xa9, 0x05, 0x9c, 0xbb)                                                 // transfer = 0xa9059cbb
	tmp = append(tmp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // pad 12 zeroes
	tmpAddr, _ := hex.DecodeString("357dd3856d856197c1a000bbAb4aBCB97Dfc92c4")
	tmp = append(tmp, tmpAddr...) // to
	tmpAmt := make([]byte, 32)
	tmpAmt[31] = 0x5f
	tmpAmt[30] = 0x2a
	tmp = append(tmp, tmpAmt...) // transfer of 0x2a5f (10847)

	gas, err := c.EstimateGas(token, "0x00", "0x"+hex.EncodeToString(tmp))
	require.NoError(t, err)

	if gas != GasTransferToken {
		t.Errorf("Got wrong gas %d (expected %d)\n", gas, GasTransferToken)
	}
}

func TestGet(t *testing.T) {
	c, err := connectToEthereum()
	require.NoError(t, err)

	defer c.End()

	mock = &[]interface{}{
		// TestGet 1... we need input for the 3 calls to the node!! GetTrx calls: GetTransactionByHash, GetTransactionReceipt and GetBlockByNumber
		map[string]interface{}{"blockHash": "0x16dbfc327f67e38fed909a08ad71eb4ebffdda704632236cb7519c0843a04299", "blockNumber": "0x6af53f", "from": "0xcba75f167b03e34b8a572c50273c082401b073ed", "gas": "0x5208", "gasPrice": "0x989680", "hash": "0x3f3f895f532d7aab86a0a25f6df799f673d35e27dd48ecb73c76e824fb63d302", "input": "0x", "nonce": "0x1c", "r": "0x5d1177210a7032e95241f9e920971d450fa3a8e8a2fd2963ba3fe7fadb2a4a50", "s": "0x7ec0db51d8904fe408a91658fcbd6742a29a9150507583ff6b5ba8c4dd6b501c", "to": "0x357dd3856d856197c1a000bbab4abcb97dfc92c4", "transactionIndex": "0x26", "v": "0x2a", "value": "0x500000"},
		map[string]interface{}{"blockHash": "0x16dbfc327f67e38fed909a08ad71eb4ebffdda704632236cb7519c0843a04299", "blockNumber": "0x6af53f", "contractAddress": nil, "cumulativeGasUsed": "0x2120e6", "from": "0xcba75f167b03e34b8a572c50273c082401b073ed", "gasUsed": "0x5208", "logs": []interface{}{}, "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "status": "0x1", "to": "0x357dd3856d856197c1a000bbab4abcb97dfc92c4", "transactionHash": "0x3f3f895f532d7aab86a0a25f6df799f673d35e27dd48ecb73c76e824fb63d302", "transactionIndex": "0x26"},
		map[string]interface{}{"difficulty": "0x73622046", "extraData": "0xde8302050c8f5061726974792d457468657265756d86312e33382e30826c69", "gasLimit": "0x7a121d", "gasUsed": "0x2120e6", "hash": "0x16dbfc327f67e38fed909a08ad71eb4ebffdda704632236cb7519c0843a04299", "logsBloom": "0x00000008000000000000200000000000020000000040000000000000000000000000000020008000000000001000000000000200000000004000800080000000000000000000000000000008000000000000004000000000000000000000000000000400005000880000000000400020000004000000000008000010000000000000000000000000000000000800002000000000000000000000100000000000000000000000000020000000000000000000000000000000020000000000000000000002400000000402000000200000000000000000004000400000000401000000000000000040000000000000000001000108000000000000001000000000", "miner": "0x635b4764d1939dfacd3a8014726159abc277becc", "mixHash": "0x0d186ce62b77e466e4f66b30d1bbeff71b210f3bce72a6f7210a34edf84d9d98", "nonce": "0x87cce426abc7bcd5", "number": "0x6af53f", "parentHash": "0x89cde9ba035de527c0fc03dd816e8205cb9c52bd9b7dc79567e72adce2460686", "receiptsRoot": "0x572216203b3b24631ea63c2f366f4d15612b6b120590350f3b8dffb69c6549bc", "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", "size": "0x1936", "stateRoot": "0xd6805cc98512c0f1f0086761f15a5bcbeb45db4c4b30997d08ca50511b127d72", "timestamp": "0x5dfeaab3", "totalDifficulty": "0x6912173ecef77f", "transactions": []string{"0x8f138401bff60dbd947ccdf9eceef46c8e0ccd97043027de566c42f022a8abcc", "0x8b2db064cdeacff34f18eb16c74298f6b5692b095c678759a39e16682c98ea7a", "0xe6ee32f5df6a617bb965df1356842cb9b34c3ccc11049cb9cf2f8a6a6afcc0f9", "0x795aad22918d79ccfe1ef7522b4c147a0fc650014e5f240ed04c16334ab7240c", "0xb8afe6057b31c7c63c5382175da72bd026e0f5b7e05800c5801cc41fb43db798", "0x4411c92db0d7b4b8d77fe53f4111712fc7cdecaa78725076544fbc6abdf2d019", "0xf536f7479394bd241be973677cbffe5fec6d28b536d5f30979281de5c34ceebf", "0x8bafdabef7b99aefeafbd8539e2b7072f4cf56a3c92e20dc2c201f5855ff39b3", "0x5c1e8a3b59838a2b961fcd548ab06fea00273f23e0174dbcf0196213f0da4265", "0x0ef5e2aec0545017fa27a65eeeb45f587098f38ede31a57589d3f5d6f3043bdf", "0x9bcfe01a8242a0d2b422527cd6abc704fab21424bf8c0e7d759b639eff1f8f69", "0xcdbb0dc7d6c661fddfd9c1a728fed43fe65c2eea3380f9688a6fc30e85e20d24", "0x48633a32b409defbd805b07418827c647a2eb29d3f53ccdd22a901a304f7c9c5", "0xb92ebb3c76e8e24950560d370b233d0ab14061be41f830392cf0ceee6f73cc2c", "0x7eef4a0785fe1bf02e8a8c727c4b956f1abf0096e2186b64e8be50f504ad1447", "0x366f653f97a3d2705ece8b76f6df9b0243afbacb838fb80c96e24957ab17b5bc", "0x36e20c01159d2aab0100b00ca2758a4b066c947b051cf71f29a9efea594e57a0", "0x194a774856c85facc98cea05681aea3078b0cbd9ff908b5a7cbe1d70b9d28751", "0xdab4600e32a7f839b47f8d9e6e081b22b4ab744c462f75414f4d43100203e01b", "0xfb2ffb9c643dca812999a3fa4d14c7f78e0b80333789a33bd7ed54521b82ecc5", "0xc4f0690dd1e1c0e3c99418529da10463c46942979d905abfaf2eb126aeeedc21", "0x85564c0b32204909c77f73c23df7e8484655dde3e62b06f887e6095c79f67f3e", "0xe309317b02143e481a98174c1cfe2a5cfac6b0662f5b1f370fc3f34ee9d8da91", "0x096760b5183b7e53d7e4e74f5e82d92616850eb307e81d9c94fdc5a18e93f670", "0x0bd588bd04af3acb6b5d4bfc699d715aadb3c7084da4ccb21dd1b830d214edd0", "0x0e3875750c6292529ce4e1a8d407f478fb78bdfc20ee328f5a88558e0ccc3de3", "0x2e476d344e24108e215f3f110b2315c53ef47552f434b3746e1df9ae42fc65be", "0xa26bf3698db9b0664fcd91296642e31918faafe94794bf59f3a251196d3d06a3", "0x8eabd6f7894194cc6e523a30ffd4ccb41b87219f52460a93aac31114dd54c1bc", "0xba414f298d033d570db3fa83611f3f9be4e91a01d4dfcdcb2fb06fee02332cfd", "0xeb2dee95e748feca129635bef1ab2b22ff6695306ddd653185382861db1c7f51", "0x2fb5cca0931f44bb5a1169f7b3aad7defbe1d78e4b24bdc4da19313193000c81", "0x38e67f95ef6b730bc04da132df3b2530118f9d2963cbd6bb4f750779aa3e5653", "0x33764f5c8e687b7841c50861fac9770f0f4f3fe09ef9f713137dbe806516449c", "0x83cf99e79755a0604bfee68daa7ab81b2f14e5ba1c8f320b13b24abe4a6517d1", "0x9bc276f828200578c9ee5fcc4ba7459bbf01cc5192ed6aa8aacc34b22a7fd896", "0x18385aea472253973fc2b1266a0b22ff53052107c6345681e74df48f05b2bf6a", "0xce978f61e64a174ee56d3414887270598f574eb5a2038f51685981bafc8c78d7", "0x3f3f895f532d7aab86a0a25f6df799f673d35e27dd48ecb73c76e824fb63d302"}, "transactionsRoot": "0x0ba49975aecff1120685561471fcc58c87d3c270361d56367fd5206cb8957687", "uncles": []string{}},
		// TestGet 2... we need input for the 3 calls to the node!!
		map[string]interface{}{"blockHash": "0x77823505e555924410be7c871f0cabe419af2f92a702e629f907117aa1229021", "blockNumber": "0x6b303b", "from": "0xcba75f167b03e34b8a572c50273c082401b073ed", "gas": "0x10e72", "gasPrice": "0xf4240", "hash": "0x9626a3677e30331fc29a6e24d4e2c1693cd287c3588031ca43e18a27cedf3a6d", "input": "0xa9059cbb000000000000000000000000357dd3856d856197c1a000bbab4abcb97dfc92c400000000000000000000000000000000000000000000000000038d7ea4c68000", "nonce": "0x1f", "r": "0xb66b4ec5c25cda43dd1916242643c98d57edf8b7cc7b0dbac9304405b46d0248", "s": "0x1276dac595819201cf4783ae746a46f64195c6d71f30d535cfec8b277afc6b5e", "to": "0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f", "transactionIndex": "0x2", "v": "0x2a", "value": "0x0"},
		map[string]interface{}{"blockHash": "0x77823505e555924410be7c871f0cabe419af2f92a702e629f907117aa1229021", "blockNumber": "0x6b303b", "contractAddress": nil, "cumulativeGasUsed": "0x133b4", "from": "0xcba75f167b03e34b8a572c50273c082401b073ed", "gasUsed": "0x8fa4", "logs": map[string]interface{}{"address": "0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f", "blockHash": "0x77823505e555924410be7c871f0cabe419af2f92a702e629f907117aa1229021", "blockNumber": "0x6b303b", "data": "0x00000000000000000000000000000000000000000000000000038d7ea4c68000", "logIndex": "0x0", "removed": false, "topics": []string{"0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", "0x000000000000000000000000cba75f167b03e34b8a572c50273c082401b073ed", "0x000000000000000000000000357dd3856d856197c1a000bbab4abcb97dfc92c4"}, "transactionHash": "0x9626a3677e30331fc29a6e24d4e2c1693cd287c3588031ca43e18a27cedf3a6d", "transactionIndex": "0x2"}, "logsBloom": "0x00000000000008000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000200000000000000000000000000000000002000000000000000000100000000000000000000004000000000000000040000000000000000000000000002000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000", "status": "0x1", "to": "0xa34de7bd2b4270c0b12d5fd7a0c219a4d68d732f", "transactionHash": "0x9626a3677e30331fc29a6e24d4e2c1693cd287c3588031ca43e18a27cedf3a6d", "transactionIndex": "0x2"},
		map[string]interface{}{"difficulty": "0x89a5ec70", "extraData": "0xde8302050c8f5061726974792d457468657265756d86312e33382e30826c69", "gasLimit": "0x7a121d", "gasUsed": "0x133b4", "hash": "0x77823505e555924410be7c871f0cabe419af2f92a702e629f907117aa1229021", "logsBloom": "0x00000000000008000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000200000000000000000000000000000000002000000000000000000100000000000000000000004000000000000000040000000000000000000000000002000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000", "miner": "0x635b4764d1939dfacd3a8014726159abc277becc", "mixHash": "0x98373e0a0dc859e622b0e9225e3dcbe3752b69f73e126d1b999b00312ce37801", "nonce": "0x9dac2ca17b8a2868", "number": "0x6b303b", "parentHash": "0xdaa5bd3f936859cc387f3866869fe59367a08d6b7da5a70961a19596e8ac46bd", "receiptsRoot": "0xe57b309c48b14df1bc19137c8f8d561ebf75705e692aa10ab71e8a0072d5d1e4", "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347", "size": "0x3aa", "stateRoot": "0x369b4a8adbcce57916023e137d99557fdffcaf71b8dc9a98ace7e20047b06041", "timestamp": "0x5e022fc0", "totalDifficulty": "0x692e2cdb829482", "transactions": []string{"0xb5a7e7c029d7c4a86ef5580d0edd4988ba3c0b7b52aeeb29722f49864616679c", "0xa75024305176e89095a1d6842eb1d7f1a6954f569ab93071f367a1414e7eed0e", "0x9626a3677e30331fc29a6e24d4e2c1693cd287c3588031ca43e18a27cedf3a6d"}, "transactionsRoot": "0x514bda3e48a406cac464758c5ad16aac24f8a48e7cf3036dd1bbcd952819dfc0", "uncles": []string{}},
		// TestSend 1.. we need input for the 4 calls to the node!! TODO!!
		// TestSend 2.. we need input for the 4 calls to the node!! TODO!!
	}

	expected := []*Trx{
		{
			Hash:   "0x3f3f895f532d7aab86a0a25f6df799f673d35e27dd48ecb73c76e824fb63d302",
			From:   "0xcba75f167b03e34b8a572c50273c082401b073ed",
			To:     "0x357dd3856d856197c1a000bbab4abcb97dfc92c4",
			Amount: "0x500000",
			Token:  nil,
			Data:   []byte{},
			Status: TrxSuccess,
			TS:     1576970931,
			Blk:    7009599,
			Price:  10000000,
			Gas:    GasTransferEther,
			Fee:    210000000000,
		},
		{
			Hash:   "0x9626a3677e30331fc29a6e24d4e2c1693cd287c3588031ca43e18a27cedf3a6d",
			To:     "0x357dd3856d856197c1a000bbab4abcb97dfc92c4",
			From:   "0xcba75f167b03e34b8a572c50273c082401b073ed",
			Amount: "0x038d7ea4c68000",
			Token:  []byte{0xa3, 0x4d, 0xe7, 0xbd, 0x2b, 0x42, 0x70, 0xc0, 0xb1, 0x2d, 0x5f, 0xd7, 0xa0, 0xc2, 0x19, 0xa4, 0xd6, 0x8d, 0x73, 0x2f},
			Data:   []byte{0xa9, 0x5, 0x9c, 0xbb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x35, 0x7d, 0xd3, 0x85, 0x6d, 0x85, 0x61, 0x97, 0xc1, 0xa0, 0x0, 0xbb, 0xab, 0x4a, 0xbc, 0xb9, 0x7d, 0xfc, 0x92, 0xc4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x8d, 0x7e, 0xa4, 0xc6, 0x80, 0x0},
			Status: TrxSuccess,
			TS:     1577201600,
			Blk:    7024699,
			Price:  1000000,
			Gas:    36772,
			Fee:    36772000000,
		},
	}

	// Test ether transfer
	trx, err := c.GetTrx(expected[0].Hash)
	require.NoError(t, err)
	testCompareTrx(t, expected[0], trx)

	// Test token transfer
	trx, err = c.GetTrx(expected[1].Hash)
	require.NoError(t, err)
	testCompareTrx(t, expected[1], trx)
}

func testCompareTrx(t *testing.T, expected, actual *Trx) {
	require.Equal(t, expected.Hash, actual.Hash)
	require.Equal(t, expected.To, actual.To)
	require.Equal(t, expected.From, actual.From)
	require.Equal(t, expected.Amount, actual.Amount)
	require.Equal(t, expected.Token, actual.Token)
	require.Equal(t, expected.Data, actual.Data)
	require.Equal(t, expected.Status, actual.Status)
	require.Equal(t, expected.TS, actual.TS)
	require.Equal(t, expected.Blk, actual.Blk)
	require.Equal(t, expected.Price, actual.Price)
	require.Equal(t, expected.Gas, actual.Gas)
	require.Equal(t, expected.Fee, actual.Fee)
}
