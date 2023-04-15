package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type game struct {
	ChainName          string
	BidIncrement       float32
	BidToken           string
	Playercount        int
	StartingCoinAmount int
}

type gameRes struct {
	Link string
}

type Controller struct {
	rpcServers             map[string]*ethclient.Client
	signers                map[string]*bind.TransactOpts
	winningInfos           map[string]map[int64]*WinningInfo
	chainIDs               map[string]*big.Int
	supportedTokens        map[string]map[string]common.Address
	gameABI                abi.ABI
	eventHashes            map[string]common.Hash
	supportedBidIncrements map[float32]*big.Int
}

type WinningInfo struct {
	tippingCoinAmount uint16
	randomHash        [32]byte
}

var masterController *Controller
var gameAddress = common.HexToAddress("0xd8496B7CEa1844A6097351DA3ADd39560bf1B8Ea")
var tokenAddress = common.HexToAddress("0x4520452457766B8a5C5371081b13F7B3D44C47c4")
var linkPrefix = "https://shishiodoshi.com/game/"

func loadABI(filepath string) abi.ABI {
	file, err := os.Open(filepath)
	if err != nil {
		utils.Fatalf(filepath, " not found")
	}
	scanner := bufio.NewScanner(file)
	scanner.Scan()

	loadedABI, _ := abi.JSON(strings.NewReader(scanner.Text()))
	file.Close()
	return loadedABI
}

func newController() *Controller {
	privateKey, _ := crypto.HexToECDSA("1d157ebdd499df99ae3b04e9182e061426cc6a69e947406f7f0f2eb0a5082574")
	rpcList := map[string]string{
		"celo": "wss://alfajores-forno.celo-testnet.org/ws",
	}
	ETH0010 := big.NewInt(10000000000000000)
	ETH010 := big.NewInt(100000000000000000)
	ETH1 := big.NewInt(1000000000000000000)
	ETH10 := new(big.Int).Mul(ETH1, big.NewInt(10))
	bidIncrements := map[float32]*big.Int{
		0.01: ETH0010,
		0.1:  ETH010,
		1:    ETH1,
		10:   ETH10,
	}
	controller := &Controller{
		rpcServers:             make(map[string]*ethclient.Client),
		signers:                make(map[string]*bind.TransactOpts),
		winningInfos:           make(map[string]map[int64]*WinningInfo),
		chainIDs:               make(map[string]*big.Int),
		gameABI:                loadABI("gameABI.json"),
		eventHashes:            make(map[string]common.Hash),
		supportedTokens:        make(map[string]map[string]common.Address),
		supportedBidIncrements: bidIncrements,
	}
	controller.eventHashes["GameCreated"] = common.HexToHash("0xbd19c47e9925eb6f7be8bb1c13a841e0240aaeaf17f217e90022e9c8eb66877f")
	controller.eventHashes["GameInitialized"] = common.HexToHash("0x58c011e13f011724a561d208ce5f8def502e1b072aab1a73ced847c0ba0fc428")
	controller.eventHashes["BidReceived"] = common.HexToHash("0xbbcba7ae13bb34e2e0f19c6207137f14a40a59d139e097e31bc83c847477f7c5")

	for name, rpcLink := range rpcList {
		client, err := ethclient.Dial(rpcLink)
		if err != nil {
			fmt.Println("CELO IS DOWN")
		}
		chainID, err := client.ChainID(context.Background())
		if err != nil {
			fmt.Println("CANT GET ID", name)

		}
		controller.chainIDs[name] = chainID
		signer, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
		controller.winningInfos[name] = make(map[int64]*WinningInfo)
		controller.supportedTokens[name] = make(map[string]common.Address)

		controller.rpcServers[name] = client
		controller.signers[name] = signer

		controller.supportedTokens[name]["sso"] = common.HexToAddress("0x4520452457766B8a5C5371081b13F7B3D44C47c4")
	}

	return controller
}

func (ct *Controller) initializeGame(networkName string, gameID *big.Int, blockNumber *big.Int) {
	client := ct.rpcServers[networkName]
	signer := ct.signers[networkName]
	chainID := ct.chainIDs[networkName]

	data, _ := ct.gameABI.Pack("gameInfos", gameID)
	fmt.Println(common.Bytes2Hex(data))
	getGameInfo, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &gameAddress,
		Data: data,
	}, blockNumber)
	if err != nil {
		fmt.Println("Can't initialize gameInfo", networkName, gameID, err)
		return
	}
	unpacked, err := ct.gameABI.Unpack("gameInfos", getGameInfo)
	if err != nil {
		fmt.Println("Can't initialize unpack", networkName, gameID, err)
	}

	tokenPerPlayer := unpacked[2].(uint8)
	playercount := unpacked[3].(uint8)

	minBid := (tokenPerPlayer * playercount) / 2
	maxBid := (tokenPerPlayer * playercount) / 5 * 9

	rand.Seed(time.Now().UnixNano())
	tippingAmount := uint16(rand.Intn(int(maxBid)-int(minBid)+1) + int(minBid))

	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, tippingAmount)

	randomBytes := make([]byte, 32)
	for i := range randomBytes {
		randomBytes[i] = byte(rand.Intn(256))
	}

	randomBytesHash := sha256.Sum256(randomBytes)

	ct.winningInfos[networkName][gameID.Int64()] = &WinningInfo{
		tippingCoinAmount: tippingAmount,
		randomHash:        randomBytesHash,
	}

	winningBytes := make([]byte, 32)
	copy(winningBytes[0:2], bs)
	copy(winningBytes[2:32], randomBytesHash[0:30])

	winningBytesHash := sha256.Sum256(winningBytes)

	initGameData, _ := ct.gameABI.Pack("initGame", gameID, winningBytesHash)
	fmt.Println(common.Bytes2Hex(initGameData))

	initializeGameParams := ethereum.CallMsg{
		From: signer.From,
		To:   &gameAddress,
		Data: initGameData,
	}

	usedGas, err := client.EstimateGas(context.Background(), initializeGameParams)
	if err != nil {
		fmt.Println(err)
		return
	}
	nonce, err := client.NonceAt(context.Background(), signer.From, blockNumber)
	if err != nil {
		fmt.Println(err)
		return
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	gasPrice.Mul(gasPrice, common.Big2)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		Gas:       usedGas * 3,
		To:        &gameAddress,
		Value:     common.Big0,
		Data:      initGameData,
		GasTipCap: gasPrice,
		GasFeeCap: gasPrice,
	})

	signedTx, _ := signer.Signer(signer.From, tx)

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("%10s game %10s random hash: %s tippingAmount %3d hash %s\n", networkName, gameID.String(), common.Bytes2Hex(randomBytesHash[:]), tippingAmount, tx.Hash().String())
}

func (ct *Controller) newGame(networkName string, bidToken common.Address, bidIncrement *big.Int, playerCount uint8, startingCoinAmount uint8) string {
	client := ct.rpcServers[networkName]
	signer := ct.signers[networkName]
	chainID := ct.chainIDs[networkName]

	getNextIDdata, err := ct.gameABI.Pack("nextGameID")
	fmt.Println(getNextIDdata, err)
	getNextRes, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &gameAddress,
		Data: getNextIDdata,
	}, nil)
	if err != nil {
		return err.Error()
	}
	unpacked, err := ct.gameABI.Unpack("nextGameID", getNextRes)
	if err != nil {
		return err.Error()
	}

	newGameData, _ := ct.gameABI.Pack("newGame", bidToken, bidIncrement, playerCount, startingCoinAmount)

	newGameParams := ethereum.CallMsg{
		From: signer.From,
		To:   &gameAddress,
		Data: newGameData,
	}

	usedGas, err := client.EstimateGas(context.Background(), newGameParams)
	if err != nil {
		fmt.Println("endGame", err)
		return err.Error()
	}
	nonce, err := client.NonceAt(context.Background(), signer.From, nil)
	if err != nil {
		fmt.Println(err)
		return err.Error()
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		fmt.Println(err)
		return err.Error()
	}
	gasPrice.Mul(gasPrice, common.Big2)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     nonce,
		Gas:       usedGas * 3,
		To:        &gameAddress,
		Value:     common.Big0,
		Data:      newGameData,
		GasTipCap: gasPrice,
		GasFeeCap: gasPrice,
	})

	signedTx, _ := signer.Signer(signer.From, tx)

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		fmt.Println(err)
		return err.Error()
	}
	return unpacked[0].(*big.Int).String()

}

func (ct *Controller) checkGame(networkName string, gameID *big.Int, blockNumber *big.Int) {
	client := ct.rpcServers[networkName]
	signer := ct.signers[networkName]
	chainID := ct.chainIDs[networkName]
	data, _ := ct.gameABI.Pack("gameInfos", gameID)
	fmt.Println(common.Bytes2Hex(data))
	getGameInfo, err := client.CallContract(context.Background(), ethereum.CallMsg{
		To:   &gameAddress,
		Data: data,
	}, blockNumber)
	if err != nil {
		fmt.Println("Can't initialize gameInfo", networkName, gameID, err)
		return
	}
	unpacked, err := ct.gameABI.Unpack("gameInfos", getGameInfo)
	if err != nil {
		fmt.Println("Can't initialize unpack", networkName, gameID, err)
	}

	winningInfo := ct.winningInfos[networkName][gameID.Int64()]
	totalBid := unpacked[6].(uint16)
	if totalBid > winningInfo.tippingCoinAmount {
		endGameData, err := ct.gameABI.Pack("endGame", gameID, winningInfo.tippingCoinAmount, winningInfo.randomHash)
		if err != nil {
			fmt.Println("endGame", err)
		}
		fmt.Println(endGameData)

		initializeGameParams := ethereum.CallMsg{
			From: signer.From,
			To:   &gameAddress,
			Data: endGameData,
		}

		usedGas, err := client.EstimateGas(context.Background(), initializeGameParams)
		if err != nil {
			fmt.Println("endGame", err)
			return
		}
		nonce, err := client.NonceAt(context.Background(), signer.From, blockNumber)
		if err != nil {
			fmt.Println(err)
			return
		}

		gasPrice, err := client.SuggestGasPrice(context.Background())
		if err != nil {
			fmt.Println(err)
			return
		}
		gasPrice.Mul(gasPrice, common.Big2)

		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     nonce,
			Gas:       usedGas * 3,
			To:        &gameAddress,
			Value:     common.Big0,
			Data:      endGameData,
			GasTipCap: gasPrice,
			GasFeeCap: gasPrice,
		})

		signedTx, _ := signer.Signer(signer.From, tx)

		err = client.SendTransaction(context.Background(), signedTx)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func (ct *Controller) monitorLogs(networkName string) {
	client := ct.rpcServers[networkName]

	query := ethereum.FilterQuery{
		Addresses: []common.Address{gameAddress},
	}
	logs := make(chan types.Log)
	sub, err := client.SubscribeFilterLogs(context.Background(), query, logs)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Monitoring", networkName)
	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case vLog := <-logs:
			if vLog.Topics[0] == ct.eventHashes["GameCreated"] {
				gameID := big.NewInt(int64(vLog.BlockNumber))
				fmt.Println("Received GameCreated from", networkName, "gameID", gameID)
				ct.initializeGame(networkName, new(big.Int).SetBytes((vLog.Data)), gameID)
			} else if vLog.Topics[0] == ct.eventHashes["BidReceived"] {
				gameID := big.NewInt(int64(vLog.BlockNumber))
				fmt.Println("Received BidReceived from", networkName, "gameID", gameID)
				ct.checkGame(networkName, new(big.Int).SetBytes(vLog.Data), gameID)
			}
		}
	}
}

func newGame(rw http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(req.Body)
	var g game
	err := decoder.Decode(&g)
	if err != nil {
		panic(err)
	}
	log.Println("Create Game request received", g)

	response := gameRes{}
	rw.Header().Set("Content-Type", "application/json")

	_, ok := masterController.rpcServers[g.ChainName]
	if !ok {
		response.Link = "Error: unsupported chainName"
		json.NewEncoder(rw).Encode(response)
		return
	}
	bidToken, ok := masterController.supportedTokens[g.ChainName][g.BidToken]
	if !ok {
		response.Link = "Error: unsupported token"
		json.NewEncoder(rw).Encode(response)
		return
	}
	bidIncrement, ok := masterController.supportedBidIncrements[g.BidIncrement]
	if !ok {
		response.Link = "Error: unsupported bidIncrement"
		json.NewEncoder(rw).Encode(response)
		return
	}

	gameID := masterController.newGame(g.ChainName, bidToken, bidIncrement, uint8(g.Playercount), uint8(g.StartingCoinAmount))
	response.Link = linkPrefix + gameID + "?networkName=" + g.ChainName
	json.NewEncoder(rw).Encode(response)
	return
}

func main() {
	masterController = newController()
	http.HandleFunc("/newGame", newGame)
	go http.ListenAndServe(":8082", nil)
	go masterController.monitorLogs("celo")

	for {
	}
}
