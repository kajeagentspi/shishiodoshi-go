package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type game struct {
	ChainName          string
	BidIncrement       int
	BidToken           string
	Playercount        int
	StartingCoinAmount int
}

type gameRes struct {
	Link string
}

func newGame(rw http.ResponseWriter, req *http.Request) {

	decoder := json.NewDecoder(req.Body)
	var g game
	err := decoder.Decode(&g)
	if err != nil {
		panic(err)
	}
	log.Println("New Game Created", g)

	response := gameRes{
		Link: "hello",
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(response)
}

func main() {
	http.HandleFunc("/newGame", newGame)
	log.Fatal(http.ListenAndServe(":8082", nil))
}
