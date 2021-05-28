package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

type Block struct {
	Proof         int64  `json:"Proof"`
	Timestamp     int64  `json:"Timestamp"`
	Data          []byte `json:"Data"`
	PrevBlockHash []byte `json:"PrevBlockHash"`
	Hash          []byte `json:"Hash"`
}

type DisplayBlock struct {
	Proof         int64  `json:"Proof"`
	Data          string `json:"Data"`
	PrevBlockHash string `json:"PrevBlockHash"`
	Hash          string `json:"Hash"`
}

type readData struct {
	Data string `json:"Data"`
}

type Blockchain struct {
	blocks []*Block
}

var tpl *template.Template
var bc *Blockchain
var allBlock []DisplayBlock

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	bc = NewBlockchain()
}

func main() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/", index)
	myRouter.HandleFunc("/blockchain", returnAllBlocks)
	myRouter.HandleFunc("/addBlock", addBlockPost).Methods("POST")
	http.ListenAndServe(":8080", myRouter)
}

func index(res http.ResponseWriter, req *http.Request) {
	transaction := req.FormValue("data")
	nblock := bc.AddBlock(transaction)
	currBlock := DisplayBlock{
		Proof:         nblock.Proof,
		Data:          transaction,
		Hash:          hex.EncodeToString(nblock.Hash),
		PrevBlockHash: hex.EncodeToString(nblock.PrevBlockHash),
	}
	tpl.ExecuteTemplate(res, "blockchain.gohtml", currBlock)
}

func returnAllBlocks(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(allBlock)
	json.NewEncoder(w).Encode(200)
}

func addBlockPost(w http.ResponseWriter, r *http.Request) {
	reqbody, _ := ioutil.ReadAll(r.Body)
	var rdata readData
	json.Unmarshal(reqbody, &rdata)
	bc.AddBlock(rdata.Data)
	json.NewEncoder(w).Encode(201)
}

func (b *Block) SetHash() {
	timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))
	headers := bytes.Join([][]byte{b.PrevBlockHash, b.Data, timestamp}, []byte{})
	hash := sha256.Sum256(headers)

	b.Hash = hash[:]
}

func NewBlock(proof int64, data string, prevBlockHash []byte) *Block {
	block := &Block{proof, time.Now().Unix(), []byte(data), prevBlockHash, []byte{}}
	block.SetHash()
	return block
}

func (bc *Blockchain) AddBlock(data string) *Block {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(1, data, prevBlock.Hash)
	newBlock.proofOfWork()
	newDisplayBlock := DisplayBlock{
		Data:          string(newBlock.Data),
		Hash:          hex.EncodeToString(newBlock.Hash),
		PrevBlockHash: hex.EncodeToString(newBlock.PrevBlockHash),
		Proof:         newBlock.Proof,
	}
	allBlock = append(allBlock, newDisplayBlock)
	bc.blocks = append(bc.blocks, newBlock)
	return newBlock
}

func GetBlockHash(b Block) [32]byte {
	timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))
	headers := bytes.Join([][]byte{b.PrevBlockHash, b.Data, timestamp, []byte(strconv.FormatInt(b.Proof, 10))}, []byte{})
	hash := sha256.Sum256(headers)
	return hash
}

func (b *Block) proofOfWork() {
	new_proof := 1
	check_proof := false

	for !check_proof {
		hash := GetBlockHash(*b)
		hash_operation := hex.EncodeToString(hash[:])
		if hash_operation[:4] == "0000" {
			check_proof = true
		} else {
			new_proof++
			b.Proof = int64(new_proof)
		}
	}
	updatehash := GetBlockHash(*b)
	b.Hash = updatehash[:]
}

func NewGenesisBlock() *Block {
	return NewBlock(0, "Genesis Block", []byte{})
}

func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewGenesisBlock()}}
}
