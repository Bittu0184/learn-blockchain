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
	"strings"
	"time"

	"github.com/gorilla/mux"
)

type Block struct {
	Index         int           `json:"Index"`
	Proof         int64         `json:"Proof"`
	Timestamp     int64         `json:"Timestamp"`
	Transaction   []Transaction `json:"Transaction"`
	PrevBlockHash string        `json:"PrevBlockHash"`
	Hash          string        `json:"Hash"`
}

type Transaction struct {
	Sender   string `json:"Sender"`
	Receiver string `json:"Receiver"`
	Amount   int    `json:"Amount"`
}

type ResponseChainAndLength struct {
	Chain  []*Block
	Length int `json:"length"`
}

type Blockchain struct {
	chain []*Block
	nodes *set
}

var tpl *template.Template
var bc *Blockchain
var node_address = "random_UUID_number"
var lastMinedBlock = 1

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
	bc = NewBlockchain()
}

func main() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/", index)
	myRouter.HandleFunc("/get_blockchain", get_chain)
	myRouter.HandleFunc("/isvalid", isValid)
	myRouter.HandleFunc("/add_transaction", addTransaction).Methods("POST")
	myRouter.HandleFunc("/mine_block", mineBlock)
	myRouter.HandleFunc("/coonect_node", connectNode).Methods("POST")
	myRouter.HandleFunc("/replace_chain", replaceChain)
	http.ListenAndServe(":8080", myRouter)
}

// Handler Functions
func index(res http.ResponseWriter, req *http.Request) {
	tpl.ExecuteTemplate(res, "blockchain.gohtml", nil)
}

func get_chain(w http.ResponseWriter, r *http.Request) {
	res := ResponseChainAndLength{
		Chain:  bc.chain,
		Length: len(bc.chain),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func addTransaction(w http.ResponseWriter, r *http.Request) {
	reqbody, _ := ioutil.ReadAll(r.Body)
	var transaction []Transaction
	json.Unmarshal(reqbody, &transaction)
	index := bc.AddTransactionInMemPool(transaction)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Block Added with index: " + strconv.Itoa(index)))
}

func isValid(w http.ResponseWriter, r *http.Request) {
	if bc.isChainValid(bc.chain) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode("Chain Valid")
	} else {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode("Chain Invalid")
	}
}

func mineBlock(w http.ResponseWriter, r *http.Request) {
	if len(bc.chain) == lastMinedBlock {
		w.Write([]byte("No new transactions to add"))
	} else {
		bc.MineBlock()
		w.Write([]byte("Congratulations! Block Mined"))
		w.WriteHeader(http.StatusCreated)
	}
}

func connectNode(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	var n []string
	json.Unmarshal(body, &n)
	if len(n) == 0 {
		w.WriteHeader(http.StatusBadRequest)
	} else {
		for _, node := range n {
			bc.nodes.Add(node)
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

func replaceChain(w http.ResponseWriter, r *http.Request) {
	isChainReplaced := bc.replaceChain()
	if isChainReplaced {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

//Utility functions
func (bc *Blockchain) AddTransactionInMemPool(transaction []Transaction) int {
	if len(bc.chain) == lastMinedBlock {
		prevBlock := bc.chain[lastMinedBlock-1]
		newBlock := NewBlock(prevBlock.Index+1, 1, transaction, prevBlock.Hash)
		bc.chain = append(bc.chain, newBlock)
	} else {
		curr_block := bc.chain[len(bc.chain)-1]
		curr_block.Transaction = append(curr_block.Transaction, transaction...)
	}
	return bc.chain[len(bc.chain)-1].Index + 1
}

func (bc *Blockchain) MineBlock() {
	lastMinedBlock++
	blockToMine := bc.chain[lastMinedBlock-1]
	blockToMine.Transaction = append(blockToMine.Transaction, Transaction{node_address, "Me", 1})
	blockToMine.proofOfWork()
}

func (b *Block) proofOfWork() {
	new_proof := 1
	check_proof := false
	for !check_proof {
		hash := GetBlockHash(*b)
		if hash[:5] == "00000" {
			check_proof = true
		} else {
			new_proof++
			b.Proof = int64(new_proof)
		}
	}
	updatehash := GetBlockHash(*b)
	b.Hash = updatehash
}

func (bc *Blockchain) isChainValid(chain []*Block) bool {
	previous_block := chain[1]
	block_index := 2
	var cur_block *Block
	for block_index < len(chain) {
		cur_block = chain[block_index]
		if !strings.EqualFold(cur_block.PrevBlockHash, previous_block.Hash) {
			return false
		}
		block_hash := GetBlockHash(*cur_block)
		if block_hash[:5] != "00000" {
			return false
		}
		previous_block = cur_block
		block_index++
	}
	return true
}

func GetBlockHash(b Block) string {
	timestamp := []byte(strconv.FormatInt(time.Now().Unix(), 10))
	transactionInByte, _ := json.Marshal(b.Transaction)
	headers := bytes.Join([][]byte{[]byte(strconv.Itoa(b.Index)), []byte(b.PrevBlockHash), transactionInByte, timestamp, []byte(strconv.FormatInt(b.Proof, 10))}, []byte{})
	hash := sha256.Sum256(headers)
	hashInString := hex.EncodeToString(hash[:])
	return hashInString
}

func NewGenesisBlock() *Block {
	return NewBlock(1, 0, []Transaction{{"Dad", "me", 1000}}, "0")
}

func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewGenesisBlock()}, NewSet()}
}

func NewBlock(index int, proof int64, transaction []Transaction, prevBlockHash string) *Block {
	block := &Block{index, proof, time.Now().Unix(), transaction, prevBlockHash, ""}
	return block
}

//CryptoCurrrency
func (bc *Blockchain) addNodes(adrress string) {
	bc.nodes.Add(adrress)
}

func (bc *Blockchain) replaceChain() bool {
	network := bc.nodes
	max_length := len(bc.chain)
	longest_chain := bc.chain
	flag := 0
	for node := range network.m {
		url := "http://" + node + "/blockchain"
		res, err := http.Get(url)
		if err == nil {
			var resp ResponseChainAndLength
			responseDec := json.NewDecoder(res.Body)
			responseDec.Decode(&resp)
			if resp.Length > max_length && bc.isChainValid(resp.Chain) {
				max_length = resp.Length
				longest_chain = resp.Chain
				flag = 1
			}
		}
	}
	if flag == 1 {
		bc.chain = longest_chain
		return true
	}
	return false
}
