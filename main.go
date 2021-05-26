package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

type Block struct {
	Proof         int64
	Timestamp     int64
	Data          []byte
	PrevBlockHash []byte
	Hash          []byte
}

type Blockchain struct {
	blocks []*Block
}

func main() {
	bc := NewBlockchain()

	bc.AddBlock("Send 1 BTC to Ivan")
	bc.AddBlock("Send 2 more BTC to Ivan")
	bc.AddBlock("Send 1 more BTC to Ivan")
	bc.AddBlock("Send 4 more BTC to Ivan")

	for _, block := range bc.blocks {
		fmt.Printf("Prev. hash: %x\n", block.PrevBlockHash)
		fmt.Printf("Data: %s\n", block.Data)
		fmt.Printf("Hash: %x\n", block.Hash)
		fmt.Printf("Proof Of Work: %d\n", block.Proof)
		fmt.Println()
	}
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

func (bc *Blockchain) AddBlock(data string) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(1, data, prevBlock.Hash)
	newBlock.proofOfWork()
	bc.blocks = append(bc.blocks, newBlock)
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
		if hash_operation[:5] == "00000" {
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
