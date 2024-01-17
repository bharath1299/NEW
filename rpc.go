package main

import "math/big"

type Args struct {
	Command  string
	Address  string
	Offset   int64
	Filename string
}
type Reply struct {
	Found      bool
	Reply      string
	Forward    string
	Successors []NodeAddress
	Content    string
}
type s struct {
	ID *big.Int
}
type r struct {
	Address NodeAddress
}
