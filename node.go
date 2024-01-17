package main

import (
	"fmt"
	"io"
	"math"
	"math/big"
	"crypto/sha1"
	"os"
	"sync"
)

//structure defining properties of a node in DHT
type Node struct { 
	mutex          sync.Mutex    
	Address     nodeAddress    
	FingerTable []nodeAddress  
	Predecessor nodeAddress    
	Successors  []nodeAddress  
	Bucket      map[Key]string 
}

type Key string 
type nodeAddress string

func (n *Node) create() { //function to initialize a node
	n.mutex.Lock()
	n.Predecessor = ""                             // its predecessor to an empty string
	n.Successors = append(n.Successors, n.Address) // adding itself as the only entry in the successor list
	n.mutex.Unlock()
}

func (n *Node) HandlePing(args *Args, reply *Reply) error {
	n.mutex.Lock()
	if args.Command == "CP" { //if command is Check Predecessor
		reply.Reply = "CP reply" //sets the reply to CP reply
	}
	n.mutex.Unlock()
	return nil
}

//Checks if add is between start and end on the ring.

func Inbetween(start *big.Int, add *big.Int, end *big.Int, inclusive bool) bool {
	if end.Cmp(start) > 0 {
		return (start.Cmp(add)) < 0 && add.Cmp(end) < 0) || (inclusive && add.Cmp(end) == 0)
	} else {
		return start.Cmp(add) < 0 || add.Cmp(end) < 0 || (inclusive && Add.Cmp(end) == 0)
	}
}

// handles the node joining an existing ring, updating its predecessor and successors
func (n *Node) join(address nodeAddress) {
	n.mutex.Lock()
	node.Predecessor = ""
	node.Successors = []nodeAddress{address}
	n.mutex.Unlock()
}


// Retrieves the predecessor of the node and sets it in the reply
func (n *Node) Get_predecessor(args *Args, reply *Reply) error {
	n.mutex.Lock()
	reply.Reply = string(node.Predecessor)
	n.mutex.Unlock()
	return nil

}

// Finds the closest preceeding node to a given ID in the finger table
func (n *Node) closest_preceding_node(id *big.Int) nodeAddress {
	for i := len(n.FingerTable) - 1; i >= 0; i-- {
		addH := hashAddress(n.Address)
		fingerH := hashAddress(n.FingerTable[i])

		if Inbetween(addH, fingerH, id, true) {
			return n.FingerTable[i]
		}
	}
	return n.Successors[0]
}

// computes the SHA-1 hash of a node address and returns it as a big.Int
func hashAddress(add nodeAddress) *big.Int {
	hasher := sha1.New()
	hasher.Write([]byte(add))

	t := new(big.Int).SetBytes(hasher.Sum(nil))

	return new(big.Int).Mod(t, big.NewInt(int64(1024)))
}

// Finds the successor of a given key ID, updating the reply with the result
func (n *Node) FindSuccessor(args *Args, reply *Reply) error {
	n.mutex.Lock()
	addH := hashAddress(n.Address)

	ID := hashAddress(nodeAddress(args.Address))
	ID.Add(ID, big.NewInt(args.Offset))
	ID.Mod(ID, big.NewInt(int64(math.Pow(2, float64(FingerTableSize)))))

	successor_Hash := hashAddress(nodeAddress(n.Successors[0]))

	//If the ID is between self and immediate successor
	if Inbetween(addH, ID, successor_Hash, false) {
		reply.Found = true
		reply.Reply = string(n.Successors[0])
	} else {
		//if the file is outside. Should return the closest preceding node before ID. Have to implement fix_fingers for this to work.
		//Right now it will return the next successor, jumping only 1 step on the ring. Search time is O(N), we want O(log(N))
		reply.Found = false
		reply.Forward = string(n.closest_preceding_node(ID))
	}
	n.mutex.Unlock()
	return nil
}

// Retrieves the sucessors of the node and sets them in the reply
func (n *Node) Get_successors(args *Args, reply *Reply) error {
	n.mutex.Lock()
	reply.Successors = node.Successors
	n.mutex.Unlock()
	return nil
}

//function is called by other nodes to notify the current node of a possible new predecessor
func (n *Node) Notify(args *Args, reply *Reply) error {
	n.mutex.Lock()
	addH := hashAddress(nodeAddress(args.Address))

	current_addressH := hashAddress(n.Address)

	predecessorH := hashAddress(nodeAddress(n.Predecessor))

	if n.Predecessor == "" || (Inbetween(prepredecessorH, addH, current_addressH, false)) {
		n.Predecessor = nodeAddress(args.Address)
		reply.Reply = "Success"
	} else {
		reply.Reply = "Fail"
	}
	n.mutex.Unlock()
	return nil
}

//Handles storing a file locally on the node
func (n *Node) Store(args *Args, reply *Reply) error {
	filename := args.Filename
	content := []byte(args.Command)

	//if the file is to be stored locally then there is no need to make a call
	if hashAddress(nodeAddress(add)) == hashAddress(node.Address) {
		return nil
	}

	err := os.WriteFile(filename, []byte(content), 0777)
	if err != nil {
		fmt.Println("Error writing file!!")
	}
	return nil
}

//Retrieves the content of a file stored on the node
func (n *Node) GetFile(args *Args, reply *Reply) error {
	f, err := os.Open(args.Filename)
	if err != nil {
		return nil
	}

	content, err := io.ReadAll(f)
	if err != nil {
		return nil
	}

	reply.Content = string(content)
	return nil
}
