package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/rpc"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)


// mutex and a map are used to manage concurrent access.
var m sync.Mutex
var connections = make(map[string]*rpc.Client)

// variables store the command line arguments for configuring the DHT.
var address *string
var port *int
var joinAddress *string
var joinPort *int
var timeToStablize *int
var timeToFixFingers *int
var timeToCheckPredecessor *int
var id *string
var numberSuccessor *int

//used to control the main execution flow, store local node information.
var localPort string
var running, alreadyCreated bool
var node *Node
var add NodeAddress

var FingerTableSize = 5

func main() {

	address = flag.String("a", "", " IP address")
	port = flag.Int("p", -1, "Port")
	joinAddress = flag.String("ja", "", "Join address")
	joinPort = flag.Int("jp", -1, "Join port")
	timeToCheckPredecessor = flag.Int("tcp", -1, "Time between invocations of check predecessor")
	timeToStablize = flag.Int("ts", -1, "Time between invocations of stabilize call")
	timeToFixFingers = flag.Int("tff", -1, "Time between invocations of fix fingers call")
	id = flag.String("i", "", "The string identifier of a node")
	numberSuccessor = flag.Int("r", -1, "The amount of successors maintained")
	
	flag.Parse()
	
	*address = strings.TrimSpace(*address)
	*joinAddress = strings.TrimSpace(*joinAddress)
	*id = strings.TrimSpace(*id)
	localPort = ":" + strconv.Itoa(*port)

	if (*port < 0 || *timeToStablize < 1 || *timeToCheckPredecessor < 1 || *timeToFixFingers < 1) ||
		(*timeToStablize > 60000 || *timeToCheckPredecessor > 60000 || *timeToFixFingers > 60000) {
		fmt.Println("Invalid")
		return
	}
	
	if (len(*joinAddress) == 0 && *joinPort >= 0) || (len(*joinAddress) > 0 && *joinPort < 0) {
		fmt.Printf("You have to provide both -ja and -jp flags")
		return
	}
	
	add = NodeAddress(*address + localPort)
	node = &Node{
		Address:     add,
		Successors:  []NodeAddress{},
		Predecessor: "",
		FingerTable: []NodeAddress{},
		Bucket:      make(map[Key]string),
	}

	server(*address, localPort)

	var str string

	if len(*joinAddress) > 0 && *joinPort > 0 { 
		add := NodeAddress(*joinAddress + ":" + strconv.Itoa(*joinPort))
		join(add)
	} else {
		args := []string{*address + localPort}
		create(args)
	}

	go CP(time.Duration(*timeToCheckPredecessor))
	
	go Stab(time.Duration(*timeToStablize))
	
	go FF(time.Duration(*timeToFixFingers))

	running = true
	alreadyCreated = false
	
	res := bufio.NewReader(os.Stdin)
	cmd := make(map[string]func([]string))
	cmd["StoreFile"] = StoreFile
	cmd["LookUp"] = LookUp
	cmd["PrintState"] = PrintState
	cmd["Dump"] = dump
	cmd["Quit"] = quit
	
	for running {
		fmt.Println("Enter Command: ")
		str, _ = res.ReadString('\n')
		str = strings.TrimSpace(str)
		args := strings.Split(str, " ")

		input, same := cmd[args[0]]
		if same {
			input(args)
		} else {
			fmt.Println("Enter the correct command (StoreFile <filename> || PrinState || LookUp <filename> ).")
		}
	}
}

func create(args []string) { //function to create a new Chord ring
	if alreadyCreated {
		fmt.Println("Node has been already created")
		return
	}
	node.create()
}

func StoreFile(args []string) {  //function to store a file in the Chord DHT
	filename := args[1]
	EncryptingFile([]byte("Hello! This is the encrypted key"), filename, filename)
	fileContent, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Cannot read the file: " + err.Error())
	}

	content := string(fileContent)
	add := findNode(args)

	//if the address maps to itself then there is no need to make a call
	if strings.Compare(add, string(node.Address)) == 0 {
		return
	}

	reply := Reply{}
	arguments := Args{Command: content, Address: string(node.Address), Filename: filename, Offset: 0}

	successful := call(string(add), "Node.Store", &arguments, &reply)
	if !successful {
		fmt.Println("Cannot reach the node")
		return
	}
}

// A function to find the node responsible for storing a file in the Chord DHT.
func findNode(args []string) string {
	filename := args[1]

	reply := Reply{}
	arguments := Args{Command: "", Address: filename, Offset: 0}

	add := node.Address
	flag := false

	for !flag {
		successful := call(string(add), "Node.FindSuccessor", &arguments, &reply)
		if !successful {
			fmt.Println("Not found")
		}
		switch found := reply.Found; found {

		case true:
			flag = true
		case false:
			add = NodeAddress(reply.Forward)
		}
	}
	return reply.Reply
}

func EncryptingFile(key []byte, filename string, out string) { //function to encrypt the contents of a file using AES encryption.

	fileOpen, err := os.Open(filename)
	if err != nil {
		log.Printf("Error Opening the file.")
	}

	content, err := io.ReadAll(fileOpen)
	if err != nil {
		log.Printf("Error Reading the file.")
	}

	fileOpen.Close()

	encryption, err := MsgEncryption(key, string(content))
	if err != nil {
		log.Printf("Error encrypting message.")
	}

	encodeData := base64.StdEncoding.EncodeToString(encryption)

	outFile, err := os.Create(out)
	if err != nil {
		log.Printf("Error creating file.")
	}

	outFile.Write([]byte(encodeData))
	outFile.Close()
}

func MsgEncryption(key []byte, message string) ([]byte, error) { // function to encrypt a message using AES encryption
	block, err := aes.NewCipher(key) //Creating a new AES cipher block with the provided key 
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block) //Creating a new AES-GCM cipher block using the previously created block
	if err != nil {
		return nil, err
	}

	number_once := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, number_once); err != nil {
		return nil, err
	}

	encryptedData := aesGCM.Seal(number_once, number_once, []byte(message), nil)

	return encryptedData, nil
}

func LookUp(args []string) { //function to look up the node responsible for storing a file in the Chord DHT.
	add := findNode(args)
	fmt.Println(hashAddress(NodeAddress(add)), add)
	SendRequest(add, args[1])
}

func CP(t time.Duration) { //function to periodically check the predecessor of the current node.
	for {
		cp([]string{})
		time.Sleep(t * time.Millisecond)
	}
}

func FF(t time.Duration) { //function to periodically fix the finger table of the current node.
	for {
		fix_fingers()
		time.Sleep(t * time.Millisecond)
	}
}

func Stab(t time.Duration) { //function to periodically stabilize the Chord ring.
	for { 
		stabilize([]string{})
		time.Sleep(t * time.Millisecond)
	}
}

func quit(args []string) {//function to gracefully quit the Chord DHT, closing connections and cleaning up resources
	running = false
	m.Lock()
	defer m.Unlock()
	fmt.Println(len(connections))
	for add, conn := range connections {
		err := conn.Close()
		if err != nil {
			fmt.Println("error closing :", add, err)
		}
	}
	fmt.Print("Quitting!\n")
}

func cp(args []string) { //function to handle predecessor checks.
	arguments := Args{Command: "CP", Address: string(node.Address), Offset: 0}
	reply := Reply{}

	if string(node.Predecessor) == "" {
		return
	}

	ok := call(string(node.Predecessor), "Node.HandlePing", &arguments, &reply)
	if !ok {
		node.mutex.Lock()
		fmt.Println("Can not connect to predecessor")
		node.Predecessor = NodeAddress("")
		node.mutex.Unlock()
		return
	}
}

func fix_fingers() { //function to fix the finger table of the current node.
	if len(node.FingerTable) == 0 {
		node.mutex.Lock()
		node.FingerTable = []NodeAddress{node.Successors[0]}
		node.mutex.Unlock()
		return
	}

	node.mutex.Lock()
	node.FingerTable = []NodeAddress{}
	node.mutex.Unlock()
	for next := 1; next <= FingerTableSize; next++ {
		offset := int64(math.Pow(2, float64(next)-1)) //Calculates the offset for the next finger using the Chord formula
		add := node.Address
		flag := false
		for !flag {
			reply := Reply{}
			args := Args{Command: "", Address: string(node.Address), Offset: offset}
			ok := call(string(add), "Node.FindSuccessor", &args, &reply)
			if !ok {
				fmt.Println("Error")
				return
			}

			switch found := reply.Found; found {
			case true:
				node.mutex.Lock()

				node.FingerTable = append(node.FingerTable, NodeAddress(reply.Reply))
				flag = true
				node.mutex.Unlock()
			case false:
				if strings.Compare(reply.Forward, string(node.Address)) == 0 {
					node.mutex.Lock()
					flag = true
					node.FingerTable = append(node.FingerTable, NodeAddress(reply.Forward))
					node.mutex.Unlock()
					break
				}
				add = NodeAddress(reply.Forward)
			}
		}
	}
}

func stabilize(args []string) { //function to stabilize the Chord ring
	arguments := Args{Command: "", Address: string(node.Address), Offset: 0}
	reply := Reply{}

	ok := call(string(node.Successors[0]), "Node.Get_predecessor", &arguments, &reply)
	if !ok {
		fmt.Println("Could not connect to predecessor")
		dump([]string{})
		node.mutex.Lock()
		node.Successors = node.Successors[1:]
		if len(node.Successors) == 0 {
			node.Successors = []NodeAddress{node.Address}
		}
		node.mutex.Unlock()
		return
	}
	node.mutex.Lock()
	addH := hashAddress(node.Address)                 // Current node
	addressH := hashAddress(NodeAddress(reply.Reply)) // Predecessor
	succH := hashAddress(node.Successors[0])          // Successor

	if Inbetween(addH, addressH, succH, true) && reply.Reply != "" {
		node.Successors = []NodeAddress{NodeAddress(reply.Reply)}
	}

	node.mutex.Unlock()
	arguments = Args{Command: "", Address: string(node.Address), Offset: 0}
	reply = Reply{}
	ok = call(string(node.Successors[0]), "Node.Get_successors", &arguments, &reply)
	if !ok {
		fmt.Println("Call failed to successor while stabilizing")
	}
	node.mutex.Lock()

	node.Successors = []NodeAddress{node.Successors[0]}
	node.Successors = append(node.Successors, reply.Successors...)
	if len(node.Successors) > *numberSuccessor {
		node.Successors = node.Successors[:*numberSuccessor]
	}
	node.mutex.Unlock()

	arguments = Args{Command: "Stabilize", Address: string(node.Address), Offset: 0}
	reply = Reply{}
	notify([]string{})
}

func notify(args []string) { //function to notify the successor of the current node.
	arguments := Args{Command: "Notify", Address: string(node.Address), Offset: 0}
	reply := Reply{}

	ok := call(string(node.Successors[0]), "Node.Notify", &arguments, &reply)
	if !ok {
		fmt.Println("Call failed to notify")
	}
}

func server(address string, port string) {//function to start the RPC server for the current node.
	rpc.Register(node)
	rpc.HandleHTTP()
	l, err := net.Listen("tcp", port)
	if err != nil {
		panic("Error starting RPC")
	}
	go http.Serve(l, nil)
	fmt.Println("Created node at address: " + address + localPort)
}

func join(address NodeAddress) { //function to join an existing Chord ring.
	reply := Reply{}
	args := Args{Command: "", Address: string(node.Address), Offset: 0}

	add := address
	loop := false

	for !loop {
		call(string(add), "Node.FindSuccessor", &args, &reply)

		fmt.Println(reply.Successors)

		switch found := reply.Found; found {
		case true:
			node.join(NodeAddress(reply.Reply))
			loop = true
		case false:
			add = NodeAddress(reply.Forward)
		}
	}
}

func call(address string, method string, args interface{}, reply interface{}) bool { //function to make RPC calls to other nodes in the Chord DHT.
	m.Lock()
	defer m.Unlock()

	cl, ok := connections[address]
	if ok { // if already connection to address
		err := cl.Call(method, args, reply)
		if err == nil {
			return true
		}

		fmt.Println("CALL ERROR: ", err)
		delete(connections, address)
		return false
	}

	cl, err := rpc.DialHTTP("tcp", address)
	if err != nil {
		fmt.Println("ERROR :", err)
		return false
	}
	connections[address] = cl
	err = cl.Call(method, args, reply)

	if err == nil {
		return true
	}
	fmt.Println("CALL ERROR: ", err)
	return false
}

func SendRequest(address string, filename string) error { //function to send a request for a file stored in the Chord DHT.

	args := Args{Filename: filename}
	reply := Reply{}

	ok := call(address, "Node.GetFile", &args, &reply)
	if !ok {
		fmt.Println("Error requesting")
		return nil
	}

	text, err := DecryptingMessage([]byte("Secret key"), reply.Content)
	if err != nil {
		fmt.Println("Error decrypting ", err)
		return nil
	}
	fmt.Println("Encoded content:", reply.Content)
	fmt.Println("Decrypted content: ", text)
	return nil
}

func DecryptingMessage(key []byte, message string) (string, error) {//function to decrypt a message using AES encryption.
	cipherText, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return "", fmt.Errorf("Could not base64 decode: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("Failed to create a cipher block: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("Failed to create GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherText) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	number_once, cipherData := cipherText[:nonceSize], cipherText[nonceSize:]
	decryptedData, err := aesGCM.Open(nil, number_once, cipherData, nil)
	if err != nil {
		return "", fmt.Errorf("Failed to decrypt: %v", err)
	}
	return string(decryptedData), nil
}

func dump(args []string) { //function to print the state of the current node.
	fmt.Println("Address: " + node.Address)
	fmt.Println("ID: " + hashAddress(node.Address).String())
	fmt.Print("Finger table: ")
	fmt.Println(node.FingerTable)
	fmt.Println("Predecessor: " + node.Predecessor)
	fmt.Print("Successors: ")
	fmt.Println(node.Successors)
	fmt.Print("Bucket: ")
	fmt.Println(node.Bucket)
}

func PrintState(args []string) { //function to print the state of the Chord DHT.

	fmt.Println("Chord client’s own node information: ")
	fmt.Println(node.Address, hashAddress(node.Address))

	fmt.Println("Successor list:")
	for _, s := range node.Successors {
		fmt.Println(s, hashAddress(s))
	}

	fmt.Println("Finger Table:")
	for _, f := range node.FingerTable {
		fmt.Println(f, hashAddress(f))
	}
}