package main

import (
	"encoding/hex"
	"fmt"
)

func main()  {
	pk := "0x4646464646464646464646464646464646464646464646464646464646464646"
	privatekey, err := hex.DecodeString(pk)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(privatekey)

}
