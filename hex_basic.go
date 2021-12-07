package main

import (
    "fmt"
    "encoding/hex"
    "log"
    "os"
)

func main() {
    // Encode 
    src := []byte("Hi Irene!")
    dst1 := make([]byte, hex.EncodedLen(len(src)))
    hex.Encode(dst1, src)
    fmt.Printf("EX1: %s encode is %s \n", src, dst1)

    dst2 := hex.EncodeToString(src)
    fmt.Printf("EX2: %s encode is %s\n", src, dst2)

    //Decode
    src = dst1
    dst3 := make([]byte, hex.DecodedLen(len(src)))
    dst3_len, err := hex.Decode(dst3, src)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("EX3: %s decode is \"%s\", length is %d\n", src, dst3, dst3_len)

    //Decode String
    tmp := string(dst1)
    dst4, err := hex.DecodeString(tmp)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("EX4: %s decode is \"%s\" \n", tmp, dst4)

    //Dump
    src = []byte("Go is an open source programing language.")
    dst5 := hex.Dump(src)
    fmt.Printf("EX5:\n%s\n", dst5)

    //Dumper
    lines := []string{
	"Go is an open source programming language.",
	"\n",
	"We encourage all Go users to subscribe to golang-announce.",
    }

    stdoutDumper := hex.Dumper(os.Stdout)
    defer stdoutDumper.Close()

    for _, line := range lines {
	stdoutDumper.Write([]byte(line))
    }
}
