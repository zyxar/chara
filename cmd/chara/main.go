package main

import (
	"flag"
	"fmt"
	"github.com/zyxar/chara"
)

var (
	clearBits = flag.Bool("clearbits", false, "clear bits when calculating hash")
)

func main() {
	flag.Parse()
	for i := 0; i < flag.NArg(); i++ {
		filename := flag.Arg(i)
		_, hash, err := chara.ScanFile(filename, *clearBits)
		if err != nil {
			fmt.Printf("scan %s error: %v", filename, err)
			continue
		}
		fmt.Printf("%s\n%02x\n\n", filename, hash)
	}
}
