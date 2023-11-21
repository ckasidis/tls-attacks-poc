package main

import (
	"fmt"
	"os"

	"github.com/ckasidis/tls-attacks-poc/poodle"
	"github.com/ckasidis/tls-attacks-poc/utils"
)

func main() {
	fmt.Fprintf(os.Stdout, "%sPOODLE Attack Demonstration%s\n", utils.ColorCyan, utils.ColorNone)
	fmt.Println()
	secret := "Never gonna give you up, never gonna let you down"
	fmt.Fprintf(os.Stdout, "%sSecret:%s\n%s\n", utils.ColorRed, utils.ColorNone, secret)
	fmt.Println()
	poodle.Attack([]byte(secret))
	fmt.Println()
}
