package main

import (
	"fmt"
	"os"

	"github.com/ckasidis/tls-attacks-poc/beast"
	"github.com/ckasidis/tls-attacks-poc/poodle"
	"github.com/ckasidis/tls-attacks-poc/utils"
)

func main() {
	secret := "Never gonna give you up, never gonna let you down"

	fmt.Fprintf(os.Stdout, "%s/* ------------------------------ BEAST Attack ------------------------------ */%s\n", utils.ColorRed, utils.ColorNone)
	fmt.Println()
	fmt.Fprintf(os.Stdout, "%sSecret:%s\n", utils.ColorRed, utils.ColorNone)
	fmt.Fprintf(os.Stdout, "%s%s%s\n", utils.ColorCyan, secret, utils.ColorNone)
	fmt.Println()
	beast.Attack([]byte(secret))
	fmt.Println()

	fmt.Fprintf(os.Stdout, "%s/* ------------------------------ POODLE Attack ----------------------------- */%s\n", utils.ColorRed, utils.ColorNone)
	fmt.Println()
	fmt.Fprintf(os.Stdout, "%sSecret:%s\n", utils.ColorRed, utils.ColorNone)
	fmt.Fprintf(os.Stdout, "%s%s%s\n", utils.ColorCyan, secret, utils.ColorNone)
	fmt.Println()
	poodle.Attack([]byte(secret))
	fmt.Println()
}
