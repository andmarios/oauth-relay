package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "oauth-token-relay starting...")
	// TODO: Load config, init store, start server
	os.Exit(0)
}
