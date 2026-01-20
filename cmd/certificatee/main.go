package main

import (
	"fmt"
	"os"
)

var (
	version = "dev" // GoReleaser will inject the Git tag here
)

func main() {
	// Parse subcommand
	args := os.Args[1:]
	cmd := "sync" // default command

	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd = args[0]
		args = args[1:]
	}

	switch cmd {
	case "sync":
		syncCmd(args)
	case "list-certs":
		listCertsCmd(args)
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: certificatee [command] [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  sync         Run the certificate sync daemon (default)")
	fmt.Println("  list-certs   List certificates from HAProxy instances")
	fmt.Println("  help         Show this help message")
	fmt.Println()
	fmt.Println("Options for list-certs:")
	fmt.Println("  -v, --verbose    Show detailed certificate information")
}
