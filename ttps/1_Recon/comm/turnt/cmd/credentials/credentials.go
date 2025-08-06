package main

import (
	"fmt"
	"log"
	"os"

	"github.com/praetorian-inc/turnt/internal/msteams"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Manage credentials for various services",
}

var (
	outputFile string
)

var teamsCmd = &cobra.Command{
	Use:   "msteams",
	Short: "Get Microsoft Teams TURN credentials",
	Run: func(cmd *cobra.Command, args []string) {
		creds, err := msteams.GetTurnCredentials()
		if err != nil {
			log.Fatalf("Failed to get Teams credentials: %v", err)
		}

		if err := msteams.SaveConfig(creds, outputFile); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}

		fmt.Printf("Successfully retrieved Teams credentials and saved to %s\n", outputFile)
	},
}

func main() {
	teamsCmd.Flags().StringVarP(&outputFile, "output", "o", "config.yaml", "output file path")
	rootCmd.AddCommand(teamsCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
