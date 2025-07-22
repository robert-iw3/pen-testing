package adfs

import (
	"GoMapEnum/src/logger"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

var level logger.Level
var verbose bool
var debug bool
var validUsers string
var output string
var proxyString string

// AdfsCmd represents the ADFS command
var AdfsCmd = &cobra.Command{
	Use:   "adfs",
	Short: "Commands for ADFS module",
	Long:  `ADFS (Active Directory Federation Service) is a role that can be installed on a windows server to provide Single Sign-on.`,
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if output != "" {
			if err := os.WriteFile(output, []byte(validUsers), 0666); err != nil {
				fmt.Println(err)
			}
		}
	},
}

func init() {

	cobra.OnInitialize(initLogger)
	cobra.OnInitialize(initProxy)
	AdfsCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose")
	AdfsCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Debug")
	AdfsCmd.PersistentFlags().StringVarP(&output, "output-file", "o", "", "The out file for valid emails")
	AdfsCmd.PersistentFlags().StringVar(&proxyString, "proxy", "", "Proxy to use (ex: http://localhost:8080)")

	AdfsCmd.AddCommand(bruteCmd)
}

func initLogger() {
	if debug {
		level = logger.DebugLevel
	} else if verbose {
		level = logger.VerboseLevel
	} else {
		level = logger.InfoLevel
	}

}

func initProxy() {
	if proxyString != "" {
		url, err := url.Parse(proxyString)
		if err != nil {
			fmt.Println("Fail to parse URL " + proxyString + " - error " + err.Error())
			os.Exit(1)
		}
		adfsOptions.ProxyHTTP = http.ProxyURL(url)
	}
}
