package kerberos

import (
	"GoMapEnum/src/logger"
	"GoMapEnum/src/modules/kerberos"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
)

var level logger.Level
var verbose bool
var debug bool
var outputCmd string
var output string
var proxyString string

var kerberosOptions kerberos.Options

// KerberosCmd represents the owa command
var KerberosCmd = &cobra.Command{
	Use:   "kerberos",
	Short: "Commands for kerberos module",
	Long:  ``,
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if output != "" {
			if err := os.WriteFile(output, []byte(outputCmd), 0666); err != nil {
				fmt.Println(err)
			}
		}
	},
}

func init() {

	cobra.OnInitialize(initLogger)
	cobra.OnInitialize(initProxy)
	KerberosCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose")
	KerberosCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Debug")
	KerberosCmd.PersistentFlags().StringVarP(&output, "output-file", "o", "", "The out file for valid emails")
	KerberosCmd.PersistentFlags().StringVar(&proxyString, "proxy", "", "Socks5 proxy to use (ex: localhost:8080)")
	//KerberosCmd.PersistentFlags().StringVarP(&kerberosOptions.Users, "user", "u", "", "User or file containing the emails")
	//KerberosCmd.PersistentFlags().StringVarP(&kerberosOptions.Passwords, "password", "p", "", "Password or file containing the passwords")
	//KerberosCmd.PersistentFlags().StringVarP(&kerberosOptions.Hash, "hash", "H", "", "Hash or file containing the hashes")
	KerberosCmd.PersistentFlags().StringVarP(&kerberosOptions.Target, "target", "t", "", "Host pointing to the kerberos server")
	KerberosCmd.PersistentFlags().StringVarP(&kerberosOptions.Domain, "domain", "d", "", "Domain for the authentication in netbios format (by default the domain name will be guessed with a ldap connection)")
	KerberosCmd.PersistentFlags().IntVar(&kerberosOptions.Thread, "thread", 2, "Number of threads")

	KerberosCmd.AddCommand(enumCmd)
	KerberosCmd.AddCommand(bruteCmd)
	KerberosCmd.AddCommand(kerberoastingCmd)
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
		var err error
		defaultDailer := &net.Dialer{Timeout: time.Duration(kerberosOptions.Timeout * int(time.Second))}
		kerberosOptions.ProxyTCP, err = proxy.SOCKS5("tcp", proxyString, nil, defaultDailer)
		if err != nil {
			fmt.Println("fail to use the proxy " + proxyString + ": " + err.Error())
			os.Exit(1)
		}
	}
}
