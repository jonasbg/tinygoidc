package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"

	"tinygoidc/internal/config"
	"tinygoidc/internal/oidc"
	"tinygoidc/internal/server"
)

type options struct {
	usersPath string
	host      string
	port      string
	usersFromEnv  bool
	usersFromFlag bool
}

func main() {
	opts := parseOptions()

	users, err := config.LoadUsers(opts.usersPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !opts.usersFromEnv && !opts.usersFromFlag && config.HasEmbeddedUsers() {
			users, err = config.LoadEmbeddedUsers()
			if err != nil {
				log.Fatalf("failed to load embedded users: %v", err)
			}
		} else {
			log.Fatalf("failed to load users (%s): %v", opts.usersPath, err)
		}
	}

	keys := oidc.GenerateKeySet()
	s := server.New(users, keys)

	addr := net.JoinHostPort(opts.host, opts.port)
	s.Engine.SetTrustedProxies(nil)
	printBanner(opts.host, opts.port)
	log.Fatal(s.Engine.Run(addr))
}

func parseOptions() options {
	const (
		defaultUsersPath = "users.yaml"
		defaultHost      = "0.0.0.0"
		defaultPort      = "9999"
	)

	opts := options{
		usersPath: defaultUsersPath,
		host:      defaultHost,
		port:      defaultPort,
	}

	if val := firstNonEmpty(os.Getenv("TINYGOIDC_USERS"), os.Getenv("USERS")); val != "" {
		opts.usersPath = val
		opts.usersFromEnv = true
	}
	if val := firstNonEmpty(os.Getenv("TINYGOIDC_HOST"), os.Getenv("HOST")); val != "" {
		opts.host = val
	}
	if val := firstNonEmpty(os.Getenv("TINYGOIDC_PORT"), os.Getenv("PORT")); val != "" {
		opts.port = val
	}

	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagSet.Usage = func() {
		out := flagSet.Output()
		fmt.Fprintf(out, "Usage: %s [flags]\n\n", os.Args[0])
		fmt.Fprintln(out, "tinygoidc is a mock OIDC provider useful for local development.")
		fmt.Fprintln(out, "Configuration precedence: flags > environment variables > defaults.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Environment variables:")
		fmt.Fprintln(out, "  TINYGOIDC_USERS, USERS — path to users YAML (default: users.yaml)")
		fmt.Fprintln(out, "  TINYGOIDC_HOST, HOST   — address to bind (default: 0.0.0.0)")
		fmt.Fprintln(out, "  TINYGOIDC_PORT, PORT   — port to bind (default: 9999)")
		fmt.Fprintln(out)
		flagSet.PrintDefaults()
	}

	flagSet.StringVar(&opts.usersPath, "users", opts.usersPath, "Path to the users YAML file")
	flagSet.StringVar(&opts.host, "host", opts.host, "Host/IP address to bind to")
	flagSet.StringVar(&opts.port, "port", opts.port, "Port to listen on")

	_ = flagSet.Parse(os.Args[1:])

	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == "users" {
			opts.usersFromFlag = true
		}
	})

	return opts
}

func firstNonEmpty(values ...string) string {
	for _, val := range values {
		if val != "" {
			return val
		}
	}
	return ""
}

func printBanner(host, port string) {
	const banner = `


                     &$$$$$$$$                        
                 $$$$$::::::::+$$                     
               $$:$::;$::::::::$;:$$                  
             $x::::X::x+::::::::$:$:$$                
            $;::::::::;$::::::::$::::;$               
           $;;::::::::;$::::::::+x::::+$              
           $;;:::::::::$:::::::::$:::::$              
    $X;;;x$X+$$$$:::::;$XX$$$$Xx;$:::::;$x;;:$&       
   $$;:$+$+;;;::::::::::::::::::::::::;X$X:$;;$       
    $;;;;$$;;;$$$$$$$$$XXXxxxx+++++xxxXX$$X;:;$       
     $$;$;;$.       ;$;;;;;;;;;$.       :$X$$$        
       $;;$           $;:;;;;;$           $+$         
      $;:X.     $$$:  ;:;;:;;+.  $$ $     :+$         
      $;;X.    .$$$$  ;;;;:;;;;  $$$X     ;;;$        
     &X;;;$.          $;XXXX$:$.          $;;$        
     $;;:;;$+.      X$$;;+$$;;$+$..     $+;:;$        
     $;;;;;;;:X$$$X;;;$;;;;;;;;$;;:+Xx:;;:;;;$        
     $;;;:;;;;;;;;;;;;;;$ ; .X;;;;;;;;;:;;:;:$        
     $;;;;;:;;;:;:;:;;;;;$$$$;:;:;:;:;;;;;;;;$        
     $;;+$$$X;;;;;;;:;:;;;;;;;;;;;;;;;;;X$$X:$        
     $;::x;::;;;:$$;;;;;:;;:;:;:;$X;:;;:::$::$&       

`
	fmt.Println(banner)
	fmt.Printf("tinygoidc ready on http://%s:%s — happy mocking!\n\n", host, port)
}
