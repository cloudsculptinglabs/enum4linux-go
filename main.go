// enum4linux-go — SMB / Active Directory enumeration for Windows and Samba hosts.
//
// A modern Go rewrite of CiscoCXSecurity/enum4linux (Perl). SMB session setup
// and share enumeration are native (go-smb2); user/group/policy enumeration is
// driven over MS-RPC. Single static binary, concurrent, no Samba install needed
// for the SMB checks.
//
// For authorized assessment of hosts you own or have permission to test.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cloudsculptinglabs/enum4linux-go/internal/rpc"
	"github.com/cloudsculptinglabs/enum4linux-go/internal/smb"
)

type shareInfo struct {
	Name     string `json:"name"`
	Readable bool   `json:"readable"`
}

type report struct {
	Target   string      `json:"target"`
	Session  string      `json:"session"`
	Shares   []shareInfo `json:"shares,omitempty"`
	Users    []string    `json:"users,omitempty"`
	Groups   []string    `json:"groups,omitempty"`
	Policy   string      `json:"password_policy,omitempty"`
	Warnings []string    `json:"warnings,omitempty"`
}

func main() {
	var (
		user     = flag.String("u", "", "username (empty = null session)")
		pass     = flag.String("p", "", "password")
		domain   = flag.String("w", "", "workgroup / domain")
		doShares = flag.Bool("S", false, "enumerate shares")
		doUsers  = flag.Bool("U", false, "enumerate users (RPC)")
		doGroups = flag.Bool("G", false, "enumerate groups (RPC)")
		doPol    = flag.Bool("P", false, "dump password policy (RPC)")
		all      = flag.Bool("a", false, "run all checks")
		tSec     = flag.Int("t", 10, "timeout seconds per operation")
		asJSON   = flag.Bool("json", false, "output JSON")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: enum4linux-go [options] <host>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	host := flag.Arg(0)
	timeout := time.Duration(*tSec) * time.Second

	if *all {
		*doShares, *doUsers, *doGroups, *doPol = true, true, true, true
	}
	if !*doShares && !*doUsers && !*doGroups && !*doPol {
		*doShares = true // sensible default
	}

	rep := report{Target: host}
	if *user == "" {
		rep.Session = "null"
	} else {
		rep.Session = *user
	}

	sess, err := smb.Connect(host, *user, *pass, *domain, timeout)
	if err != nil {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("SMB session failed: %v", err))
	} else {
		defer sess.Close()
		if *doShares {
			names, err := sess.Shares()
			if err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("share enum failed: %v", err))
			} else {
				for _, n := range names {
					rep.Shares = append(rep.Shares, shareInfo{Name: n, Readable: sess.Readable(n)})
				}
			}
		}
	}

	if *doUsers {
		if u, err := rpc.Users(host, *user, *pass, timeout); err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("user enum: %v", err))
		} else {
			rep.Users = u
		}
	}
	if *doGroups {
		if g, err := rpc.Groups(host, *user, *pass, timeout); err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("group enum: %v", err))
		} else {
			rep.Groups = g
		}
	}
	if *doPol {
		if p, err := rpc.PasswordPolicy(host, *user, *pass, timeout); err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("policy: %v", err))
		} else {
			rep.Policy = p
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	}
	printText(rep)
}

func printText(r report) {
	fmt.Printf("Target: %s  (session: %s)\n", r.Target, r.Session)
	if len(r.Shares) > 0 {
		fmt.Println("\nShares:")
		for _, s := range r.Shares {
			flag := "  -"
			if s.Readable {
				flag = "  READ"
			}
			fmt.Printf("%s  %s\n", flag, s.Name)
		}
	}
	if len(r.Users) > 0 {
		fmt.Printf("\nUsers (%d):\n", len(r.Users))
		for _, u := range r.Users {
			fmt.Printf("  %s\n", u)
		}
	}
	if len(r.Groups) > 0 {
		fmt.Printf("\nGroups (%d):\n", len(r.Groups))
		for _, g := range r.Groups {
			fmt.Printf("  %s\n", g)
		}
	}
	if r.Policy != "" {
		fmt.Printf("\nPassword policy:\n%s\n", r.Policy)
	}
	if len(r.Warnings) > 0 {
		fmt.Println("\nWarnings:")
		for _, w := range r.Warnings {
			fmt.Printf("  ! %s\n", w)
		}
	}
}
