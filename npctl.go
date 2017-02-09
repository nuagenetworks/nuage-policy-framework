package main

import (
	"flag"
	"fmt"
	"github.com/nuagenetworks/nuage-policy-framework/implementer"
	"github.com/nuagenetworks/nuage-policy-framework/policies"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	flagVSDCredentials = "vsd-credentials"
	flagPolicyFile     = "policy-file"
	flagPolicyID       = "policy-id"
	flagEnterprise     = "enterprise"
	flagDomain         = "domain"
)

func main() {
	var addCmd = flag.NewFlagSet("add", flag.ExitOnError)
	var delCmd = flag.NewFlagSet("delete", flag.ExitOnError)

	if len(os.Args) < 2 {
		fmt.Println("add or delete subcommand is required")
		os.Exit(1)
	}

	var vsdCredentialsYAML *string
	var enterprise *string
	var domain *string
	var policyFile *string
	var policyID *string

	switch os.Args[1] {
	case "add":
		vsdCredentialsYAML = addCmd.String(flagVSDCredentials, "", "YAML file with VSD credentials")
		enterprise = addCmd.String(flagEnterprise, "", "Enterprise")
		domain = addCmd.String(flagDomain, "", "Domain")
		policyFile = addCmd.String(flagPolicyFile, "", "Policy YAML")

		if err := addCmd.Parse(os.Args[2:]); err != nil {
			fmt.Println("Unable to parse the add sub command")
			os.Exit(1)
		}
	case "delete":
		vsdCredentialsYAML = delCmd.String(flagVSDCredentials, "", "YAML file with VSD credentials")
		enterprise = delCmd.String(flagEnterprise, "", "Enterprise")
		domain = delCmd.String(flagDomain, "", "Domain")
		policyID = delCmd.String(flagPolicyID, "", "Policy ID")

		if err := delCmd.Parse(os.Args[2:]); err != nil {
			fmt.Println("Unable to parse the delete sub command")
			os.Exit(1)
		}
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}

	if addCmd.Parsed() {
		if enterprise == nil || *enterprise == "" {
			addCmd.PrintDefaults()
			os.Exit(1)
		}

		if domain == nil || *domain == "" {
			addCmd.PrintDefaults()
			os.Exit(1)
		}
	}

	if delCmd.Parsed() {
		if enterprise == nil || *enterprise == "" {
			delCmd.PrintDefaults()
			os.Exit(1)
		}

		if domain == nil || *domain == "" {
			delCmd.PrintDefaults()
			os.Exit(1)
		}

		if policyID == nil || *policyID == "" {
			delCmd.PrintDefaults()
			os.Exit(1)
		}
	}

	if vsdCredentialsYAML == nil {
		fmt.Printf("Vsd credential file missing\n")
		os.Exit(1)
	}

	credFile, err := filepath.Abs(*vsdCredentialsYAML)
	if err != nil {
		fmt.Printf("Unable to the absolute path for the vsd credential file\n")
		os.Exit(1)
	}

	credData, err := ioutil.ReadFile(credFile)
	if err != nil {
		fmt.Printf("Problem reading the VSD credentials\n")
		os.Exit(1)
	}

	var vsdCredentials implementer.VSDCredentials
	err = yaml.Unmarshal(credData, &vsdCredentials)
	if err != nil {
		fmt.Printf("Problem unmarshalling the VSD credentials\n")
		os.Exit(1)
	}

	var policyImplementer implementer.PolicyImplementer
	if err := policyImplementer.Init(&vsdCredentials); err != nil {
		fmt.Printf("Unable to connect to VSD\n")
		os.Exit(1)
	}

	if addCmd.Parsed() {
		if policyFile == nil {
			fmt.Printf("Policy file missing\n")
			os.Exit(1)
		}

		pfile, err := filepath.Abs(*policyFile)
		if err != nil {
			fmt.Printf("Unable to the absolute path for the policy file\n")
			os.Exit(1)
		}

		policyData, err := ioutil.ReadFile(pfile)
		if err != nil {
			fmt.Printf("Problem reading the policy file\n")
			os.Exit(1)
		}

		nuagePolicy, err := policies.LoadPolicyFromYAML(string(policyData))
		if err != nil {
			fmt.Printf("Problem loading the nuage policy %+v\n", err)
			os.Exit(1)
		}

		err = policyImplementer.ImplementPolicy(nuagePolicy)
		if err != nil {
			fmt.Printf("Problem implementing the nuage policy %+v\n", err)
			os.Exit(1)
		}
	}

	if delCmd.Parsed() {
		err := policyImplementer.DeletePolicy(*policyID, *enterprise, *domain)
		if err != nil {
			fmt.Printf("Problem deleting the policy\n")
			os.Exit(1)
		}
	}
}
