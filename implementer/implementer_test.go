package implementer

import (
	"fmt"
	"github.com/nuagenetworks/nuage-policy-framework/policies"
	"testing"
)

const (
	VsdURL          = "https://192.168.103.200:8443"
	VsdUsername     = "csproot"
	VsdPassword     = "csproot"
	VsdOrganization = "csp"

	Enterprise = "nuage"
	Domain     = "openshift"

	Zone1 = "default"
	Zone2 = "kube-system"

	AnnoZone1 = "test-1"
	AnnoZone2 = "test-2"

	Subnet1 = "default-0"
	Subnet2 = "kube-system-0"

	ClientPg = "ClientPG1"
	ServerPg = "ServerPG"

	PG2PGPolicyName     = "k8s-pg-2-pg-policy"
	PG2PGPolicyID       = PG2PGPolicyName
	PG2PGPolicyPriority = 1000

	Subnet2ZonePolicyName     = "k8s-subnet-2-zone-policy"
	Subnet2ZonePolicyID       = Subnet2ZonePolicyName
	Subnet2ZonePolicyPriority = 2000

	Zone2PGPolicyName     = "k8s-zone-2-pg-policy"
	Zone2PGPolicyID       = Zone2PGPolicyName
	Zone2PGPolicyPriority = 3000

	ZoneAnnotationTemplate = "Namespace Annotations"
)

var policyImplementer PolicyImplementer

func InitSession() {
	var vsdCredentials VSDCredentials
	vsdCredentials.Username = VsdUsername
	vsdCredentials.Password = VsdPassword
	vsdCredentials.Organization = VsdOrganization
	vsdCredentials.URL = VsdURL

	if err := policyImplementer.Init(&vsdCredentials); err != nil {
		panic("Unable to connect to VSD")
	}
}

func addSubnet2ZonePolicy() error {
	nuagePolicy := policies.NuagePolicy{
		Version:    policies.V1Alpha,
		Type:       policies.Default,
		Enterprise: Enterprise,
		Domain:     Domain,
		Name:       Subnet2ZonePolicyName,
		ID:         Subnet2ZonePolicyID,
		Priority:   Subnet2ZonePolicyPriority,
	}

	defaultPolicyElement := policies.DefaultPolicyElement{
		Name:   "Access Control",
		From:   policies.EndPoint{Name: Subnet1, Type: policies.Subnet},
		To:     policies.EndPoint{Name: Zone1, Type: policies.Zone},
		Action: policies.Allow,
		NetworkParameters: policies.NetworkParameters{
			Protocol:             policies.TCP,
			DestinationPortRange: policies.PortRange{StartPort: 100, EndPort: 200},
		},
	}

	nuagePolicy.PolicyElements = []policies.DefaultPolicyElement{defaultPolicyElement}
	err := policyImplementer.ImplementPolicy(&nuagePolicy)
	return err
}

func addZone2PGPolicy() error {
	nuagePolicy := policies.NuagePolicy{
		Version:    policies.V1Alpha,
		Type:       policies.Default,
		Enterprise: Enterprise,
		Domain:     Domain,
		Name:       Zone2PGPolicyName,
		ID:         Zone2PGPolicyID,
		Priority:   Zone2PGPolicyPriority,
	}

	defaultPolicyElement := policies.DefaultPolicyElement{
		Name:   "Access Control",
		From:   policies.EndPoint{Name: Zone1, Type: policies.Zone},
		To:     policies.EndPoint{Name: ServerPg, Type: policies.PolicyGroup},
		Action: policies.Allow,
		NetworkParameters: policies.NetworkParameters{
			Protocol:             policies.TCP,
			DestinationPortRange: policies.PortRange{StartPort: 100, EndPort: 200},
		},
	}

	nuagePolicy.PolicyElements = []policies.DefaultPolicyElement{defaultPolicyElement}
	err := policyImplementer.ImplementPolicy(&nuagePolicy)
	return err
}

func addPG2PGPolicy() error {
	nuagePolicy := policies.NuagePolicy{
		Version:    policies.V1Alpha,
		Type:       policies.Default,
		Enterprise: Enterprise,
		Domain:     Domain,
		Name:       PG2PGPolicyName,
		ID:         PG2PGPolicyID,
		Priority:   PG2PGPolicyPriority,
	}

	defaultPolicyElement := policies.DefaultPolicyElement{
		Name:   "Access Control",
		From:   policies.EndPoint{Name: ClientPg, Type: policies.PolicyGroup},
		To:     policies.EndPoint{Name: ServerPg, Type: policies.PolicyGroup},
		Action: policies.Allow,
		NetworkParameters: policies.NetworkParameters{
			Protocol:             policies.TCP,
			DestinationPortRange: policies.PortRange{StartPort: 100, EndPort: 200},
		},
	}

	nuagePolicy.PolicyElements = []policies.DefaultPolicyElement{defaultPolicyElement}
	err := policyImplementer.ImplementPolicy(&nuagePolicy)
	return err
}

func TestZone2PGPolicyAddRemove(t *testing.T) {
	InitSession()

	err := addZone2PGPolicy()
	if err != nil {
		t.Fatalf("Failed to apply policy with error %+v", err)
	}

	err = policyImplementer.DeletePolicy(Zone2PGPolicyName, Enterprise, Domain)
	if err != nil {
		t.Fatalf("Unable to delete the policy %+v", err)
	}
}

func TestSubnet2ZonePolicyAddRemove(t *testing.T) {
	InitSession()

	err := addSubnet2ZonePolicy()
	if err != nil {
		t.Fatalf("Failed to apply policy with error %+v", err)
	}

	err = policyImplementer.DeletePolicy(Subnet2ZonePolicyID, Enterprise, Domain)
	if err != nil {
		t.Fatalf("Unable to delete the policy %+v", err)
	}
}

func TestPG2PGPolicyAddRemove(t *testing.T) {
	InitSession()

	err := addPG2PGPolicy()
	if err != nil {
		t.Fatalf("Failed to apply policy with error %+v", err)
	}

	err = policyImplementer.DeletePolicy(PG2PGPolicyID, Enterprise, Domain)
	if err != nil {
		t.Fatalf("Unable to delete the policy %+v", err)
	}
}

const testZone2ZoneEndpointYaml = `
--- 
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "Block intra zone traffic"
name: "Block intra zone traffic"
priority: 1000
policy-elements: 
    - name: "Access control 1"
      from:
        name: default 
        type: zone 
      to:
        name: default
        type: endpoint-zone
      action: DENY 
      network-parameters:
        protocol: 6 
`

func TestZone2EndpointZonePolicy(t *testing.T) {
	InitSession()

	nuagePolicy, err := policies.LoadPolicyFromYAML(testZone2ZoneEndpointYaml)
	if err != nil {
		t.Fatalf("Unable to unmarshal policy %s , err %+v", testZone2ZoneEndpointYaml, err)
	}

	err = policyImplementer.ImplementPolicy(nuagePolicy)
	if err != nil {
		t.Fatalf("Unable to implement the nuage policy %+v err %+v", nuagePolicy, err)
	}

	err = policyImplementer.DeletePolicy(nuagePolicy.ID, Enterprise, Domain)
	if err != nil {
		t.Fatalf("Unable to delete the policy %+v", err)
	}
}

const testPolicyUpdateBase = `
---
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "Multi level access control"
name: "Multi level access control"
priority: 1024
policy-elements:
    - name: "Access control 1"
      from:
        name: ClientPG1
        type: policy-group
      to:
        name: default
        type: zone
      action: ALLOW
      network-parameters:
        protocol: 6 
`

const testPolicyUpdateNewACL = `
---
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "Multi level access control"
name: "Multi level access control"
priority: 1024
policy-elements:
    - name: "Access control 2"
      from:
        name: kube-system
        type: zone
      to:
        name: ServerPG
        type: policy-group
      action: ALLOW
      network-parameters:
        protocol: 6 
`

func TestPolicyUpdateAdd(t *testing.T) {
	InitSession()

	nuagePolicy, err := policies.LoadPolicyFromYAML(testPolicyUpdateBase)
	if err != nil {
		t.Fatalf("Unable to parse the policy yaml\n %s \n", testPolicyUpdateBase)
	}

	err = policyImplementer.ImplementPolicy(nuagePolicy)
	if err != nil {
		t.Fatalf("Unable to implement the nuage policy %+v %+v", nuagePolicy, err)
	}

	nuagePolicyDelta, err := policies.LoadPolicyFromYAML(testPolicyUpdateNewACL)
	if err != nil {
		t.Fatalf("Unable to parse the policy yaml\n %s \n", testPolicyUpdateNewACL)
	}

	err = policyImplementer.UpdatePolicy(nuagePolicyDelta, policies.UpdateAdd)
	if err != nil {
		if derr := policyImplementer.DeletePolicy(nuagePolicy.ID, Enterprise, Domain); derr != nil {
			fmt.Println("Unable to delete policy")
		}
		t.Fatalf("Unable to update the nuage policy err %+v", err)
	}

	err = policyImplementer.DeletePolicy(nuagePolicy.ID, Enterprise, Domain)
	if err != nil {
		t.Fatalf("Unable to delete the policy %+v", err)
	}
}

const testPolicyUpdateRemoveBase = `
---
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "Multi level access control"
name: "Multi level access control"
priority: 1024
policy-elements:
    - name: "Access control 1"
      from:
        name: ClientPG1
        type: policy-group
      to:
        name: default
        type: zone
      action: ALLOW
      network-parameters:
        protocol: 6
        destination-port-range:
           start-port: 80
           end-port: 80
    - name: "Access control 2"
      from:
        name: kube-system
        type: zone
      to:
        name: ServerPG
        type: policy-group
      action: ALLOW
      network-parameters:
        protocol: 6
        destination-port-range:
           start-port: 90
           end-port: 90
    - name: "Access control 3"
      from:
        name: ClientPG1
        type: policy-group
      to:
        name: ServerPG
        type: policy-group
      action: ALLOW
      network-parameters:
        protocol: 6
        destination-port-range:
           start-port: 100
           end-port: 100
`
const testPolicyUpdateRemoveACL = `
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "Multi level access control"
name: "Multi level access control"
priority: 1024
policy-elements:
    - name: "Access control 1"
      from:
        name: ClientPG1
        type: policy-group
      to:
        name: default
        type: zone
      action: ALLOW
      network-parameters:
        protocol: 6
        destination-port-range:
           start-port: 80
           end-port: 80
`

func TestPolicyUpdateRemove(t *testing.T) {
	InitSession()

	nuagePolicy, err := policies.LoadPolicyFromYAML(testPolicyUpdateRemoveBase)
	if err != nil {
		t.Fatalf("Unable to parse the policy yaml\n %s \n", testPolicyUpdateRemoveBase)
	}

	err = policyImplementer.ImplementPolicy(nuagePolicy)
	if err != nil {
		t.Fatalf("Unable to implement the nuage policy %+v %+v", nuagePolicy, err)
	}

	nuagePolicyDelta, err := policies.LoadPolicyFromYAML(testPolicyUpdateRemoveACL)
	if err != nil {
		t.Fatalf("Unable to parse the policy yaml\n %s \n", testPolicyUpdateRemoveACL)
	}

	err = policyImplementer.UpdatePolicy(nuagePolicyDelta, policies.UpdateRemove)
	if err != nil {
		if derr := policyImplementer.DeletePolicy(nuagePolicy.ID, Enterprise, Domain); derr != nil {
			fmt.Println("Unable to delete policy")
		}

		t.Fatalf("Unable to update the nuage policy err %+v", err)
	}

	err = policyImplementer.DeletePolicy(nuagePolicy.ID, Enterprise, Domain)
	if err != nil {
		t.Fatalf("Unable to delete the policy %+v", err)
	}
}

const testMultiPolicyElementsYaml = `
---
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "Multi level access control"
name: "Multi level access control"
priority: 1024
policy-elements:
    - name: "Access control 1"
      from:
        name: ClientPG1
        type: policy-group
      to:
        name: default
        type: zone
      action: ALLOW
      network-parameters:
        protocol: 6 
    - name: "Access control 2"
      from:
        name: kube-system
        type: zone
      to:
        name: ServerPG
        type: policy-group
      action: ALLOW
      network-parameters:
        protocol: 6 
    - name: "Access control 3"
      from:
        name: ClientPG1
        type: policy-group
      to:
        name: ServerPG
        type: policy-group
      action: ALLOW
      network-parameters:
        protocol: 6
        destination-port-range:
          start-port: 80
          end-port: 80
`

func TestYAMLPolicyAddRemove(t *testing.T) {
	InitSession()

	nuagePolicy, err := policies.LoadPolicyFromYAML(testMultiPolicyElementsYaml)
	if err != nil {
		t.Fatalf("Unable to parse the policy yaml\n %s \n", testMultiPolicyElementsYaml)
	}

	err = policyImplementer.ImplementPolicy(nuagePolicy)
	if err != nil {
		t.Fatalf("Unable to implement the nuage policy %+v", nuagePolicy)
	}

	err = policyImplementer.DeletePolicy(nuagePolicy.ID, Enterprise, Domain)
	if err != nil {
		t.Fatalf("Unable to delete the policy %+v", err)
	}
}

func TestZoneAnnotationUpdateAdd(t *testing.T) {
	InitSession()

	nuagePolicy := policies.NuagePolicy{
		Version:    policies.V1Alpha,
		Type:       policies.Default,
		Enterprise: Enterprise,
		Domain:     Domain,
		Name:       ZoneAnnotationTemplate,
	}

	defaultPolicyElement1 := policies.DefaultPolicyElement{
		Name:   fmt.Sprintf("Namespace annotation for %s", AnnoZone1),
		From:   policies.EndPoint{Name: AnnoZone1, Type: policies.Zone},
		To:     policies.EndPoint{Name: AnnoZone1, Type: policies.EndPointZone},
		Action: policies.Allow,
		NetworkParameters: policies.NetworkParameters{
			Protocol:             policies.TCP,
			DestinationPortRange: policies.PortRange{StartPort: 1, EndPort: 65535},
		},
	}

	nuagePolicy.PolicyElements = []policies.DefaultPolicyElement{defaultPolicyElement1}
	err := policyImplementer.UpdatePolicy(&nuagePolicy, policies.UpdateAdd)
	if err != nil {
		t.Fatalf("Unable to update policy %+v %+v", nuagePolicy, err)
	}

	defaultPolicyElement2 := policies.DefaultPolicyElement{
		Name:   fmt.Sprintf("Namespace annotation for %s", AnnoZone1),
		From:   policies.EndPoint{Name: AnnoZone2, Type: policies.Zone},
		To:     policies.EndPoint{Name: AnnoZone2, Type: policies.EndPointZone},
		Action: policies.Allow,
		NetworkParameters: policies.NetworkParameters{
			Protocol:             policies.TCP,
			DestinationPortRange: policies.PortRange{StartPort: 1, EndPort: 65535},
		},
	}

	nuagePolicy.PolicyElements = []policies.DefaultPolicyElement{defaultPolicyElement2}
	err = policyImplementer.UpdatePolicy(&nuagePolicy, policies.UpdateAdd)
	if err != nil {
		t.Fatalf("Unable to update policy %+v %+v", nuagePolicy, err)
	}

	nuagePolicy.PolicyElements = []policies.DefaultPolicyElement{defaultPolicyElement1}
	err = policyImplementer.UpdatePolicy(&nuagePolicy, policies.UpdateRemove)
	if err != nil {
		t.Fatalf("Unable to update (remove) policy %+v %+v", nuagePolicy, err)
	}

	nuagePolicy.PolicyElements = []policies.DefaultPolicyElement{defaultPolicyElement2}
	err = policyImplementer.UpdatePolicy(&nuagePolicy, policies.UpdateRemove)
	if err != nil {
		t.Fatalf("Unable to update (remove) policy %+v %+v", nuagePolicy, err)
	}
}
