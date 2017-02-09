package policies

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"testing"
)

const (
	ClientPg = "ClientPG"
	ServerPg = "ServerPG"
)

func init() {
	fmt.Println("Initing test bundle")
}

func TestDefaultPolicyMarshalling(t *testing.T) {
	nuagePolicy := NuagePolicy{
		Version:    V1Alpha,
		Type:       Default,
		Enterprise: "nuage",
		Domain:     "openshift",
		Name:       "k8s allow traffic",
		ID:         "k8s allow traffic",
		Priority:   10000,
	}

	defaultPolicyElement := DefaultPolicyElement{
		Name:   "Access Control",
		From:   EndPoint{Name: ClientPg, Type: PolicyGroup},
		To:     EndPoint{Name: ServerPg, Type: PolicyGroup},
		Action: Allow,
		NetworkParameters: NetworkParameters{
			Protocol:             TCP,
			DestinationPortRange: PortRange{100, 200},
		},
	}

	nuagePolicy.PolicyElements = []DefaultPolicyElement{defaultPolicyElement}
	d, err := yaml.Marshal(&nuagePolicy)
	if err != nil {
		t.Fatalf("Error while marshalling %+v", err)
	}
	t.Logf("Marshalled YAML %s", string(d))
}

const testPG2PGYaml = `
--- 
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "k8s allow web traffic"
name: "k8s allow web traffic"
priority: 10
policy-elements: 
    - name: "Access control"
      from: 
        name: busybox
        type: policy-group
      to: 
        name: nginx
        type: policy-group
      action: ALLOW
      network-parameters:
        protocol: 6
        destination-port-range: 
          start-port: 80
          end-port: 80
        source-port-range:
          start-port: 0
          end-port: 65535
          
`

const testPG2SubetYaml = `
--- 
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "k8s allow web traffic"
name: "k8s allow web traffic"
priority: 100
policy-elements: 
    - name: "Access control"
      from: 
        name: busybox
        type: policy-group
      to: 
        name: nginx
        type: subnet 
      action: DENY 
      network-parameters:
        protocol: 6
        destination-port-range: 
          start-port: 80
          end-port: 80
`
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
    - name: "Block intra zone traffic"
      from: 
        name: default 
        type: zone 
      to: 
        name: default 
        type: endpoint_zone 
      action: DENY 
      network-parameters:
        protocol: 6
        destination-port-range:
          start-port: 0
          end-port: 65535 
`
const testZone2SubetYaml = `
--- 
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "k8s allow web traffic"
name: "k8s allow web traffic"
priority: 300
policy-elements: 
    - name: "Access control"
      from: 
        name: busybox
        type: zone 
      to: 
        name: nginx
        type: subnet 
      action: ALLOW 
`

const testMultiPolicyElementsYaml = `
--- 
version: v1-alpha
type: default
enterprise: nuage
domain: openshift
id: "k8s allow web traffic"
name: "k8s allow web traffic"
priority: 500
policy-elements: 
    - name: "Access control 1"
      from: 
        name: busybox
        type: policy-group 
      to: 
        name: nginx
        type: zone 
      action: ALLOW 
    - name: "Access control 2"
      from: 
        name: busybox
        type: zone 
      to: 
        name: nginx
        type: policy-group 
      action: DENY
    - name: "Access control 3"
      from: 
        name: busybox
        type: policy-group
      to: 
        name: nginx
        type: policy-group
      action: ALLOW
      network-parameters:
        protocol: 6
        destination-port-range: 
          start-port: 80
          end-port: 80
`

func TestYamlUnmarshalling(t *testing.T) {
	yamlPolicies := []string{testPG2SubetYaml, testPG2PGYaml,
		testZone2SubetYaml, testMultiPolicyElementsYaml, testZone2ZoneEndpointYaml}

	for _, yamlPolicy := range yamlPolicies {
		nuagePolicy, err := LoadPolicyFromYAML(yamlPolicy)
		if err != nil {
			t.Fatalf("Unable to unmarshal policy %s , err %+v", yamlPolicy, err)
		}
		t.Logf("Successfully unmarshalled policy %+v", nuagePolicy)
	}
}
