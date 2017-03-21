package netpolicy

import "github.com/nuagenetworks/vspk-go/vspk"

// A network policy domain corresponds to a VSPK Domain
type PolicyDomain vspk.Domain

// What kind of network policies we support
type Kind string

const (
	NuageACLPolicy Kind = "NuageACLPolicy" // Only ACL-based network policies atm.
)

///// Policy Version
//  Supported version should coincide with the version of Nuage VSD API supported
type Version string

const (
	v4_0 Version = "v4_0"
)

var CurrentVersion = v4_0

//// Policy types
type PolicyType string

const (
	Ingress PolicyType = "Ingress"
	Egress  PolicyType = "Egress"
)

// Mapping to VSD names
var VSDPolicyTypes = map[PolicyType]string{
	"Ingress": "INGRESS",
	"Egress":  "EGRESS",
}

//// Policy element Actions
type Action string

const (
	Allow Action = "Allow"
	Deny  Action = "Deny"
)

// Mapping to VSD names
var VSDActions = map[Action]string{
	Allow: "FORWARD",
	Deny:  "DROP",
}

// The reverse mappings
var Actions = map[string]Action{
	"FORWARD": Allow,
	"DROP":    Deny,
}

////  Network protocols
type Protocol string

const (
	ProtoAny Protocol = "Any"
	TCP      Protocol = "TCP"
	UDP      Protocol = "UDP"
)

// Mapping to VSD names
var VSDProtocols = map[Protocol]string{
	ProtoAny: "ANY",
	TCP:      "6",
	UDP:      "17",
}

// The reverse mapping
var Protocols = map[string]Protocol{
	"ANY": ProtoAny,
	"6":   TCP,
	"17":  UDP,
}

//// Traffic specification

type TrafficSpec struct {
	Protocol     Protocol `yaml:"protocol"`
	SrcPortRange *string  `yaml:"source-port-range"` // nil pointer (valid for Protocol "Any" only). For TCP/UDP: "80" or "0-65535" or "*" (all ports for that protocol)
	DstPortRange *string  `yaml:"destination-port-range"`
}

//// Allowed types of policy scopes for "Location" (L)  (as per VSPK terminology)
//// Those are valid as traffic source scopes (for Ingress Policy / Ingress PolicyElement), respectively as traffic destination scopes for Egress counterparts
type LScope string

const (
	LAny         LScope = "Any"
	LSubnet      LScope = "Subnet"
	LZone        LScope = "Zone"
	LPolicyGroup LScope = "PolicyGroup"
	LVPortTag    LScope = "VPortTag"
)

// Mapping to VSD names
var VSDLScopes = map[LScope]string{
	LAny:         "ANY",
	LSubnet:      "SUBNET",
	LZone:        "ZONE",
	LPolicyGroup: "POLICYGROUP",
	LVPortTag:    "VPPORTTAG",
}

// Reverse mapping
var LScopes = map[string]LScope{
	"ANY":         LAny,
	"SUBNET":      LSubnet,
	"ZONE":        LZone,
	"POLICYGROUP": LPolicyGroup,
	"VPPORTTAG":   LVPortTag,
}

//// Allowed types of policy scopes for "Network" (N) (as per VSPK terminology)
//// Those are valid as traffic destination scopes (for Ingress Policy / Ingress PolicyElement), respectively as traffic source scopes for Egress counterparts
type NScope string

const (
	NAny         NScope = "Any"
	NSubnet      NScope = "Subnet"
	NZone        NScope = "Zone"
	NPolicyGroup NScope = "PolicyGroup"

	MyDomain NScope = "MyDomain"
	MyZone   NScope = "MyZone"
	MySubnet NScope = "MySubnet"

	NetworkMacroGroup NScope = "NetworkMacroGroup" // Only available for "N" scopes
	NetworkMacro      NScope = "NetworkMacro"      // Only available for "N" scopes

)

// Mapping to VSD names
var VSDNScopes = map[NScope]string{
	NAny:              "ANY",
	NSubnet:           "SUBNET",
	NZone:             "ZONE",
	NPolicyGroup:      "POLICYGROUP",
	MyDomain:          "ENDPOINT_DOMAIN",
	MyZone:            "ENDPOINT_ZONE",
	MySubnet:          "ENDPOINT_SUBNET",
	NetworkMacroGroup: "NETWORK_MACRO_GROUP",
	NetworkMacro:      "ENTERPRISE_NETWORK",
}

// Reverse mappings
var NScopes = map[string]NScope{
	"ANY":                 NAny,
	"SUBNET":              NSubnet,
	"ZONE":                NZone,
	"POLICYGROUP":         NPolicyGroup,
	"ENDPOINT_DOMAIN":     MyDomain,
	"ENDPOINT_ZONE":       MyZone,
	"ENDPOINT_SUBNET":     MySubnet,
	"NETWORK_MACRO_GROUP": NetworkMacroGroup,
	"ENTERPRISE_NETWORK":  NetworkMacro,
}

// The scope for the traffic sources to which a policy element applies to
type PolicySrcScope struct {
	Type string  `yaml:"source-type"`    // The type of this policy scope. Needs to be validated against "LScope" (for Ingress) resp. "NScope" (for Egress)
	Name *string `yaml:"name,omitempty"` // Name of the traffic source policy scope. May be "nil" (for: LAny / "Any")
}

// The scope for the traffic destinations to which a policy element applies to
type PolicyDstScope struct {
	Type string  `yaml:"destination-type"` // The type of this policy scope. Needs to be validated against "NScope" (for Ingress) resp. "LScope" (for Ingress)
	Name *string `yaml:"name,omitempty"`   // Name of the traffic destination policy scope. May be "nil" (for: NAny / MyDomain / MyZone / MySubnet)
}

////////
//////// Network Policies
////////

//// It maps to a VSD "IngressACLTemplate" or "EgressACLTemplate", depending on "Type"
type Policy struct {
	// Populated by the VSD (i.e. only after a connection to the VSD is established)
	ID     string        `yaml:"-"` // Mapped from: "ID" when/if a Policy is applied to a Policy Domain (vspk.Domain) and/or updated
	Parent *PolicyDomain `yaml:"-"` // Maps to corresponding "vspk.Domain"
	// Externally visible
	Kind    Kind       `yaml:"kind"`        // Not mapped. Fixed string. Currently only "NuageNetworkPolicy"
	Version Version    `yaml:"version"`     // Not mapped. Fixed string. Currently only "v4_0".
	Name    string     `yaml:"name"`        // Maps to: "name"
	Type    PolicyType `yaml:"policy-type"` // Not mapped. Currently only "Ingress" or "Egress".

	Enterprise string `yaml:"enterprise"` // The context in which the policy applies. Must match (parent)->(parent)->"name". Maps to: (PolicyElement) -> Enterprise
	Domain     string `yaml:"domain"`     // The context in which the policy applies. Must match (parent) -> "name". Maps to: (PolicyElement) -> Domain

	Priority int `yaml:"priority"` // Of this policy. Values 1 - 1,000,000,000. Maps to: "priority"

	PolicyElements []PolicyElement `yaml:"policy-elements"` // A valid policy needs to have at least one valid entry (Policy Element)
}

//// A "PolicyElement" is an entry in a policy specification. Defines a scope for which traffic sources -- respectively traffic destinations -- this policy entry applies to
//// It maps to a VSD "IngressACLEntryTemplate" or "EngressACLEntryTemplate" (depending on parent policy "Type")
type PolicyElement struct {
	// Parent Populated
	Parent     *Policy `yaml:"-"` // Valid only when added to a Policy
	Enterprise string  `yaml:"-"` // Mapped by parent to: "enterpriseName"
	Domain     string  `yaml:"-"` // Mapped by parent to: "domainName"
	// Populated by the VSD (i.e. only after a connection to the VSD is established)
	ID       string `yaml:"-"` // Mapped from: "ID" when the PE is applied
	SourceID string `yaml:"-"` // Mapped from: "locationID" (for Ingress) resp. "networkID" (for Egress)
	TargetID string `yaml:"-"` // Mapped from: "networkID" (for Ingress) resp. "locationID" (for Egress)
	// Externally visible
	Name        string         `yaml:"name"`         // Maps to: ACL Entry "description". Required field.
	Priority    int            `yaml:"priority"`     // Of this particular element within the policy. Values:  1 - 1,000,000,000. Maps to: "priority"
	From        PolicySrcScope `yaml:"from"`         // (PolicySrcScope)->Type maps to "locationType" (for Ingress) resp .."networkType" (for Egress)
	To          PolicyDstScope `yaml:"to"`           // (PolicyDstScope)->Type maps to "networkType" (for Ingress) resp .."locationType" (for Egress)
	TrafficSpec TrafficSpec    `yaml:"traffic-spec"` // Matching traffic. Maps to: "protocol" +  "sourcePort" +  "destinationPort"
	Action      Action         `yaml:"action"`       // Maps to: "action"

}

////////
//////// Some useful defaults
////////

var (
	MatchAllTraffic = TrafficSpec{ProtoAny, nil, nil}

	// Ingress
	AllSrcsIngress = PolicySrcScope{string(LAny), nil}
	AllDstsIngress = PolicyDstScope{string(NAny), nil}

	AllowAllIngressPE = PolicyElement{
		Name:        "Allow all traffic -- Any to Any",
		Priority:    999999999,
		From:        AllSrcsIngress,
		To:          AllDstsIngress,
		TrafficSpec: MatchAllTraffic,
		Action:      Allow,
	}

	DenyAllIngressPE = PolicyElement{
		Name:        "Drop all traffic -- Any to Any",
		Priority:    1000000000,
		From:        AllSrcsIngress,
		To:          AllDstsIngress,
		TrafficSpec: MatchAllTraffic,
		Action:      Deny,
	}

	// Egress
	AllSrcsEgress = PolicySrcScope{string(NAny), nil}
	AllDstsEgress = PolicyDstScope{string(LAny), nil}

	AllowAllEgressPE = PolicyElement{
		Name:        "Allow all traffic -- Any to Any",
		Priority:    999999999,
		From:        AllSrcsEgress,
		To:          AllDstsEgress,
		TrafficSpec: MatchAllTraffic,
		Action:      Allow,
	}

	DenyAllEgressPE = PolicyElement{
		Name:        "Drop all traffic -- Any to Any",
		Priority:    1000000000,
		From:        AllSrcsEgress,
		To:          AllDstsEgress,
		TrafficSpec: MatchAllTraffic,
		Action:      Deny,
	}
)
