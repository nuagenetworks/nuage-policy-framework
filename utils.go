package netpolicy

import (
	"fmt"
	"strings"
	// log "github.com/Sirupsen/logrus"

	"github.com/nuagenetworks/go-bambou/bambou"
)

////////
//////// Private methods and functions
////////

// Sanity check a policy content + internal mappings
func scrubPolicy(p *Policy) error {
	if p.Name == "" {
		return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "No Name given")
	}

	if p.Kind != NuageACLPolicy {
		return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "Invalid Policy Kind: "+string(p.Kind))
	}

	if p.Version != CurrentVersion {
		return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "Invalid Policy Version: "+string(p.Version))
	}

	if _, okptype := VSDPolicyTypes[p.Type]; !okptype {
		return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "Invalid Policy Type: "+string(p.Type))
	}
	if p.Enterprise == "" {
		return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "No Enterprise Name")
	}

	if p.Domain == "" {
		return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "No Domain name")
	}

	if p.Priority < 1 || p.Priority > 1000000000 {
		return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "Priority must be in the range 1 - 1,000,000,000")
	}
	// If the Policy has some PolicyElements given, make sure they are added correctly

	var spes []PolicyElement // New slice to hold PEs after scrubbing. XXX -- Still TBD why not they can be scrubbed in place (YAML Unmarshall ?)

	peprios := make(map[int]int) // Populate it with the priorities of PEs already added to this Policy

	for _, pe := range p.PolicyElements {
		pe.Parent = p
		pe.Enterprise = p.Enterprise
		pe.Domain = p.Domain
		if err := scrubPE(&pe); err != nil {
			return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, err.Error())
		}

		if _, exists := peprios[pe.Priority]; exists { // Check for PE Priority duplicates
			return bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "Found two Policy Elemens with Priority: "+string(pe.Priority))
		}

		peprios[pe.Priority] = pe.Priority
		// Add this PE to the list of PEs associated with this Policy
		spes = append(spes, pe)
	}

	p.PolicyElements = spes // Replace the old set of PEs with the scrubbed ones
	return nil
}

// Sanity checking for a Policy Element
func scrubPE(pe *PolicyElement) error {

	if pe == nil {
		return bambou.NewBambouError(ErrorPEInvalid, "Cannot scrub empty PolicyElement")
	}
	if pe.Name == "" {
		// In case we actually allow PEs to be unnamed, we just log a warning
		// log.Warningf("Unnamed Policy Element detected - PEs should have a valid 'name'")
		// For now we actually require policy elements to have a name
		return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "No Name given")
	}

	// This cannot happen -- A PolicyElement _must_ be attached to a Policy
	if pe.Parent == nil {
		return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "Policy Element is not attached to Policy")
	}

	// These should not happen since they are mapped by the parent. Still.
	if pe.Enterprise == "" || pe.Domain == "" {
		return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "Policy Element lacks a valid Enterprise/Domain name")
	}

	if pe.Priority < 1 || pe.Priority > 1000000000 {
		return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "Priority must be in the range 1 - 1,000,000,000")
	}

	// Valid values for "From" / "To" depend on the parent Policy "Type" ("Ingress" or "Egress")

	switch pe.Parent.Type {
	case Ingress:
		////////
		//////// Valid PE From / To Scopes for PolicySrcScope.Type: LScope (for "From") respectively NScope (for "To")
		////////

		//// Scrub: From
		if _, okfrom := VSDLScopes[LScope(pe.From.Type)]; !okfrom {
			return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field: Invalid source type: "+pe.From.Type)
		}

		// Empty "name" allowed only for 'LAny'
		if pe.From.Name == nil {
			if LScope(pe.From.Type) != LAny {
				return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field: No 'name' given and 'type' is not: "+pe.From.Type)
			}
		} else {
			// Conversely, for "LAny" we cannot have a non-nil Name
			if LScope(pe.From.Type) == LAny {
				return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field: For 'type': "+pe.From.Type+" a name cannot be given")
			}
		}

		//// Scrub: To
		if _, okto := VSDNScopes[NScope(pe.To.Type)]; !okto {
			return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field: Invalid destination type: "+pe.To.Type)
		}
		// Empty "name" allowed only for a few types of Policy detination scopes
		if pe.To.Name == nil {
			switch NScope(pe.To.Type) {
			case NAny, MyDomain, MyZone, MySubnet:
			default:
				return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field: No 'name' given for destination type: "+pe.To.Type)
			}
		} else {
			// Conversely, for those types, name _must_ be empty
			switch NScope(pe.To.Type) {
			case NAny, MyDomain, MyZone, MySubnet:
				return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field: For 'type': "+pe.To.Type+" a name cannot be given")
			}
		}

	case Egress:
		//////// Valid PE To / From Scopes for PolicySrcScope.Type: NScope (for "From") respectively LScope (for "To")
		////////
		////////

		//// Scrub: From
		if _, okfrom := VSDNScopes[NScope(pe.From.Type)]; !okfrom {
			return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field: Invalid source type: "+pe.From.Type)
		}
		// Empty "name" allowed only for a few types of Policy destination scopes
		if pe.From.Name == nil {
			switch NScope(pe.From.Type) {
			case NAny, MyDomain, MyZone, MySubnet:
			default:
				return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field: No 'name' given for source type: "+pe.From.Type)
			}
		} else {
			// Conversely, for those types, name _must_ be empty
			switch NScope(pe.From.Type) {
			case NAny, MyDomain, MyZone, MySubnet:
				return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field: For 'type': "+pe.From.Type+" a name cannot be given")
			}
		}

		//// Scrub: To
		if _, okto := VSDLScopes[LScope(pe.To.Type)]; !okto {
			return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field: Invalid destination type: "+pe.To.Type)
		}

		// Empty "name" allowed only for 'LAny'
		if pe.To.Name == nil {
			if LScope(pe.To.Type) != LAny {
				return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field: No 'name' given and 'type' is not: "+pe.To.Type)
			}
		} else {
			// Conversely, for "LAny" we cannot have a non-nil Name
			if LScope(pe.To.Type) == LAny {
				return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field: For 'type': "+pe.To.Type+" a name cannot be given")
			}
		}
	}

	//// Scrub: Traffic spec
	if _, okproto := VSDProtocols[pe.TrafficSpec.Protocol]; !okproto {
		return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'traffic-spec' field: Invalid network protocol: "+string(pe.TrafficSpec.Protocol))
	}
	if pe.TrafficSpec.Protocol == ProtoAny { // For protocol "Any" , no port ranges should be defined
		if pe.TrafficSpec.SrcPortRange != nil || pe.TrafficSpec.DstPortRange != nil {
			return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'traffic-spec' field: For protocol: "+string(ProtoAny)+" no port ranges should be defined ")
		}
	} else { // TCP or UDP
		var err error
		if pe.TrafficSpec.SrcPortRange, err = scrubPortRange(pe.TrafficSpec.SrcPortRange); err != nil {
			return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "Invalid source port range: "+*pe.TrafficSpec.SrcPortRange+" Error: "+err.Error())
		}
		if pe.TrafficSpec.DstPortRange, err = scrubPortRange(pe.TrafficSpec.DstPortRange); err != nil {
			return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "Invalid destination port range: "+*pe.TrafficSpec.DstPortRange+" Error: "+err.Error())
		}
	}

	//// Scrub: Action
	if _, okaction := VSDActions[pe.Action]; !okaction {
		return bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'action' field: Invalid action: "+string(pe.Action))
	}

	return nil
}

// Scrub port ranges for named protocols (i.e. not "Any"). Allowed formats: nil (replaced with "*"); [ <port> | <start port range>-<end port range>]
// Still TBD: Allow comma separated sets of port specifications: [ <port> | <start port range>-<end port range>], [ <port> | <start port range>-<end port range>]...
func scrubPortRange(prange *string) (*string, error) {
	if prange == nil {
		prange = new(string)
		*prange = "*"
		return prange, nil
	}

	if *prange == "*" {
		return prange, nil
	}

	// Scrub port specification: [ <port#> | <lowport#> - <highport#> ]
	ports := strings.Split(*prange, "-")

	var lowport, highport int
	switch len(ports) {
	case 2:
		if _, err := fmt.Sscanf(ports[0], "%d", &lowport); err != nil {
			return prange, err
		}
		// if lowport < 0 || lowport > 65535 {
		//     return prange, fmt.Errorf("Invalid low port number %d in port range: '%s'", lowport, *prange)
		// }
		if _, err := fmt.Sscanf(ports[1], "%d", &highport); err != nil {
			return prange, err
		}
		//if highport < 0 || highport > 65535 {
		//     return prange, fmt.Errorf("Invalid high port number %d in port range: '%s'", highport, *prange)
		// }
		if lowport > highport {
			return prange, fmt.Errorf("Invalid low/high port numbers in port range: '%s'", *prange)
		}
		*prange = fmt.Sprintf("%d-%d", lowport, highport)
	case 1:
		if _, err := fmt.Sscanf(ports[0], "%d", &lowport); err != nil {
			return prange, err
		}
		*prange = fmt.Sprintf("%d", lowport)
	default:
		return prange, fmt.Errorf("Cannot process port range: '%s'", *prange)
	}
	return prange, nil
}
