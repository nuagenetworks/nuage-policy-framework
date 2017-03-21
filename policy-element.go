package netpolicy

import (
	"github.com/golang/glog"
	"github.com/nuagenetworks/vspk-go/vspk"

	"github.com/nuagenetworks/go-bambou/bambou"

	yaml "gopkg.in/yaml.v2"
)

// YAML PrettyPrint
func (pe PolicyElement) String() string {
	peyaml, _ := yaml.Marshal(pe)
	return string(peyaml)
}

////////
//////// Ingress parent Policy
////////

// Mutates the receiver
// XXX - Notes:
// - Does _not_ populate "Parent" Policy. This needs to be done by the caller (e.g. in a context of a "Policy")
// - Does not insure / check that Parent Policy Type is "Ingress"
// - Minimal checks to insure the argument is a valid (active, live) IngressACLEntryTemplate
func (pe *PolicyElement) MapFromIngressACLEntry(iaclentry *vspk.IngressACLEntryTemplate) {
	if iaclentry == nil || iaclentry.ID == "" || iaclentry.PolicyState != "LIVE" {
		return
	}

	pe.ID = iaclentry.ID
	pe.Enterprise = iaclentry.EnterpriseName
	pe.Domain = iaclentry.DomainName
	pe.SourceID = iaclentry.LocationID
	pe.TargetID = iaclentry.NetworkID
	pe.Name = iaclentry.Description
	pe.Priority = iaclentry.Priority
	// From
	pe.From.Type = string(LScopes[iaclentry.LocationType])
	switch LScope(pe.From.Type) {
	case LAny: // pe.From.Name left nil
	case LSubnet:
		// Find subnet name
		pe.From.Name = new(string)
		subnet := new(vspk.Subnet)
		subnet.ID = iaclentry.LocationID
		subnet.Fetch()
		*pe.From.Name = subnet.Name
	case LZone:
		// Find subnet name
		pe.From.Name = new(string)
		zone := new(vspk.Zone)
		zone.ID = iaclentry.LocationID
		zone.Fetch()
		*pe.From.Name = zone.Name
	case LPolicyGroup:
		// Find VSD Policy Group Name
		pe.From.Name = new(string)
		vsdpg := new(vspk.PolicyGroup)
		vsdpg.ID = iaclentry.LocationID
		vsdpg.Fetch()
		*pe.From.Name = vsdpg.Name
	case LVPortTag:
		// Not implemented. Raise exception.
		glog.Fatalf("Implementing Ingress ACL LocationType %#s is not yet supported", iaclentry.LocationType)
	default:
		glog.Fatalf("Don't know how to map Ingress ACL LocationType %#s into a Policy Source Type", iaclentry.LocationType)
	}
	// To
	pe.To.Type = string(NScopes[iaclentry.NetworkType])
	switch NScope(pe.To.Type) {
	case NAny: // pe.To.Name left nil
	case NSubnet:
		// Find subnet name
		pe.To.Name = new(string)
		subnet := new(vspk.Subnet)
		subnet.ID = iaclentry.NetworkID
		subnet.Fetch()
		*pe.To.Name = subnet.Name
	case NZone:
		// Find subnet name
		pe.To.Name = new(string)
		zone := new(vspk.Zone)
		zone.ID = iaclentry.NetworkID
		zone.Fetch()
		*pe.To.Name = zone.Name
	case NPolicyGroup:
		// Find VSD Policy Group Name
		pe.To.Name = new(string)
		vsdpg := new(vspk.PolicyGroup)
		vsdpg.ID = iaclentry.NetworkID
		vsdpg.Fetch()
		*pe.To.Name = vsdpg.Name
	case MyDomain, MyZone, MySubnet: // Leave pe.To.Name nil
	case NetworkMacroGroup:
		// Find VSD Network Macro Group Name
		pe.To.Name = new(string)
		vsdnmg := new(vspk.NetworkMacroGroup)
		vsdnmg.ID = iaclentry.NetworkID
		vsdnmg.Fetch()
		*pe.To.Name = vsdnmg.Name
	case NetworkMacro:
		// Find VSD Enterprise Network (aka "Network Macro") Name
		pe.To.Name = new(string)
		vsden := new(vspk.EnterpriseNetwork)
		vsden.ID = iaclentry.NetworkID
		vsden.Fetch()
		*pe.To.Name = vsden.Name
	default:
		glog.Fatalf("Don't know how to map Ingress ACL NetworkType %#s into a Policy Source Type", iaclentry.NetworkType)

	}

	// Traffic spec
	pe.TrafficSpec.Protocol = Protocols[iaclentry.Protocol]
	switch pe.TrafficSpec.Protocol {
	case ProtoAny: // We don't allow port ranges to be defined. Leave the ranges as nil
	case TCP, UDP:
		// Default is "*" (all ports)
		pe.TrafficSpec.SrcPortRange = new(string)
		*pe.TrafficSpec.SrcPortRange = "*"
		pe.TrafficSpec.DstPortRange = new(string)
		*pe.TrafficSpec.DstPortRange = "*"
		// Specific ports / port ranges are given, override this default
		if iaclentry.SourcePort != "" {
			*pe.TrafficSpec.SrcPortRange = iaclentry.SourcePort
		}
		if iaclentry.DestinationPort != "" {
			*pe.TrafficSpec.DstPortRange = iaclentry.DestinationPort
		}

	default:
		glog.Fatalf("Don't know how to map Ingress ACL Protocol %#s ", iaclentry.Protocol)
	}

	// Action
	pe.Action = Actions[iaclentry.Action]
}

// XXX - This also validates if the PE points to valid VSD constructs
func (pe *PolicyElement) MapToIngressACLEntry() (*vspk.IngressACLEntryTemplate, error) {
	iaclentry := new(vspk.IngressACLEntryTemplate)

	if err := scrubPE(pe); err != nil {
		return iaclentry, err
	}
	// The PE must point to a Policy that is 1) already applied or 2) is being applied togehter with this PE as part of a batch. In both cases the parent Policy must be associated with a parent Policy Domain
	if pe.Parent.Parent == nil {
		return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "Parent Policy not associated with a Policy Domain")
	}
	// XXX - Cast parent Policy' parent PolicyDomain back to VSD domain. No fresh fetch / check is done (efficiency)
	vsdd := vspk.Domain(*pe.Parent.Parent)

	// Build the IngressACLEntryTemplate

	// Hardcoded fields
	iaclentry.DSCP = "*"

	iaclentry.EtherType = "0x0800"

	// XXX - Notes
	// - This works for TCP/UDP/Any. Also, when "Stateful" is true, the ACLEntry has to be "Reflexive" as well. In effect, this takes care of reverse traffic direction as well
	// - This only works for "Allow" rules
	if pe.Action == Allow {
		iaclentry.Stateful = true
		iaclentry.Reflexive = true
	}

	iaclentry.ACLTemplateName = pe.Parent.Name // XXX Valid only for Applied Policies / Valid IngressACLTemplates
	iaclentry.EnterpriseName = pe.Enterprise
	iaclentry.DomainName = pe.Domain
	iaclentry.Description = pe.Name
	iaclentry.Priority = pe.Priority
	// From
	iaclentry.LocationType = VSDLScopes[LScope(pe.From.Type)]

	switch LScope(pe.From.Type) {
	case LAny: // iaclentry.LocationID left to empty string
	case LSubnet: // Find subnet by name & get its ID
		sl, _ := vsdd.Subnets(&bambou.FetchingInfo{Filter: "name == \"" + *pe.From.Name + "\""})
		if len(sl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field, cannot find Subnet with name: "+*pe.From.Name)
		}
		iaclentry.LocationID = sl[0].ID

	case LZone: // Find Zone by name & get its ID
		zl, _ := vsdd.Zones(&bambou.FetchingInfo{Filter: "name == \"" + *pe.From.Name + "\""})
		if len(zl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field, cannot find Zone with name: "+*pe.From.Name)
		}
		iaclentry.LocationID = zl[0].ID
	case LPolicyGroup: // Find VSD Policy Group by Name and get its ID
		pgl, _ := vsdd.PolicyGroups(&bambou.FetchingInfo{Filter: "name == \"" + *pe.From.Name + "\""})
		if len(pgl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field, cannot find PolicyGroup with name: "+*pe.From.Name)
		}
		iaclentry.LocationID = pgl[0].ID
	case LVPortTag:
		// Not implemented yet. Raise exception.
		glog.Fatalf("Implementing Ingress ACL Entry LocationType %#s is not yet supported", pe.From.Type)
	}
	// To
	iaclentry.NetworkType = VSDNScopes[NScope(pe.To.Type)]
	switch NScope(pe.To.Type) {
	case NAny: // iaclentry.NetworkID left to empty string
	case NSubnet:
		sl, _ := vsdd.Subnets(&bambou.FetchingInfo{Filter: "name == \"" + *pe.To.Name + "\""})
		if len(sl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field, cannot find Subnet with name: "+*pe.To.Name)
		}
		iaclentry.NetworkID = sl[0].ID
	case NZone:
		zl, _ := vsdd.Zones(&bambou.FetchingInfo{Filter: "name == \"" + *pe.To.Name + "\""})
		if len(zl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field, cannot find Zone with name: "+*pe.To.Name)
		}
		iaclentry.NetworkID = zl[0].ID
	case NPolicyGroup:
		pgl, _ := vsdd.PolicyGroups(&bambou.FetchingInfo{Filter: "name == \"" + *pe.To.Name + "\""})
		if len(pgl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field, cannot find PolicyGroup with name: "+*pe.To.Name)
		}
		iaclentry.NetworkID = pgl[0].ID
	case MyDomain, MyZone, MySubnet: // iaclentry.NetworkID left to empty string
	case NetworkMacroGroup:
		// XXX - We can only list Network Macro Group for Enterprise.
		vsdorg := new(vspk.Enterprise)
		vsdorg.ID = vsdd.ParentID
		vsdorg.Fetch()
		nmgl, _ := vsdorg.NetworkMacroGroups(&bambou.FetchingInfo{Filter: "name == \"" + *pe.To.Name + "\""})
		if len(nmgl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field, cannot find NetworkMacroGroup with name: "+*pe.To.Name)
		}
		iaclentry.NetworkID = nmgl[0].ID
	case NetworkMacro:
		// XXX - We can only list Enterprise Networks (Network Macros) for an Enterprise.
		vsdorg := new(vspk.Enterprise)
		vsdorg.ID = vsdd.ParentID
		vsdorg.Fetch()
		nml, _ := vsdorg.EnterpriseNetworks(&bambou.FetchingInfo{Filter: "name == \"" + *pe.To.Name + "\""})
		if len(nml) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field, cannot find NetworkMacro with name: "+*pe.To.Name)
		}
		iaclentry.NetworkID = nml[0].ID
	}

	// Traffic spec
	iaclentry.Protocol = VSDProtocols[pe.TrafficSpec.Protocol]
	switch pe.TrafficSpec.Protocol {
	case ProtoAny: // Leave SourcePort / DestinationPort empty strings
	case TCP, UDP:
		iaclentry.SourcePort = *pe.TrafficSpec.SrcPortRange
		iaclentry.DestinationPort = *pe.TrafficSpec.DstPortRange
	}

	// Action
	iaclentry.Action = VSDActions[pe.Action]
	return iaclentry, nil
}

////////
//////// Egress parent Policy
////////

// Mutates the receiver
// XXX - Notes:
// - Does _not_ populate "Parent" Policy. This needs to be done by the caller (e.g. in a context of a "Policy")
// - Does not insure / check that Parent Policy Type is "Egress"
// - Minimal checks to insure the argument is a valid (active, live) EgressACLEntryTemplate
func (pe *PolicyElement) MapFromEgressACLEntry(eaclentry *vspk.EgressACLEntryTemplate) {
	if eaclentry == nil || eaclentry.ID == "" || eaclentry.PolicyState != "LIVE" {
		return
	}

	pe.ID = eaclentry.ID
	pe.Enterprise = eaclentry.EnterpriseName
	pe.Domain = eaclentry.DomainName

	pe.SourceID = eaclentry.NetworkID
	pe.TargetID = eaclentry.LocationID

	pe.Name = eaclentry.Description
	pe.Priority = eaclentry.Priority

	// From
	pe.From.Type = string(NScopes[eaclentry.NetworkType])
	switch NScope(pe.From.Type) {
	case NAny: // pe.From.Name left nil
	case NSubnet:
		// Find subnet name
		pe.From.Name = new(string)
		subnet := new(vspk.Subnet)
		subnet.ID = eaclentry.NetworkID
		subnet.Fetch()
		*pe.From.Name = subnet.Name
	case NZone:
		// Find zone name
		pe.From.Name = new(string)
		zone := new(vspk.Zone)
		zone.ID = eaclentry.NetworkID
		zone.Fetch()
		*pe.From.Name = zone.Name
	case NPolicyGroup:
		// Find VSD Policy Group Name
		pe.From.Name = new(string)
		vsdpg := new(vspk.PolicyGroup)
		vsdpg.ID = eaclentry.NetworkID
		vsdpg.Fetch()
		*pe.From.Name = vsdpg.Name
	case MyDomain, MyZone, MySubnet: // Leave pe.From.Name nil
	case NetworkMacroGroup:
		// Find VSD Network Macro Group Name
		pe.From.Name = new(string)
		vsdnmg := new(vspk.NetworkMacroGroup)
		vsdnmg.ID = eaclentry.NetworkID
		vsdnmg.Fetch()
		*pe.From.Name = vsdnmg.Name
	case NetworkMacro:
		// Find VSD Enterprise Network (aka "Network Macro") Name
		pe.From.Name = new(string)
		vsden := new(vspk.EnterpriseNetwork)
		vsden.ID = eaclentry.NetworkID
		vsden.Fetch()
		*pe.From.Name = vsden.Name
	default:
		glog.Fatalf("Don't know how to map Egress ACL NetworkType %#s into a Policy Source Type", eaclentry.NetworkType)

	}

	// To
	pe.To.Type = string(LScopes[eaclentry.LocationType])
	switch LScope(pe.To.Type) {
	case LAny: // pe.To.Name left nil
	case LSubnet:
		// Find subnet name
		pe.To.Name = new(string)
		subnet := new(vspk.Subnet)
		subnet.ID = eaclentry.LocationID
		subnet.Fetch()
		*pe.To.Name = subnet.Name
	case LZone:
		// Find zone name
		pe.To.Name = new(string)
		zone := new(vspk.Zone)
		zone.ID = eaclentry.LocationID
		zone.Fetch()
		*pe.To.Name = zone.Name
	case LPolicyGroup:
		// Find VSD Policy Group Name
		pe.To.Name = new(string)
		vsdpg := new(vspk.PolicyGroup)
		vsdpg.ID = eaclentry.LocationID
		vsdpg.Fetch()
		*pe.To.Name = vsdpg.Name
	case LVPortTag:
		// Not implemented. Raise exception.
		glog.Fatalf("Implementing Egress ACL LocationType %#s is not yet supported", eaclentry.LocationType)
	default:
		glog.Fatalf("Don't know how to map Egress ACL LocationType %#s into a Policy Destination Type", eaclentry.LocationType)
	}

	// Traffic spec
	pe.TrafficSpec.Protocol = Protocols[eaclentry.Protocol]
	switch pe.TrafficSpec.Protocol {
	case ProtoAny: // We don't allow port ranges to be defined. Leave the ranges as nil
	case TCP, UDP:
		// Default is "*" (all ports)
		pe.TrafficSpec.SrcPortRange = new(string)
		*pe.TrafficSpec.SrcPortRange = "*"
		pe.TrafficSpec.DstPortRange = new(string)
		*pe.TrafficSpec.DstPortRange = "*"
		// Specific ports / port ranges are given, override this default
		if eaclentry.SourcePort != "" {
			*pe.TrafficSpec.SrcPortRange = eaclentry.SourcePort
		}
		if eaclentry.DestinationPort != "" {
			*pe.TrafficSpec.DstPortRange = eaclentry.DestinationPort
		}

	default:
		glog.Fatalf("Don't know how to map Egress ACL Protocol %#s ", eaclentry.Protocol)
	}

	// Action
	pe.Action = Actions[eaclentry.Action]
}

// XXX - This also validates if the PE points to valid VSD constructs
func (pe *PolicyElement) MapToEgressACLEntry() (*vspk.EgressACLEntryTemplate, error) {
	eaclentry := new(vspk.EgressACLEntryTemplate)

	if err := scrubPE(pe); err != nil {
		return eaclentry, err
	}
	// The PE must point to a Policy that is 1) already applied or 2) is being applied togehter with this PE as part of a batch. In both cases the parent Policy must be associated with a parent Policy Domain
	if pe.Parent.Parent == nil {
		return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "Parent Policy not associated with a Policy Domain")
	}
	// XXX - Cast parent Policy' parent PolicyDomain back to VSD domain. No fresh fetch / check is done (efficiency)
	vsdd := vspk.Domain(*pe.Parent.Parent)

	// Build the EgressACLEntryTemplate

	// Hardcoded fields
	eaclentry.DSCP = "*"
	eaclentry.EtherType = "0x0800"

	// XXX - Notes
	// - This works for TCP/UDP/Any. Also, when "Stateful" is true, the ACLEntry has to be "Reflexive" as well. In effect, this takes care of reverse traffic direction as well
	// - This only works for "Allow" rules
	if pe.Action == Allow {
		eaclentry.Stateful = true
		eaclentry.Reflexive = true
	}

	eaclentry.ACLTemplateName = pe.Parent.Name // XXX Valid only for Applied Policies / Valid EgressACLTemplates
	eaclentry.EnterpriseName = pe.Enterprise
	eaclentry.DomainName = pe.Domain
	eaclentry.Description = pe.Name
	eaclentry.Priority = pe.Priority

	// From
	eaclentry.NetworkType = VSDNScopes[NScope(pe.From.Type)]
	switch NScope(pe.From.Type) {
	case NAny: // eaclentry.NetworkID left from empty string
	case NSubnet:
		sl, _ := vsdd.Subnets(&bambou.FetchingInfo{Filter: "name == \"" + *pe.From.Name + "\""})
		if len(sl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field, cannot find Subnet with name: "+*pe.From.Name)
		}
		eaclentry.NetworkID = sl[0].ID
	case NZone:
		zl, _ := vsdd.Zones(&bambou.FetchingInfo{Filter: "name == \"" + *pe.From.Name + "\""})
		if len(zl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field, cannot find Zone with name: "+*pe.From.Name)
		}
		eaclentry.NetworkID = zl[0].ID
	case NPolicyGroup:
		pgl, _ := vsdd.PolicyGroups(&bambou.FetchingInfo{Filter: "name == \"" + *pe.From.Name + "\""})
		if len(pgl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field, cannot find PolicyGroup with name: "+*pe.From.Name)
		}
		eaclentry.NetworkID = pgl[0].ID
	case MyDomain, MyZone, MySubnet: // eaclentry.NetworkID left from empty string
	case NetworkMacroGroup:
		// XXX - We can only list Network Macro Group for Enterprise.
		vsdorg := new(vspk.Enterprise)
		vsdorg.ID = vsdd.ParentID
		vsdorg.Fetch()
		nmgl, _ := vsdorg.NetworkMacroGroups(&bambou.FetchingInfo{Filter: "name == \"" + *pe.From.Name + "\""})
		if len(nmgl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field, cannot find NetworkMacroGroup with name: "+*pe.From.Name)
		}
		eaclentry.NetworkID = nmgl[0].ID
	case NetworkMacro:
		// XXX - We can only list Enterprise Networks (Network Macros) for an Enterprise.
		vsdorg := new(vspk.Enterprise)
		vsdorg.ID = vsdd.ParentID
		vsdorg.Fetch()
		nml, _ := vsdorg.EnterpriseNetworks(&bambou.FetchingInfo{Filter: "name == \"" + *pe.From.Name + "\""})
		if len(nml) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'from' field, cannot find NetworkMacro with name: "+*pe.From.Name)
		}
		eaclentry.NetworkID = nml[0].ID
	}

	// To
	eaclentry.LocationType = VSDLScopes[LScope(pe.To.Type)]

	switch LScope(pe.To.Type) {
	case LAny: // eaclentry.LocationID left to empty string
	case LSubnet: // Find subnet by name & get its ID
		sl, _ := vsdd.Subnets(&bambou.FetchingInfo{Filter: "name == \"" + *pe.To.Name + "\""})
		if len(sl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field, cannot find Subnet with name: "+*pe.To.Name)
		}
		eaclentry.LocationID = sl[0].ID

	case LZone: // Find Zone by name & get its ID
		zl, _ := vsdd.Zones(&bambou.FetchingInfo{Filter: "name == \"" + *pe.To.Name + "\""})
		if len(zl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field, cannot find Zone with name: "+*pe.To.Name)
		}
		eaclentry.LocationID = zl[0].ID
	case LPolicyGroup: // Find VSD Policy Group by Name and get its ID
		pgl, _ := vsdd.PolicyGroups(&bambou.FetchingInfo{Filter: "name == \"" + *pe.To.Name + "\""})
		if len(pgl) != 1 {
			return nil, bambou.NewBambouError(ErrorPEInvalid+pe.Name, "'to' field, cannot find PolicyGroup with name: "+*pe.To.Name)
		}
		eaclentry.LocationID = pgl[0].ID
	case LVPortTag:
		// Not implemented yet. Raise exception.
		glog.Fatalf("Implementing Egress ACL Entry LocationType %#s is not yet supported", pe.To.Type)
	}

	// Traffic spec
	eaclentry.Protocol = VSDProtocols[pe.TrafficSpec.Protocol]
	switch pe.TrafficSpec.Protocol {
	case ProtoAny: // Leave SourcePort / DestinationPort empty strings
	case TCP, UDP:
		eaclentry.SourcePort = *pe.TrafficSpec.SrcPortRange
		eaclentry.DestinationPort = *pe.TrafficSpec.DstPortRange
	}

	// Action
	eaclentry.Action = VSDActions[pe.Action]
	return eaclentry, nil
}
