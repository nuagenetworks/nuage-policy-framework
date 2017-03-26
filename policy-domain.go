package netpolicy

import (
	"time"

	"github.com/golang/glog"

	// log "github.com/Sirupsen/logrus"

	"github.com/nuagenetworks/go-bambou/bambou"
	"github.com/nuagenetworks/vspk-go/vspk"
)

// Wrapper around VSD jobs
func (pd *PolicyDomain) Job(cmd string) error {

	//// XXX -- Timeouts. Adjust accordingly
	wait := 100 * time.Millisecond
	timeout := 1777 * time.Millisecond

	//XXX --  Cast back the Policy Domain back to a VSD domain. No checks done.
	vsdd := (*vspk.Domain)(pd)
	job := vspk.Job{Command: cmd}

	if joberr := vsdd.CreateJob(&job); joberr != nil {
		return bambou.NewBambouError("VSD Job error", joberr.Error())
	}

	// Verify the job finsihed executing. Waiting loop with exponential backoff...
	for t := wait; t < timeout; t = t * 2 {
		time.Sleep(t)
		if err := job.Fetch(); err != nil {
			return err
		}
		if job.Status == "SUCCESS" {
			break
		}
		if job.Status == "FAILED" {
			return bambou.NewBambouError("VSD Job error", "Job Failed")
		}
	}

	return nil
}

// For a given Policy Domain (VSD domain) get all policies with a policyState of "LIVE" policies of a given type
func (pd *PolicyDomain) GetPoliciesByType(ptype PolicyType) ([]*Policy, error) {

	if pd.ID == "" { // The given Policy/VSD domain should have _at_least_ an ID
		return nil, bambou.NewBambouError(ErrorPolicyNotFound, "Invalid Policy Domain - no valid ID")
	}

	// Assumption:  Domains are quite static / IDs do not change much. So if we have valid policy ID we can simply cast back a PolicyDomain to (valid) VSD Domain
	// Altneratively, fetch a new copy & refresh (commented code below)
	vsdd := (*vspk.Domain)(pd)

	/*
			// Gettting a fresh copy. Alternatively, if caller guarantees the PolicyDomain is cast from a valid VSD domain already, we could simply cast it back. Still, this is more defensive / robust
			vsdd := vspk.Domain{}
			vsdd.ID = pd.ID
			if err := vsdd.Fetch(); err != nil {
				return nil, err
			}

		// Refresh PolicyDomain with latest info retreived
		*pd = PolicyDomain(vsdd)
	*/

	// Get parent Enterprise
	vsdorg := new(vspk.Enterprise)
	vsdorg.ID = vsdd.ParentID
	if err := vsdorg.Fetch(); err != nil {
		return nil, err
	}

	var ps []*Policy // Resulting slice of "*Policy"

	switch ptype {
	case Ingress:
		iacls, err := vsdd.IngressACLTemplates(&bambou.FetchingInfo{Filter: "policyState == \"LIVE\""})
		if err != nil {
			return nil, err
		}
		for _, iacl := range iacls {

			p, _ := NewPolicy(iacl.Name, Ingress, vsdorg.Name, vsdd.Name, iacl.Priority)
			// Add the VSD provided fields -- i.e. attach the Policy to this PolicyDomain
			p.ID = iacl.ID
			p.Parent = pd

			//// Get the underlying (children) ACL Entries

			// Two alternatives:
			// 1) Get All Ingress ACL Entry for the domain, then filter to those that have this ACL template as parent
			// 2) Get all Ingress ACL Entry Templates have this ACL Template as parent
			// The two _should_ be the same. While 1) is more conservative (and logical), we use 2)  since it's faster
			iaclentries, err := iacl.IngressACLEntryTemplates(&bambou.FetchingInfo{})
			if err != nil {
				return nil, err
			}
			for _, iaclentry := range iaclentries {
				pe := new(PolicyElement)
				pe.MapFromIngressACLEntry(iaclentry)
				// Add this PE to Policy's list of Policy Elements
				p.AttachPE(pe)
			}
			ps = append(ps, p)
		}

	case Egress:
		eacls, err := vsdd.EgressACLTemplates(&bambou.FetchingInfo{Filter: "policyState == \"LIVE\""})
		if err != nil {
			return nil, err
		}
		for _, eacl := range eacls {

			p, _ := NewPolicy(eacl.Name, Egress, vsdorg.Name, vsdd.Name, eacl.Priority)
			// Add the VSD provided fields -- i.e. attach the Policy to this PolicyDomain
			p.ID = eacl.ID
			p.Parent = pd

			//// Get the underlying (children) ACL Entries

			// Two alternatives:
			// 1) Get All Egress ACL Entry for the domain, then filter to those that have this ACL template as parent
			// 2) Get all Egress ACL Entry Templates have this ACL Template as parent
			// The two _should_ be the same. While 1) is more conservative (and logical), we use 2)  since it's faster
			eaclentries, err := eacl.EgressACLEntryTemplates(&bambou.FetchingInfo{})
			if err != nil {
				return nil, err
			}
			for _, eaclentry := range eaclentries {
				pe := new(PolicyElement)
				pe.MapFromEgressACLEntry(eaclentry)
				// Add this PE to Policy's list of Policy Elements
				p.AttachPE(pe)
			}
			ps = append(ps, p)
		}
	}

	return ps, nil
}

// For a given Policy Domain (VSD domain) get Policies with a given name.
// XXX -- limit to policyState of "LIVE"
func (pd *PolicyDomain) GetPolicies() ([]*Policy, error) {

	if pd.ID == "" { // The given Policy/VSD domain should have _at_least_ an ID
		return nil, bambou.NewBambouError(ErrorPolicyNotFound, "Invalid Policy Domain - lacks valid ID")
	}

	// Assumption:  Domains are quite static / IDs do not change much. So if we have valid policy ID we can simply cast back a PolicyDomain to (valid) VSD Domain
	// Altneratively, fetch a new copy & refresh (commented code below)
	vsdd := (*vspk.Domain)(pd)

	/*
				// Get corresponding VSD domain
				// Gettting a fresh copy. Alternatively, if caller guarantees the PolicyDomain is cast from a valid VSD domain already, we could simply cast it back. Still, this is more defensive / robust
				vsdd := vspk.Domain{}
				vsdd.ID = pd.ID
				if err := vsdd.Fetch(); err != nil {
					return nil, err
				}

		                // Refresh PolicyDomain with latest info retreived
				*pd = PolicyDomain(vsdd)
	*/

	// Get parent Enterprise
	vsdorg := new(vspk.Enterprise)
	vsdorg.ID = vsdd.ParentID
	if err := vsdorg.Fetch(); err != nil {
		return nil, err
	}

	var ps []*Policy

	for ptype, _ := range VSDPolicyTypes {
		switch ptype {
		case Ingress:
			/////
			///// Ingress Policies
			/////

			// Limit to "LIVE" ones
			iacls, _ := vsdd.IngressACLTemplates(&bambou.FetchingInfo{Filter: "policyState == \"LIVE\""})

			for _, iacl := range iacls { // This list should contain _at_most_ one element
				p, _ := NewPolicy(iacl.Name, Ingress, vsdorg.Name, vsdd.Name, iacl.Priority)

				// Attach Policy to Policy Domain, incl. (latest) ID for the Policy
				p.ID = iacl.ID
				p.Parent = pd

				//// Get the underlying ACL Entries
				// Two alternatives:
				// 1) Get All Ingress ACL Entry for the domain, then filter to those that have this ACL template as parent
				// 2) Get all Ingress ACL Entry Templates have this ACL Template as parent
				// The two _should_ be the same. While 1) is more conservative (and logical), we use 2)  since it's faster
				iaclentries, _ := iacl.IngressACLEntryTemplates(&bambou.FetchingInfo{})

				for _, iaclentry := range iaclentries {
					pe := new(PolicyElement)
					pe.MapFromIngressACLEntry(iaclentry)
					// Add this to Policy's list of Policy Elements
					p.AttachPE(pe)
				}
				// Found one matching policy. Add it to the list
				ps = append(ps, p)
			}

		case Egress:
			/////
			///// Egress Policies
			/////

			// Limit to "LIVE" ones
			eacls, _ := vsdd.EgressACLTemplates(&bambou.FetchingInfo{Filter: "policyState == \"LIVE\""})

			for _, eacl := range eacls { // This list should contain _at_most_ one element
				p, _ := NewPolicy(eacl.Name, Egress, vsdorg.Name, vsdd.Name, eacl.Priority)

				// Attach Policy to Policy Domain, incl. (latest) ID for the Policy
				p.ID = eacl.ID
				p.Parent = pd

				//// Get the underlying ACL Entries
				// Two alternatives:
				// 1) Get All Ingress ACL Entry for the domain, then filter to those that have this ACL template as parent
				// 2) Get all Ingress ACL Entry Templates have this ACL Template as parent
				// The two _should_ be the same. While 1) is more conservative (and logical), we use 2)  since it's faster
				eaclentries, _ := eacl.EgressACLEntryTemplates(&bambou.FetchingInfo{})

				for _, eaclentry := range eaclentries {
					pe := new(PolicyElement)
					pe.MapFromEgressACLEntry(eaclentry)
					// Add this to Policy's list of Policy Elements
					p.AttachPE(pe)
				}
				// Found one matching policy. Add it to the list
				ps = append(ps, p)
			}

		}
	}

	return ps, nil
}

// Apply a Policy and any PEs it may contain
// Used for applying several  PEs in single batch
func (pd *PolicyDomain) ApplyPolicy(p *Policy) error {
	// Sanity check the Policy
	if err := scrubPolicy(p); err != nil {
		return err
	}

	// Get all existing policies of same type.
	ps, err := pd.GetPoliciesByType(p.Type)

	if err != nil {
		return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, err.Error())
	}

	//XXX --  Cast back the Policy Domain back to a VSD domain. No checks done.
	vsdd := (*vspk.Domain)(pd)

	// Get Policy Domain parent Enterprise
	vsdorg := new(vspk.Enterprise)
	vsdorg.ID = vsdd.ParentID
	if err := vsdorg.Fetch(); err != nil {
		return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, err.Error())
	}

	// Check if Policy Enterprise / Domain names match the ones of the Policy Domain / parent Enterprise
	if vsdorg.Name != p.Enterprise || vsdd.Name != p.Domain {
		return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, "Enterprise or Domain names do not match the given Policy Domain")
	}

	// Check to see if there is already another policy with  1)Same Name 2) Same Priority
	for _, appliedp := range ps {
		if appliedp.Name == p.Name {
			return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, "A Policy with same Name already exists")
		}
		if appliedp.Priority == p.Priority {
			return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, "A Policy with same Priority already exists")
		}
	}

	// (Tentatively) attach Policy to Policy Domain (subseq checks will fail otherwise)
	p.Parent = pd

	// Start VSD job
	if err := pd.Job("BEGIN_POLICY_CHANGES"); err != nil {
		return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, err.Error())
	}

	var batcherr error

	switch p.Type {
	case Ingress:
		/////
		///// Ingress Policies
		/////
		iacl := new(vspk.IngressACLTemplate)
		// Hardcoded fields
		iacl.Active = true
		// Mapped fields
		iacl.Name = p.Name
		iacl.Priority = p.Priority
		if err := vsdd.CreateIngressACLTemplate(iacl); err != nil {
			batcherr = err
			goto batch_error
		}

		// Process Policy's PEs
		for _, pe := range p.PolicyElements {
			iaclentry, err := pe.MapToIngressACLEntry()
			if err != nil {
				batcherr = err
				goto batch_error
			}
			if err := iacl.CreateIngressACLEntryTemplate(iaclentry); err != nil {
				batcherr = err
				goto batch_error
			}
		}

	case Egress:
		/////
		///// Egress Policies
		/////

		eacl := new(vspk.EgressACLTemplate)
		// Hardcoded fields
		eacl.Active = true
		// Mapped fields
		eacl.Name = p.Name
		eacl.Priority = p.Priority
		if err := vsdd.CreateEgressACLTemplate(eacl); err != nil {
			batcherr = err
			goto batch_error
		}

		// Process Policy's PEs
		for _, pe := range p.PolicyElements {
			eaclentry, err := pe.MapToEgressACLEntry()
			if err != nil {
				batcherr = err
				goto batch_error
			}
			if err := eacl.CreateEgressACLEntryTemplate(eaclentry); err != nil {
				batcherr = err
				goto batch_error
			}
		}
	}

	//// At this point all the bacherr should be nil.  This is a bit overkill but leave it in place until code matures
	if batcherr != nil {
		glog.Warningf("====> vspk-wrapper.go ApplyPolicy() assertion: At this point batcherr SHOULD be nil but is: %+v", batcherr)
	}

	if joberr := pd.Job("APPLY_POLICY_CHANGES"); joberr != nil {
		return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, joberr.Error())
	}

	return nil

batch_error: //Errors encountered during batch processing. Clean-up & Discard any draft changes by sending a job with command "DISCARD_POLICY_CHANGES".
	// Clean up
	p.ID = ""
	p.Parent = nil // Detach Policy from Policy Domain

	if joberr := pd.Job("DISCARD_POLICY_CHANGES"); joberr != nil {
		return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, batcherr.Error()+joberr.Error())
	}
	return bambou.NewBambouError(ErrorPolicyCannotApply+p.Name, batcherr.Error())
}

// Test if a Policy Domain has a given Policy applied to it
func (pd *PolicyDomain) HasPolicy(p *Policy) error {
	// Sanity check the Policy
	if err := scrubPolicy(p); err != nil {
		return err
	}
	// Get all "LIVE" policies of same type
	if pl, err := pd.GetPoliciesByType(p.Type); err != nil {
		return bambou.NewBambouError(ErrorPolicyNotFound+p.Name, err.Error())
	} else {
		for _, policy := range pl { // Short list -- At most one policy with same Name per Type
			if policy.Name == p.Name { // Check if Policy Names  match
				// Refresh Policy with latest copy from the VSD (refresh latest ID)
				*p = *policy
				return nil // Policy found, no errors.
			}
		}
	}

	return bambou.NewBambouError(ErrorPolicyNotFound+p.Name, "No live Policy with this Name and Type could be found in Policy Domain")
}

// Deletes a Policy from a Policy Domain (i.e. un-apply). All in one go, no need to do it in a batch and/or delete individual ACLEntries (VSD takes care of that)
// XXX - Not using VSD jobs. For some strange reason, deletion works without (VSD bug) !!
func (pd *PolicyDomain) DeletePolicy(p *Policy) error {
	if err := pd.HasPolicy(p); err != nil { // Refreshes Policy in the process (incl. latest ID)
		return bambou.NewBambouError(ErrorPolicyCannotDelete+p.Name, err.Error())
	}

	switch p.Type {
	case Ingress:
		////////
		//////// Ingress Policies
		////////
		iacl := new(vspk.IngressACLTemplate)
		iacl.ID = p.ID // Up-to-date since it was refreshed above
		if err := iacl.Delete(); err != nil {
			return bambou.NewBambouError(ErrorPolicyCannotDelete+p.Name, err.Error())
		} else { // Detach Policy from Policy Domain
			p.ID = ""
			p.Parent = nil
			return nil
		}
	case Egress:
		////////
		//////// Insert logic here
		////////
	}

	return bambou.NewBambouError(ErrorPolicyCannotDelete+p.Name, "")
}
