package netpolicy

import (
	"errors"
	"io/ioutil"

	"github.com/nuagenetworks/go-bambou/bambou"
	"github.com/nuagenetworks/vspk-go/vspk"
	"github.com/golang/glog"

	yaml "gopkg.in/yaml.v2"
)

// Create a new Network Policy  with given arguments
// Only non-VSD dependent fields needed at this point
func NewPolicy(name string, ptype PolicyType, enterprise string, domain string, priority int) (Policy, error) {
	p := Policy{
		Kind:       NuageACLPolicy,
		Version:    CurrentVersion,
		Name:       name,
		Type:       ptype,
		Enterprise: enterprise,
		Domain:     domain,
		Priority:   priority,
	}
	// Sanity check the arguments
	err := scrubPolicy(&p)
	return p, err
}

// Read a Policy with Policy Elements from file
func ReadPolicy(fname string) (Policy, error) {

	p := Policy{}

	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return p, err
	}

	if err := yaml.Unmarshal(data, &p); err != nil {
		return p, err
	}

	// A Policy needs to have at least one PE defined

	if len(p.PolicyElements) <= 0 {
		return p, bambou.NewBambouError(ErrorPolicyInvalid+p.Name, "Policy does not have any valid PolicyElements")
	}

	if err := scrubPolicy(&p); err != nil {
		return p, err
	}

	return p, nil
}

// YAML PrettyPrint
func (p Policy) String() string {
	pyaml, _ := yaml.Marshal(p)
	return string(pyaml)
}

//
// Apply a single PE to a single Policy.
// The must be already applied to a PolicyDomain ("policyState" is "LIVE")
// Very similar to ApplyPolicy()
func (p *Policy) ApplyPE(pe *PolicyElement) error {
	// Try to attach PE to Policy. Scrubs PE in the process
	if err := p.attachPE(pe); err != nil {
		return err
	}

	// Basic check: Is Policy Attached to a Policy Domain ?
	if p.Parent == nil {
		return bambou.NewBambouError(ErrorPECannotApply+pe.Name, "Parent Policy not attached to a Policy Domain")
	}

	pd := p.Parent // Shortcut

	// In depth check: Is parent  Policy applied to the Policy Domain ?
	if err := pd.HasPolicy(p); err != nil { // Updates Parent Policy with latest ID.
		return bambou.NewBambouError(ErrorPECannotApply+pe.Name, "Parent Policy not applied to a Policy Domain")
	}

	vsdd := (*vspk.Domain)(pd)

	// Start VSD job
	if joberr := pd.Job("BEGIN_POLICY_CHANGES"); joberr != nil {
		return bambou.NewBambouError(ErrorPECannotApply+pe.Name, joberr.Error())
	}

	var batcherr error

	switch p.Type {
	case Ingress:
		////////
		//////// Ingress Policies
		////////

		// XXX --  Since we need to add this PE under IngressACLTemplate in "DRAFT" state, we need to find its ID.
		// This as opposed to pe.Parent, which points to its previous, "LIVE" counterpart

		draftiacls, err := vsdd.IngressACLTemplates(&bambou.FetchingInfo{Filter: "name == \"" + p.Name + "\" and policyState == \"DRAFT\""})
		if err != nil {
			batcherr = err
			goto batch_error
		}

		if len(draftiacls) != 1 {
			batcherr = errors.New("Cannot find Parent Policy Draft")
			goto batch_error
		} else {
			iaclentry, err := pe.MapToIngressACLEntry()
			if err != nil {
				batcherr = err
				goto batch_error
			}

			if err := draftiacls[0].CreateIngressACLEntryTemplate(iaclentry); err != nil {
				batcherr = err
				goto batch_error
			}
		}

	case Egress:
		/////
		/////  Egress policies
		/////
		// XXX --  Since we need to add this PE under EgressACLTemplate in "DRAFT" state, we need to find its ID.
		// This as opposed to pe.Parent, which points to its previous, "LIVE" counterpart

		drafteacls, err := vsdd.EgressACLTemplates(&bambou.FetchingInfo{Filter: "name == \"" + p.Name + "\" and policyState == \"DRAFT\""})
		if err != nil {
			batcherr = err
			goto batch_error
		}

		if len(drafteacls) != 1 {
			batcherr = errors.New("Cannot find Parent Policy Draft")
			goto batch_error
		} else {
			eaclentry, err := pe.MapToEgressACLEntry()
			if err != nil {
				batcherr = err
				goto batch_error
			}

			if err := drafteacls[0].CreateEgressACLEntryTemplate(eaclentry); err != nil {
				batcherr = err
				goto batch_error
			}
		}

	}

	//// At this point all the bacherr should be nil.  This is a bit overkill but leave it in place until code matures
	if batcherr != nil {
		glog.Warningf("====> vspk-wrapper.go ApplyPE() assertion: At this point batcherr SHOULD be nil but is: %+v", batcherr)
	}

	if joberr := pd.Job("APPLY_POLICY_CHANGES"); joberr != nil {
		return bambou.NewBambouError(ErrorPECannotApply+pe.Name, joberr.Error())
	}
	return nil

batch_error: //Errors encountered during batch processing. Discard any draft changes by sending a job with command "DISCARD_POLICY_CHANGES"
	p.detachPE(pe)
	if joberr := pd.Job("DISCARD_POLICY_CHANGES"); joberr != nil {
		return bambou.NewBambouError(ErrorPECannotApply+pe.Name, batcherr.Error()+joberr.Error())
	}
	return bambou.NewBambouError(ErrorPECannotApply+pe.Name, batcherr.Error())
}

// Check if a Policy has a Policy Element applied to it.
// XXX -- Mutates (fetches new copies) of both parent Policy and the PE
func (p *Policy) HasPE(pe *PolicyElement) error {
	// Sanity check the PE
	if err := scrubPE(pe); err != nil {
		return err
	}

	// Basic check: Is Policy Attached to a Policy Domain ?
	if p.Parent == nil {
		return bambou.NewBambouError(ErrorPENotFound+pe.Name, "Parent Policy not attached to a Policy Domain")
	}
	pd := p.Parent // Shortcut

	if err := pd.HasPolicy(pe.Parent); err != nil { // Fectch new copy of parent Policy in the process
		return bambou.NewBambouError(ErrorPENotFound+pe.Name, err.Error())
	}

	switch pe.Parent.Type {
	case Ingress:
		////////
		//////// Ingress Policies
		////////

		iacl := vspk.IngressACLTemplate{}
		iacl.ID = pe.Parent.ID // XXX - Up to date since it was refreshed above
		// iacl.Fetch()
		iaclentries, err := iacl.IngressACLEntryTemplates(&bambou.FetchingInfo{Filter: "description == \"" + pe.Name + "\" and policyState == \"LIVE\""})
		if err != nil {
			return bambou.NewBambouError(ErrorPENotFound+pe.Name, err.Error())
		}

		// We should get (at most) one entry in that list
		switch len(iaclentries) {
		case 1:
			pe.MapFromIngressACLEntry(iaclentries[0])
			return nil
		case 0: // Not found return error (below)
		}

	case Egress:
		////////
		//////// Egress Policies
		////////

		eacl := vspk.EgressACLTemplate{}
		eacl.ID = pe.Parent.ID // XXX - Up to date since it was refreshed above
		// iacl.Fetch()
		eaclentries, err := eacl.EgressACLEntryTemplates(&bambou.FetchingInfo{Filter: "description == \"" + pe.Name + "\" and policyState == \"LIVE\""})
		if err != nil {
			return bambou.NewBambouError(ErrorPENotFound+pe.Name, err.Error())
		}

		// We should get (at most) one entry in that list
		switch len(eaclentries) {
		case 1:
			pe.MapFromEgressACLEntry(eaclentries[0])
			return nil
		case 0: // Not found return error (below)
		}

	}

	return bambou.NewBambouError(ErrorPENotFound+pe.Name, "")

}

// Delete a PolicyElement form an applied Policy (and detach it from the Policy). All in one go.
func (p *Policy) DeletePE(pe *PolicyElement) error {
	if p.Parent == nil {
		return bambou.NewBambouError(ErrorPECannotDelete+pe.Name, "Parent Policy not attached to a Policy Domain")
	}

	if err := p.HasPE(pe); err != nil { // Refreshes Policy and the PE in the process
		return bambou.NewBambouError(ErrorPECannotDelete+pe.Name, err.Error())
	}

	switch p.Type {
	case Ingress:
		////////
		//////// Ingress Policies
		////////
		iaclentry := new(vspk.IngressACLEntryTemplate)
		iaclentry.ID = pe.ID // Up-to-date since it was refreshed above
		if err := iaclentry.Delete(); err != nil {
			return bambou.NewBambouError(ErrorPECannotDelete+pe.Name, err.Error())
		} else {
			// Detach the PE from the Policy
			p.detachPE(pe)
			return nil
		}

	case Egress:
		////////
		//////// Insert logic here
		////////
		eaclentry := new(vspk.EgressACLEntryTemplate)
		eaclentry.ID = pe.ID // Up-to-date since it was refreshed above
		if err := eaclentry.Delete(); err != nil {
			return bambou.NewBambouError(ErrorPECannotDelete+pe.Name, err.Error())
		} else {
			// Detach the PE from the Policy
			p.detachPE(pe)
			return nil
		}

	}

	return bambou.NewBambouError(ErrorPECannotDelete+pe.Name, "")

}
