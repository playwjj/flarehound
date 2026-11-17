// Package fakecf is an in-memory stand-in for the Cloudflare write API,
// shared by the blocking tests. It enforces the behaviours the blocking
// module relies on: the custom-rule quota, entrypoint creation only when
// absent, and async list operations.
package fakecf

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"

	"github.com/playwjj/flarehound/internal/cfapi"
)

type CF struct {
	Plan           string
	HasEP          bool
	RS             cfapi.Ruleset
	ListsV         []cfapi.List
	Items          map[string][]cfapi.ListItem
	Access         []cfapi.AccessRule
	Origins        []netip.Addr
	FailCreateList bool
	FailDNS        bool
	Limit          int // custom-rule quota enforced on add
	Calls          []string
	seq            int
}

func New(plan string, limit int) *CF {
	return &CF{Plan: plan, Limit: limit, Items: map[string][]cfapi.ListItem{}}
}

func (c *CF) id(p string) string { c.seq++; return fmt.Sprintf("%s%d", p, c.seq) }
func (c *CF) log(s string)       { c.Calls = append(c.Calls, s) }

// UserRule adds a rule the user owns (FlareHound must never touch it).
func (c *CF) UserRule(desc, expr string) {
	c.HasEP = true
	if c.RS.ID == "" {
		c.RS.ID = "rs1"
	}
	c.RS.Rules = append(c.RS.Rules, cfapi.Rule{ID: c.id("u"), Description: desc, Expression: expr, Action: "block", Enabled: true})
}

func (c *CF) ZonePlan(context.Context, string) (string, error) { return c.Plan, nil }
func (c *CF) Entrypoint(context.Context, string) (cfapi.Ruleset, bool, error) {
	if !c.HasEP {
		return cfapi.Ruleset{}, false, nil
	}
	return clone(c.RS), true, nil
}
func clone(rs cfapi.Ruleset) cfapi.Ruleset { rs.Rules = slices.Clone(rs.Rules); return rs }

func (c *CF) CreateEntrypoint(_ context.Context, _ string, r cfapi.Rule) (cfapi.Ruleset, error) {
	if c.HasEP {
		return cfapi.Ruleset{}, fmt.Errorf("test: CreateEntrypoint on existing entrypoint would wipe user rules")
	}
	c.log("create_entrypoint " + r.Ref)
	c.HasEP = true
	c.RS = cfapi.Ruleset{ID: "rs1"}
	r.ID = c.id("r")
	c.RS.Rules = []cfapi.Rule{r}
	return clone(c.RS), nil
}
func (c *CF) AddRule(_ context.Context, _, _ string, r cfapi.Rule) (cfapi.Ruleset, error) {
	if c.Limit > 0 && len(c.RS.Rules) >= c.Limit {
		return cfapi.Ruleset{}, &cfapi.APIError{Status: 400, Message: "quota exceeded"}
	}
	c.log("add_rule " + r.Ref)
	r.ID = c.id("r")
	c.RS.Rules = append(c.RS.Rules, r)
	return clone(c.RS), nil
}
func (c *CF) UpdateRule(_ context.Context, _, _ string, r cfapi.Rule) (cfapi.Ruleset, error) {
	for i := range c.RS.Rules {
		if c.RS.Rules[i].ID == r.ID {
			if c.RS.Rules[i].Ref == "" && c.RS.Rules[i].Description != "" && c.RS.Rules[i].Description[0] != 'f' {
				return cfapi.Ruleset{}, fmt.Errorf("test: updated a user rule")
			}
			c.log("update_rule " + r.Ref + " " + r.Expression)
			c.RS.Rules[i] = r
			return clone(c.RS), nil
		}
	}
	return cfapi.Ruleset{}, &cfapi.APIError{Status: http.StatusNotFound}
}
func (c *CF) DeleteRule(_ context.Context, _, _, id string) (cfapi.Ruleset, error) {
	for i := range c.RS.Rules {
		if c.RS.Rules[i].ID == id {
			c.log("delete_rule " + c.RS.Rules[i].Ref)
			c.RS.Rules = slices.Delete(c.RS.Rules, i, i+1)
			return clone(c.RS), nil
		}
	}
	return cfapi.Ruleset{}, &cfapi.APIError{Status: http.StatusNotFound}
}
func (c *CF) Lists(context.Context, string) ([]cfapi.List, error) { return slices.Clone(c.ListsV), nil }
func (c *CF) CreateList(_ context.Context, _, name, _ string) (cfapi.List, error) {
	if c.FailCreateList {
		return cfapi.List{}, &cfapi.APIError{Status: 400, Message: "list limit"}
	}
	c.log("create_list " + name)
	l := cfapi.List{ID: c.id("l"), Name: name, Kind: "ip"}
	c.ListsV = append(c.ListsV, l)
	return l, nil
}
func (c *CF) ListItems(_ context.Context, _, id string) ([]cfapi.ListItem, error) {
	return slices.Clone(c.Items[id]), nil
}
func (c *CF) AddListItems(_ context.Context, _, id string, items []cfapi.ListItem) error {
	for _, it := range items {
		c.log("add_item " + it.IP)
		it.ID = c.id("i")
		c.Items[id] = append(c.Items[id], it)
	}
	return nil
}
func (c *CF) DeleteListItems(_ context.Context, _, id string, ids []string) error {
	c.Items[id] = slices.DeleteFunc(c.Items[id], func(it cfapi.ListItem) bool {
		if slices.Contains(ids, it.ID) {
			c.log("delete_item " + it.IP)
			return true
		}
		return false
	})
	return nil
}
func (c *CF) AccessRules(context.Context, string, string) ([]cfapi.AccessRule, error) {
	return slices.Clone(c.Access), nil
}
func (c *CF) CreateAccessRule(_ context.Context, _, mode, target, value, notes string) (cfapi.AccessRule, error) {
	c.log("create_access " + target + " " + value)
	r := cfapi.AccessRule{ID: c.id("a"), Mode: mode, Notes: notes}
	r.Configuration.Target, r.Configuration.Value = target, value
	c.Access = append(c.Access, r)
	return r, nil
}
func (c *CF) DeleteAccessRule(_ context.Context, _, id string) error {
	c.Access = slices.DeleteFunc(c.Access, func(r cfapi.AccessRule) bool { return r.ID == id })
	c.log("delete_access " + id)
	return nil
}
func (c *CF) OriginIPs(context.Context, string) ([]netip.Addr, error) {
	if c.FailDNS {
		return nil, &cfapi.APIError{Status: 403, Message: "no DNS permission"}
	}
	return c.Origins, nil
}
func (c *CF) CloudflareRanges(context.Context) ([]netip.Prefix, error) {
	return nil, fmt.Errorf("offline")
}

// Rule returns the FlareHound rule with the given ref, if any.
func (c *CF) Rule(ref string) (cfapi.Rule, bool) {
	for _, r := range c.RS.Rules {
		if r.Ref == ref {
			return r, true
		}
	}
	return cfapi.Rule{}, false
}
