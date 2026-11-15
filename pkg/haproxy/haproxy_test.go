package haproxy

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/browningluke/opnsense-go/pkg/api"
)

// The CI image does not ship the os-haproxy plugin, so these tests only run when
// OPNSENSE_TEST_HAPROXY=1 says the plugin is installed on the target.
func TestMain(m *testing.M) {
	if os.Getenv("OPNSENSE_URI") == "" || os.Getenv("OPNSENSE_TEST_HAPROXY") != "1" {
		fmt.Fprintln(os.Stderr, "OPNSENSE_URI or OPNSENSE_TEST_HAPROXY=1 not set; skipping integration tests in pkg/haproxy")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestHAProxyRuleChain(t *testing.T) {
	c := &Controller{Api: api.NewClient(api.Options{
		Uri:           os.Getenv("OPNSENSE_URI"),
		APIKey:        os.Getenv("OPNSENSE_API_KEY"),
		APISecret:     os.Getenv("OPNSENSE_API_SECRET"),
		AllowInsecure: true,
		MaxBackoff:    30,
		MinBackoff:    1,
		MaxRetries:    4,
	})}
	ctx := context.Background()

	must := func(id string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	serverID := must(c.AddServer(ctx, &Server{Enabled: "1", Name: "ogo-test-server", Address: "192.0.2.10", Port: "80", Mode: "active", SSL: "0", SSLVerify: "1"}))
	t.Cleanup(func() { _ = c.DeleteServer(ctx, serverID) })

	backendID := must(c.AddBackend(ctx, &Backend{Enabled: "1", Name: "ogo-test-backend", Mode: "http", Algorithm: "source", LinkedServers: api.SelectedMapList{serverID}, HealthCheckEnabled: "0"}))
	t.Cleanup(func() { _ = c.DeleteBackend(ctx, backendID) })

	aclID := must(c.AddAcl(ctx, &Acl{Name: "ogo-test-acl", Expression: "path_beg", Negate: "0", PathBeg: "/.well-known/acme-challenge/"}))
	t.Cleanup(func() { _ = c.DeleteAcl(ctx, aclID) })

	newAction := func(name string) string {
		id := must(c.AddAction(ctx, &Action{Enabled: "1", Name: name, TestType: "if", LinkedAcls: api.SelectedMapList{aclID}, Operator: "and", Type: "use_backend", UseBackend: api.SelectedMap(backendID)}))
		t.Cleanup(func() { _ = c.DeleteAction(ctx, id) })
		return id
	}
	// Names sort opposite to the order under test, so alphabetical output would fail.
	actionA := newAction("ogo-test-a")
	actionZ := newAction("ogo-test-z")

	frontend := &Frontend{Enabled: "1", Name: "ogo-test-frontend", Bind: api.SelectedMapList{"127.0.0.1:18080"}, Mode: "http", DefaultBackend: api.SelectedMap(backendID)}
	frontendID := must(c.AddFrontend(ctx, frontend))
	t.Cleanup(func() { _ = c.DeleteFrontend(ctx, frontendID) })

	for _, want := range []api.SelectedMapListOrdered{{actionZ, actionA}, {actionA, actionZ}} {
		if err := c.UpdateFrontendActions(ctx, frontendID, &FrontendActions{LinkedActions: want}); err != nil {
			t.Fatalf("UpdateFrontendActions(%v): %v", want, err)
		}
		got, err := c.GetFrontendActions(ctx, frontendID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.LinkedActions, want) {
			t.Fatalf("linkedActions: got %v, want %v", got.LinkedActions, want)
		}
	}

	// Updating the frontend settings must keep the rule list ...
	frontend.Description = "updated"
	if err := c.UpdateFrontend(ctx, frontendID, frontend); err != nil {
		t.Fatal(err)
	}
	rules, err := c.GetFrontendActions(ctx, frontendID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rules.LinkedActions, api.SelectedMapListOrdered{actionA, actionZ}) {
		t.Fatalf("frontend update changed linkedActions: %v", rules.LinkedActions)
	}

	// ... and updating the rule list must keep the settings.
	if err := c.UpdateFrontendActions(ctx, frontendID, &FrontendActions{LinkedActions: api.SelectedMapListOrdered{}}); err != nil {
		t.Fatal(err)
	}
	gotFE, err := c.GetFrontend(ctx, frontendID)
	if err != nil {
		t.Fatal(err)
	}
	if gotFE.Name != "ogo-test-frontend" || gotFE.Description != "updated" || gotFE.Mode != "http" ||
		gotFE.DefaultBackend.String() != backendID || !reflect.DeepEqual(gotFE.Bind, api.SelectedMapList{"127.0.0.1:18080"}) {
		t.Fatalf("frontend read back wrong after rule list update: %+v", gotFE)
	}

	got, err := c.GetAcl(ctx, aclID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Expression != "path_beg" || got.PathBeg != "/.well-known/acme-challenge/" {
		t.Fatalf("acl read back wrong: %+v", got)
	}
}
