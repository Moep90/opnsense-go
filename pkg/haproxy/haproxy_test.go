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

// fullFrontend carries the fields a new frontend needs; Frontend itself only models the rule list.
type fullFrontend struct {
	Name string `json:"name"`
	Bind string `json:"bind"`
	Mode string `json:"mode"`
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

	frontendID := must(api.Add(c.Client(), ctx, FrontendOpts, &fullFrontend{Name: "ogo-test-frontend", Bind: "127.0.0.1:18080", Mode: "http"}))
	t.Cleanup(func() { _ = c.DeleteFrontend(ctx, frontendID) })

	for _, want := range []api.SelectedMapListOrdered{{actionZ, actionA}, {actionA, actionZ}, {}} {
		if err := c.UpdateFrontend(ctx, frontendID, &Frontend{LinkedActions: want}); err != nil {
			t.Fatalf("UpdateFrontend(%v): %v", want, err)
		}
		got, err := c.GetFrontend(ctx, frontendID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.LinkedActions, want) {
			t.Fatalf("linkedActions: got %v, want %v", got.LinkedActions, want)
		}
	}

	// The partial update must leave the unmodelled frontend fields alone.
	var name struct {
		Name string `json:"name"`
	}
	if _, err := api.Get(c.Client(), ctx, FrontendOpts, &name, frontendID); err != nil {
		t.Fatal(err)
	}
	if name.Name != "ogo-test-frontend" {
		t.Fatalf("frontend name changed by partial update: %q", name.Name)
	}

	got, err := c.GetAcl(ctx, aclID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Expression != "path_beg" || got.PathBeg != "/.well-known/acme-challenge/" {
		t.Fatalf("acl read back wrong: %+v", got)
	}
}
