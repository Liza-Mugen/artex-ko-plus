package db

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestHuntDurableAdmissionCancellationAndRecovery(t *testing.T) {
	d := defensiveDB(t)
	in := json.RawMessage(`{"term":"php2shell","scope_confirmed":true,"scope":{"target":"fixture.lab"}}`)
	h, created, err := d.CreateHunt(t.Context(), in)
	if err != nil || !created {
		t.Fatal(h, created, err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM defensive_hunts WHERE id=$1`, h.ID) })
	duplicate, created, err := d.CreateHunt(t.Context(), in)
	if err != nil || created || duplicate.ID != h.ID {
		t.Fatal("duplicate paid work admitted", duplicate, created, err)
	}
	if _, _, err = d.CreateHunt(t.Context(), json.RawMessage(`{"term":"other"}`)); !errors.Is(err, ErrHuntActive) {
		t.Fatal("concurrent campaign admitted", err)
	}
	started, err := d.StartHunt(t.Context(), h.ID)
	if err != nil || !started {
		t.Fatal(err)
	}
	if err = d.AppendHuntEvent(t.Context(), h.ID, "research_completed", json.RawMessage(`{"source":"fixture","excerpt":"immutable evidence"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CancelHunt(t.Context(), h.ID); err != nil {
		t.Fatal(err)
	}
	if ok, err := d.FinishHunt(t.Context(), h.ID, "completed", json.RawMessage(`{"false":"late verdict"}`), ""); err != nil || ok {
		t.Fatal("late worker overwrote cancellation", ok, err)
	}
	if err = d.AppendHuntEvent(t.Context(), h.ID, "late", json.RawMessage(`{}`)); !errors.Is(err, ErrHuntInactive) {
		t.Fatal(err)
	}
	sealed, err := d.GetHunt(t.Context(), h.ID)
	if err != nil || sealed.Status != "cancelled" || len(sealed.Events) != 1 {
		t.Fatal(sealed, err)
	}
	h2, _, err := d.CreateHunt(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM defensive_hunts WHERE id=$1`, h2.ID) })
	if n, err := d.RecoverHunts(t.Context()); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if ok, err := d.StartHunt(t.Context(), h2.ID); err != nil || ok {
		t.Fatal("recovered work silently restarted", ok, err)
	}
	recovered, _ := d.GetHunt(t.Context(), h2.ID)
	if recovered.Status != "interrupted" {
		t.Fatal(recovered)
	}
	list, err := d.ListHunts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(list)
	if len(list) < 2 || json.Valid(raw) == false {
		t.Fatal(string(raw))
	}
}
