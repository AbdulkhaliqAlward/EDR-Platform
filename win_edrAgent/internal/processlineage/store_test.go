package processlineage

import (
	"testing"
	"time"
)

func TestExitedRootAndReusedPIDKeepSeparateDescendants(t *testing.T) {
	now := time.Unix(1800000000, 0)
	s := New(20, time.Hour)
	s.BeginCoverage(now.Add(-time.Minute))
	root := Identity{100, now.Add(-30 * time.Second).UnixNano()}
	child := Identity{200, root.Started + 100}
	grandchild := Identity{300, child.Started + 100}
	newRoot := Identity{100, now.Add(-time.Second).UnixNano()}
	foreign := Identity{400, newRoot.Started + 100}
	s.Record(root, Identity{}, now)
	s.Record(child, root, now)
	s.Record(grandchild, child, now)
	s.Record(newRoot, Identity{}, now)
	s.Record(foreign, newRoot, now)
	got := s.Tree(root, now)
	if !got.Found || !got.Complete || len(got.Descendants) != 2 || got.Descendants[0] != grandchild || got.Descendants[1] != child {
		t.Fatalf("old process generation lost its original descendants: %+v", got)
	}
	// A minimal observation of the same generation cannot erase its parent.
	s.Record(child, Identity{}, now)
	if len(s.Tree(root, now).Descendants) != 2 {
		t.Fatal("refresh erased lineage")
	}
	if s.Tree(Identity{100, root.Started + 1}, now).Found {
		t.Fatal("unknown creation time was accepted")
	}
}

func TestGapsAndEvictionInvalidateCompleteness(t *testing.T) {
	now := time.Unix(1800000000, 0)
	s := New(2, time.Minute)
	s.BeginCoverage(now.Add(-time.Second))
	root := Identity{100, now.UnixNano()}
	s.Record(root, Identity{}, now)
	s.Gap(now.Add(time.Nanosecond))
	if s.Tree(root, now).Complete {
		t.Fatal("telemetry gap claimed complete tree")
	}
	s.Record(Identity{200, root.Started + 2}, root, now.Add(time.Second))
	s.Record(Identity{300, root.Started + 3}, root, now.Add(2*time.Second))
	if s.Tree(root, now.Add(2*time.Second)).Found {
		t.Fatal("capacity eviction did not remove oldest root")
	}
	if len(s.entries) > 2 {
		t.Fatal("store exceeded bound")
	}
	if s.Tree(Identity{300, root.Started + 3}, now.Add(3*time.Minute)).Found {
		t.Fatal("expired history remained actionable")
	}
}

func TestUnknownOrNewerParentsNeverBind(t *testing.T) {
	now := time.Now()
	s := New(10, time.Hour)
	root := Identity{100, now.UnixNano()}
	s.Record(root, Identity{}, now)
	s.Record(Identity{200, root.Started - 1}, root, now)
	s.Record(Identity{300, root.Started + 1}, Identity{100, 0}, now)
	if len(s.Tree(root, now).Descendants) != 0 {
		t.Fatal("uncertain parent relationship accepted")
	}
}
