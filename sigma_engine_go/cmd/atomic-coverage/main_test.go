package main

import (
	"github.com/edr-platform/sigma-engine/internal/domain"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestReadIndexDeduplicatesTacticsAndRejectsConflicts(t *testing.T) {
	header := "Tactic,Technique #,Test Name,Test GUID,Executor Name\n"
	rows, err := readIndex(strings.NewReader(header + "a,T1006,Read disk,id,powershell\nb,T1006,Read disk,id,powershell\n"))
	require.NoError(t, err)
	require.Len(t, rows, 1)
	_, err = readIndex(strings.NewReader(header + "a,T1006,Read disk,id,powershell\nb,T1217,Other,id,powershell\n"))
	require.Error(t, err)
	_, err = readIndex(strings.NewReader("Test GUID\nid\n"))
	require.Error(t, err)
	_, err = readIndex(strings.NewReader(header + "a,T1006,Read disk,,powershell\n"))
	require.Error(t, err)
}

func TestCandidatesNeverPromoteParentTagToExactTestCoverage(t *testing.T) {
	rs := []*domain.SigmaRule{{ID: "parent", Tags: []string{"attack.t1059"}}, {ID: "exact", Tags: []string{"attack.t1059.001"}}, {ID: "sibling", Tags: []string{"attack.t1059.003"}}}
	exact, parent, _ := candidates("T1059.001", rs)
	require.Equal(t, []string{"exact"}, exact)
	require.Equal(t, []string{"parent"}, parent)
	exact, parent, _ = candidates("T1059", rs)
	require.Equal(t, []string{"parent"}, exact)
	require.Empty(t, parent)
}
