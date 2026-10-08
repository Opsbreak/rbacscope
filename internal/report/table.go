// Package report renders rbacscope results as text tables, JSON, SARIF
// 2.1.0, Graphviz DOT and Mermaid.
package report

import (
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// Table is a minimal column-aligned text table.
type Table struct {
	Header []string
	Rows   [][]string
}

// Add appends a row.
func (t *Table) Add(cols ...string) { t.Rows = append(t.Rows, cols) }

// Write renders the table with two-space column gaps. The last column is
// never padded.
func (t *Table) Write(w io.Writer) error {
	widths := make([]int, len(t.Header))
	measure := func(row []string) {
		for i, c := range row {
			if i < len(widths) && utf8.RuneCountInString(c) > widths[i] {
				widths[i] = utf8.RuneCountInString(c)
			}
		}
	}
	measure(t.Header)
	for _, r := range t.Rows {
		measure(r)
	}
	var b strings.Builder
	line := func(row []string) {
		var l strings.Builder
		for i, c := range row {
			l.WriteString(c)
			if i < len(row)-1 {
				l.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c)+2))
			}
		}
		b.WriteString(strings.TrimRight(l.String(), " "))
		b.WriteString("\n")
	}
	line(t.Header)
	for _, r := range t.Rows {
		line(r)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// JSON writes v as indented JSON.
func JSON(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// Join renders a list, using "*" verbatim and quoting the empty API group.
func Join(list []string) string {
	if len(list) == 0 {
		return "-"
	}
	out := make([]string, len(list))
	for i, s := range list {
		if s == "" {
			s = `""`
		}
		out[i] = s
	}
	return strings.Join(out, ",")
}
