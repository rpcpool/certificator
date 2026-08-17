package main

import (
	"strings"
	"testing"
)

func TestDedupeURLs(t *testing.T) {
	tests := []struct {
		name string
		urls []string
		want []string
	}{
		{
			name: "no duplicates",
			urls: []string{"http://10.0.0.1:5555", "http://10.0.0.2:5555"},
			want: []string{"http://10.0.0.1:5555", "http://10.0.0.2:5555"},
		},
		{
			name: "removes exact duplicates regardless of input order",
			urls: []string{"http://10.0.0.2:5555", "http://10.0.0.1:5555", "http://10.0.0.2:5555"},
			want: []string{"http://10.0.0.1:5555", "http://10.0.0.2:5555"},
		},
		{
			name: "a node matching multiple service tags collapses to one entry",
			urls: []string{"http://10.0.0.1:5555", "http://10.0.0.1:5555", "http://10.0.0.1:5555"},
			want: []string{"http://10.0.0.1:5555"},
		},
		{
			name: "empty input",
			urls: nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedupeURLs(tt.urls)
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("dedupeURLs(%v) = %v, want %v", tt.urls, got, tt.want)
			}
		})
	}
}
