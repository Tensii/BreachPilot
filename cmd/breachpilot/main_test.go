package main

import (
	"os"
	"reflect"
	"testing"
)

func TestParseTargetsFile(t *testing.T) {
	content := `
# Test targets file
# Handles newlines, commas, spaces, semicolons, and comments.

example1.com
example2.com, example3.com

   example4.com   example5.com # with trailing comment
example6.com;example7.com
`
	tmpfile, err := os.CreateTemp("", "test-targets-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	targets, err := parseTargetsFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("parseTargetsFile failed: %v", err)
	}

	expected := []string{"example1.com", "example2.com", "example3.com", "example4.com", "example5.com", "example6.com", "example7.com"}

	if !reflect.DeepEqual(targets, expected) {
		t.Errorf("Mismatched targets.\nGot:      %v\nExpected: %v", targets, expected)
	}
}

func TestParseTargetsFile_Empty(t *testing.T) {
	content := `
# This file is empty or only has comments
`
	tmpfile, err := os.CreateTemp("", "test-targets-empty-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = parseTargetsFile(tmpfile.Name())
	if err == nil {
		t.Errorf("Expected an error for a file with no targets, but got nil")
	}
}
