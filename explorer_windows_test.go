//go:build windows

package main

import "testing"

func TestExplorerSelectArg(t *testing.T) {
	cases := map[string]string{
		`D:\Demo\a.age`:           `/select,"D:\Demo\a.age"`,
		`D:\a,b\x.age`:            `/select,"D:\a,b\x.age"`, // quoted: a comma would split it
		`D:\with space\x.age`:     `/select,"D:\with space\x.age"`,
		`\\?\D:\long\x.age`:       `/select,"D:\long\x.age"`, // Explorer doesn't take \\?\
		`\\?\UNC\nas\share\x.age`: `/select,"\\nas\share\x.age"`,
		`\\nas\share\x.age`:       `/select,"\\nas\share\x.age"`,
	}
	for in, want := range cases {
		if got := explorerSelectArg(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}
