// Copyright 2023 Philipp Stephani
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary sri computes secure hashes in Subresource Integrity format for files or URLs.
package main

import (
	"crypto"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"io"
	"os"
	"sort"
	"strings"

	_ "crypto/sha256"
	_ "crypto/sha512"
)

func main() {
	flag.Usage = usage
	hashes := map[string]crypto.Hash{
		"sha256": crypto.SHA256,
		"sha384": crypto.SHA384,
		"sha512": crypto.SHA512,
	}
	var hashNames []string
	for n := range hashes {
		hashNames = append(hashNames, n)
	}
	sort.Strings(hashNames)
	var hashName string
	flag.StringVar(&hashName, "hash", "sha384", fmt.Sprintf("hash function to use (one of %v)", hashNames))
	flag.Parse()
	hash, ok := hashes[hashName]
	if !ok {
		fmt.Fprintf(os.Stderr, "sri: unknown hash function %s", hashName)
		os.Exit(2)
	}
	files := flag.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}
	ch := make(chan result)
	for _, f := range files {
		go run(f, hash, ch)
	}
	ok = true
	suffix := len(files) > 1
	for range files {
		r := <- ch
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "sri: %s: %s\n", r.file, r.err)
			ok = false
		}
		var s strings.Builder
		s.WriteString(hashName)
		s.WriteByte('-')
		s.WriteString(base64.StdEncoding.EncodeToString(r.hash))
		if suffix {
			s.WriteByte('\t')
			s.WriteString(r.file)
		}
		s.WriteByte('\n')
		if _, err := os.Stdout.WriteString(s.String()); err != nil {
			fmt.Fprintf(os.Stderr, "sri: %s: %s", r.file, err)
			ok = false
		}
	} 
	if !ok {
		os.Exit(1)
	}
}

func usage() {
	os.Stderr.WriteString(`sri [options] [files and URLs...]

Computes a cryptographic hash for each of the given files or HTTP URLs.
For each file/URL, prints the hash in Subresource Integrity format,
followed by a tab character, the filename/URL and a newline.
If no files are given, reads standard input.
A file named "-" is also interpreted to mean standard input.
If zero or one positional arguments are given,
print only the hash without a filename.
`)
	flag.PrintDefaults()
}

func run(f string, hash crypto.Hash, ch chan <-result) {
	r, err := open(f)
	if err != nil {
		ch <- result{file: f, err: err}
		return
	}
	defer r.Close()
	h := hash.New()
	if _, err := io.Copy(h, r); err != nil {
		ch <- result{file: f, err: err}
		return
	}
	ch <- result{file: f, hash: h.Sum(nil)}
}

type result struct {
	file string
	err error
	hash []byte
}

func open(f string) (io.ReadCloser, error) {
	if f == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
		r, err := http.Get(f)
		if err != nil {
			return nil, err
		}
		if r.StatusCode != http.StatusOK {
			r.Body.Close()
			return nil, fmt.Errorf("HTTP error %s", r.Status)
		}
		return r.Body, nil
	}
	return os.Open(f)
}