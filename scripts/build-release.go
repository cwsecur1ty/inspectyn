//go:build ignore

package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cwsecur1ty/inspectyn/internal/inspect"
)

func main() {
	out := flag.String("out", "release", "new release directory")
	flag.Parse()
	if err := build(*out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build(out string) error {
	if err := os.Mkdir(out, 0755); err != nil {
		return err
	}
	license, err := os.ReadFile("LICENSE")
	if err != nil {
		return err
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		return err
	}
	var sums []string
	for _, platform := range []struct{ os, arch string }{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}} {
		name := "inspectyn"
		if platform.os == "windows" {
			name += ".exe"
		}
		temp, err := os.MkdirTemp(out, ".build-")
		if err != nil {
			return err
		}
		binary := filepath.Join(temp, name)
		command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", binary, "./cmd/inspectyn")
		for _, entry := range os.Environ() {
			key := strings.SplitN(entry, "=", 2)[0]
			if key != "GOOS" && key != "GOARCH" && key != "CGO_ENABLED" {
				command.Env = append(command.Env, entry)
			}
		}
		command.Env = append(command.Env, "GOOS="+platform.os, "GOARCH="+platform.arch, "CGO_ENABLED=0")
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			return err
		}
		data, err := os.ReadFile(binary)
		if err != nil {
			return err
		}
		files := map[string][]byte{name: data, "LICENSE": license, "README.md": readme}
		archive := fmt.Sprintf("inspectyn_%s_%s_%s", inspect.Version, platform.os, platform.arch)
		if platform.os == "windows" {
			archive += ".zip"
		} else {
			archive += ".tar.gz"
		}
		path := filepath.Join(out, archive)
		if err := pack(path, files, name, platform.os == "windows"); err != nil {
			return err
		}
		packed, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sums = append(sums, fmt.Sprintf("%x  %s", sha256.Sum256(packed), archive))
		if err := os.Remove(binary); err != nil {
			return err
		}
		if err := os.Remove(temp); err != nil {
			return err
		}
		fmt.Println(archive)
	}
	sort.Strings(sums)
	return os.WriteFile(filepath.Join(out, "checksums.txt"), []byte(strings.Join(sums, "\n")+"\n"), 0644)
}

func pack(path string, files map[string][]byte, executable string, windows bool) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	if windows {
		writer := zip.NewWriter(file)
		for _, name := range names {
			header := &zip.FileHeader{Name: name, Method: zip.Deflate}
			header.SetModTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
			header.SetMode(0644)
			if name == executable {
				header.SetMode(0755)
			}
			entry, err := writer.CreateHeader(header)
			if err != nil {
				return err
			}
			if _, err := entry.Write(files[name]); err != nil {
				return err
			}
		}
		return writer.Close()
	}
	compressed := gzip.NewWriter(file)
	writer := tar.NewWriter(compressed)
	for _, name := range names {
		mode := int64(0644)
		if name == executable {
			mode = 0755
		}
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(files[name]))}); err != nil {
			return err
		}
		if _, err := io.Copy(writer, bytes.NewReader(files[name])); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return compressed.Close()
}
