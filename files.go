package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const maxEdit = 2 << 20

func jsonDecode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(v)
}

// resolves rel inside the project folder; refuses anything that escapes it (.. or symlinks)
func safePath(p Project, rel string) (string, error) {
	root, err := filepath.EvalSymlinks(projDir(p))
	if err != nil {
		return "", errors.New("project folder is empty — upload code or use a Git link first")
	}
	rel = filepath.Clean("/" + filepath.FromSlash(rel))
	abs := filepath.Join(root, rel)
	if fi, e := os.Lstat(abs); e == nil && fi.Mode()&os.ModeSymlink != 0 {
		if _, e2 := filepath.EvalSymlinks(abs); e2 != nil {
			return "", errors.New("broken symlink")
		}
	}
	probe := abs
	var tail []string
	resolved := ""
	for {
		r, e := filepath.EvalSymlinks(probe)
		if e == nil {
			resolved = filepath.Join(append([]string{r}, tail...)...)
			break
		}
		if !os.IsNotExist(e) {
			return "", e
		}
		tail = append([]string{filepath.Base(probe)}, tail...)
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", errors.New("bad path")
		}
		probe = parent
	}
	if resolved != root && !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
		return "", errors.New("path is outside the project")
	}
	return abs, nil
}

type FileEntry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Dir  bool   `json:"dir"`
}

var skipDirs = map[string]bool{"node_modules": true, ".git": true, "__pycache__": true, ".venv": true, "venv": true, "target": true, ".next": true}

func handleFiles(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	root := projDir(p)
	out := []FileEntry{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil || rel == "." {
			return nil
		}
		if d.IsDir() && skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		if len(out) >= 3000 {
			return filepath.SkipAll
		}
		var sz int64
		if !d.IsDir() {
			if info, e := d.Info(); e == nil {
				sz = info.Size()
			}
		}
		out = append(out, FileEntry{Path: filepath.ToSlash(rel), Size: sz, Dir: d.IsDir()})
		return nil
	})
	jsonOut(w, 200, out)
}

func handleFileGet(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	abs, err := safePath(p, r.URL.Query().Get("path"))
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	fi, err := os.Stat(abs)
	if err != nil {
		jsonErr(w, 404, "file not found")
		return
	}
	if fi.IsDir() {
		jsonErr(w, 400, "this is a folder")
		return
	}
	if fi.Size() > maxEdit {
		jsonErr(w, 413, "file is too large to edit here (max 2 MB)")
		return
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if bytes.IndexByte(b, 0) >= 0 {
		jsonErr(w, 415, "binary file — cannot edit here")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(b)
}

func handleFilePut(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	if err := diskErr(p, r.ContentLength); err != nil {
		jsonErr(w, 413, err.Error())
		return
	}
	rel := r.URL.Query().Get("path")
	if strings.Trim(rel, "/ ") == "" {
		jsonErr(w, 400, "file path required")
		return
	}
	abs, err := safePath(p, rel)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxEdit+1))
	if err != nil || len(b) > maxEdit {
		jsonErr(w, 413, "file too large (max 2 MB)")
		return
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if err := os.WriteFile(abs, b, 0644); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func handleFileDel(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	rel := r.URL.Query().Get("path")
	if strings.Trim(rel, "/ ") == "" {
		jsonErr(w, 400, "path required")
		return
	}
	abs, err := safePath(p, rel)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	if err := os.RemoveAll(abs); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}
