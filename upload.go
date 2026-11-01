package main

import (
	"archive/zip"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const maxExtract = 500 << 20

// Extracts a ZIP INTO the project (merge: existing files stay, same names are overwritten).
// Every path goes through safePath, so nothing can escape the project folder.
func extractZipMerge(p Project, zr *zip.Reader, destRel string) (int, error) {
	var total int64
	n := 0
	for _, zf := range zr.File {
		if zf.Mode()&os.ModeSymlink != 0 || strings.HasPrefix(zf.Name, "__MACOSX/") {
			continue
		}
		abs, err := safePath(p, filepath.Join(destRel, filepath.FromSlash(zf.Name)))
		if err != nil {
			return n, err
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(abs, 0755); err != nil {
				return n, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			return n, err
		}
		in, err := zf.Open()
		if err != nil {
			return n, err
		}
		out, err := os.OpenFile(abs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			in.Close()
			return n, err
		}
		c, err := io.Copy(out, io.LimitReader(in, maxExtract-total+1))
		in.Close()
		out.Close()
		if err != nil {
			return n, err
		}
		total += c
		if total > maxExtract {
			return n, errors.New("zip too large after extraction (max 500 MB)")
		}
		n++
	}
	return n, nil
}

// POST /api/projects/{id}/files/upload
// multipart: file (many), paths (one per file, optional relative path), dir, extract=0|1, restart=0|1
func handleFilesUpload(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	if err := diskErr(p, r.ContentLength); err != nil {
		jsonErr(w, 413, err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 200<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		jsonErr(w, 400, "upload invalid or larger than 200MB")
		return
	}
	defer r.MultipartForm.RemoveAll()
	dir := strings.Trim(filepath.ToSlash(strings.TrimSpace(r.FormValue("dir"))), "/")
	extract := r.FormValue("extract") != "0"
	restart := r.FormValue("restart") == "1"
	fhs := r.MultipartForm.File["file"]
	paths := r.MultipartForm.Value["paths"]
	if len(fhs) == 0 {
		jsonErr(w, 400, "no file selected")
		return
	}
	if err := os.MkdirAll(projDir(p), 0755); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	saved, extracted := 0, 0
	for i, fh := range fhs {
		name := fh.Filename
		if i < len(paths) && strings.TrimSpace(paths[i]) != "" {
			name = paths[i]
		}
		name = strings.Trim(filepath.ToSlash(name), "/")
		if name == "" {
			continue
		}
		f, err := fh.Open()
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		if extract && strings.HasSuffix(strings.ToLower(name), ".zip") {
			zr, err := zip.NewReader(f, fh.Size)
			if err != nil {
				f.Close()
				jsonErr(w, 400, name+": not a valid ZIP file")
				return
			}
			n, err := extractZipMerge(p, zr, dir)
			f.Close()
			if err != nil {
				jsonErr(w, 400, "zip error: "+err.Error())
				return
			}
			extracted += n
			continue
		}
		abs, err := safePath(p, filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			f.Close()
			jsonErr(w, 400, err.Error())
			return
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			f.Close()
			jsonErr(w, 500, err.Error())
			return
		}
		mode := os.FileMode(0644)
		if strings.HasSuffix(name, ".sh") {
			mode = 0755
		}
		out, err := os.OpenFile(abs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			f.Close()
			jsonErr(w, 500, err.Error())
			return
		}
		_, err = io.Copy(out, f)
		out.Close()
		f.Close()
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		saved++
	}
	dlog(p, "files uploaded: %d saved, %d extracted from ZIP", saved, extracted)
	if restart {
		if err := startProject(p); err != nil {
			jsonErr(w, 500, "uploaded, but auto-deploy failed: "+err.Error())
			return
		}
	}
	jsonOut(w, 200, map[string]any{"ok": true, "saved": saved, "extracted": extracted, "restarted": restart})
}
