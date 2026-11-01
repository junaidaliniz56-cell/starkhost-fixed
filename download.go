package main

import (
	"archive/zip"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// GET /api/projects/{id}/zip  — download the whole project (your edited scripts included) as a ZIP.
// node_modules, .git, venv etc. are left out to keep the file small.
func handleZip(w http.ResponseWriter, r *http.Request) {
	p, ok := getProject(w, r)
	if !ok {
		return
	}
	root := projDir(p)
	if !dirHasFiles(root) {
		jsonErr(w, 404, "this project has no files yet — upload your ZIP first")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+p.Name+`.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()
	addDirToZip(zw, root, "")
}

// GET /api/admin/users/{id}/zip — admin downloads every project of one user (one folder per project)
func handleAdminUserZip(w http.ResponseWriter, r *http.Request) {
	u, ok := userByID(r.PathValue("id"))
	if !ok {
		jsonErr(w, 404, "user not found")
		return
	}
	ps := store.projectsOf(u.ID)
	has := false
	for _, p := range ps {
		if dirHasFiles(projDir(p)) {
			has = true
			break
		}
	}
	if !has {
		jsonErr(w, 404, "this user has no project files yet")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.NewReplacer("@", "_", "/", "_", `"`, "").Replace(u.Email)+`-projects.zip"`)
	zw := zip.NewWriter(w)
	defer zw.Close()
	for _, p := range ps {
		if root := projDir(p); dirHasFiles(root) {
			addDirToZip(zw, root, strings.NewReplacer("/", "_", "\\", "_").Replace(p.Name)+"/")
		}
	}
}

func addDirToZip(zw *zip.Writer, root, prefix string) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil || rel == "." {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, e := d.Info()
		if e != nil {
			return nil
		}
		hdr, e := zip.FileInfoHeader(info)
		if e != nil {
			return nil
		}
		hdr.Name = prefix + filepath.ToSlash(rel)
		hdr.Method = zip.Deflate
		fw, e := zw.CreateHeader(hdr)
		if e != nil {
			return e
		}
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		_, e = io.Copy(fw, f)
		f.Close()
		return e
	})
}

// true when the folder holds at least one real file (skipping node_modules, .git, venv ...)
func dirHasFiles(root string) bool {
	found := false
	_ = filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if path != root && skipDirs[e.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if e.Type().IsRegular() {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}
