// Copyright © 2023 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"aconcli/config"
	"aconcli/cryptoutil"
	"aconcli/fileutil"
)

type Alias struct {
	Content map[string][]string `json:"contents,omitempty"`
	Self    map[string][]string `json:"self,omitempty"`
}

type Policy struct {
	Accept []string `json:"accepts,omitempty"`
	Reject bool     `json:"rejectUnaccepted"`
}

type Workload struct {
	SpecVersion [2]uint32 `json:"aconSpecVersion"`
	Layer       []string  `json:"layers,omitempty"`
	Alias       Alias     `json:"aliases"`
	Entrypoint  []string  `json:"entrypoint,omitempty"`
	Env         []string  `json:"env,omitempty"`
	WorkingDir  string    `json:"workingDir"`
	Uids        []uint32  `json:"uids"`
	LogFDs      []uint32  `json:"logFDs"`
	WritableFS  bool      `json:"writableFS"`
	NoRestart   bool      `json:"noRestart"`
	Signals     []int32   `json:"signals"`
	MaxInstance uint32    `json:"maxInstances"`
	Policy      Policy    `json:"policy"`
}

type Blob struct {
	Layer []string `json:"layers"`
}

type Repo struct {
	path string
}

func FindRepo(startingDir string) (*Repo, error) {
	repopath, err := findAconRepo(startingDir)
	if err != nil {
		return nil, fmt.Errorf("find repo: cannot locate ACON repository directory: %v", err)
	}
	return &Repo{repopath}, nil
}

func (r *Repo) CommitBlob(blobs [][]byte, diffIds []string) error {
	for i, blob := range blobs {
		bpath, err := r.generateBlobPath(blob, config.PrimaryHashAlgo)
		if err != nil {
			return fmt.Errorf("blob path: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(bpath), 0750); err != nil {
			return fmt.Errorf("mkdir: %v", err)
		}
		if err := os.WriteFile(bpath, blob, 0600); err != nil {
			return fmt.Errorf("write blob: %v", err)
		}
		_, sha256Digest, found := strings.Cut(diffIds[i], ":")
		if !found {
			return fmt.Errorf("cannot found sha256 digest: %v", diffIds[i])
		}

		base := sha256Digest + config.BlobExtension
		bpath_ := filepath.Join(r.blobDirPath(), config.DockerHashAlgo, base)
		if err := os.MkdirAll(filepath.Dir(bpath_), 0750); err != nil {
			return fmt.Errorf("mkdir: %v", err)
		}
		if err := createSymlink(bpath, bpath_); err != nil {
			return fmt.Errorf("symlink %v -> %v,  err %v", bpath_, bpath, err)
		}
	}
	return nil
}

func (r *Repo) PrimaryDigest(digest string) (string, error) {
	base := strings.ReplaceAll(digest, ":", "/") + config.BlobExtension
	blobPath := filepath.Join(r.blobDirPath(), base)

	// evaluate the symlink to get the primary hash
	if _, err := os.Lstat(blobPath); err != nil {
		return "", fmt.Errorf("lstat: %v", err)
	}

	primaryPath, err := filepath.EvalSymlinks(blobPath)
	if err != nil {
		return "", fmt.Errorf("eval symlink: %v", err)
	}

	rel, err := filepath.Rel(r.blobDirPath(), primaryPath)
	if err != nil {
		return "", fmt.Errorf("cannot get relative path")
	}

	hashAlgo, fileName, ok := strings.Cut(rel, "/")
	if !ok {
		return "", fmt.Errorf("symlink broken")
	}

	if hashAlgo != config.PrimaryHashAlgo ||
		filepath.Ext(fileName) != config.BlobExtension {
		return "", fmt.Errorf("symlink broken")
	}

	primaryDigest := strings.TrimSuffix(fileName, config.BlobExtension)
	if len(primaryDigest) != config.PrimaryHashAlgoLen {
		return "", fmt.Errorf("symlink broken")
	}

	return filepath.Join(config.PrimaryHashAlgo, primaryDigest), nil
}

func (r *Repo) CommitManifest(mfile, cfile, kfile string) error {
	var resign bool
	certfile := cfile
	keyfile := kfile

	bundle, err := r.FindBundle(mfile)
	if err == nil {
		resign = true
		if certfile == "" {
			certfile = bundle.Cert()
		}
		if keyfile == "" {
			keyfile = bundle.Key()
		}
	} else if certfile == "" || keyfile == "" {
		return fmt.Errorf("commit manifest: missing input cert and key file")
	}

	content, err := os.ReadFile(filepath.Clean(mfile))
	if err != nil {
		return fmt.Errorf("commit manifest: cannot read manifest %s: %v", mfile, err)
	}

	// canonical json
	content, err = canonicalJson(content)
	if err != nil {
		return fmt.Errorf("commit manifest: cannot canonnical manifest %s: %v", mfile, err)
	}

	sigBytes, err := cryptoutil.Sign(content, certfile, keyfile)
	if err != nil {
		return fmt.Errorf("commit manifest: cannot sign manifest %s with certfile %s and keyfile %s: %v", mfile, certfile, keyfile, err)
	}

	hashAlgo, err := cryptoutil.GetHashAlgoFromCert(certfile)
	if err != nil {
		return fmt.Errorf("commit manifest: cannot get hash algo from cert %s: %v", certfile, err)
	}

	manifestDigest, err := cryptoutil.BytesDigest(content, hashAlgo)
	if err != nil {
		return fmt.Errorf("commit manifest: cannot digest for %s using hash algorithm %s: %v", mfile, hashAlgo, err)
	}

	target := filepath.Join(r.manifestDirPath(), hashAlgo, hex.EncodeToString(manifestDigest))

	if !resign {
		if err := os.MkdirAll(target, 0750); err != nil {
			return fmt.Errorf("commit manifest: cannot make directory %s: %v", target, err)
		}
	} else {
		if bundle.path != target {
			if err := os.Rename(bundle.path, target); err != nil {
				return fmt.Errorf("commit manifest: cannot rename directory %s: %v", bundle.path, err)
			}
		}
	}

	// create symlink for manifest/cert/key file
	if err := createSymlink(mfile, filepath.Join(target, config.ManifestFileName)); err != nil {
		return fmt.Errorf("commit manifest: cannot symlink for %s: %v", mfile, err)
	}

	if cfile != "" {
		if err := createSymlink(certfile, filepath.Join(target, config.CertFileName)); err != nil {
			return fmt.Errorf("commit manifest: cannot symlink for %s: %v", certfile, err)
		}
	}

	if kfile != "" {
		if err := createSymlink(keyfile, filepath.Join(target, config.PrivKeyFileName)); err != nil {
			return fmt.Errorf("commit manifest: cannot symlink for %s: %v", keyfile, err)
		}
	}

	// write signature file
	outSigFile := filepath.Join(target, config.SignatureFileName)
	if err := os.WriteFile(outSigFile, sigBytes, 0600); err != nil {
		return fmt.Errorf("commit manifest: cannot create sig file for %s: %v", mfile, err)
	}

	return nil
}

func (r *Repo) RemoveBundle(id string) error {
	b, err := r.FindBundle(id)
	if err != nil {
		return fmt.Errorf("repo remove bundle: no such bundle %s", id)
	}
	if err := b.Remove(); err != nil {
		return fmt.Errorf("repo remove bundle: %v", err)
	}
	return nil
}

func (r *Repo) Prune() error {
	blobs, err := r.blobInUse()
	if err != nil {
		return fmt.Errorf("prune: cannot get blobs in use: %v", err)
	}

	blobDir := filepath.Join(r.blobDirPath(), config.PrimaryHashAlgo)
	files, err := os.ReadDir(blobDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("prune: cannot read blob directory %s: %v", blobDir, err)
	}

	// Clean up unused blobs
	primaryBlobNameLen := len(config.PrimaryHashAlgo) + 1 + config.PrimaryHashAlgoLen
	for _, f := range files {
		if f.Type().IsRegular() && len(f.Name()) >= config.PrimaryHashAlgoLen {
			b := config.PrimaryHashAlgo + "/" + f.Name()
			if _, in := blobs[b[:primaryBlobNameLen]]; !in {
				bPath := filepath.Join(r.blobDirPath(), filepath.FromSlash(b))
				if err := os.Remove(bPath); err != nil {
					fmt.Fprintln(os.Stderr, "error removing", bPath)
				} else {
					fmt.Println("removed", b[:primaryBlobNameLen])
				}
			}
		}
	}

	// Clean up dangling symlinks
	for _, d := range []string{config.DockerHashAlgo} {
		symlinkDir := filepath.Join(r.blobDirPath(), d)
		if files, err := os.ReadDir(symlinkDir); err == nil {
			for _, f := range files {
				fPath := filepath.Join(symlinkDir, f.Name())
				if _, err := os.Stat(fPath); os.IsNotExist(err) {
					if err := os.Remove(fPath); err != nil {
						fmt.Fprintln(os.Stderr, "error removing dangling symlink", fPath)
					}
				}
			}
		}
	}

	return nil
}

func (r *Repo) ExportBundle(bundle, exportpath string) error {
	deps, err := r.BundleChain(bundle)
	if err != nil {
		return fmt.Errorf("export bundle: cannot get bundle chain: %v", err)
	}

	var fileToArchive []string
	for _, b := range deps {
		m := b.Manifest()
		if !b.IsManifestUpdated() {
			return fmt.Errorf("export bundle: manifest %s has been modified since last signing", m)
		}

		if !b.IsSignatureValid() {
			return fmt.Errorf("export bundle: signature for manifest %s is not valid", m)
		}
		sigfile := b.Sig()
		fileToArchive = append(fileToArchive, sigfile)
		fileToArchive = append(fileToArchive, b.Cert())
		fileToArchive = append(fileToArchive, m)

		layers, err := b.Layers()
		if err != nil {
			return fmt.Errorf("export bundle: cannot get layers from bundle %s: %v", b.path, err)
		}
		for _, layer := range layers {
			if strings.HasPrefix(layer, "sha") {
				blob := filepath.Join(r.blobDirPath(), layer+config.BlobExtension)
				fileToArchive = append(fileToArchive, blob)
			}
		}
	}

	if err = fileutil.Tar(exportpath, fileToArchive, getFileRepoPath); err != nil {
		return fmt.Errorf("export bundle: cannot archive to %s: %v", exportpath, err)
	}
	return nil
}

func (r *Repo) ImportBundle(bundles []string) error {
	for i, bundleFile := range bundles {
		tmpDir, err := os.MkdirTemp("", "acon")
		if err != nil {
			fmt.Fprintf(os.Stderr, "import bundle: bundles %v are not imported\n", bundles[i:])
			return fmt.Errorf("import bundle: cannot create tmp directory: %v", err)
		}
		f, err := os.Open(filepath.Clean(bundleFile))
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open archive file %v: %v\n", bundleFile, err)
			os.RemoveAll(tmpDir)
			continue
		}
		var buf bytes.Buffer
		tee := io.TeeReader(f, &buf)
		err = fileutil.Untar(tmpDir, tee)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot untar %s to %s: %v\n", bundleFile, tmpDir, err)
			os.RemoveAll(tmpDir)
			continue
		}
		// check the bundles
		tmpRepo, err := FindRepo(tmpDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "malformed bundle file %s, expected directory %s in it\n", bundleFile, config.RepoDirName)
			os.RemoveAll(tmpDir)
			continue
		}
		if valid := tmpRepo.checkBundles(); !valid {
			fmt.Fprintf(os.Stderr, "bundle %s is not valid, skipped\n", bundleFile)
			os.RemoveAll(tmpDir)
			continue
		}
		err = fileutil.Untar(filepath.Dir(r.path), &buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot import archive %s to repo %s: %v\n", bundleFile, r.path, err)
			os.RemoveAll(tmpDir)
			continue
		}
		os.RemoveAll(tmpDir)
	}
	return nil
}

func (r *Repo) Alias(mfile string, bundleFilter func(*Bundle) bool) error {
	_, err := r.findManifest(mfile)
	if err != nil {
		return fmt.Errorf("alias: %v", err)
	}

	refBundles := []*Bundle{}
	bundles, err := r.AllBundles()
	if err != nil {
		return fmt.Errorf("alias: cannot find all bundles: %v", err)
	}
	for _, b := range bundles {
		if bundleFilter == nil || bundleFilter(b) {
			refBundles = append(refBundles, b)
		}
	}
	if len(refBundles) == 0 {
		fmt.Fprintf(os.Stderr, "alias: no qualified reference manifests to use for substitution\n")
		return nil
	}

	content, err := os.ReadFile(filepath.Clean(mfile))
	if err != nil {
		return fmt.Errorf("alias: cannot read manifest %s: %v", mfile, err)
	}
	w := Workload{}
	if err := json.Unmarshal(content, &w); err != nil {
		return fmt.Errorf("alias: cannot unmarshal manifest %s: %v", mfile, err)
	}

	mapAlias := make(map[string]string)
	mapSource := make(map[string]int)
	if err := aliasSubstitution(w.Layer, refBundles, mapAlias, mapSource); err != nil {
		return fmt.Errorf("alias: cannot alias %s: %v", mfile, err)
	}
	for i, layer := range w.Layer {
		if alias, found := mapAlias[layer]; found {
			w.Layer[i] = alias
		}
	}

	// insert the dependent bundles
	for b := range mapSource {
		if !hasBundle(w.Policy.Accept, b) {
			w.Policy.Accept = append(w.Policy.Accept, b)
		}
	}

	m, err := json.MarshalIndent(w, "", "    ")
	if err != nil {
		return fmt.Errorf("alias: cannot marshal resulting manifest file")
	}
	if err := os.WriteFile(mfile, m, 0600); err != nil {
		return fmt.Errorf("alias: cannot write out resulting manifest file")
	}
	return nil
}

func (r *Repo) BundleChain(mfile string) ([]*Bundle, error) {
	top, err := r.FindBundle(mfile)
	if err != nil {
		return nil, fmt.Errorf("get bundle chain: %v", err)
	}
	rmap := make(map[string]int)
	mEntries, err := r.findAllManifestEntry()
	if err != nil {
		return nil, fmt.Errorf("get bundle chain: cannot find all manifest entries: %v", err)
	}
	if err = r.getBundleDependency(mEntries, mfile, rmap); err != nil {
		return nil, fmt.Errorf("get bundle chain: cannot get bundle dependency: %v", err)
	}
	result := make([]*Bundle, 0, len(rmap)+1)
	for m := range rmap {
		result = append(result, NewBundle(m))
	}
	result = append(result, top)
	return result, nil
}

func (r *Repo) BlobPath(blob string) string {
	blobpath := filepath.Join(r.path, config.BlobDirName, blob+config.BlobExtension)
	return filepath.Clean(blobpath)
}

func (r *Repo) AllBundles() ([]*Bundle, error) {
	mEntries, err := r.findAllManifestEntry()
	if err != nil {
		return nil, fmt.Errorf("all bundles: cannot get all manifest entries: %v", err)
	}
	bundles := make([]*Bundle, len(mEntries))
	for i, e := range mEntries {
		b := NewBundle(e)
		bundles[i] = b
	}
	return bundles, nil
}

func (r *Repo) FindBundle(mfile string) (*Bundle, error) {
	mEntry, found := r.findManifestEntry(mfile)
	if !found {
		return nil, fmt.Errorf("cannot find bundle for manifest %s", mfile)
	}
	return NewBundle(mEntry), nil
}

func (r *Repo) findManifestEntry(id string) (string, bool) {
	dir := r.manifestDirPath()
	hashDirs, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	for _, h := range hashDirs {
		if h.IsDir() {
			hpath := filepath.Join(dir, h.Name())
			dirs, err := os.ReadDir(hpath)
			if err != nil {
				continue
			}
			for _, m := range dirs {
				if !m.IsDir() {
					continue
				}
				mpath := filepath.Join(hpath, m.Name())
				if strings.HasPrefix(m.Name(), id) ||
					isSameFile(id, filepath.Join(mpath, config.ManifestFileName)) {
					return mpath, true
				}
			}
		}
	}
	return "", false
}

func (r *Repo) findManifest(mfile string) (string, error) {
	mEntry, found := r.findManifestEntry(mfile)
	if !found {
		return "", fmt.Errorf("find manifest: cannot find %s in repo", mfile)
	}
	return filepath.Join(mEntry, config.ManifestFileName), nil
}

func (r *Repo) findAllManifestEntry() ([]string, error) {
	var manifests []string
	mDir := r.manifestDirPath()
	hashDirs, err := os.ReadDir(mDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("find all manifest dirs, read manifest directory: %v", err)
	}

	for _, h := range hashDirs {
		if h.IsDir() {
			hpath := filepath.Join(mDir, h.Name())
			dirs, err := os.ReadDir(hpath)
			if err != nil {
				continue
			}
			for _, m := range dirs {
				if m.IsDir() {
					mpath := filepath.Join(hpath, m.Name())
					manifests = append(manifests, mpath)
				}
			}
		}
	}
	return manifests, nil
}

func (r *Repo) findAllManifest() ([]string, error) {
	mEntries, err := r.findAllManifestEntry()
	if err != nil {
		return nil, fmt.Errorf("find all manifest files: %v", err)
	}
	manifests := make([]string, len(mEntries))
	for i, e := range mEntries {
		manifests[i] = filepath.Join(e, config.ManifestFileName)
	}
	return manifests, nil
}

func (r *Repo) generateBlobPath(blob []byte, hashAlgo string) (string, error) {
	digest, err := cryptoutil.BytesDigest(blob, hashAlgo)
	if err != nil {
		return "", fmt.Errorf("get blob path failed: %v", err)
	}
	base := fmt.Sprintf("%s"+config.BlobExtension, hex.EncodeToString(digest))
	return filepath.Join(r.blobDirPath(), hashAlgo, base), nil
}

func (r *Repo) getBlobDependency(mEntries []string, alias string, result map[string]int) (bool, error) {
	components := strings.Split(alias, "/")
	if len(components) != 4 || components[0] != "signer" {
		return false, fmt.Errorf("get blob dependency: malformed alias name %v", alias)
	}
	hashAlgo := components[1]
	hashValue := components[2]
	name := components[3]

	for _, mEntry := range mEntries {
		cert := filepath.Join(mEntry, config.CertFileName)
		_, err := os.Stat(cert)
		if err != nil {
			continue
		}
		d, a, err := cryptoutil.GetCertDigest(cert)
		if err != nil || a != hashAlgo || hex.EncodeToString(d) != hashValue {
			continue
		}

		manifest := filepath.Join(mEntry, config.ManifestFileName)
		// if manifest already recorded, there exists loop dependency
		if _, found := result[manifest]; found {
			return false, nil
		}
		content, err := os.ReadFile(filepath.Clean(manifest))
		if err != nil {
			continue
		}
		w := Workload{}
		if err := json.Unmarshal(content, &w); err != nil {
			continue
		}
		for layer, aliasList := range w.Alias.Content {
			for _, n := range aliasList {
				if n != name {
					continue
				}
				// successfully resolved
				if strings.HasPrefix(layer, "sha") {
					result[manifest]++
					return true, nil
				} else {
					// still in the form of alias, try to resolve again
					return r.getBlobDependency(mEntries, layer, result)
				}
			}
		}
	}
	return false, nil
}

func (r *Repo) getBundleDependency(mEntries []string, manifest string, result map[string]int) error {
	var deps map[string]int
	var blob Blob
	content, err := os.ReadFile(filepath.Clean(manifest))
	if err != nil {
		return fmt.Errorf("get bundle dependency for %v: %v", manifest, err)
	}

	if err := json.Unmarshal(content, &blob); err != nil {
		return fmt.Errorf("get bundle dependency for %v: %v", manifest, err)
	}

	for _, layer := range blob.Layer {
		if strings.HasPrefix(layer, "signer") {
			_, err := r.getBlobDependency(mEntries, layer, deps)
			if err != nil {
				return fmt.Errorf("get bundle dependency: %v", err)
			}

			for dep, count := range deps {
				if _, found := result[dep]; found {
					continue
				}
				result[dep] += count
				err := r.getBundleDependency(mEntries, dep, result)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *Repo) manifestDirPath() string {
	return filepath.Join(r.path, config.ManifestDirName)
}

func (r *Repo) blobDirPath() string {
	return filepath.Join(r.path, config.BlobDirName)
}

func (r *Repo) checkBundles() bool {
	bundles, err := r.AllBundles()
	if err != nil {
		return false
	}
	for _, b := range bundles {
		if !b.IsManifestUpdated() {
			return false
		}
		if !b.IsSignatureValid() {
			return false
		}
	}
	return true
}

func (r *Repo) blobInUse() (map[string]int, error) {
	bundles, err := r.AllBundles()
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	inUse := map[string]int{}

	primaryBlobNameLen := len(config.PrimaryHashAlgo) + 1 + config.PrimaryHashAlgoLen
	for _, b := range bundles {
		layers, err := b.Layers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot get layers from bundle %s: %v", b.path, err)
			continue
		}
		for _, layer := range layers {
			inUse[layer]++
			layerPath := filepath.Join(r.blobDirPath(), filepath.FromSlash(layer)+".tar")
			if t, err := os.Readlink(layerPath); err == nil {
				if !strings.HasPrefix(t, filepath.Join("..", config.PrimaryHashAlgo)+string(filepath.Separator)) ||
					len(t) < 3+primaryBlobNameLen {
					fmt.Fprintln(os.Stderr, "malformed symlink", layerPath)
				} else {
					inUse[filepath.ToSlash(t[3:3+primaryBlobNameLen])]++
				}
			}
		}
	}
	return inUse, nil
}

// test whether the file specified by 'parent/child' is a directory
func isDir(parent, child string) bool {
	finfo, err := os.Stat(filepath.Join(parent, child))
	if err != nil {
		return false
	}
	return finfo.IsDir()
}

// Get ACON repository path, searching from the specified directory
func findAconRepo(startingDir string) (string, error) {
	userHomeDir, err := os.UserHomeDir()
	if err != nil {
		userHomeDir = "/"
	}

	startDirAbs, err := filepath.Abs(startingDir)
	if err != nil {
		return "", err
	}

	currDir := startDirAbs
	for {
		if found := isDir(currDir, config.RepoDirName); found {
			return filepath.Join(currDir, config.RepoDirName), nil
		}
		if isSameFile(currDir, userHomeDir) {
			return "", fmt.Errorf("repo not found, reach %s", currDir)
		}
		currDir = filepath.Dir(currDir)
	}
}

func isSameFile(f1, f2 string) bool {
	fi1, err := os.Stat(f1)
	if err != nil {
		return false
	}
	fi2, err := os.Stat(f2)
	if err != nil {
		return false
	}
	return os.SameFile(fi1, fi2)
}

func createSymlink(oldname, newname string) error {
	oldAbs, err := filepath.Abs(oldname)
	if err != nil {
		return err
	}
	newAbs, err := filepath.Abs(newname)
	if err != nil {
		return err
	}

	rel, err := filepath.Rel(filepath.Dir(newAbs), oldAbs)
	if err != nil {
		return err
	}

	// remove obsolete symlink
	if finfo, err := os.Lstat(newname); err == nil {
		if finfo.Mode()&fs.ModeSymlink == fs.ModeSymlink {
			os.Remove(newname)
		}
	}
	return os.Symlink(rel, newname)
}

func canonicalJson(data []byte) ([]byte, error) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func getFileRepoPath(path string) string {
	if index := strings.LastIndex(path, config.RepoDirName); index >= 0 {
		return string(path[index:])
	} else {
		return path
	}
}

func aliasSubstitution(layers []string, refs []*Bundle, alias map[string]string, source map[string]int) error {
	// termination condition for the recursive searching
	if len(layers) == 0 || len(refs) == 0 {
		return nil
	}

	// check all the possible matches in next reference manifest
	bundle := refs[0]
	mfile := bundle.Manifest()

	content, err := os.ReadFile(filepath.Clean(mfile))
	if err != nil {
		return nil
	}
	content, err = canonicalJson(content)
	if err != nil {
		return nil
	}

	w := Workload{}
	if err := json.Unmarshal(content, &w); err != nil {
		return fmt.Errorf("cannot unmarshal %s: %v", mfile, err)
	}

	unresolved := []string{}
	for _, d := range layers {
		if names, found := w.Alias.Content[d]; found {
			digest, algo, err := bundle.SignerDigest()
			if err != nil {
				return fmt.Errorf("cannot get cert digest for %s: %v", bundle.Cert(), err)
			}
			signer := hex.EncodeToString(digest)
			s := fmt.Sprintf("signer/%s/%s/%s", algo, signer, names[0])
			alias[d] = s

			var bundleName string
			if prods, found := w.Alias.Self["."]; found {
				bundleName = prods[0]
			} else {
				digest, err := cryptoutil.BytesDigest(content, algo)
				if err != nil {
					fmt.Fprintf(os.Stderr, "cannot get digest for manifest %s: %v\n", mfile, err)
					continue
				} else {
					bundleName = hex.EncodeToString(digest)
				}
			}
			bundleID := fmt.Sprintf("%s/%s/%s", algo, signer, bundleName)
			source[bundleID]++
		} else {
			unresolved = append(unresolved, d)
		}
	}

	// next round searching
	return aliasSubstitution(unresolved, refs[1:], alias, source)
}

func hasBundle(bundles []string, b string) bool {
	for _, bundle := range bundles {
		if bundle == b {
			return true
		}
	}
	return false
}
