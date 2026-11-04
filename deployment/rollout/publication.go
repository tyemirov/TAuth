package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const rolloutImageDeclaration = "tauth-image"

// selectedImage consumes the current declaration receipts after Gateway preflight.
// It joins prepared content, its publication envelope, and the published image.
func selectedImage(root string) (string, string, error) {
	gitPath, err := exec.Command("git", "-C", root, "rev-parse", "--git-path", "mprlab-lifecycle").Output()
	if err != nil {
		return "", "", err
	}
	lifecycle := strings.TrimSpace(string(gitPath))
	if !filepath.IsAbs(lifecycle) {
		lifecycle = filepath.Join(root, lifecycle)
	}
	var current struct {
		Preparation      string `json:"preparation"`
		PublicationState string `json:"publication_state"`
		Release          struct {
			Version   string `json:"version"`
			Artifacts []struct {
				Catalog        string `json:"catalog"`
				DeclarationID  string `json:"declaration_id"`
				ID, Kind, Path string
			} `json:"artifacts"`
		} `json:"release"`
		Publication struct {
			Version            string                                           `json:"version"`
			PublishedArtifacts map[string][]struct{ ID, Kind, Identity string } `json:"published_artifacts"`
		} `json:"publication"`
	}
	payload, err := os.ReadFile(filepath.Join(lifecycle, "current-release.json"))
	if err != nil {
		return "", "", err
	}
	if err = json.Unmarshal(payload, &current); err != nil {
		return "", "", fmt.Errorf("read current release: %w", err)
	}
	version := current.Release.Version
	if !strings.HasPrefix(version, "v") || strings.ContainsAny(version, "/\\") {
		return "", "", errors.New("cutover.release_selection_invalid")
	}
	if current.Preparation != "sealed" || current.PublicationState != "published" || current.Publication.Version != version {
		return "", "", errors.New("cutover.publication_invalid")
	}
	releaseRoot := filepath.Join(lifecycle, "releases", version)
	contentCount, publicationCount := 0, 0
	publicationPath := ""
	for _, artifact := range current.Release.Artifacts {
		if artifact.DeclarationID != rolloutImageDeclaration || artifact.ID != "prepare" {
			continue
		}
		if artifact.Catalog == "artifact" && artifact.Kind == "container_image" {
			contentCount++
		}
		if artifact.Catalog == "publication" && artifact.Kind == "ghcr_image" {
			publicationCount++
			publicationPath = artifact.Path
		}
	}
	if contentCount > 1 || publicationCount > 1 {
		return "", "", errors.New("cutover.image_ambiguous")
	}
	if contentCount == 0 || publicationCount == 0 {
		return "", "", errors.New("cutover.image_absent")
	}
	if !filepath.IsLocal(publicationPath) {
		return "", "", errors.New("cutover.publication_invalid")
	}
	var envelope struct {
		Result struct {
			SchemaVersion                                 int `json:"schema_version"`
			Owner, Publication, Artifact, Family, Version string
			Destination                                   struct{ Repository string }
		}
	}
	payload, err = os.ReadFile(filepath.Join(releaseRoot, publicationPath))
	if err != nil {
		return "", "", fmt.Errorf("read sealed image publication: %w", err)
	}
	if err = json.Unmarshal(payload, &envelope); err != nil {
		return "", "", fmt.Errorf("read sealed image publication: %w", err)
	}
	publication := envelope.Result
	if publication.SchemaVersion != 1 || publication.Owner != "tauth" || publication.Publication != rolloutImageDeclaration || publication.Artifact != rolloutImageDeclaration || publication.Family != "ghcr_image" || publication.Version != version || publication.Destination.Repository == "" {
		return "", "", errors.New("cutover.publication_invalid")
	}
	identity := ""
	publishedCount := 0
	for _, artifact := range current.Publication.PublishedArtifacts[rolloutImageDeclaration] {
		if artifact.ID == "image" && artifact.Kind == "container_image" {
			publishedCount++
			identity = artifact.Identity
		}
	}
	if publishedCount > 1 {
		return "", "", errors.New("cutover.image_ambiguous")
	}
	if publishedCount == 0 {
		return "", "", errors.New("cutover.image_absent")
	}
	if identity != publication.Destination.Repository+":"+strings.TrimPrefix(version, "v") {
		return "", "", errors.New("cutover.image_identity_invalid")
	}
	return identity, releaseRoot, nil
}
