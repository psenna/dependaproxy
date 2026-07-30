// Package maven is the Maven registry adapter. v2 ships only the skeleton:
// the data model (maven-metadata.xml) and adapter registration with a 501
// placeholder handler. Full Maven Central routing + storage land in a future
// issue. It proves a new registry slots in via the adapter contract with no
// shared-core changes.
package maven

import "encoding/xml"

// Metadata models a Maven maven-metadata.xml document.
type Metadata struct {
	XMLName    xml.Name   `xml:"metadata"`
	GroupID    string     `xml:"groupId"`
	ArtifactID string     `xml:"artifactId"`
	Versioning Versioning `xml:"versioning"`
}

// Versioning is the <versioning> block of maven-metadata.xml.
type Versioning struct {
	Latest      string   `xml:"latest"`
	Release     string   `xml:"release"`
	Versions    []string `xml:"versions>version"`
	LastUpdated string   `xml:"lastUpdated"`
}

// Artifact identifies one Maven artifact (a file within a release).
type Artifact struct {
	GroupID    string
	ArtifactID string
	Version    string
	Classifier string // may be empty
	Type       string // jar, pom, war, ... (default "jar")
}
