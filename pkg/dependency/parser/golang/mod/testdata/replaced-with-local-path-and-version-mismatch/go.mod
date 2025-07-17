module github.com/org/repo

go 1.24.4

toolchain go1.24.5

require github.com/aquasecurity/trivy v0.64.1

require (
	github.com/fatih/color v1.18.0 // indirect
	github.com/google/go-containerregistry v0.20.6 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/package-url/packageurl-go v0.1.3 // indirect
	github.com/samber/lo v1.51.0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	golang.org/x/xerrors v0.0.0-20240716161551-93cc26a95ae9 // indirect
	k8s.io/utils v0.0.0-20241104100929-3ea5e8cea738 // indirect
)

replace golang.org/x/xerrors v0.0.1 => ./xerrors
