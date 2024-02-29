package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/langpkg"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/sirupsen/logrus"
)

func main() {
	imageFlag := flag.String("image", "", "image reference")
	insecureFlag := flag.Bool("insecure", false, "skip tls verify")
	// outputTypeFlag := flag.String("output", "tabel", "output type: tabel, json")
	flag.Parse()

	if *imageFlag == "" {
		logrus.Errorf("image reference not provided")
		flag.Usage()
		os.Exit(1)
	}

	// standalone mode
	fsCache, err := cache.NewFSCache(fsutils.CacheDir())
	if err != nil {
		logrus.Fatalf("Failed to init fs cache: %v", err)
	}

	applierApplier := applier.NewApplier(fsCache)
	ospkgScanner := ospkg.NewScanner()
	langpkgScanner := langpkg.NewScanner()
	config := db.Config{}
	client := vulnerability.NewClient(config)
	localScanner := local.NewScanner(applierApplier, ospkgScanner, langpkgScanner, client)

	typesImage, cleanup, err := image.NewContainerImage(context.TODO(), *imageFlag, ftypes.ImageOptions{
		RegistryOptions: ftypes.RegistryOptions{
			Insecure: *insecureFlag,
		},
		DockerOptions: ftypes.DockerOptions{},
		ImageSources:  ftypes.AllImageSources,
	})
	if err != nil {
		logrus.Fatalf("NewContainerImage failed: %v", err)
	}
	defer cleanup()

	artifactArtifact, err := image2.NewArtifact(typesImage, fsCache, artifact.Option{
		ImageOption: ftypes.ImageOptions{
			RegistryOptions: ftypes.RegistryOptions{
				Insecure: *insecureFlag,
			},
			DockerOptions: ftypes.DockerOptions{},
			ImageSources:  ftypes.AllImageSources,
		},
	})
	if err != nil {
		logrus.Fatalf("NewArtifact failed: %v", err)
	}

	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	report, err := scannerScanner.ScanArtifact(context.TODO(), types.ScanOptions{
		Scanners: types.AllScanners,
	})
	if err != nil {
		logrus.Fatalf("ScanArtifact failed: %v", err)
	}
	if len(report.Results) == 0 {
		logrus.Infof("No vulnerabilities found...")
		return
	}

	for _, result := range report.Results {
		b, _ := json.MarshalIndent(result, "", "  ")
		logrus.Infof("%v", string(b))
	}
}
