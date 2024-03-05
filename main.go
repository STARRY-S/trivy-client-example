package main

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"

	tcache "github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/sirupsen/logrus"

	_ "modernc.org/sqlite" // sqlite driver for RPM DB and Java DB
)

func main() {
	serverFlag := flag.String("server", "", "trivy server URL")
	imageFlag := flag.String("image", "", "image reference")
	insecureFlag := flag.Bool("insecure", false, "skip tls verify")
	debugFlag := flag.Bool("debug", false, "show debug output")
	flag.Parse()

	if *debugFlag {
		logrus.SetLevel(logrus.DebugLevel)
	}
	log.InitLogger(*debugFlag, false)
	if *serverFlag == "" {
		logrus.Errorf("trivy server not provided")
		flag.Usage()
		os.Exit(1)
	}
	if *imageFlag == "" {
		logrus.Errorf("image reference not provided")
		flag.Usage()
		os.Exit(1)
	}

	initDB(insecureFlag)

	clientScanner := client.NewScanner(client.ScannerOption{
		RemoteURL: *serverFlag,
		Insecure:  *insecureFlag,
	}, []client.Option(nil)...)

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

	remoteCache := tcache.NewRemoteCache(*serverFlag, http.Header{}, *insecureFlag)
	cache := tcache.NopCache(remoteCache)
	artifactArtifact, err := image2.NewArtifact(typesImage, cache, artifact.Option{
		DisabledAnalyzers: []analyzer.Type{},
		DisabledHandlers:  nil,
		SkipFiles:         nil,
		SkipDirs:          nil,
		FilePatterns:      nil,
		NoProgress:        false,
		Insecure:          *insecureFlag,
		SBOMSources:       nil,
		RekorURL:          "https://rekor.sigstore.dev",
		Parallel:          1,
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

	scannerScanner := scanner.NewScanner(clientScanner, artifactArtifact)
	report, err := scannerScanner.ScanArtifact(context.TODO(), types.ScanOptions{
		VulnType:            types.VulnTypes,
		Scanners:            types.AllScanners,
		ImageConfigScanners: nil,
		ScanRemovedPackages: false,
		ListAllPackages:     false,
		// LicenseCategories:   types.AllImageConfigScanners,
		FilePatterns:   nil,
		IncludeDevDeps: false,
	})
	if err != nil {
		logrus.Fatalf("ScanArtifact failed: %v", err)
	}
	if len(report.Results) == 0 {
		logrus.Infof("No results output...")
		return
	}

	for _, result := range report.Results {
		b, _ := json.MarshalIndent(result, "", "  ")
		logrus.Infof("%v", string(b))
	}
}

func initDB(insecure *bool) {
	javadb.Init(
		// "~/.cache/trivy" on Linux
		// "~/Library/Caches/trivy" on darwin
		fsutils.CacheDir(),
		"ghcr.io/aquasecurity/trivy-java-db",
		false, false,
		ftypes.RegistryOptions{
			Credentials:   nil,
			RegistryToken: "",
			Insecure:      *insecure,
			Platform:      ftypes.Platform{},
			AWSRegion:     "",
		},
	)
}
