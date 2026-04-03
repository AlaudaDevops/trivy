package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/moby/moby/client"
	"golang.org/x/xerrors"

	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

// imageInspectExtra captures fields that are still returned by the daemon JSON API,
// but are not represented in the current moby inspect response struct.
type imageInspectExtra struct {
	// Container stores the legacy container ID used to create the image.
	Container string `json:"Container,omitempty"`
	// DockerVersion stores the daemon version used to build the image.
	DockerVersion string `json:"DockerVersion,omitempty"`
}

// DockerImage implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func DockerImage(ref name.Reference, host string) (Image, func(), error) {
	cleanup := func() {}

	// Resolve Docker host based on priority: --docker-host > DOCKER_HOST > DOCKER_CONTEXT > current context
	resolvedHost, err := resolveDockerHost(host)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to resolve Docker host: %w", err)
	}

	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}
	if resolvedHost != "" {
		opts = append(opts, client.WithHost(resolvedHost))
	}
	c, err := client.NewClientWithOpts(opts...)

	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to initialize a docker client: %w", err)
	}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()

	// <image_name>:<tag> pattern like "alpine:3.15"
	// or
	// <image_name>@<digest> pattern like "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300"
	imageID := ref.Name()
	inspectRaw := bytes.NewBuffer(nil)
	inspect, err := c.ImageInspect(context.Background(), imageID, client.ImageInspectWithRawResponse(inspectRaw))
	if err != nil {
		imageID = ref.String() // <image_id> pattern like `5ac716b05a9c`
		inspectRaw.Reset()
		inspect, err = c.ImageInspect(context.Background(), imageID, client.ImageInspectWithRawResponse(inspectRaw))
		if err != nil {
			return nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", imageID, err)
		}
	}
	var inspectExtra imageInspectExtra
	if err = json.Unmarshal(inspectRaw.Bytes(), &inspectExtra); err != nil {
		return nil, cleanup, xerrors.Errorf("unable to parse image inspect response (%s): %w", imageID, err)
	}

	history, err := c.ImageHistory(context.Background(), imageID)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to get history (%s): %w", imageID, err)
	}

	f, err := xos.CreateTemp("", "docker-export-")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to create a temporary file: %w", err)
	}

	cleanup = func() {
		_ = c.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener: imageOpener(context.Background(), imageID, f,
			func(ctx context.Context, imageIDs []string, saveOpts ...client.ImageSaveOption) (io.ReadCloser, error) {
				return c.ImageSave(ctx, imageIDs, saveOpts...)
			},
		),
		inspect:       inspect.InspectResponse,
		history:       configHistory(history.Items),
		container:     inspectExtra.Container,
		dockerVersion: inspectExtra.DockerVersion,
	}, cleanup, nil
}
