package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	dimage "github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
	"golang.org/x/xerrors"

	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

var (
	inspectURL = "http://podman/images/%s/json"
	historyURL = "http://podman/images/%s/history"
	saveURL    = "http://podman/images/%s/get"
)

type podmanClient struct {
	c http.Client
}

func newPodmanClient(host string) (podmanClient, error) {
	// Get Podman socket location
	sockDir := os.Getenv("XDG_RUNTIME_DIR")
	socket := filepath.Join(sockDir, "podman", "podman.sock")
	if host != "" {
		socket = host
	}
	socket = filepath.Clean(socket)
	if !filepath.IsAbs(socket) {
		return podmanClient{}, xerrors.Errorf("podman socket path must be absolute: %s", socket)
	}

	root, err := os.OpenRoot(filepath.Dir(socket))
	if err != nil {
		return podmanClient{}, xerrors.Errorf("failed to open podman socket directory: %w", err)
	}
	defer root.Close()

	if _, err = root.Stat(filepath.Base(socket)); err != nil {
		return podmanClient{}, xerrors.Errorf("no podman socket found: %w", err)
	}

	dialer := &net.Dialer{}
	return podmanClient{
		c: http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return dialer.DialContext(context.Background(), "unix", socket) //nolint:gosec // socket path is validated as a local absolute filesystem path above
				},
			},
		},
	}, nil
}

type errResponse struct {
	Message string
}

func (p podmanClient) imageInspect(imageName string) (dimage.InspectResponse, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, podmanURL(inspectURL, imageName), http.NoBody)
	if err != nil {
		return dimage.InspectResponse{}, xerrors.Errorf("request creation error: %w", err)
	}
	resp, err := p.c.Do(req)
	if err != nil {
		return dimage.InspectResponse{}, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var res errResponse
		if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return dimage.InspectResponse{}, xerrors.Errorf("unknown status code from Podman: %d", resp.StatusCode)
		}
		return dimage.InspectResponse{}, xerrors.New(res.Message)
	}

	var inspect dimage.InspectResponse
	if err = json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return dimage.InspectResponse{}, xerrors.Errorf("unable to decode JSON: %w", err)
	}
	return inspect, nil
}

func (p podmanClient) imageHistoryInspect(imageName string) ([]dimage.HistoryResponseItem, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, podmanURL(historyURL, imageName), http.NoBody)
	if err != nil {
		return []dimage.HistoryResponseItem{}, xerrors.Errorf("request creation error: %w", err)
	}
	resp, err := p.c.Do(req)
	if err != nil {
		return []dimage.HistoryResponseItem{}, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var res errResponse
		if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
			return []dimage.HistoryResponseItem{}, xerrors.Errorf("unknown status code from Podman: %d", resp.StatusCode)
		}
		return []dimage.HistoryResponseItem{}, xerrors.New(res.Message)
	}

	var history []dimage.HistoryResponseItem
	if err = json.NewDecoder(resp.Body).Decode(&history); err != nil {
		return []dimage.HistoryResponseItem{}, xerrors.Errorf("unable to decode JSON: %w", err)
	}
	return history, nil
}

func (p podmanClient) imageSave(_ context.Context, imageNames []string, _ ...client.ImageSaveOption) (io.ReadCloser, error) {
	if len(imageNames) < 1 {
		return nil, xerrors.Errorf("no specified image")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, podmanURL(saveURL, imageNames[0]), http.NoBody)
	if err != nil {
		return nil, xerrors.Errorf("request creation error: %w", err)
	}
	resp, err := p.c.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("http error: %w", err)
	}
	return resp.Body, nil
}

func podmanURL(template, imageName string) string {
	return fmt.Sprintf(template, imageName)
}

// PodmanImage implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func PodmanImage(ref, host string) (Image, func(), error) {
	cleanup := func() {}

	c, err := newPodmanClient(host)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to initialize Podman client: %w", err)
	}
	inspect, err := c.imageInspect(ref)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", ref, err)
	}

	history, err := c.imageHistoryInspect(ref)
	if err != nil {
		return nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", ref, err)
	}

	f, err := xos.CreateTemp("", "podman-export-")
	if err != nil {
		return nil, cleanup, xerrors.Errorf("failed to create a temporary file: %w", err)
	}

	cleanup = func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(context.Background(), ref, f, c.imageSave),
		inspect: inspect,
		history: configHistory(history),
	}, cleanup, nil
}
