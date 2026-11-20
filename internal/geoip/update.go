package geoip

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// DownloadBase is where DB-IP publishes its free libraries.
var DownloadBase = "https://download.db-ip.com/free/"

// URLFor is DB-IP's free country library for a month (published at the
// start of each month).
func URLFor(t time.Time) string {
	return DownloadBase + "dbip-country-lite-" + t.UTC().Format("2006-01") + ".mmdb.gz"
}

// maxDownload bounds the uncompressed library (the lite file is ~8 MB).
const maxDownload = 256 << 20

// Update downloads the newest DB-IP lite library (this month's, else
// last month's while this month's is not out yet), checks that it opens
// as a country library, and atomically replaces dest. It returns the URL
// used and the new library's info. dest is untouched on any failure.
func Update(ctx context.Context, client *http.Client, dest string, now time.Time) (string, Info, error) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return "", Info{}, err
	}
	var errs []error
	for _, t := range []time.Time{now, now.AddDate(0, 0, -now.Day())} { // this month, then last
		url := URLFor(t)
		info, err := fetch(ctx, client, url, dest)
		if err == nil {
			return url, info, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", url, err))
		if ctx.Err() != nil {
			break
		}
	}
	return "", Info{}, errors.Join(errs...)
}

func fetch(ctx context.Context, client *http.Client, url, dest string) (Info, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Info{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Info{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Info{}, fmt.Errorf("HTTP %s", resp.Status)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return Info{}, fmt.Errorf("not a gzip file: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".country-*.mmdb")
	if err != nil {
		return Info{}, err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	n, err := io.Copy(tmp, io.LimitReader(zr, maxDownload+1))
	if err == nil && n > maxDownload {
		err = fmt.Errorf("larger than %d MB", maxDownload>>20)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Info{}, err
	}
	d, err := Open(tmp.Name())
	if err != nil {
		return Info{}, err
	}
	info := d.Info()
	d.Close()
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return Info{}, err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return Info{}, err
	}
	return info, nil
}
