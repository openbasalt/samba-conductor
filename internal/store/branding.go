package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// BrandingVersion is one saved version of the branding.
type BrandingVersion struct {
	Version      int64
	Data         string // JSON of branding.Branding
	CreatedAt    time.Time
	CreatedBy    string
	RevertedFrom int64
}

// BrandingAsset is a stored image.
type BrandingAsset struct {
	SHA256      string
	ContentType string
	Data        []byte
}

// ErrStale is returned when the branding changed since the editor read it.
var ErrStale = errors.New("store: changed since it was read")

// KeepBrandingVersions bounds the history.
const KeepBrandingVersions = 50

// CurrentBranding returns the newest version, or ErrNotFound when the
// branding was never saved (the product look).
func (s *Store) CurrentBranding(ctx context.Context) (*BrandingVersion, error) {
	return s.brandingVersion(ctx, `SELECT version, data, created_at, created_by, reverted_from FROM branding_versions ORDER BY version DESC LIMIT 1`)
}

// GetBrandingVersion returns one version or ErrNotFound.
func (s *Store) GetBrandingVersion(ctx context.Context, version int64) (*BrandingVersion, error) {
	return s.brandingVersion(ctx, `SELECT version, data, created_at, created_by, reverted_from FROM branding_versions WHERE version = ?`, version)
}

func (s *Store) brandingVersion(ctx context.Context, q string, args ...any) (*BrandingVersion, error) {
	var v BrandingVersion
	var at string
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&v.Version, &v.Data, &at, &v.CreatedBy, &v.RevertedFrom)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	v.CreatedAt = parseTS(at)
	return &v, nil
}

// BrandingVersions lists the kept versions, newest first.
func (s *Store) BrandingVersions(ctx context.Context) ([]BrandingVersion, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version, data, created_at, created_by, reverted_from FROM branding_versions ORDER BY version DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []BrandingVersion
	for rows.Next() {
		var v BrandingVersion
		var at string
		if err := rows.Scan(&v.Version, &v.Data, &at, &v.CreatedBy, &v.RevertedFrom); err != nil {
			return nil, err
		}
		v.CreatedAt = parseTS(at)
		out = append(out, v)
	}
	return out, rows.Err()
}

// SaveBranding stores a new version on top of base (ErrStale when another
// save came first) with the images it references (hashes; new ones in
// assets), prunes the history and the images no kept version uses, and
// returns the new version number.
func (s *Store) SaveBranding(ctx context.Context, base int64, data string, hashes []string, assets []BrandingAsset, by string, revertedFrom int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var cur int64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM branding_versions`).Scan(&cur); err != nil {
		return 0, err
	}
	if cur != base {
		return 0, ErrStale
	}
	next := cur + 1
	now := ts(s.now())
	if _, err := tx.ExecContext(ctx, `INSERT INTO branding_versions(version, data, created_at, created_by, reverted_from) VALUES (?, ?, ?, ?, ?)`,
		next, data, now, clip(by, 256), revertedFrom); err != nil {
		return 0, err
	}
	for _, a := range assets {
		if _, err := tx.ExecContext(ctx, `INSERT INTO branding_assets(sha256, content_type, data, created_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(sha256) DO NOTHING`, a.SHA256, a.ContentType, a.Data, now); err != nil {
			return 0, err
		}
	}
	for _, h := range hashes {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM branding_assets WHERE sha256 = ?`, h).Scan(&n); err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, errors.New("store: branding image missing: " + h)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO branding_version_assets(version, sha256) VALUES (?, ?)`, next, h); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM branding_versions WHERE version <= ?`, next-KeepBrandingVersions); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM branding_assets WHERE sha256 NOT IN (SELECT sha256 FROM branding_version_assets)`); err != nil {
		return 0, err
	}
	return next, tx.Commit()
}

// BrandingAssets returns the stored images with these digests.
func (s *Store) BrandingAssets(ctx context.Context, hashes []string) ([]BrandingAsset, error) {
	var out []BrandingAsset
	for _, h := range hashes {
		var a BrandingAsset
		err := s.db.QueryRowContext(ctx, `SELECT sha256, content_type, data FROM branding_assets WHERE sha256 = ?`, h).
			Scan(&a.SHA256, &a.ContentType, &a.Data)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}
