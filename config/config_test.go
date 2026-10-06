package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	d := Default()
	if d.Workers != 10 || d.MaxFileSize != "5M" || d.NoColor || d.Debug {
		t.Fatalf("unexpected defaults: %+v", d)
	}
}

func TestLoadExplicitPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"workers": 4, "debug": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := v.GetInt("workers"); got != 4 {
		t.Fatalf("workers = %d, want 4", got)
	}
	var c Config
	if err := v.Unmarshal(&c); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if c.Workers != 4 || !c.Debug {
		t.Fatalf("unexpected Config: %+v", c)
	}
}

func TestLoadExplicitMissingPathErrors(t *testing.T) {
	// An explicitly requested config file that does not exist is a user
	// error and must not be silently ignored: Load must return a
	// non-nil error.
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	v, err := Load(filepath.Join(dir, "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error for missing explicit config path, got nil")
	}
	if v == nil {
		t.Fatal("expected non-nil viper")
	}
}

func TestLoadImplicitMissingIsNotAnError(t *testing.T) {
	// No config anywhere is the normal case for a first run, so implicit
	// discovery failure must be swallowed and defaults applied.
	t.Setenv("HOME", t.TempDir())
	v, err := Load("")
	if err != nil {
		t.Fatalf("expected nil error when no config exists, got: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil viper")
	}
	if got := v.GetInt("workers"); got != 10 {
		t.Fatalf("workers = %d, want default 10", got)
	}
}

func TestLoadMalformedFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{not valid json`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for malformed config, got nil")
	}
}

func TestLoadIgnoresUserHomeConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	homeCfg := filepath.Join(dir, ".config", "syck")
	if err := os.MkdirAll(homeCfg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(homeCfg, "config.json"), []byte(`{"workers": 99}`), 0o644); err != nil {
		t.Fatal(err)
	}
	explicit := filepath.Join(dir, "explicit.json")
	if err := os.WriteFile(explicit, []byte(`{"workers": 3}`), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := Load(explicit)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := v.GetInt("workers"); got != 3 {
		t.Fatalf("workers = %d, want 3 (explicit path, not home config)", got)
	}
}
