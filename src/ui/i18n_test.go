//go:build windows

package ui

import "testing"

func TestResolveStartupLanguagePrefersAvailableUILanguageBundle(t *testing.T) {
	previousPreferred := getPreferredUILanguages
	previousLocale := detectLocaleLanguage
	previousExists := uiLanguageBundleExists
	defer func() {
		getPreferredUILanguages = previousPreferred
		detectLocaleLanguage = previousLocale
		uiLanguageBundleExists = previousExists
	}()

	getPreferredUILanguages = func() ([]string, error) {
		return []string{"fr-FR", "en-US", "zh-CN"}, nil
	}
	detectLocaleLanguage = func() string {
		return "zh_CN"
	}
	uiLanguageBundleExists = func(language string) bool {
		return language == "en_US" || language == "zh_CN"
	}

	got := resolveStartupLanguage("auto")
	if got != "en_US" {
		t.Fatalf("resolveStartupLanguage(auto) = %q, want %q", got, "en_US")
	}
}

func TestResolveStartupLanguageFallsBackToLocaleThenDefaultBundle(t *testing.T) {
	previousPreferred := getPreferredUILanguages
	previousLocale := detectLocaleLanguage
	previousExists := uiLanguageBundleExists
	defer func() {
		getPreferredUILanguages = previousPreferred
		detectLocaleLanguage = previousLocale
		uiLanguageBundleExists = previousExists
	}()

	getPreferredUILanguages = func() ([]string, error) {
		return []string{"fr-FR", "de-DE"}, nil
	}
	detectLocaleLanguage = func() string {
		return "en_US"
	}
	uiLanguageBundleExists = func(language string) bool {
		return language == "zh_CN"
	}

	got := resolveStartupLanguage("auto")
	if got != "zh_CN" {
		t.Fatalf("resolveStartupLanguage(auto) = %q, want %q", got, "zh_CN")
	}
}
