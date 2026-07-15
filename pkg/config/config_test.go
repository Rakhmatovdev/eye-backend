package config

import "testing"

func TestIsWeakSecret(t *testing.T) {
	weak := []string{
		"short",
		"default-secret-change-in-production-32chars",
		"anything-with-change-in-production-here",
	}
	for _, s := range weak {
		if !isWeakSecret(s) {
			t.Errorf("expected %q to be weak", s)
		}
	}
	strong := "76bbd9482b67ec3acef969d88451245b100eb818ee6fa8bf212fc82d776374b1"
	if isWeakSecret(strong) {
		t.Errorf("expected %q to be strong", strong)
	}
}

func TestIsProduction(t *testing.T) {
	if !(&Config{Environment: "production"}).IsProduction() {
		t.Error("production should be production")
	}
	if !(&Config{Environment: "PROD"}).IsProduction() {
		t.Error("PROD should be production")
	}
	if (&Config{Environment: "development"}).IsProduction() {
		t.Error("development is not production")
	}
}
