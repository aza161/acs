package main

import (
	"acs/internal/jsonutils"
	"acs/pkg/passutils"
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/google/uuid"
)

// ------------------------------------------------------------
// CONFIG + FILE PATHS
// ------------------------------------------------------------

type AppConfig struct {
	ClientID  string `json:"client_id"`
	VaultPath string `json:"vault_path"`
}

const (
	configDirName  = ".acs_passmgr"
	configFileName = "config.json"
	vaultFileName  = "vault.json"
)

// ------------------------------------------------------------
// ENTRYPOINT
// ------------------------------------------------------------

func main() {
	if err := run(); err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
}

func run() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := filepath.Join(home, configDirName)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return err
	}

	configPath := filepath.Join(configDir, configFileName)
	cfg, err := loadOrCreateConfig(configPath, configDir)
	if err != nil {
		return err
	}

	vaultPath := cfg.VaultPath
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== ACS Secure Password Manager ===")
	fmt.Println("Config loaded for client:", cfg.ClientID)
	fmt.Println()

	var entries []jsonutils.Entry
	var master string

	if fileExists(vaultPath) {
		for {
			master = promptHidden("Enter master password: ")

			encVault, err := readEncryptedVault(vaultPath)
			if err != nil {
				// don’t reveal decryption errors
				fmt.Println("An error occurred while opening the vault")
				continue
			}

			entries, err = jsonutils.DecryptPasswords(master, encVault)
			if err != nil {
				// don’t reveal decryption errors
				fmt.Println("An error occurred while opening the vault")
				continue
			}

			break
		}
		fmt.Printf("Vault unlocked. %d entries loaded.\n\n", len(entries))
	} else {
		// new vault → create master
		fmt.Println("No vault found. Let's create one.")
		for {
			master = promptHidden("Create master password: ")
			confirm := promptHidden("Confirm master password: ")
			if master != confirm {
				fmt.Println("Passwords do not match, try again.")
				continue
			}

			// ✅ FIX: pass a non-nil symbols pointer and 0 min symbols
			emptySymbols := ""
			if err := passutils.CheckPasswordStrength(master, nil, &emptySymbols, 0); err != nil {
				fmt.Println("Password not strong enough:", err)
				continue
			}

			fmt.Println("Master password accepted ✅")
			break
		}

		entries = []jsonutils.Entry{}
		if err := writeEncryptedVault(vaultPath, master, entries); err != nil {
			return err
		}
		fmt.Println("Vault created.\n")
	}

	// main menu
	for {
		fmt.Println("Choose an option:")
		fmt.Println("1) Add password")
		fmt.Println("2) List entries (URLs)")
		fmt.Println("3) View entry details")
		fmt.Println("4) Generate password (customizable)")
		fmt.Println("5) Save & Exit")
		fmt.Print("> ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			newEntry, err := addPasswordFlow(entries)
			if err != nil {
				fmt.Println("error adding password:", err)
				continue
			}
			entries = append(entries, newEntry)
			if err := writeEncryptedVault(vaultPath, master, entries); err != nil {
				fmt.Println("error saving vault:", err)
			} else {
				fmt.Println("Entry added and saved.")
			}
		case "2":
			listEntries(entries)
		case "3":
			viewEntryDetails(entries)
		case "4":
			gen := passwordGenerationFlow()
			fmt.Println("Generated password:", gen)
			fmt.Println("You can use this when adding a new password (option 1).")
		case "5":
			if err := writeEncryptedVault(vaultPath, master, entries); err != nil {
				fmt.Println("error saving vault:", err)
			}
			fmt.Println("Goodbye 👋")
			return nil
		default:
			fmt.Println("invalid choice")
		}
		fmt.Println()
	}
}

// ------------------------------------------------------------
// CONFIG HANDLING
// ------------------------------------------------------------

func loadOrCreateConfig(configPath, baseDir string) (AppConfig, error) {
	if fileExists(configPath) {
		f, err := os.Open(configPath)
		if err != nil {
			return AppConfig{}, err
		}
		defer f.Close()

		var cfg AppConfig
		if err := json.NewDecoder(f).Decode(&cfg); err != nil {
			return AppConfig{}, err
		}
		if cfg.VaultPath == "" {
			cfg.VaultPath = filepath.Join(baseDir, vaultFileName)
			_ = saveConfig(configPath, cfg)
		}
		return cfg, nil
	}

	cfg := AppConfig{
		ClientID:  uuid.NewString(),
		VaultPath: filepath.Join(baseDir, vaultFileName),
	}

	if err := saveConfig(configPath, cfg); err != nil {
		return AppConfig{}, err
	}

	return cfg, nil
}

func saveConfig(path string, cfg AppConfig) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(cfg)
}

// ------------------------------------------------------------
// VAULT HANDLING
// ------------------------------------------------------------

func readEncryptedVault(path string) (jsonutils.EncryptedPasswords, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return jsonutils.EncryptedPasswords{}, err
	}

	var encVault jsonutils.EncryptedPasswords
	if err := json.Unmarshal(data, &encVault); err != nil {
		return jsonutils.EncryptedPasswords{}, err
	}
	return encVault, nil
}

func writeEncryptedVault(path, master string, entries []jsonutils.Entry) error {
	encVault, err := jsonutils.EncryptPasswords(master, entries)
	if err != nil {
		return err
	}

	encVault.UpdateDate = time.Now().UTC()

	data, err := json.MarshalIndent(encVault, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0o600)
}

// ------------------------------------------------------------
// FLOWS
// ------------------------------------------------------------

func addPasswordFlow(existing []jsonutils.Entry) (jsonutils.Entry, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Service / URL: ")
	url, _ := reader.ReadString('\n')
	url = strings.TrimSpace(url)

	fmt.Print("Username / Email (for the site): ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Do you want to generate a password? (y/n): ")
	genAns, _ := reader.ReadString('\n')
	genAns = strings.TrimSpace(strings.ToLower(genAns))

	var password string
	if genAns == "y" {
		password = passwordGenerationFlow()
		fmt.Println("Generated password:", password)
	} else {
		for {
			pass := promptHidden("Enter password for this entry: ")

			// ✅ FIX: pass non-nil symbols and 0 min symbols
			emptySymbols := ""
			// we can use username as userInfo to prevent too-similar passwords
			uInfo := []string{username}
			if err := passutils.CheckPasswordStrength(pass, uInfo, &emptySymbols, 0); err != nil {
				fmt.Println("Password weak:", err)
				fmt.Println("Try again or Ctrl+C to abort.")
				continue
			}
			password = pass
			break
		}
	}

	fmt.Print("Notes (optional): ")
	notes, _ := reader.ReadString('\n')
	notes = strings.TrimSpace(notes)

	now := time.Now().UTC()
	entry := jsonutils.Entry{
		URL:        url,
		UserName:   username,
		Password:   password,
		CreateDate: now,
		UpdateDate: now,
		AccessDate: now,
		Info:       notes,
	}

	return entry, nil
}

func listEntries(entries []jsonutils.Entry) {
	if len(entries) == 0 {
		fmt.Println("No entries.")
		return
	}

	fmt.Println("Entries:")
	for i, e := range entries {
		fmt.Printf("%d) %s (%s)\n", i+1, e.URL, e.UserName)
	}
}

func viewEntryDetails(entries []jsonutils.Entry) {
	if len(entries) == 0 {
		fmt.Println("No entries.")
		return
	}

	reader := bufio.NewReader(os.Stdin)
	listEntries(entries)
	fmt.Print("Select entry index: ")
	idxStr, _ := reader.ReadString('\n')
	idxStr = strings.TrimSpace(idxStr)

	var idx int
	fmt.Sscanf(idxStr, "%d", &idx)
	idx = idx - 1
	if idx < 0 || idx >= len(entries) {
		fmt.Println("invalid index")
		return
	}

	e := entries[idx]
	fmt.Println("---- Entry ----")
	fmt.Println("URL:       ", e.URL)
	fmt.Println("Username:  ", e.UserName)
	fmt.Println("Password:  ", e.Password)
	fmt.Println("Notes:     ", e.Info)
	fmt.Println("Created:   ", e.CreateDate)
	fmt.Println("Updated:   ", e.UpdateDate)
	fmt.Println("Last used: ", e.AccessDate)

	entries[idx].AccessDate = time.Now()
}

func passwordGenerationFlow() string {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Exclude uppercase letters? (y/n): ")
	noUpStr, _ := reader.ReadString('\n')
	noUpStr = strings.TrimSpace(strings.ToLower(noUpStr))
	noUpper := noUpStr == "y"

	fmt.Print("Custom symbols (leave empty for default): ")
	custSym, _ := reader.ReadString('\n')
	custSym = strings.TrimSpace(custSym)

	pass := passutils.GeneratePassword(custSym, noUpper)
	return pass
}

// ------------------------------------------------------------
// HELPERS
// ------------------------------------------------------------

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func promptHidden(msg string) string {
	fmt.Print(msg)
	b, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return strings.TrimSpace(string(b))
}
