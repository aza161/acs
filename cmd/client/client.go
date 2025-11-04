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

type AppConfig struct {
	ClientID  string `json:"client_id"`
	VaultPath string `json:"vault_path"`
}

const (
	configDirName  = ".acs_passmgr"
	configFileName = "config.json"
	vaultFileName  = "vault.json"
)

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

	var entries []jsonutils.Entry
	var master string

	// unlock or create vault
	if fileExists(vaultPath) {
		for {
			clearScreen()
			showBanner()
			master = promptHidden("Enter master password: ")

			encVault, err := readEncryptedVault(vaultPath)
			if err != nil {
				fmt.Println("An error occurred while opening the vault.")
				continue
			}

			entries, err = jsonutils.DecryptPasswords(master, encVault)
			if err != nil {
				fmt.Println("An error occurred while opening the vault.")
				continue
			}

			fmt.Printf("\x1b[32mVault unlocked. %d entries loaded.\x1b[0m\n", len(entries))
			time.Sleep(2 * time.Second)
			break
		}
	} else {
		clearScreen()
		showBanner()
		fmt.Println("No vault found. Let's create one.")

		for {
			master = promptHidden("Create master password: ")
			confirm := promptHidden("Confirm master password: ")
			if master != confirm {
				fmt.Println("Passwords do not match, try again.")
				continue
			}

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
		fmt.Println("\x1b[32mVault created successfully.\x1b[0m")
		time.Sleep(2 * time.Second)
	}

	// main loop
	for {
		clearScreen()
		showBanner()
		fmt.Printf("Client ID: %s\n", cfg.ClientID)
		fmt.Printf("Entries in vault: %d\n\n", len(entries))

		menuSpeed := 8 * time.Millisecond
		typeLine("\x1b[33m1)\x1b[0m Add password", menuSpeed)
		typeLine("\x1b[33m2)\x1b[0m List entries (URLs)", menuSpeed)
		typeLine("\x1b[33m3)\x1b[0m View entry details", menuSpeed)
		typeLine("\x1b[33m4)\x1b[0m Generate password (customizable)", menuSpeed)
		typeLine("\x1b[33m5)\x1b[0m Save & Exit", menuSpeed)
		fmt.Print("> ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			newEntry, err := addPasswordFlow(entries)
			if err != nil {
				fmt.Println("Error adding password:", err)
				fmt.Println("Press Enter to continue...")
				reader.ReadString('\n')
				continue
			}
			entries = append(entries, newEntry)
			if err := writeEncryptedVault(vaultPath, master, entries); err != nil {
				fmt.Println("Error saving vault:", err)
			} else {
				fmt.Println("\x1b[32mEntry added and saved.\x1b[0m")
			}
			fmt.Println("Press Enter to continue...")
			reader.ReadString('\n')

		case "2":
			listEntries(entries)
			fmt.Println("Press Enter to continue...")
			reader.ReadString('\n')

		case "3":
			viewEntryDetails(entries)
			fmt.Println("Press Enter to continue...")
			reader.ReadString('\n')

		case "4":
			gen := passwordGenerationFlow()
			fmt.Println("Generated:", gen)
			fmt.Println("Press Enter to continue...")
			reader.ReadString('\n')

		case "5":
			if err := writeEncryptedVault(vaultPath, master, entries); err != nil {
				fmt.Println("Error saving vault:", err)
			}
			fmt.Println("Goodbye 👋")
			return nil

		default:
			fmt.Println("Invalid choice.")
			fmt.Println("Press Enter to continue...")
			reader.ReadString('\n')
		}
	}
}

// -------------------------- UI --------------------------

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func typeLine(s string, delay time.Duration) {
	for _, ch := range s {
		fmt.Printf("%c", ch)
		time.Sleep(delay)
	}
	fmt.Println()
}

func showBanner() {
	fmt.Println("\x1b[36m==============================\x1b[0m")
	fmt.Println("\x1b[36m     ACS Password Manager     \x1b[0m")
	fmt.Println("\x1b[36m==============================\x1b[0m")
}

// -------------------------- config --------------------------

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

// -------------------------- vault --------------------------

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

// -------------------------- flows --------------------------

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
			emptySymbols := ""
			uInfo := []string{username}
			if err := passutils.CheckPasswordStrength(pass, uInfo, &emptySymbols, 0); err != nil {
				fmt.Println("Password weak:", err)
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
		fmt.Println("Invalid index.")
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

	fmt.Print("Generate passphrase instead of random password? (y/n): ")
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(strings.ToLower(mode))

	if mode == "y" {
		opts := passutils.PassphraseOptions{}

		fmt.Print("How many words? (enter for 7): ")
		wstr, _ := reader.ReadString('\n')
		wstr = strings.TrimSpace(wstr)
		if wstr == "" {
			opts.Length = 7
		} else {
			var l int
			fmt.Sscanf(wstr, "%d", &l)
			opts.Length = l
		}

		fmt.Print("Separator (enter for '-'): ")
		sep, _ := reader.ReadString('\n')
		sep = strings.TrimSpace(sep)
		if sep != "" {
			opts.Separator = sep
		}

		fmt.Print("Casing? (none/title/random) [enter for none]: ")
		cs, _ := reader.ReadString('\n')
		cs = strings.TrimSpace(strings.ToLower(cs))
		if cs != "" {
			opts.CaseStyle = cs
		}

		fmt.Print("Add a digit? (y/n): ")
		ad, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(ad)) == "y" {
			opts.AddNumber = true
			fmt.Print("Digit position? (prefix/suffix/between, enter for suffix): ")
			dp, _ := reader.ReadString('\n')
			dp = strings.TrimSpace(strings.ToLower(dp))
			if dp != "" {
				opts.NumberPosition = dp
			}
		}

		fmt.Print("Add a symbol? (y/n): ")
		as, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(as)) == "y" {
			opts.AddSymbol = true
			fmt.Print("Symbol set (enter for !@#$%^&*): ")
			ss, _ := reader.ReadString('\n')
			ss = strings.TrimSpace(ss)
			if ss != "" {
				opts.SymbolSet = ss
			}
			fmt.Print("Symbol position? (prefix/suffix/between, enter for suffix): ")
			sp, _ := reader.ReadString('\n')
			sp = strings.TrimSpace(strings.ToLower(sp))
			if sp != "" {
				opts.SymbolPosition = sp
			}
		}

		pp, err := passutils.GeneratePassphraseAdvanced(opts)
		if err != nil {
			fmt.Println("error generating passphrase:", err)
			return ""
		}
		return pp
	}

	const defaultLen = 16
	const defaultDigits = 3
	const defaultSymbols = 1

	popts := passutils.PasswordOptions{}

	fmt.Printf("Password length (enter for %d): ", defaultLen)
	lenStr, _ := reader.ReadString('\n')
	lenStr = strings.TrimSpace(lenStr)
	if lenStr != "" {
		var l int
		fmt.Sscanf(lenStr, "%d", &l)
		popts.Length = l
	} else {
		popts.Length = defaultLen
	}

	fmt.Printf("Min digits (enter for %d): ", defaultDigits)
	dStr, _ := reader.ReadString('\n')
	dStr = strings.TrimSpace(dStr)
	if dStr != "" {
		var d int
		fmt.Sscanf(dStr, "%d", &d)
		popts.MinDigits = d
	} else {
		popts.MinDigits = defaultDigits
	}

	fmt.Printf("Min symbols (enter for %d): ", defaultSymbols)
	sStr, _ := reader.ReadString('\n')
	sStr = strings.TrimSpace(sStr)
	if sStr != "" {
		var s int
		fmt.Sscanf(sStr, "%d", &s)
		popts.MinSymbols = s
	} else {
		popts.MinSymbols = defaultSymbols
	}

	fmt.Print("Allow uppercase? (y/n, enter for yes): ")
	au, _ := reader.ReadString('\n')
	au = strings.TrimSpace(strings.ToLower(au))
	popts.AllowUpper = (au != "n")

	fmt.Print("Allow lowercase? (y/n, enter for yes): ")
	al, _ := reader.ReadString('\n')
	al = strings.TrimSpace(strings.ToLower(al))
	popts.AllowLower = (al != "n")

	fmt.Print("Allow character repetition? (y/n, enter for yes): ")
	ar, _ := reader.ReadString('\n')
	ar = strings.TrimSpace(strings.ToLower(ar))
	popts.AllowRepeat = (ar != "n")

	fmt.Print("Custom symbols (leave empty for default): ")
	cs, _ := reader.ReadString('\n')
	cs = strings.TrimSpace(cs)
	if cs != "" {
		popts.CustomSymbols = cs
	}

	pwd, err := passutils.GeneratePasswordAdvanced(popts)
	if err != nil {
		fmt.Println("error generating password:", err)
		return ""
	}
	return pwd
}

// -------------------------- misc --------------------------

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
