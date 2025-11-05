package main

import (
	"acs/internal/jsonutils"
	encrypt "acs/pkg/crypt"
	"acs/pkg/passutils"
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/atotto/clipboard"
	"github.com/google/uuid"
)

// ------------------------------------------------------------
// CONFIG + FILE PATHS
// ------------------------------------------------------------

type AppConfig struct {
	ClientID  string `json:"client_id"`
	VaultPath string `json:"vault_path"`
	SeverURL  string `json:"server_url"`
	UserName  string `json:"username"`
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

	var entries []jsonutils.Entry
	var master string
	var encVault jsonutils.EncryptedPasswords
	if fileExists(vaultPath) {
		for {
			clearScreen()
			showBanner()
			master = promptHidden("Enter master password: ")

			encVault, err = readEncryptedVault(vaultPath)
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
		fmt.Printf("\x1b[32mVault unlocked. %d entries loaded.\x1b[0m\n", len(entries))
		time.Sleep(2 * time.Second)
	} else {
		clearScreen()
		showBanner()
		// new vault → create master
		fmt.Println("No vault found. Let's create one.")
		fmt.Println("You will be prompted to enter a secure master password of your own.\nYou can also use our secure passphrase generator")
		fmt.Println("Do you want to use it? [y]es/[n]o")
		var ans string
		var master string
		for {
			fmt.Scanf("%s", &ans)
			if ans == "y" || ans == "Y" {
				master, err = passutils.GeneratePassphrase(7)
				if err != nil {
					fmt.Println("An error occured while generating a passpharse", err)
					os.Exit(1)
				}
				fmt.Println("This is you passpharse please store somewhere safe, and no don't save it on your device, a piece of paper will do.", master)
				break
			} else if ans == "n" || ans == "N" {
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

					fmt.Println("Master password accepted")
					break
				}
				break
			} else {
				fmt.Println("Invalid input. Please enter 'y' or 'n'.")
			}
		}

		entries = []jsonutils.Entry{}
		serverURL := ""
		serverUserName := ""
		fmt.Println("Would you like to sync your passwords to a server?", "NOTE: You have to setup the server yourself, please check the acs repo for more details")
		for {
			fmt.Scanf("%s", &ans)
			if ans == "y" || ans == "Y" {
				fmt.Println("Please eneter server url")
				for {
					fmt.Scanf("%s", &serverURL)
					_, err := url.ParseRequestURI(serverURL)
					if err != nil {
						fmt.Println("Please eneter a valid address")
						continue
					}
					break
				}
				fmt.Println("Please eneter your username on the server, note in case you enter this wrong you need to edit the config file manually")
				fmt.Scanf("%s", &serverUserName)
				break
			} else if ans == "n" || ans == "N" {
				break
			} else {
				fmt.Println("Invalid input. Please enter 'y' or 'n'.")
			}
		}
		cfg.SeverURL = serverURL
		cfg.UserName = serverUserName

		if err := saveConfig(configPath, cfg); err != nil {
			return err
		}

		if err := writeEncryptedVault(vaultPath, master, entries); err != nil {
			return err
		}

		fmt.Println("\x1b[32mVault created successfully.\x1b[0m")
		time.Sleep(2 * time.Second)

		fmt.Println("Do you already have an account on the server? [y]es, [no]")
		var pwd string
		for {
			fmt.Scanf("%s", &ans)
			if ans == "y" || ans == "Y" {
				break
			} else if ans == "n" || ans == "N" {
				pwd = promptHidden("Please eneter a new password for you server account, make sure that this is different than your master password!!")
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // Should be changed to flase for use in production
					},
				}

				client := &http.Client{
					Transport: tr,
				}
				if err := register(client, cfg.SeverURL, cfg.UserName, pwd, uuid.MustParse(cfg.ClientID)); err != nil {
					fmt.Println("registeration failed", err)
				}
				break
			} else {
				fmt.Println("Invalid input. Please enter 'y' or 'n'.")
			}
		}

	}

	if cfg.SeverURL != "" {
		if err := syncRoutine(cfg, vaultPath, master, encVault, &entries); err != nil {
			fmt.Println("An error occured when syncing", err)
		}
	}

	// main menu
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
			newEntry, err := addPasswordFlow()
			if err != nil {
				fmt.Println("Error adding password:", err)
				fmt.Println("Press Enter to continue...")
				reader.ReadString('\n')
				continue
			}
			entries = append(entries, newEntry)
			if err := writeEncryptedVault(vaultPath, master, entries); err != nil {
				fmt.Println("error saving vault:", err)
			} else {
				fmt.Println("\x1b[32mEntry added and saved.\x1b[0m")
			}
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
				fmt.Println("error saving vault:", err)
			}
			if cfg.SeverURL != "" {
				if err := syncRoutine(cfg, vaultPath, master, encVault, &entries); err != nil {
					fmt.Println("An error occured when syncing", err)
				}
			}
			fmt.Println("Goodbye 👋")
			return nil
		default:
			fmt.Println("invalid choice")
			fmt.Println("Press Enter to continue...")
			reader.ReadString('\n')
		}
		fmt.Println()
	}
}

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

func addPasswordFlow() (jsonutils.Entry, error) {
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
	if err := clipboard.WriteAll(e.Password); err != nil {
		fmt.Println("Some error happened password was not saved to clipboard")
	}
	fmt.Println("password copied to clipboard, it will be cleared in 30 seconds")

	go clearClipBoard()

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

func clearClipBoard() error {
	<-time.After(30 * time.Second)
	err := clipboard.WriteAll("")
	if err != nil {
		return err
	}
	return nil
}

func register(client *http.Client, url, userName, password string, uuid uuid.UUID) error {
	urlAPI := fmt.Sprintf("%s/register", url)
	jsonRequest, err := jsonutils.GenerateJson(jsonutils.RegisterRequest{UserName: userName, Password: password, UniqueDeviceID: uuid})
	if err != nil {
		return err
	}
	request, err := http.NewRequest("POST", urlAPI, bytes.NewBuffer(jsonRequest))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusCreated {
		return nil
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	switch response.StatusCode {
	case http.StatusBadRequest:
		return fmt.Errorf("bad request: %s", body)
	case http.StatusConflict:
		return fmt.Errorf("user name is already taken: %s", body)
	default:
		return fmt.Errorf("unexpected status code %d: %s", response.StatusCode, body)
	}
}

func logIn(client *http.Client, url, userName, password string) (string, error) {
	urlAPI := fmt.Sprintf("%s/login", url)
	jsonRequest, err := jsonutils.GenerateJson(jsonutils.LoginRequest{UserName: userName, Password: password})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequest("POST", urlAPI, bytes.NewBuffer(jsonRequest))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed with status %d", response.StatusCode)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read response body: %v", err)
	}

	var responseMap map[string]any
	err = json.Unmarshal(body, &responseMap)
	if err != nil {
		return "", fmt.Errorf("Failed to unmarshal response JSON: %v", err)
	}

	if token, ok := responseMap["token"].(string); ok {
		return token, nil
	} else {
		return "", fmt.Errorf("Token not found or is not a string in the response")
	}
}

func sync(client *http.Client, vaultPath, url, jwt, masterPass string, isMerged bool, env jsonutils.EncryptedPasswords, uuid uuid.UUID, entries *[]jsonutils.Entry, maxRetries int) error {
	if maxRetries <= 0 {
		return fmt.Errorf("too many retries, giving up")
	}
	urlAPI := fmt.Sprintf("%s/sync", url)
	//byteEnv, _ := jsonutils.GenerateJson(env)
	//strEnv := string(byteEnv)
	jsonRequest, err := jsonutils.GenerateJson(jsonutils.SyncRequest{JWT: jwt,
		UniqueDeviceID: uuid,
		UpdateDate:     env.UpdateDate.UTC(),
		IsMerged:       isMerged,
		EncryptedData:  env,
	})

	request, err := http.NewRequest("POST", urlAPI, bytes.NewBuffer([]byte(string(jsonRequest))))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		var env jsonutils.EncryptedPasswords
		decoder := json.NewDecoder(response.Body)
		if err := decoder.Decode(&env); err != nil {
			return fmt.Errorf("failed to decode remote env from conflict response: %w", err)
		}
		nonce, _ := base64.StdEncoding.DecodeString(env.Nonce)
		salt, _ := base64.StdEncoding.DecodeString(env.Salt)
		key, _ := passutils.Argon2ID(masterPass, salt, env.Threads)
		ciphertext, _ := base64.StdEncoding.DecodeString(env.EncryptedData)
		remoteEntriesBytes, _ := encrypt.DecryptAESGCM(key, nonce, ciphertext, []byte("Encrypted_Passwords"))
		var remoteEntries []jsonutils.Entry
		json.Unmarshal(remoteEntriesBytes, &remoteEntries)
		*entries = merge(*entries, remoteEntries)
		if err := writeEncryptedVault(vaultPath, masterPass, *entries); err != nil {
			return fmt.Errorf("failed to encrypt merged remote entries: %w", err)
		}
		return sync(client, vaultPath, url, jwt, masterPass, true, env, uuid, entries, maxRetries-1)
	}
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected response status: %d", response.StatusCode)
	}

	return nil
}

func merge(localEntries []jsonutils.Entry, remoteEntries []jsonutils.Entry) []jsonutils.Entry {

	// maps for efficient lookups
	localMap := make(map[string]jsonutils.Entry)
	for _, entry := range localEntries {
		localMap[entry.Key()] = entry
	}

	remoteMap := make(map[string]jsonutils.Entry)
	for _, entry := range remoteEntries {
		remoteMap[entry.Key()] = entry
	}

	// This map will hold the final merged state
	finalMap := make(map[string]jsonutils.Entry)

	for key, local := range localMap {
		remote, existsInRemote := remoteMap[key]

		if local.IsDeleted {
			finalMap[key] = local
			if existsInRemote {
				delete(remoteMap, key)
			}
			continue
		}

		if existsInRemote {
			// Check update date
			if local.UpdateDate.Equal(remote.UpdateDate) {
				finalMap[key] = local
			} else if local.UpdateDate.After(remote.UpdateDate) {
				finalMap[key] = local
			} else {
				finalMap[key] = remote
			}

			delete(remoteMap, key)
			continue
		}

		if !existsInRemote {
			finalMap[key] = local
		}
	}

	for key, remote := range remoteMap {
		if !remote.IsDeleted {
			finalMap[key] = remote
		}
	}

	mergedSlice := make([]jsonutils.Entry, 0, len(finalMap))
	for _, entry := range finalMap {
		mergedSlice = append(mergedSlice, entry)
	}

	return mergedSlice
}

func syncRoutine(cfg AppConfig, vaultPath, master string, encVault jsonutils.EncryptedPasswords, entries *[]jsonutils.Entry) error {
	tr := &http.Transport{}
	client := &http.Client{}
	// log in to server
	if cfg.SeverURL != "" {
		var token string
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Should be changed to flase for use in production
			},
		}

		client = &http.Client{
			Transport: tr,
		}
		pwd := promptHidden(fmt.Sprintf("Please enter your server password for username %s", cfg.UserName))
		token, err := logIn(client, cfg.SeverURL, cfg.UserName, pwd)
		if err != nil {
			fmt.Println("An error happened when trying to log-in, will continue without online features", err)
		}
		return sync(client, vaultPath, cfg.SeverURL, token, master, false, encVault, uuid.MustParse(cfg.ClientID), entries, 3)
	}
	return nil
}
