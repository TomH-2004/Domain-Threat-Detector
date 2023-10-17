//THIS IS A VERY GOOD COMMIT. PLEASE DO NOT DO ANYTHING STUPID

package main

import (
	"crypto/tls"
	"database/sql"

	"fmt"
	"io/ioutil"
	"log"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"

	_ "github.com/go-sql-driver/mysql"
)

const (
	configFilePath = "config.json"
)

type WordPriority int

const (
	LowPriority    WordPriority = 1
	MediumPriority WordPriority = 2
	HighPriority   WordPriority = 3
)

const (
	Reset  = "\x1b[0m"
	Red    = "\x1b[31m"
	Yellow = "\x1b[33m"
)

type DomainInfo struct {
	Name          string
	Status        string
	Threats       int
	ThreatDetails []string
}

type SearchPhrase struct {
	Phrase   string
	Priority WordPriority
	Selected bool
	Regex    *regexp.Regexp
}

type PatternInfo struct {
	Name    string
	Pattern string
}

type DomainThreatInfo struct {
	DomainName    string
	Status        string
	PatternName   string
	DetectionTime MyTime
}

func (p WordPriority) String() string {
	switch p {
	case LowPriority:
		return "Low"
	case MediumPriority:
		return "Medium"
	case HighPriority:
		return "High"
	default:
		return "Unknown"
	}
}

type MyTime struct {
	time.Time
}

func (t *MyTime) Scan(value interface{}) error {
	if value == nil {
		*t = MyTime{time.Time{}}
		return nil
	}

	rawTime, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("Scan error: expected []byte, got %T", value)
	}

	parsedTime, err := time.Parse("2006-01-02 15:04:05", string(rawTime))
	if err != nil {
		return err
	}

	*t = MyTime{parsedTime}
	return nil
}

func searchFile(filePath string, searchPhrases []SearchPhrase, domainInfo *DomainInfo, db *sql.DB, domainID int) string {
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error reading %s: %s\n", filePath, err)
		return ""
	}

	lines := strings.Split(string(fileContent), "\n")

	fmt.Printf("Scanning file: %s\n\n", filePath)

	var threatDetails string
	threatsFound := 0
	ignoreMode := false

	for lineNum, line := range lines {

		if strings.Contains(line, "//scanignore") ||
			strings.Contains(line, "<!-- scanignore") ||
			strings.Contains(line, "<!--scanignore") ||
			strings.Contains(line, "/* scanignore */") {

			ignoreMode = !ignoreMode
			continue
		}

		if ignoreMode {
			continue
		}

		for _, phrase := range searchPhrases {
			if !phrase.Selected {
				continue
			}

			lowerLine := strings.ToLower(line)
			lowerPhrase := strings.ToLower(phrase.Phrase)

			if strings.Contains(lowerLine, lowerPhrase) {
				result := fmt.Sprintf("  - Regex Pattern \"%s\" (Priority: %s) matched in \"%s\" at line %d: %s\n",
					phrase.Phrase, phrase.Priority, filePath, lineNum+1, line)

				threatDetails += result
				threatsFound++

				insertThreatDetails(db, domainID, phrase.Phrase)
			}

			if phrase.Regex != nil {
				if phrase.Regex.MatchString(line) {
					result := fmt.Sprintf("  - Regex Pattern \"%s\" (Priority: %s) matched in \"%s\" at line %d: %s\n",
						phrase.Phrase, phrase.Priority, filePath, lineNum+1, line)

					threatDetails += result
					threatsFound++

					insertThreatDetails(db, domainID, phrase.Phrase)
				}
			}
		}
	}

	if threatsFound > 0 {
		threatDetails = fmt.Sprintf("Threats: %d\n", threatsFound) + threatDetails
		domainInfo.Threats += threatsFound
		domainInfo.ThreatDetails = append(domainInfo.ThreatDetails, threatDetails)
	}

	return threatDetails
}

func main() {
	scannedDomains := make(map[string]bool)

	logFileName := "scanlog.txt"
	logFile, err := os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening log file: %s\n", err)
	}
	defer logFile.Close()
	logger := log.New(logFile, "", 0)
	logger.SetOutput(logFile)

	viper.SetConfigFile(configFilePath)
	if err := viper.ReadInConfig(); err != nil {
		logger.Printf("Error reading config file: %s\n", err)
		os.Exit(1)
	}

	db, err := connectToDatabase()
	if err != nil {
		logger.Printf("Error connecting to the database: %s\n", err)
		os.Exit(1)
	}
	defer db.Close()

	xss := `<script[^>]*>[\s\S]*?<\/script>|javascript:|eval\s*\(|\b(alert|prompt|confirm)\s*\(|\bcookie\s*=`
	commandInjection := `(?i)\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\b|(?i)\b(?:;|\||&&)\s*(?:[A-Za-z0-9_]+\s*=\s*)?['"]?([^'"]+)['"]?`
	SensitiveData := `(?i)\b(?:\d[ -]*?){13,16}\b`
	Passwords := `(?i)\b(?:password|pwd)\b.*?=.*?['"]?([^'"]+)['"]?`
	Malware := `(?i)\b(?:malware|virus|trojan)\b`
	Base64 := `eval \(base64_decode\)`
	xxeInjection := `(?i)\b<!ENTITY\s+[^\s]+\s+SYSTEM\s+['"]?[^\s]+['"]?>`
	csrf := `(?i)<input[^>]*\btype\s*=\s*['"]?hidden['"]?\b[^>]*\bname\s*=\s*['"]?csrf_token['"]?\b[^>]*>`

	patterns := []struct {
		Name     string
		Pattern  string
		Priority WordPriority
		Selected bool
	}{
		{"XSS", xss, HighPriority, true},
		{"Command Injection", commandInjection, LowPriority, true},
		{"Sensitive Data", SensitiveData, MediumPriority, true},
		{"Passwords", Passwords, MediumPriority, true},
		{"Malware", Malware, HighPriority, true},
		{"Base64 Eval", Base64, HighPriority, true},
		{"XXE", xxeInjection, HighPriority, true},
		{"CSRF", csrf, MediumPriority, true},
	}

	searchPhrases := make([]SearchPhrase, len(patterns))
	for i, pattern := range patterns {
		searchPhrases[i] = SearchPhrase{
			Phrase:   pattern.Name,
			Priority: pattern.Priority,
			Selected: pattern.Selected,
			Regex:    regexp.MustCompile(pattern.Pattern),
		}
	}

	dirPath := "Domains"

	for {
		logger.Println("Starting scan...")
		startTime := time.Now()

		domainScanResults := make(map[string]DomainInfo)
		var allDomainDetails string

		subdirs, err := ioutil.ReadDir(dirPath)
		if err != nil {
			os.Exit(1)
		}

		for _, subdir := range subdirs {
			if !subdir.IsDir() {
				continue
			}

			domainName := subdir.Name()
			subdirPath := filepath.Join(dirPath, domainName)

			domainID, err := getDomainIDFromDatabase(db, domainName)
			if err != nil {
				fmt.Printf("Error retrieving domain ID: %s\n", err)
				continue
			}

			if !scannedDomains[domainName] {
				fmt.Printf("Scanning domain: %s\n", domainName)
				scannedDomains[domainName] = true
			}

			numFiles, err := countFiles(subdirPath)
			if err != nil {
				os.Exit(1)
			}

			domainInfo := DomainInfo{
				Name:    domainName,
				Status:  "offline",
				Threats: 0,
			}

			if numFiles > 0 {
				domainInfo.Status = "online"
			}

			domainDetails := "Domain: " + domainName + "\nStatus: " + domainInfo.Status + "\nThreats: " + strconv.Itoa(domainInfo.Threats) + "\n"

			err = filepath.Walk(subdirPath, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				if !info.IsDir() {

					fileResults := searchFile(filePath, searchPhrases, &domainInfo, db, domainID)

					if len(fileResults) > 0 {
						if domainInfo.Threats == 0 {
							domainInfo.Threats++
						}
						domainDetails += fmt.Sprintf("- File: %s\n%s\n", filePath, fileResults)
					}
				}

				return nil
			})

			if err != nil {
				fmt.Printf("Error scanning files in %s: %s\n", domainName, err)
			}

			domainScanResults[domainName] = domainInfo

			domainDetails = "Domain: " + domainName + "\nStatus: " + domainInfo.Status + "\nThreats: " + strconv.Itoa(domainInfo.Threats) + "\n"

			if domainInfo.Threats > 0 {
				domainThreatDetails := getThreatDetails(subdirPath, searchPhrases, &domainInfo, db, domainID)

				domainDetails += "==================================== THREAT DETAILS ====================================\n"
				domainDetails += domainThreatDetails
			}

			allDomainDetails += domainDetails + "\n"

			fmt.Println()
		}

		domainThreats, err := getAllDomainThreatDetails(db)
		if err != nil {
			fmt.Printf("Error retrieving domain and threat details: %v\n", err)
			return
		}

		for _, info := range domainThreats {
			fmt.Printf("Domain: %s\n", info.DomainName)
			fmt.Printf("Status: %s\n", info.Status)
			fmt.Printf("Pattern Name: %s\n", info.PatternName)

			fmt.Printf("Detection Time: %s\n", info.DetectionTime.Format("2006-01-02 15:04:05"))
			fmt.Println()
		}

		logEntry := "Scan Complete\n"
		logEntry += "For more detail, go to: http://tomtest.datalords.net/dbpma/index.php?route=/&route=%2F&db=WordpressSecurity&table=Domains\n\n"
		logEntry += "Domains Scanned:\n"
		for _, subdir := range subdirs {
			if subdir.IsDir() {
				logEntry += "  - " + subdir.Name() + "\n"
			}
		}
		logEntry += "\n"
		logEntry += allDomainDetails

		if err := appendToLogFile(logFileName, logEntry); err != nil {
			logger.Printf("Error writing to log file: %s\n", err)
		}

		SendEmail("tom@datalords.net", "tom@tomtest.datalords.net", "", "localhost", "25", "Scan Report", logEntry)

		updateDatabase(db, domainScanResults)

		fmt.Printf("Scan completed in %s. Sleeping for 24 Hours...\n", time.Since(startTime))
		time.Sleep(24 * time.Hour)
	}
}

func SendEmail(emailTo, emailFrom, emailPass, smtpHost, smtpPort, subject, emailMessage string) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	smtpServer := smtpHost + ":" + smtpPort
	smtpClient, err := smtp.Dial(smtpServer)
	if err != nil {
		log.Println(err)
		return
	}
	defer smtpClient.Quit()

	err = smtpClient.StartTLS(tlsConfig)
	if err != nil {
		log.Println(err)
		return
	}

	if emailPass != "" {
		auth := smtp.PlainAuth("", emailFrom, emailPass, smtpHost)
		err = smtpClient.Auth(auth)
		if err != nil {
			log.Println(err)
			return
		}
	}

	msg := []byte("To: " + emailTo + "\r\n" +
		"From: " + emailFrom + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" +
		emailMessage + "\r\n")

	err = smtpClient.Mail(emailFrom)
	if err != nil {
		log.Println(err)
		return
	}

	err = smtpClient.Rcpt(emailTo)
	if err != nil {
		log.Println(err)
		return
	}

	w, err := smtpClient.Data()
	if err != nil {
		log.Println(err)
		return
	}

	_, err = w.Write(msg)
	if err != nil {
		log.Println(err)
		return
	}

	err = w.Close()
	if err != nil {
		log.Println(err)
		return
	}

	fmt.Println("Email sent successfully")
	fmt.Println("")
	fmt.Println("Check scanlog.txt")
}

func countFiles(dirPath string) (int, error) {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, file := range files {
		if !file.IsDir() {
			count++
		}
	}
	return count, nil
}

func connectToDatabase() (*sql.DB, error) {
	viper.SetConfigFile(configFilePath)

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("error reading config file: %s", err)
	}

	dbUsername := viper.GetString("dbUsername")
	dbPassword := viper.GetString("dbPassword")
	dbHost := viper.GetString("dbHost")
	dbPort := viper.GetString("dbPort")
	dbName := viper.GetString("dbName")

	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUsername, dbPassword, dbHost, dbPort, dbName))
	if err != nil {
		return nil, fmt.Errorf("error connecting to the database: %s", err)
	}

	return db, nil
}

func updateDatabase(db *sql.DB, scanResults map[string]DomainInfo) {

	_, err := db.Exec("DELETE FROM ThreatDetails WHERE DomainID IN (SELECT ID FROM Domains)")
	if err != nil {
		fmt.Printf("Error clearing ThreatDetails table: %v\n", err)
		return
	}

	_, err = db.Exec("DELETE FROM Domains")
	if err != nil {
		fmt.Printf("Error clearing the Domains table: %v\n", err)
		return
	}

	_, err = db.Exec("ALTER TABLE Domains AUTO_INCREMENT = 1")
	if err != nil {
		fmt.Printf("Error resetting auto-increment: %v\n", err)
		return
	}

	for domainName, info := range scanResults {
		insertDomainSQL := `
			INSERT INTO Domains (DomainName, Status, ThreatsDetected)
			VALUES (?, ?, ?);
		`
		_, err := db.Exec(insertDomainSQL, domainName, info.Status, info.Threats)
		if err != nil {
			fmt.Printf("Error inserting into Domains table: %v\n", err)
			continue
		}

		domainID, err := getDomainIDFromDatabase(db, domainName)
		if err != nil {
			fmt.Printf("Error retrieving DomainID: %v\n", err)
			continue
		}

		if err := resetAutoIncrement(db, "ThreatDetails"); err != nil {
			fmt.Printf("Error resetting auto-increment: %v\n", err)
			return
		}

		for _, threatDetail := range info.ThreatDetails {

			patternName := extractPatternName(threatDetail)

			insertThreatSQL := `
    INSERT INTO ThreatDetails (DomainID, PatternName, DetectionTime)
    VALUES (?, ?, ?);
`
			_, err := db.Exec(insertThreatSQL, domainID, patternName, time.Now())
			if err != nil {
				fmt.Printf("Error inserting into ThreatDetails table: %v\n", err)

			}
		}
	}
}

func appendToLogFile(fileName, text string) error {
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(text)
	if err != nil {
		return err
	}

	return nil
}

func getThreatDetails(domainPath string, searchPhrases []SearchPhrase, domainInfo *DomainInfo, db *sql.DB, domainID int) string {
	var threatDetails string

	err := filepath.Walk(domainPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("Error accessing file or directory: %s\n", err)
			return err
		}

		if !info.IsDir() {
			fileResults := searchFile(filePath, searchPhrases, domainInfo, db, domainID)

			if len(fileResults) > 0 {
				threatDetails += "- File: " + filePath + "\n"
				threatDetails += fileResults + "\n"
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error scanning files in %s: %s\n", domainPath, err)
	}

	return threatDetails
}

func insertThreatDetails(db *sql.DB, domainID int, patternName string) {
	insertSQL := `
        INSERT INTO ThreatDetails (DomainID, PatternName, DetectionTime)
        VALUES (?, ?, ?);
    `
	_, err := db.Exec(insertSQL, domainID, patternName, time.Now())
	if err != nil {
		fmt.Printf("Error inserting threat details into the database: %v\n", err)
	}
}

func getAllDomainThreatDetails(db *sql.DB) ([]DomainThreatInfo, error) {
	query := `
        SELECT Domains.DomainName, Domains.Status,
        IFNULL(ThreatDetails.PatternName, '') AS PatternName,
        IFNULL(DATE_FORMAT(ThreatDetails.DetectionTime, '%Y-%m-%d %H:%i:%s'), '') AS DetectionTime
        FROM Domains
        LEFT JOIN ThreatDetails ON Domains.ID = ThreatDetails.DomainID;
    `

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domainThreats []DomainThreatInfo
	for rows.Next() {
		var domainName, status, patternName, detectionTimeStr string

		if err := rows.Scan(&domainName, &status, &patternName, &detectionTimeStr); err != nil {
			return nil, err
		}

		var detectionTime time.Time

		if detectionTimeStr != "" {
			detectionTime, err = time.Parse("2006-01-02 15:04:05", detectionTimeStr)
			if err != nil {
				return nil, err
			}
		}

		domainThreats = append(domainThreats, DomainThreatInfo{
			DomainName:    domainName,
			Status:        status,
			PatternName:   patternName,
			DetectionTime: MyTime{detectionTime},
		})
	}

	return domainThreats, nil
}

func getDomainIDFromDatabase(db *sql.DB, domainName string) (int, error) {
	var domainID int

	query := "SELECT ID FROM Domains WHERE DomainName = ?"

	err := db.QueryRow(query, domainName).Scan(&domainID)
	if err != nil {
		if err == sql.ErrNoRows {

			insertSQL := "INSERT INTO Domains (DomainName, Status, ThreatsDetected) VALUES (?, ?, ?)"
			result, err := db.Exec(insertSQL, domainName, "offline", 0)
			if err != nil {
				return 0, err
			}

			lastInsertID, err := result.LastInsertId()
			if err != nil {
				return 0, err
			}

			return int(lastInsertID), nil
		}
		return 0, err
	}

	return domainID, nil
}

func extractPatternName(threatDetail string) string {

	re := regexp.MustCompile(`"([^"]+)"`)
	matches := re.FindStringSubmatch(threatDetail)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func resetAutoIncrement(db *sql.DB, tableName string) error {

	resetSQL := fmt.Sprintf("ALTER TABLE %s AUTO_INCREMENT = 1;", tableName)

	_, err := db.Exec(resetSQL)
	if err != nil {
		return err
	}

	return nil
}
