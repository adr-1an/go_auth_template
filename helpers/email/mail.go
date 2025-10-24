package email

import (
	"bytes"
	"gopkg.in/gomail.v2"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strconv"
)

func SendVerification(to string, verificationLink string) error {
	// Parse template
	cwd, err := os.Getwd()
	if err != nil {
		log.Println(err)
		return err
	}
	path := filepath.Join(cwd, "helpers/email/templates", "verify-email.html")
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return err
	}

	// Inject data
	var body bytes.Buffer
	err = tmpl.Execute(&body, map[string]string{
		"VerificationLink": verificationLink,
	})
	if err != nil {
		return err
	}

	// Build message
	m := gomail.NewMessage()
	from := os.Getenv("APPLICATION_NAME") + " <" + os.Getenv("SMTP_FROM") + ">"
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Verify your email")
	m.SetBody("text/html", body.String())

	// SMTP Config
	smtpHost := os.Getenv("SMTP_HOST")
	smtpUser := os.Getenv("SMTP_USERNAME")
	smtpPortStr := os.Getenv("SMTP_PORT")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return err
	}

	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPassword)

	return d.DialAndSend(m)
}

func SendReset(to string, resetLink string) error {
	// Parse template
	cwd, err := os.Getwd()
	if err != nil {
		log.Println(err)
		return err
	}
	path := filepath.Join(cwd, "helpers/email/templates", "reset-password.html")
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return err
	}

	// Inject data
	var body bytes.Buffer
	err = tmpl.Execute(&body, map[string]string{
		"ResetLink": resetLink,
	})
	if err != nil {
		return err
	}

	// Build message
	m := gomail.NewMessage()
	from := os.Getenv("APPLICATION_NAME") + " <" + os.Getenv("SMTP_FROM") + ">"
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Reset Password")
	m.SetBody("text/html", body.String())

	// SMTP Config
	smtpHost := os.Getenv("SMTP_HOST")
	smtpUser := os.Getenv("SMTP_USERNAME")
	smtpPortStr := os.Getenv("SMTP_PORT")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return err
	}

	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPassword)

	return d.DialAndSend(m)
}

func SendEmailChange(to string, link string) error {
	// Parse template
	cwd, err := os.Getwd()
	if err != nil {
		log.Println(err)
		return err
	}
	path := filepath.Join(cwd, "helpers/email/templates", "change-email.html")
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		return err
	}

	// Inject data
	var body bytes.Buffer
	err = tmpl.Execute(&body, map[string]string{
		"Link": link,
	})
	if err != nil {
		return err
	}

	// Build message
	m := gomail.NewMessage()
	from := os.Getenv("APPLICATION_NAME") + " <" + os.Getenv("SMTP_FROM") + ">"
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Change Email")
	m.SetBody("text/html", body.String())

	// SMTP Config
	smtpHost := os.Getenv("SMTP_HOST")
	smtpUser := os.Getenv("SMTP_USERNAME")
	smtpPortStr := os.Getenv("SMTP_PORT")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return err
	}

	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPassword)

	return d.DialAndSend(m)
}
