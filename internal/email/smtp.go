package email

import (
	"fmt"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
)

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type SMTPService struct {
	config SMTPConfig
}

func NewSMTPService(cfg SMTPConfig) *SMTPService {
	return &SMTPService{
		config: cfg,
	}
}

func (s *SMTPService) SendVerificationEmail(
	to string,
	verificationURL string,
) error {
	from, err := mail.ParseAddress(s.config.From)
	if err != nil || from.Address != s.config.From {
		return fmt.Errorf("invalid sender email address")
	}

	recipient, err := mail.ParseAddress(to)
	if err != nil || recipient.Address != to {
		return fmt.Errorf("invalid recipient email address")
	}

	if strings.ContainsAny(verificationURL, "\r\n") {
		return fmt.Errorf("invalid verification URL")
	}

	subject := "Verify Your EquityLens Account"

	body := fmt.Sprintf(`
Hello,

Thank you for registering with EquityLens.

Please verify your email address by clicking the link below:

%s

If you did not create an account, you can ignore this email.

Regards,
EquityLens Team
`, verificationURL)

	message := strings.Join([]string{
		"From: " + from.String(),
		"To: " + recipient.String(),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		body,
	}, "\r\n")

	auth := smtp.PlainAuth(
		"",
		s.config.Username,
		s.config.Password,
		s.config.Host,
	)

	address := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	err = smtp.SendMail(
		address,
		auth,
		from.Address,
		[]string{recipient.Address},
		[]byte(message),
	)
	if err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	return nil
}

// BuildVerificationURL creates a frontend verification link.
func BuildVerificationURL(baseURL, token string) string {
	return strings.TrimRight(baseURL, "/") +
		"/verify-email?token=" + url.QueryEscape(token)
}
