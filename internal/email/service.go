package email

type Service interface {
	SendVerificationEmail(to, verificationURL string) error
}
