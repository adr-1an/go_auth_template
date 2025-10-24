## Setup & Customization
- Configure .env
- Change app name in `/helpers/email/templates/verify-email.html`

## Frontend Compatibility
The frontend email verification route can be
modified in `/handlers/emailverification.go`,
line `200`.

Password reset route can be modified in `/handlers/auth.go`, line `504`.

Check route file (in `/routes/main.go`) to ensure compatibility with frontend API requests.
