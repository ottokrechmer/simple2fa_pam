# Commands

## Build

CGO_CFLAGS="-g -O2" go build --buildmode=c-shared -o /tmp/simple2fa_pam.so auth.go pam.go\
sudo cp /tmp/simple2fa_pam.so /usr/lib64/security/

## Restart

sudo systemctl restart openvpn-server@server

## See logs

sudo tail -200 /var/log/openvpn/openvpn.log\
search the "simple2fa" word

## Configure PAM

sudo vi /etc/pam.d/openvpn

### Args

- send / skip - send or skip sending password REQUIRED
- apiKey - API key for request Simple2fa server REQUIRED

### Example

auth    requisite   simple2fa_pam.so send FDGfdgg3in3rgnrogng34o3543vsdFGSFSGDVGDFHFEGDFGDQWE\
account sufficient  pam_permit.so\
session sufficient  pam_permit.so\
