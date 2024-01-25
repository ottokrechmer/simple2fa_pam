# build
CGO_CFLAGS="-g -O2" go build --buildmode=c-shared -o /tmp/simple2fa_pam.so auth.go pam.go
sudo cp /tmp/simple2fa_pam.so /usr/lib64/security/

# Restart
systemctl restart openvpn-server@server

# See logs
cat /etc/openvpn/server/simple2fa.log 

# Configure PAM
sudo vi /etc/pam.d/openvpn 

auth    requisite     simple2fa_pam.so <skip / send>(password) <apiKey> 
account sufficient  pam_permit.so
session sufficient  pam_permit.so
