go mod tidy
go build rawtls.go
sudo ./rawtls -listen :443 -iface tun0   # server
sudo ./rawtls -remote IP:443 -iface tun0 # client