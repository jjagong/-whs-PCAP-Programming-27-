# -whs-PCAP-Programming-27-

## 설치 
```
sudo apt update
sudo apt install -y gcc make libpcap-dev
```

## 빌드
```
make
```

## 실행

```
sudo ./pcap_packet_printer lo 0 "tcp port 8080"
```
