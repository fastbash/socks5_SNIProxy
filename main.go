package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	version string // 编译时写入版本号

	ConfigFilePath string // 配置文件
	LogFilePath    string // 日志文件
	EnableDebug    bool   // 调试模式（详细日志）

	ForwardPort = 443       // 要转发至的目标端口
	cfg         configModel // 配置文件结构
)

// 配置文件结构
type configModel struct {
	ForwardRules  []string `yaml:"rules,omitempty"`
	ListenAddr    string   `yaml:"listen_addr,omitempty"`
	EnableSocks   bool     `yaml:"enable_socks5,omitempty"`
	SocksAddr     string   `yaml:"socks_addr,omitempty"`
	SocksUser     string   `yaml:"socks_user,omitempty"`
	SocksPassword string   `yaml:"socks_password,omitempty"`
	AllowAllHosts bool     `yaml:"allow_all_hosts,omitempty"`
}

func init() {
	var printVersion bool
	var help = `
SNIProxy ` + version + `
https://github.com/XIU2/SNIProxy

参数：
    -c config.yaml
        配置文件 (默认 config.yaml)
    -l sni.log
        日志文件 (默认 无)
    -d
        调试模式 (默认 关)
    -v
        程序版本
    -h
        帮助说明
`
	flag.StringVar(&ConfigFilePath, "c", "config.yaml", "配置文件")
	flag.StringVar(&LogFilePath, "l", "", "日志文件")
	flag.BoolVar(&EnableDebug, "d", false, "调试模式")
	flag.BoolVar(&printVersion, "v", false, "程序版本")
	flag.Usage = func() { fmt.Print(help) }
	flag.Parse()
	if printVersion {
		fmt.Printf("XIU2/SNIProxy %s\n", version)
		os.Exit(0)
	}
}

func main() {
	data, err := os.ReadFile(ConfigFilePath) // 读取配置文件
	if err != nil {
		serviceLogger(fmt.Sprintf("配置文件读取失败: %v", err), 31, false)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		serviceLogger(fmt.Sprintf("配置文件解析失败: %v", err), 31, false)
		os.Exit(1)
	}
	if len(cfg.ForwardRules) <= 0 && !cfg.AllowAllHosts { // 如果 rules 为空且 allow_all_hosts 不等于 true
		serviceLogger("配置文件中 rules 不能为空（除非 allow_all_hosts 等于 true）!", 31, false)
		os.Exit(1)
	}
	for _, rule := range cfg.ForwardRules { // 输出规则中的所有域名
		serviceLogger(fmt.Sprintf("加载规则: %v", rule), 32, false)
	}
	serviceLogger(fmt.Sprintf("调试模式: %v", EnableDebug), 32, false)
	serviceLogger(fmt.Sprintf("前置代理: %v", cfg.EnableSocks), 32, false)
	serviceLogger(fmt.Sprintf("任意域名: %v", cfg.AllowAllHosts), 32, false)

	startProxy() // 启动代理服务
}

func startProxy() {
	// 监听 HTTP (80)
	go func() {
		listener, err := net.Listen("tcp", ":80")
		if err != nil {
			serviceLogger(fmt.Sprintf("HTTP 监听失败: %v", err), 31, false)
			return
		}
		defer listener.Close()
		serviceLogger("HTTP 代理已启动 (:80)", 32, false)

		for {
			conn, err := listener.Accept()
			if err != nil {
				serviceLogger(fmt.Sprintf("HTTP 接受连接失败: %v", err), 31, false)
				continue
			}
			go handleConnection(conn, conn.RemoteAddr().String())
		}
	}()

	// 监听 HTTPS (443)
	listener, err := net.Listen("tcp", ":443")
	if err != nil {
		serviceLogger(fmt.Sprintf("HTTPS 监听失败: %v", err), 31, false)
		os.Exit(1)
	}
	defer listener.Close()
	serviceLogger("HTTPS 代理已启动 (:443)", 32, false)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		listener.Close()
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			serviceLogger(fmt.Sprintf("HTTPS 接受连接失败: %v", err), 31, false)
			continue
		}
		go handleConnection(conn, conn.RemoteAddr().String())
	}
}

func handleConnection(c net.Conn, raddr string) {
	// defer c.Close() // debug

	// 读取第一个字节判断协议类型
	buf := make([]byte, 1)
	_, err := c.Read(buf)
	if err != nil {
		serviceLogger(fmt.Sprintf("读取失败: %v", err), 31, false)
		return
	}

	// 0x16 是 TLS 握手的第一字节, 其他 = HTTP
	if buf[0] == 0x16 {
		handleHTTPS(c, buf, raddr)
	} else {
		handleHTTP(c, buf, raddr)
	}
}

func handleHTTPS(c net.Conn, firstByte []byte, raddr string) {
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		serviceLogger(fmt.Sprintf("读取 HTTPS 数据失败: %v", err), 31, false)
		return
	}
	fullHeader := append(firstByte, buf[:n]...)

	ServerName := getSNIServerName(fullHeader)
	if ServerName == "" {
		serviceLogger("未找到 SNI 域名, 忽略...", 31, true)
		return
	}

	if cfg.AllowAllHosts {
		serviceLogger(fmt.Sprintf("[HTTPS] 转发目标: %s:%d", ServerName, ForwardPort), 32, false)
		forward(c, fullHeader, fmt.Sprintf("%s:%d", ServerName, ForwardPort), raddr)
		return
	}

	for _, rule := range cfg.ForwardRules {
		if strings.Contains(ServerName, rule) {
			serviceLogger(fmt.Sprintf("[HTTPS] 转发目标: %s:%d", ServerName, ForwardPort), 32, false)
			forward(c, fullHeader, fmt.Sprintf("%s:%d", ServerName, ForwardPort), raddr)
			return
		}
	}
}

func handleHTTP(c net.Conn, firstByte []byte, raddr string) {
	// 读取完整请求头（包括第一个字节）
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		serviceLogger(fmt.Sprintf("读取 HTTP 请求失败: %v", err), 31, false)
		return
	}
	fullRequest := append(firstByte, buf[:n]...) // 合并第一个字节和剩余数据

	host := extractHostFromHTTPHeader(fullRequest)
	if host == "" {
		serviceLogger("未找到 Host 头, 忽略...", 31, true)
		return
	}

	// 直接转发完整请求（不再丢弃请求头）
	serviceLogger(fmt.Sprintf("[HTTP] 转发目标: %s:80", host), 32, false)
	forward(c, fullRequest, fmt.Sprintf("%s:80", host), raddr) // 注意：目标端口固定为80
}

func extractHostFromHTTPHeader(header []byte) string {
	lines := strings.Split(string(header), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "host: ") {
			return strings.TrimSpace(line[6:])
		}
	}
	return ""
}

func forward(conn net.Conn, data []byte, dst string, raddr string) {
	backend, err := GetDialer(cfg.EnableSocks).Dial("tcp", dst)
	if err != nil {
		serviceLogger(fmt.Sprintf("无法连接到后端, %v", err), 31, false)
		return
	}
	defer backend.Close()

	if data != nil {
		if _, err = backend.Write(data); err != nil {
			serviceLogger(fmt.Sprintf("无法传输到后端, %v", err), 31, false)
			return
		}
	}

	// 移除未使用的 ctx 和 cancel
	conChk := make(chan struct{})
	go ioReflector(context.Background(), backend, conn, false, conChk, raddr, dst)
	go ioReflector(context.Background(), conn, backend, true, conChk, raddr, dst)
	<-conChk
}

func ioReflector(ctx context.Context, dst io.WriteCloser, src io.Reader, isToClient bool, conChk chan struct{}, raddr string, dsts string) {
	defer onDisconnect(dst, conChk)

	done := make(chan struct{})
	go func() {
		written, _ := io.Copy(dst, src)
		if isToClient {
			serviceLogger(fmt.Sprintf("[%v] -> [%v] %d bytes", dsts, raddr, written), 33, true)
		} else {
			serviceLogger(fmt.Sprintf("[%v] -> [%v] %d bytes", raddr, dsts, written), 33, true)
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
	case <-done:
	}
}

func onDisconnect(dst io.WriteCloser, conChk chan struct{}) {
	dst.Close()
	select {
	case conChk <- struct{}{}:
	default:
	}
}

func getSNIServerName(buf []byte) string {
	if len(buf) < 5 {
		return ""
	}

	if buf[0] != 0x16 { // 不是 TLS 握手
		return ""
	}

	length := binary.BigEndian.Uint16(buf[3:5])
	if len(buf) < int(length)+5 {
		return ""
	}

	msg := &clientHelloMsg{}
	if !msg.unmarshal(buf[5:]) {
		return ""
	}
	return msg.serverName
}

func (m *clientHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return false
	}
	m.sessionID = data[39 : 39+sessionIDLen]
	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return false
	}
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.cipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	m.compressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	m.nextProtoNeg = false
	m.serverName = ""
	m.ocspStapling = false
	m.ticketSupported = false
	m.sessionTicket = nil
	m.signatureAndHashes = nil
	m.alpnProtocols = nil
	m.scts = false

	if len(data) == 0 {
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionServerName:
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return false
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return false
				}
				if nameType == 0 {
					m.serverName = string(d[:nameLen])
					if strings.HasSuffix(m.serverName, ".") {
						return false
					}
					break
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}
	return true
}

func serviceLogger(log string, color int, isDebug bool) {
	if isDebug && !EnableDebug {
		return
	}
	log = strings.Replace(log, "\n", "", -1)
	log = strings.Join([]string{time.Now().Format("2006/01/02 15:04:05"), " ", log}, "")
	if color == 0 {
		fmt.Printf("%s\n", log)
	} else {
		fmt.Printf("%c[1;0;%dm%s%c[0m\n", 0x1B, color, log, 0x1B)
	}
	if LogFilePath != "" {
		fd, _ := os.OpenFile(LogFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		fdContent := strings.Join([]string{log, "\n"}, "")
		buf := []byte(fdContent)
		fd.Write(buf)
		fd.Close()
	}
}
