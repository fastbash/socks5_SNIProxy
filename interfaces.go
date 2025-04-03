package main

import (
	"net"
	"strings"

	"golang.org/x/net/proxy"
)

func GetDialer(isSocks5 bool) proxy.Dialer {
	if !isSocks5 || cfg.SocksAddr == "" {
		// 如果未启用 SOCKS5 或未配置地址，回退到直连
		return &net.Dialer{}
	}

	// 解析 SOCKS5 地址（兼容 IPv6）
	network := "tcp"
	socksAddr := cfg.SocksAddr

	// 如果地址包含 IPv6（如 [fe80::1]:1080）
	if strings.Contains(socksAddr, "]") {
		network = "tcp6" // 明确指定 IPv6 网络
	}

	var auth *proxy.Auth
	if cfg.SocksUser != "" || cfg.SocksPassword != "" {
		// 只有配置了用户名或密码时才设置认证
		auth = &proxy.Auth{
			User:     cfg.SocksUser,
			Password: cfg.SocksPassword,
		}
	}

	proxyDialer, err := proxy.SOCKS5(network, cfg.SocksAddr, auth, proxy.Direct)
	if err != nil {
		// log.Printf("SOCKS5 代理连接失败（地址：%s，用户名：%s），回退到直连: %v", cfg.SocksAddr, cfg.SocksUser, err)
		return &net.Dialer{}
	}
	return proxyDialer
}
