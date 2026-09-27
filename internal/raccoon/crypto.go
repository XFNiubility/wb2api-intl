// crypto.go 复刻小浣熊前端的 AES-128-CFB 敏感字段加密（phone / password）。
//
// 逆向自前端 bundle 的 Zr(R, P="senseraccoon2023")：
//   - 密钥 16 字节 ASCII "senseraccoon2023"（AES-128）
//   - 每次随机 16 字节 IV
//   - CryptoJS AES CFB（整块反馈，segment=128bit）+ NoPadding
//   - 输出 base64(iv || ciphertext)
//
// 说明：这是登录接口 login_with_password 对 phone/password 的传输层混淆，
// 密钥硬编码在公开前端，不提供任何机密性——仅为对齐上游协议格式。
package raccoon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
)

// raccoonAESKey 前端硬编码密钥（AES-128）。
var raccoonAESKey = []byte("senseraccoon2023")

// encryptField 按上游 Zr 算法加密一个字段，返回 base64(iv||ct)。
// NoPadding + CFB 全块反馈：Go 的 cipher.NewCFBEncrypter 即 128bit segment，与 CryptoJS 一致。
func encryptField(plain string) (string, error) {
	block, err := aes.NewCipher(raccoonAESKey)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pt := []byte(plain)
	ct := make([]byte, len(pt))
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ct, pt)
	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}
