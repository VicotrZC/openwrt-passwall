--[[
vpncheap 2.3.23 订阅解密

复现自客户端 P0.e.o(String)：
    data  = base64url(input)        -- 容忍缺失 padding，支持 - 与 _
    iv    = data[1..16]
    ct    = data[17..]
    key   = SHA-256(AES_SEED)       -- 32 字节 -> AES-256
    plain = AES-256-CBC/PKCS5 decrypt(key, iv, ct)  -- 严格 UTF-8

纯 Lua 实现，不依赖 openssl 等外部命令，也不依赖 bit/bit32 库，
因此在 Lua 5.1 / 5.3 / 5.5 / LuaJIT 上都能运行。

注意：密钥是客户端硬编码常量，服务端加密只提供混淆，不提供机密性。
]]

local M = {}

local band, bor, bxor, bnot, rshift, lshift
do
	-- 优先用原生位运算（5.3+ 运算符 / LuaJIT bit / 5.2 bit32），
	-- 否则退化为纯算术实现。
	local has_native_ops = pcall(function() return 1 & 1 end)
	if has_native_ops then
		band = function(a, b) return a & b end
		bor = function(a, b) return a | b end
		bxor = function(a, b) return a ~ b end
		bnot = function(a) return ~a end
		rshift = function(a, n) return a >> n end
		lshift = function(a, n) return a << n end
	else
		local ok, jit_bit = pcall(require, "bit")
		local bitlib = ok and jit_bit or nil
		if not bitlib then
			local ok2, b32 = pcall(require, "bit32")
			bitlib = ok2 and b32 or nil
		end
		if bitlib then
			band, bor, bxor = bitlib.band, bitlib.bor, bitlib.bxor
			bnot = bitlib.bnot
			rshift, lshift = bitlib.rshift, bitlib.lshift
		else
			-- 纯算术实现，全程按 32 位无符号处理
			local function norm(x)
				x = x % 4294967296
				if x < 0 then x = x + 4294967296 end
				return x
			end
			band = function(a, b)
				a, b = norm(a), norm(b)
				local res, bit = 0, 1
				for _ = 1, 32 do
					if a % 2 == 1 and b % 2 == 1 then res = res + bit end
					a, b, bit = math.floor(a / 2), math.floor(b / 2), bit * 2
				end
				return res
			end
			bor = function(a, b)
				a, b = norm(a), norm(b)
				local res, bit = 0, 1
				for _ = 1, 32 do
					if a % 2 == 1 or b % 2 == 1 then res = res + bit end
					a, b, bit = math.floor(a / 2), math.floor(b / 2), bit * 2
				end
				return res
			end
			bxor = function(a, b)
				a, b = norm(a), norm(b)
				local res, bit = 0, 1
				for _ = 1, 32 do
					if (a % 2) ~= (b % 2) then res = res + bit end
					a, b, bit = math.floor(a / 2), math.floor(b / 2), bit * 2
				end
				return res
			end
			bnot = function(a) return norm(4294967295 - norm(a)) end
			rshift = function(a, n) return math.floor(norm(a) / (2 ^ n)) end
			lshift = function(a, n) return norm(norm(a) * (2 ^ n)) end
		end
	end
end

local function u32(x) return x % 4294967296 end
local function add32(...)
	local s = 0
	for i = 1, select("#", ...) do
		s = s + (select(i, ...) or 0)
	end
	return u32(s)
end

-- 32 位循环右移 / 左移。SHA-256 的 σ/Σ 是「循环」移位，不是逻辑移位；
-- 用 rshift 代替会丢掉移出的高位（这是最初实现出错的地方）。
-- 这里只用算术运算，因此在 5.1/5.3/5.5/LuaJIT 上行为一致。
local function rotr(x, n)
	x = u32(x)
	return u32(math.floor(x / (2 ^ n)) + (x % (2 ^ n)) * (2 ^ (32 - n)))
end

local function rotl(x, n)
	x = u32(x)
	return u32((x * (2 ^ n)) % 4294967296 + math.floor(x / (2 ^ (32 - n))))
end

M.rotr, M.rotl = rotr, rotl

--[[ ---------------------------- SHA-256 ---------------------------- ]]

local K = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function sha256(msg)
	local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

	local len = #msg
	local bitlen = len * 8

	-- padding
	msg = msg .. "\128"
	while #msg % 64 ~= 56 do msg = msg .. "\0" end
	-- 长度按 64 位大端；这里长度远小于 2^32，高 32 位为 0
	msg = msg .. "\0\0\0\0"
	msg = msg .. string.char(
		math.floor(bitlen / 16777216) % 256,
		math.floor(bitlen / 65536) % 256,
		math.floor(bitlen / 256) % 256,
		bitlen % 256
	)

	local w = {}
	for i = 0, #msg / 64 - 1 do
		local base = i * 64
		for j = 0, 15 do
			local o = base + j * 4
			local b1, b2, b3, b4 = msg:byte(o + 1, o + 4)
			w[j] = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
		end
		for j = 16, 63 do
			local x, y = w[j - 15], w[j - 2]
			local s0 = bxor(bxor(rotr(x, 7), rotr(x, 18)), rshift(x, 3))
			local s1 = bxor(bxor(rotr(y, 17), rotr(y, 19)), rshift(y, 10))
			w[j] = add32(w[j - 16], s0, w[j - 7], s1)
		end

		local a, b, c, d = h0, h1, h2, h3
		local e, f, g, h = h4, h5, h6, h7

		for j = 0, 63 do
			local S1 = bxor(bxor(rotr(e, 6), rotr(e, 11)), rotr(e, 25))
			local ch = bxor(band(e, f), band(bnot(e), g))
			local t1 = add32(h, S1, ch, K[j + 1], w[j])
			local S0 = bxor(bxor(rotr(a, 2), rotr(a, 13)), rotr(a, 22))
			local maj = bxor(bxor(band(a, b), band(a, c)), band(b, c))
			local t2 = add32(S0, maj)
			h, g, f, e = g, f, e, add32(d, t1)
			d, c, b, a = c, b, a, add32(t1, t2)
		end

		h0, h1, h2, h3 = add32(h0, a), add32(h1, b), add32(h2, c), add32(h3, d)
		h4, h5, h6, h7 = add32(h4, e), add32(h5, f), add32(h6, g), add32(h7, h)
	end

	local out = {}
	for _, v in ipairs({ h0, h1, h2, h3, h4, h5, h6, h7 }) do
		out[#out + 1] = string.char(
			math.floor(v / 16777216) % 256,
			math.floor(v / 65536) % 256,
			math.floor(v / 256) % 256,
			v % 256
		)
	end
	return table.concat(out)
end

M.sha256 = sha256

--[[ ----------------------------- AES ------------------------------ ]]

-- S 盒直接用标准表：按 GF(2^8) 现算需要完整的乘法逆元迭代，
-- 在纯 Lua 里既慢又容易写错，而这张表是 AES 规范固定的。
local SBOX, INV_SBOX = {}, {}
do
	local sbox_std = {
		0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
		0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
		0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
		0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
		0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
		0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
		0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
		0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
		0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
		0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
		0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
		0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
		0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
		0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
		0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
		0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
	}
	for i = 0, 255 do SBOX[i] = sbox_std[i + 1] end
	for i = 0, 255 do INV_SBOX[SBOX[i]] = i end
end

local RCON = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
	0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000,
	0x6c000000, 0xd8000000, 0xab000000, 0x4d000000,
}

local function sub_word(w)
	return bor(
		bor(lshift(SBOX[rshift(w, 24)], 24), lshift(SBOX[band(rshift(w, 16), 0xff)], 16)),
		bor(lshift(SBOX[band(rshift(w, 8), 0xff)], 8), SBOX[band(w, 0xff)])
	)
end

local function rot_word(w)
	return bor(lshift(band(w, 0x00ffffff), 8), rshift(w, 24))
end

-- AES-256：Nk=8, Nr=14
local function expand_key(key)
	local Nk, Nr = 8, 14
	local w = {}
	for i = 0, Nk - 1 do
		local o = i * 4 + 1
		local b1, b2, b3, b4 = key:byte(o, o + 3)
		w[i] = ((b1 * 256 + b2) * 256 + b3) * 256 + b4
	end
	for i = Nk, 4 * (Nr + 1) - 1 do
		local temp = w[i - 1]
		if i % Nk == 0 then
			temp = bxor(sub_word(rot_word(temp)), RCON[math.floor(i / Nk)])
		elseif i % Nk == 4 then
			temp = sub_word(temp)
		end
		w[i] = bxor(w[i - Nk], temp)
	end
	return w
end

local function xtime(x)
	x = lshift(x, 1)
	if x >= 256 then x = bxor(x, 0x11b) end
	return x % 256
end

local function gmul(a, b)
	local p = 0
	for _ = 1, 8 do
		if band(b, 1) == 1 then p = bxor(p, a) end
		b = rshift(b, 1)
		a = xtime(a)
	end
	return p % 256
end

local function decrypt_block(block, w)
	local Nr = 14
	local s = {}
	for i = 0, 3 do
		local b1, b2, b3, b4 = block:byte(i * 4 + 1, i * 4 + 4)
		s[i * 4]     = bxor(b1, band(rshift(w[Nr * 4 + i], 24), 0xff))
		s[i * 4 + 1] = bxor(b2, band(rshift(w[Nr * 4 + i], 16), 0xff))
		s[i * 4 + 2] = bxor(b3, band(rshift(w[Nr * 4 + i], 8), 0xff))
		s[i * 4 + 3] = bxor(b4, band(w[Nr * 4 + i], 0xff))
	end

	for round = Nr - 1, 1, -1 do
		-- 每轮顺序（与 aes_ref.decrypt_block 严格一致，已用 FIPS-197 向量验证）：
		--   InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
		-- 这是「直接逆密码」形式：InvShiftRows/InvSubBytes 在前，AddRoundKey
		-- 与 InvMixColumns 保持 AddRoundKey 在先。
		-- 之前写成 AddRoundKey -> InvMixColumns -> InvShiftRows -> InvSubBytes
		-- 是「等价逆密码」的顺序，那种形式必须同时把后两个提前，混用即出错。

		-- InvShiftRows + InvSubBytes
		-- 正向 ShiftRows 是 t[c*4+r] = s[((c+r)%4)*4+r]（第 r 行左移 r），
		-- 逆向必须是 t[c*4+r] = s[((c-r)%4)*4+r]（第 r 行右移 r）。
		local t = {}
		t[0],  t[4],  t[8],  t[12] = INV_SBOX[s[0]],  INV_SBOX[s[4]],  INV_SBOX[s[8]],  INV_SBOX[s[12]]
		t[1],  t[5],  t[9],  t[13] = INV_SBOX[s[13]], INV_SBOX[s[1]],  INV_SBOX[s[5]],  INV_SBOX[s[9]]
		t[2],  t[6],  t[10], t[14] = INV_SBOX[s[10]], INV_SBOX[s[14]], INV_SBOX[s[2]],  INV_SBOX[s[6]]
		t[3],  t[7],  t[11], t[15] = INV_SBOX[s[7]],  INV_SBOX[s[11]], INV_SBOX[s[15]], INV_SBOX[s[3]]
		s = t

		-- AddRoundKey
		for i = 0, 3 do
			local k = w[round * 4 + i]
			s[i * 4]     = bxor(s[i * 4],     band(rshift(k, 24), 0xff))
			s[i * 4 + 1] = bxor(s[i * 4 + 1], band(rshift(k, 16), 0xff))
			s[i * 4 + 2] = bxor(s[i * 4 + 2], band(rshift(k, 8), 0xff))
			s[i * 4 + 3] = bxor(s[i * 4 + 3], band(k, 0xff))
		end

		-- InvMixColumns
		local m = {}
		for c = 0, 3 do
			local a0, a1, a2, a3 = s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]
			m[c * 4]     = bxor(bxor(gmul(a0, 14), gmul(a1, 11)), bxor(gmul(a2, 13), gmul(a3, 9)))
			m[c * 4 + 1] = bxor(bxor(gmul(a0, 9), gmul(a1, 14)), bxor(gmul(a2, 11), gmul(a3, 13)))
			m[c * 4 + 2] = bxor(bxor(gmul(a0, 13), gmul(a1, 9)), bxor(gmul(a2, 14), gmul(a3, 11)))
			m[c * 4 + 3] = bxor(bxor(gmul(a0, 11), gmul(a1, 13)), bxor(gmul(a2, 9), gmul(a3, 14)))
		end
		s = m
	end

	-- 最后一轮：无 InvMixColumns
	local t = {}
	t[0],  t[4],  t[8],  t[12] = INV_SBOX[s[0]],  INV_SBOX[s[4]],  INV_SBOX[s[8]],  INV_SBOX[s[12]]
	t[1],  t[5],  t[9],  t[13] = INV_SBOX[s[13]], INV_SBOX[s[1]],  INV_SBOX[s[5]],  INV_SBOX[s[9]]
	t[2],  t[6],  t[10], t[14] = INV_SBOX[s[10]], INV_SBOX[s[14]], INV_SBOX[s[2]],  INV_SBOX[s[6]]
	t[3],  t[7],  t[11], t[15] = INV_SBOX[s[7]],  INV_SBOX[s[11]], INV_SBOX[s[15]], INV_SBOX[s[3]]

	local out = {}
	for i = 0, 3 do
		local k = w[i]
		out[i * 4 + 1] = string.char(bxor(t[i * 4],     band(rshift(k, 24), 0xff)))
		out[i * 4 + 2] = string.char(bxor(t[i * 4 + 1], band(rshift(k, 16), 0xff)))
		out[i * 4 + 3] = string.char(bxor(t[i * 4 + 2], band(rshift(k, 8), 0xff)))
		out[i * 4 + 4] = string.char(bxor(t[i * 4 + 3], band(k, 0xff)))
	end
	return table.concat(out)
end

--[[ ------------------------ base64url 解码 ------------------------- ]]

local B64_LOOKUP = {}
do
	local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for i = 1, #alphabet do B64_LOOKUP[alphabet:sub(i, i)] = i - 1 end
	-- URL-safe 变体
	B64_LOOKUP["-"] = 62
	B64_LOOKUP["_"] = 63
end

local function base64_decode(input)
	input = input:gsub("%s", "")
	input = input:gsub("=", "")
	local out, buf, nbits = {}, 0, 0
	for i = 1, #input do
		local v = B64_LOOKUP[input:sub(i, i)]
		if not v then return nil, "invalid base64 character" end
		buf = buf * 64 + v
		nbits = nbits + 6
		if nbits >= 8 then
			nbits = nbits - 8
			out[#out + 1] = string.char(math.floor(buf / (2 ^ nbits)) % 256)
			buf = buf % (2 ^ nbits)
		end
	end
	return table.concat(out)
end

M.base64Decode = base64_decode

--[[ --------------------------- 对外接口 ---------------------------- ]]

local AES_SEED = "7f96f0cd9b99abedaa93f9292adcd9dbf1968e6ebba39667e8e9846203c75136"

local aes_key
local function get_key()
	if not aes_key then
		aes_key = sha256(AES_SEED)
	end
	return aes_key
end

--- 解密服务端返回的订阅正文。
-- @param body 响应正文（base64url）
-- @return 明文，或 nil + 错误信息
function M.decrypt(body)
	if not body or body == "" then
		return nil, "empty payload"
	end
	local raw, err = base64_decode(body)
	if not raw then
		return nil, "invalid base64: " .. tostring(err)
	end
	if #raw <= 16 then
		return nil, string.format("encrypted payload is truncated (%d bytes)", #raw)
	end

	local iv = raw:sub(1, 16)
	local ct = raw:sub(17)
	if #ct % 16 ~= 0 then
		return nil, "ciphertext length is not a multiple of 16"
	end

	local w = expand_key(get_key())
	local out = {}
	for i = 0, #ct / 16 - 1 do
		local block = ct:sub(i * 16 + 1, i * 16 + 16)
		local plain = decrypt_block(block, w)
		-- CBC：与前一块密文（或 IV）异或
		local prev = (i == 0) and iv or ct:sub((i - 1) * 16 + 1, i * 16)
		local xored = {}
		for j = 1, 16 do
			xored[j] = string.char(bxor(plain:byte(j), prev:byte(j)))
		end
		out[#out + 1] = table.concat(xored)
	end

	local padded = table.concat(out)
	local pad = padded:byte(#padded)
	if not pad or pad < 1 or pad > 16 or pad > #padded then
		return nil, "bad PKCS5 padding"
	end
	for i = #padded - pad + 1, #padded do
		if padded:byte(i) ~= pad then
			return nil, "bad PKCS5 padding"
		end
	end
	return padded:sub(1, #padded - pad)
end

--- 响应头是否标记正文已加密（X-Encrypted: 1）
function M.isEncrypted(header_str)
	if not header_str or header_str == "" then
		return false
	end
	for line in header_str:gmatch("[^\n]+") do
		local name, value = line:match("^([^:]+):%s*(.-)%s*$")
		if name and name:lower() == "x-encrypted" then
			return value == "1"
		end
	end
	return false
end

--- 若标记为加密则解密，否则原样返回
function M.decryptIfNeeded(body, header_str)
	if not M.isEncrypted(header_str) then
		return body
	end
	local plain, err = M.decrypt(body)
	if not plain then
		return nil, err
	end
	return plain
end

-- 仅供测试：覆盖密钥（默认是 vpncheap 的固定种子），
-- 以便用标准 AES 测试向量验证核心实现。
function M._setKeyForTest(key)
	if key == nil then
		aes_key = nil
	else
		assert(#key == 32, "AES-256 key must be 32 bytes")
		aes_key = key
	end
end

-- 仅供测试：解密单个块（不做 CBC 链接、不去 padding）
function M._decryptBlockForTest(block)
	assert(#block == 16, "block must be 16 bytes")
	return decrypt_block(block, expand_key(get_key()))
end

-- 仅供测试：返回密钥扩展结果（60 个字），用于对照标准向量
function M._keyScheduleForTest()
	return expand_key(get_key())
end

-- 仅供测试：解密轮的各中间态，用于逐步对照
function M._traceForTest(ct)
	local Nr = 14
	local w = expand_key(get_key())
	local s = {}
	for i = 0, 3 do
		local b1, b2, b3, b4 = ct:byte(i * 4 + 1, i * 4 + 4)
		s[i * 4]     = bxor(b1, band(rshift(w[Nr * 4 + i], 24), 0xff))
		s[i * 4 + 1] = bxor(b2, band(rshift(w[Nr * 4 + i], 16), 0xff))
		s[i * 4 + 2] = bxor(b3, band(rshift(w[Nr * 4 + i], 8), 0xff))
		s[i * 4 + 3] = bxor(b4, band(w[Nr * 4 + i], 0xff))
	end
	local function pack_of(tbl)
		local o = {}
		for i = 0, 15 do o[i + 1] = string.char(tbl[i]) end
		return table.concat(o)
	end
	local function pack() return pack_of(s) end
	local out = { pack() }
	for round = Nr - 1, 1, -1 do
		for i = 0, 3 do
			local k = w[round * 4 + i]
			s[i * 4]     = bxor(s[i * 4],     band(rshift(k, 24), 0xff))
			s[i * 4 + 1] = bxor(s[i * 4 + 1], band(rshift(k, 16), 0xff))
			s[i * 4 + 2] = bxor(s[i * 4 + 2], band(rshift(k, 8), 0xff))
			s[i * 4 + 3] = bxor(s[i * 4 + 3], band(k, 0xff))
		end
		out[#out + 1] = pack()
		local m = {}
		for c = 0, 3 do
			local a0, a1, a2, a3 = s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]
			m[c * 4]     = bxor(bxor(gmul(a0, 14), gmul(a1, 11)), bxor(gmul(a2, 13), gmul(a3, 9)))
			m[c * 4 + 1] = bxor(bxor(gmul(a0, 9), gmul(a1, 14)), bxor(gmul(a2, 11), gmul(a3, 13)))
			m[c * 4 + 2] = bxor(bxor(gmul(a0, 13), gmul(a1, 9)), bxor(gmul(a2, 14), gmul(a3, 11)))
			m[c * 4 + 3] = bxor(bxor(gmul(a0, 11), gmul(a1, 13)), bxor(gmul(a2, 9), gmul(a3, 14)))
		end
		out[#out + 1] = pack_of(m)
		local t = {}
		t[0],  t[4],  t[8],  t[12] = INV_SBOX[m[0]],  INV_SBOX[m[4]],  INV_SBOX[m[8]],  INV_SBOX[m[12]]
		t[1],  t[5],  t[9],  t[13] = INV_SBOX[m[13]], INV_SBOX[m[1]],  INV_SBOX[m[5]],  INV_SBOX[m[9]]
		t[2],  t[6],  t[10], t[14] = INV_SBOX[m[10]], INV_SBOX[m[14]], INV_SBOX[m[2]],  INV_SBOX[m[6]]
		t[3],  t[7],  t[11], t[15] = INV_SBOX[m[7]],  INV_SBOX[m[11]], INV_SBOX[m[15]], INV_SBOX[m[3]]
		s = t
		out[#out + 1] = pack()
	end
	local t = {}
	for c = 0, 3 do
		for r = 0, 3 do
			t[c * 4 + r] = INV_SBOX[s[((c - r) % 4) * 4 + r]]
		end
	end
	s = t
	for i = 0, 3 do
		local k = w[i]
		s[i * 4]     = bxor(s[i * 4],     band(rshift(k, 24), 0xff))
		s[i * 4 + 1] = bxor(s[i * 4 + 1], band(rshift(k, 16), 0xff))
		s[i * 4 + 2] = bxor(s[i * 4 + 2], band(rshift(k, 8), 0xff))
		s[i * 4 + 3] = bxor(s[i * 4 + 3], band(k, 0xff))
	end
	out[#out + 1] = pack()
	return out
end

return M
