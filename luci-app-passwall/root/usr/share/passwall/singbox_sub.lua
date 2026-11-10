#!/usr/bin/lua

--[[
	vpncheap 这类订阅的处理：响应是 AES-256-CBC 加密的 sing-box JSON，
	PassWall 原来只认 Clash YAML 和分享链接，于是直接订阅会解析出 0 个节点。

	本文件补两块：
	  1. singboxSubDecrypt   —— base64url(IV[16] || AES-256-CBC/PKCS7) 解密
	  2. singboxSubToLinks   —— sing-box outbounds 转成分享链接，交给现成的 parse_link

	两个函数都挂了全局名，由 subscribe.lua 在 loadfile() 之后直接调用，
	和 clash_subconverter.lua 的约定保持一致。

	密码学部分刻意不自己实现：用 openssl 命令行。密钥是 SHA-256(种子串) 的十六进制，
	直接写在这里，省掉一次 SHA-256 计算。
--]]

local api = require("luci.passwall.api")
local base64Encode = api.base64Encode

-- 注意：这里不能用 api.base64Decode。
-- 它做完解码会重新编码并去掉尾部等号，再和原输入比较：
--     local reencoded = nixio.bin.b64encode(result):gsub("=+$", "")
--     if reencoded ~= encoded then return text end
-- 服务端返回的 base64 是带 "=" 的，于是这个比较永远不成立，
-- 函数会把 base64 文本原样返回而不报错。调用方拿到一堆 ASCII 当二进制，
-- openssl 就会报「不是块长度整数倍」，最终节点数为 0。
-- 所以自己用 nixio 解码，不经过那个规范校验。
local nixio_ok, nixio = pcall(require, "nixio")

-- AES-256 密钥 = sha256("7f96f0cd9b99abedaa93f9292adcd9dbf1968e6ebba39667e8e9846203c75136")
local AES_KEY_HEX = "3d7ad5e98d00ef072810c4f7e3b140a7d1cdf3ad512f5a87ea88b91ea2c64bac"

local SKIP_TYPES = {
	["direct"] = true,
	["block"] = true,
	["dns"] = true,
	["selector"] = true,
	["urltest"] = true,
}

local function hexlify(s)
	return (s:gsub(".", function(c)
		return string.format("%02x", string.byte(c))
	end))
end

-- base64 / base64url -> 二进制。容忍尾部等号缺失、URL 安全字符、换行和空格。
local function b64_decode(raw)
	if type(raw) ~= "string" or raw == "" then return nil, "内容为空" end
	local s = raw:gsub("%s+", ""):gsub("%z", "")
	if s == "" then return nil, "内容为空" end
	s = s:gsub("%-", "+"):gsub("_", "/")
	local mod4 = #s % 4
	if mod4 == 1 then
		return nil, "base64 长度不合法（%4==1）"
	end
	if mod4 > 0 then
		s = s .. string.rep("=", 4 - mod4)
	end
	if nixio_ok and nixio and nixio.bin and nixio.bin.b64decode then
		local ok, out = pcall(nixio.bin.b64decode, s)
		if ok and out and out ~= "" then
			return out, nil
		end
		return nil, "nixio 解码失败"
	end
	-- 兜底：用 coreutils base64（Makefile 已依赖）
	local tmp_in = "/tmp/pw_singbox_b64.txt"
	local tmp_out = "/tmp/pw_singbox_b64.bin"
	local f = io.open(tmp_in, "wb")
	if not f then return nil, "无法写入 " .. tmp_in end
	f:write(s)
	f:close()
	os.execute("base64 -d " .. tmp_in .. " > " .. tmp_out .. " 2>/dev/null")
	local g = io.open(tmp_out, "rb")
	if not g then return nil, "base64 -d 失败" end
	local out = g:read("*a")
	g:close()
	os.remove(tmp_in)
	os.remove(tmp_out)
	if not out or out == "" then return nil, "base64 -d 产出为空" end
	return out, nil
end

--[[
	百分号编码。要和服务端/其它客户端生成的链接保持完全一致，
	所以严格按 Python urllib.parse.quote（safe="/"）与 quote_plus 的规则来：
	  永远不编码 A-Z a-z 0-9 _ . - ~
	  plus=true 时空格编码成 "+"，否则 "%20"
	  safe 里的字符原样保留
--]]
local function pct(s, safe, plus)
	if s == nil then return "" end
	s = tostring(s)
	local out = {}
	for i = 1, #s do
		local c = s:sub(i, i)
		local b = c:byte()
		if (b >= 48 and b <= 57) or (b >= 65 and b <= 90) or (b >= 97 and b <= 122)
			or c == "_" or c == "." or c == "-" or c == "~" then
			out[#out + 1] = c
		elseif plus and c == " " then
			out[#out + 1] = "+"
		elseif safe and safe ~= "" and safe:find(c, 1, true) then
			out[#out + 1] = c
		else
			out[#out + 1] = string.format("%%%02X", b)
		end
	end
	return table.concat(out)
end

-- 按插入顺序拼 query，键和值都用 quote_plus 规则
local function build_query(pairs)
	local out = {}
	for _, kv in ipairs(pairs) do
		local k, v = kv[1], kv[2]
		if v ~= nil and v ~= "" then
			out[#out + 1] = pct(k, nil, true) .. "=" .. pct(v, nil, true)
		end
	end
	return table.concat(out, "&")
end

local function is_str(v)
	return type(v) == "string" and v ~= ""
end

local function tag_suffix(tag)
	if is_str(tag) then
		return "#" .. pct(tag, "/", false)
	end
	return ""
end

local function host_port(cfg)
	return string.format("%s:%s", tostring(cfg.server or ""), tostring(cfg.server_port or ""))
end

-- anytls://password@host:port?sni=..&insecure=1&alpn=..#tag
local function enc_anytls(cfg, tag)
	local tls = cfg.tls or {}
	local pairs_list = {}
	if is_str(tls.server_name) then pairs_list[#pairs_list + 1] = { "sni", tls.server_name } end
	if tls.insecure then pairs_list[#pairs_list + 1] = { "insecure", "1" } end
	if type(tls.alpn) == "table" and #tls.alpn > 0 then
		pairs_list[#pairs_list + 1] = { "alpn", table.concat(tls.alpn, ",") }
	end
	local q = build_query(pairs_list)
	local link = "anytls://" .. tostring(cfg.password or "") .. "@" .. host_port(cfg)
	if q ~= "" then link = link .. "?" .. q end
	return link .. tag_suffix(tag)
end

-- hysteria2://password@host:port?sni=..&insecure=0&obfs=salamander&obfs-password=..#tag
local function enc_hysteria2(cfg, tag)
	local tls = cfg.tls or {}
	local pairs_list = {}
	if is_str(tls.server_name) then pairs_list[#pairs_list + 1] = { "sni", tls.server_name } end
	pairs_list[#pairs_list + 1] = { "insecure", tls.insecure and "1" or "0" }
	-- hop_interval 形如 "15s"，换算成端口范围（与 2.3.x 客户端一致）
	if is_str(cfg.hop_interval) then
		local n = tonumber(tostring(cfg.hop_interval):gsub("[sm]", ""))
		local base_port = tonumber(cfg.server_port) or 0
		if n and base_port > 0 then
			pairs_list[#pairs_list + 1] = { "mport", string.format("%d-%d", base_port, base_port + n * 10) }
		end
	end
	local obfs = cfg.obfs or {}
	if obfs.type == "salamander" and is_str(obfs.password) then
		pairs_list[#pairs_list + 1] = { "obfs", "salamander" }
		pairs_list[#pairs_list + 1] = { "obfs-password", obfs.password }
	end
	local q = build_query(pairs_list)
	local link = "hysteria2://" .. tostring(cfg.password or "") .. "@" .. host_port(cfg)
	if q ~= "" then link = link .. "?" .. q end
	return link .. tag_suffix(tag)
end

-- vless://uuid@host:port?flow=..&security=tls&sni=..#tag
local function enc_vless(cfg, tag)
	local tls = cfg.tls or {}
	local pairs_list = {}
	if is_str(cfg.flow) then pairs_list[#pairs_list + 1] = { "flow", cfg.flow } end
	if tls.enabled then
		pairs_list[#pairs_list + 1] = { "security", "tls" }
		if is_str(tls.server_name) then pairs_list[#pairs_list + 1] = { "sni", tls.server_name } end
	end
	local reality = tls.reality or {}
	if is_str(reality.public_key) then
		pairs_list[#pairs_list + 1] = { "security", "reality" }
		pairs_list[#pairs_list + 1] = { "pbk", reality.public_key }
	end
	local net = cfg.network or "tcp"
	if net ~= "tcp" then pairs_list[#pairs_list + 1] = { "type", net } end
	if net == "ws" then
		pairs_list[#pairs_list + 1] = { "path", cfg.ws_path or "/" }
		local h = (cfg.ws_headers or {}).Host
		if is_str(h) then pairs_list[#pairs_list + 1] = { "host", h } end
	elseif net == "grpc" then
		pairs_list[#pairs_list + 1] = { "serviceName", cfg.grpc_service_name or "" }
	end
	local q = build_query(pairs_list)
	local link = string.format("vless://%s@%s", tostring(cfg.uuid or ""), host_port(cfg))
	if q ~= "" then link = link .. "?" .. q end
	return link .. tag_suffix(tag)
end

-- trojan://password@host:port?sni=..&security=tls#tag
local function enc_trojan(cfg, tag)
	local tls = cfg.tls or {}
	local pairs_list = {}
	if tls.enabled then
		if is_str(tls.server_name) then pairs_list[#pairs_list + 1] = { "sni", tls.server_name } end
		pairs_list[#pairs_list + 1] = { "security", "tls" }
	end
	local net = cfg.network or "tcp"
	if net ~= "tcp" then pairs_list[#pairs_list + 1] = { "type", net } end
	if net == "ws" then
		pairs_list[#pairs_list + 1] = { "path", cfg.ws_path or "/" }
		local h = (cfg.ws_headers or {}).Host
		if is_str(h) then pairs_list[#pairs_list + 1] = { "host", h } end
	end
	local q = build_query(pairs_list)
	local link = "trojan://" .. tostring(cfg.password or "") .. "@" .. host_port(cfg)
	if q ~= "" then link = link .. "?" .. q end
	return link .. tag_suffix(tag)
end

-- ss://base64url(method:password)@host:port#tag
local function enc_ss(cfg, tag)
	local auth = tostring(cfg.method or "") .. ":" .. tostring(cfg.password or "")
	local payload = base64Encode(auth) or ""
	-- 转成 urlsafe 并去掉尾部等号，和常见客户端一致
	payload = payload:gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
	local link = string.format("ss://%s@%s", payload, host_port(cfg))
	return link .. tag_suffix(tag)
end

-- vmess://base64(json)，字段顺序与 2.3.x 客户端保持一致
local function json_escape(s)
	s = tostring(s)
	return (s:gsub('[\\"]', function(c) return "\\" .. c end))
		:gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
end

local function enc_vmess(cfg, tag)
	local tls = cfg.tls or {}
	local fields = {
		{ "v", "2" },
		{ "ps", tag or cfg.tag or "" },
		{ "add", cfg.server or "" },
		{ "port", tostring(cfg.server_port or "") },
		{ "id", cfg.uuid or "" },
		{ "aid", tostring(cfg.alterId or 0) },
		{ "scy", cfg.security or "auto" },
		{ "net", cfg.network or "tcp" },
		{ "type", cfg.packet_encoding or "" },
		{ "host", cfg.server_name or "" },
		{ "path", cfg.ws_path or "" },
		{ "tls", tls.enabled and "tls" or "" },
		{ "sni", tls.server_name or "" },
	}
	local parts = {}
	for _, kv in ipairs(fields) do
		parts[#parts + 1] = string.format('"%s": "%s"', kv[1], json_escape(kv[2]))
	end
	local json_str = "{" .. table.concat(parts, ", ") .. "}"
	return "vmess://" .. (base64Encode(json_str) or "")
end

local ENCODERS = {
	["anytls"] = enc_anytls,
	["hysteria2"] = enc_hysteria2,
	["hysteria"] = enc_hysteria2,
	["vless"] = enc_vless,
	["trojan"] = enc_trojan,
	["shadowsocks"] = enc_ss,
	["vmess"] = enc_vmess,
}

--[[
	解密：payload = base64url(IV[16] || AES-256-CBC(PKCS7) )
	返回 明文, nil 或 nil, 错误信息（错误信息要能看出卡在哪一步）
--]]
function singboxSubDecrypt(blob, workdir)
	if type(blob) ~= "string" or blob == "" then
		return nil, "响应为空"
	end

	local raw, derr = b64_decode(blob)
	if not raw then
		return nil, "base64 解码失败：" .. tostring(derr)
	end
	if #raw <= 16 then
		return nil, string.format("解码后只有 %d 字节，不足以构成 IV+密文", #raw)
	end

	workdir = workdir or "/tmp"
	local iv = raw:sub(1, 16)
	local ct = raw:sub(17)
	if #ct % 16 ~= 0 then
		return nil, string.format("密文 %d 字节，不是 16 的整数倍", #ct)
	end

	local in_path = workdir .. "/pw_singbox_ct.bin"
	local out_path = workdir .. "/pw_singbox_pt.json"
	local err_path = workdir .. "/pw_singbox_err.txt"
	local f = io.open(in_path, "wb")
	if not f then return nil, "无法写入 " .. in_path end
	f:write(ct)
	f:close()

	-- os.execute 的返回值跨版本不一致：Lua 5.1 返回状态码 0，
	-- Lua 5.2+ 返回 true, "exit", 0。两种都要认。
	local probe = os.execute("command -v openssl >/dev/null 2>&1")
	if not (probe == 0 or probe == true) then
		os.remove(in_path)
		return nil, "系统里没有 openssl 命令，请安装 openssl-util"
	end

	local cmd = string.format(
		"openssl enc -d -aes-256-cbc -nosalt -K %s -iv %s -in %s -out %s 2>" .. err_path,
		AES_KEY_HEX, hexlify(iv), in_path, out_path)
	local rc = os.execute(cmd)
	if not (rc == 0 or rc == true) then
		local detail = ""
		local ef = io.open(err_path, "rb")
		if ef then
			detail = (ef:read("*a") or ""):gsub("%s+$", "")
			ef:close()
		end
		os.remove(in_path)
		os.remove(out_path)
		os.remove(err_path)
		return nil, string.format("openssl 解密失败(exit=%s)：%s", tostring(rc),
			detail ~= "" and detail or "无输出")
	end
	os.remove(err_path)

	local g = io.open(out_path, "rb")
	if not g then return nil, "解密结果读不到" end
	local plain = g:read("*a")
	g:close()
	os.remove(in_path)
	os.remove(out_path)

	if not plain or plain == "" then
		return nil, "解密结果为空"
	end
	return plain, nil
end

--[[
	sing-box JSON -> 分享链接文本（一行一条）。
	json_parse 传 api.jsonc.parse 进来，避免本文件再引一次库。
	返回 文本, nil 或 nil, 错误信息
--]]
function singboxSubToLinks(text, json_parse)
	if type(text) ~= "string" or text == "" then
		return nil, "内容为空"
	end
	local ok, cfg = pcall(json_parse, text)
	if not ok or type(cfg) ~= "table" then
		return nil, "不是合法的 JSON"
	end
	local outbounds = cfg.outbounds
	if type(outbounds) ~= "table" then
		return nil, "JSON 里没有 outbounds"
	end

	local links = {}
	for _, node in ipairs(outbounds) do
		local node_type = node.type or ""
		if not SKIP_TYPES[node_type] then
			local enc = ENCODERS[node_type]
			if enc then
				local ok2, link = pcall(enc, node, node.tag)
				if ok2 and type(link) == "string" then
					links[#links + 1] = link
				end
			end
		end
	end

	if #links == 0 then
		return nil, "没有可用的节点"
	end
	return table.concat(links, "\n") .. "\n", nil
end

--[[
	把分享链接文本编码成 PassWall 能吃的 base64。

	为什么不直接传纯文本配 add_mode="1"：
	parse_link 在 add_mode ~= "2" 时会把节点塞进 nodeResult 且**不带 md5 字段**，
	后面 subscribe.lua:2282 的 uci_set(..., result.md5) 就会因为 #nil 崩溃；
	同时还会跳过订阅的关键词过滤和逐节点用量统计。

	所以仍然走 add_mode="2"，只是把内容做成它期望的 base64。
	尾部等号必须去掉：api.base64Decode 的字符集校验是 ^[A-Za-z0-9+/]*$，
	带 "=" 会被原样返回（这正是本次节点数为 0 的根因）。
--]]
function singboxSubEncode(text)
	if type(text) ~= "string" or text == "" then return nil end
	local enc = base64Encode(text)
	if not enc then return nil end
	return (enc:gsub("=+$", ""))
end

-- 判断响应头里是否声明了加密
function singboxSubIsEncrypted(header_str)
	if type(header_str) ~= "string" then return false end
	local lower = header_str:lower()
	return lower:find("x%-encrypted:%s*1", 1) ~= nil
end
