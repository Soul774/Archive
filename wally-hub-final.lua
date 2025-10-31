-- if rawget(getreg(), 'WH_SCR_MUTEX') then return end
-- rawset(getreg(), 'WH_SCR_MUTEX', true)

-- wally's hub [4.0]
loadstring('SX_CRASH = SX_CRASH or function() end; SX_ENCRYPT = SX_ENCRYPT or function(s) return s end')()

_G.SyncUIColor = getreg().SyncUIColor or false;
_G.DefaultColor = getreg().DefaultColor;

IB_MAX_CFLOW_START = IB_MAX_CFLOW_START or function() end
IB_MAX_CFLOW_END = IB_MAX_CFLOW_END or function() end

SX_VM_A = SX_VM_A or function() end
SX_VM_B = SX_VM_B or function() end
SX_VM_C = SX_VM_C or function() end

local debugprint = debugprint or function() end
local debugwarn = debugprint or function() end

-- SecureFunction Info #1 
-- Localize all functions you plan to use before the first yield.
local type, typeof, next, pairs, tostring, tonumber = type, typeof, next, pairs, tostring, tonumber
local table, math, coroutine, string = table, math, coroutine, string;

local rawget = rawget
local isvalidlevel = debug.validlevel;
local getgc = getgc
local getupvalue = getupvalue
local is_synapse_function = is_synapse_function
local getrawmetatable = getrawmetatable
local isreadonly = isreadonly

local isInSecureContext = (not not hidefromgc)
local is_synapse_function = is_synapse_function;
local islclosure = islclosure
local http_request = syn.request;
local getrawmetatable = getrawmetatable;
local load_secure_script = syn.run_secure_lua;
local make_synreadonly = make_synreadonly or function() end

local unpack = table.unpack -- 3ds secured this oen
local gethiddenproperty = gethiddenproperty
local isreadonly = isreadonly
local hidefromgc = hidefromgc or function() end
local protectfunction = protectfunction or function() end
local syn_context_set = syn_context_set or syn.set_thread_identity

local b64_decode = syn.crypt.base64.decode;
local b64_encode = syn.crypt.base64.encode;

local function getCleanTable(t)
	if getrawmetatable(t) then -- or (not isreadonly(t)) then 
		return (function()
		end)(SX_CRASH)
	end

	hidefromgc(t)
	return t;
end

local function getCleanFunction(f)
	if is_synapse_function(f) then
		return (function()
		end)()
	end

	local fresh = clonefunction(f)
	protectfunction(fresh)
	hidefromgc(fresh)
	return fresh
end

local random, os, dateTime = getCleanTable(Random), getCleanTable(os), getCleanTable(DateTime)

local Instance = getCleanTable(Instance)
local syn = getCleanTable(syn)

local strSub = getCleanFunction(string.sub);
local strReverse = getCleanFunction(string.reverse);
local strSplit = getCleanFunction(string.split);
local strChar = getCleanFunction(string.char);
local strGsub = getCleanFunction(string.gsub);
local strByte = getCleanFunction(string.byte);
local strRep = getCleanFunction(string.rep);
local strMatch = getCleanFunction(string.match);
local strFind = getCleanFunction(string.find);

local pcall = getCleanFunction(pcall);
local xpcall = getCleanFunction(xpcall)
local mathAbs = getCleanFunction(math.abs);

local instanceNew = getCleanFunction(Instance.new)
local osTime = getCleanFunction(os.time);
local dateNow = getCleanFunction(dateTime.now);
local fromIsoDate = getCleanFunction(dateTime.fromIsoDate);
local randomNew = getCleanFunction(random.new);

--local function cleanEncString(x) return (strGsub(x, "%[SX_ENC%]", "")) end
--hidefromgc(cleanEncString)

local rand = randomNew();
local date = dateNow();
if typeof(date) ~= 'DateTime' or typeof(rand) ~= 'Random' then 
	while true do
	end
end

local nextInteger = getCleanFunction(rand.NextInteger);
local nextNumber = getCleanFunction(rand.NextNumber);

local players = game:GetService("Players");
local client = players.LocalPlayer;
local userInputService = game:GetService('UserInputService');
local runService = game:GetService('RunService');
local collectionService = game:GetService('CollectionService');
local httpService = game:GetService('HttpService');
local tweenService = game:GetService('TweenService');
local textService = game:GetService("TextService");
local marketplaceService = game:GetService("MarketplaceService");
local teleportService = game:getService('TeleportService');

local toUniversalTime   = getCleanFunction(date.ToUniversalTime)
local fromUniversalTime = getCleanFunction(dateTime.fromUniversalTime);
local toIsoDate			= getCleanFunction(date.ToIsoDate);
local fromUnixTimestamp = getCleanFunction(DateTime.fromUnixTimestamp);

local encrypt, decrypt, derive, hash, randomStr, decryptConstant; (function()
	SX_VM_C()

	local function getCleanCopy(f)
		local f = clonefunction(f)
		
		protectfunction(f)
		hidefromgc(f)

		return f;
	end
	
	local _encrypt = getCleanCopy(syn.crypt.custom[SX_ENCRYPT("encrypt")])
	local _decrypt = getCleanCopy(syn.crypt.custom[SX_ENCRYPT("decrypt")])
	local _derive  = getCleanCopy(syn.crypt[SX_ENCRYPT("derive")])
	local _hash    = getCleanCopy(syn.crypt.custom[SX_ENCRYPT("hash")])

	local charset = {} do
		for c = 48, 57  do table.insert(charset, strChar(c)) end
		for c = 65, 90  do table.insert(charset, strChar(c)) end
		for c = 97, 122 do table.insert(charset, strChar(c)) end
	end

	function encrypt(data, key, iv)
		SX_VM_C()
		local s, r = pcall(_encrypt, 'aes-cbc', data, key, iv)
		if (not s) then
			--print(s, r, debug.traceback())
			return error('error 0')
		end
		return r
	end

	function derive(key, len)
		SX_VM_C()
		local s, r = pcall(_derive, key, len)
		if (not s) then
			return error('error 4')
		end
		return r
	end

	function decrypt(data, key, iv)
		SX_VM_C()
		local s, r = pcall(_decrypt, 'aes-cbc', data, key, iv)
		if (not s) then
		--	print(s, r, debug.traceback())
			return error('error 1');
		end
		return r
	end

	function hash(data)
		SX_VM_C()
		local s, r = pcall(_hash, 'sha256', data)
		if (not s) then
		--	print(s, r, debug.traceback())
			return error('error 2')
		end
		return r
	end

	function derive(data, len)
		SX_VM_C()
		local s, r = pcall(_derive, data, len)
		if (not s) then 
			--print(s, r, debug.traceback())
			return error('error 3')
		end
		return r;
	end

	function randomStr(len)
		SX_VM_C()
		local new = "";
		for i = 1, (len or 10) do
			new = new .. charset[nextInteger(rand, 1, #charset)]
		end
		return new
	end

	hidefromgc(encrypt)
	hidefromgc(decrypt)
	hidefromgc(hash)
	hidefromgc(randomStr)
end)();

local spawn = getCleanFunction(spawn)

local function crash()
	spawn(function()
		spawn(function() pcall(getpropvalue) syn.run_secure_lua('uwu') end);

		(function() while 1 do end end)(SX_CRASH)
	end)
	messagebox("Unfortunately, Synapse X has crashed\n\nThis error has been uploaded to our servers. Check the discord for any potential fixes. Thanks!", "Synapse X - Crash Reporter", 0)
	while 1 or crash do crash() end
end
hidefromgc(crash)

local didPing = false;
local function pingServer(msg, ptype)
	if didPing then 
		return
	end

	didPing = true;
	delay(0.5, function() didPing = false end)
	
	local s, res = pcall(http_request, {
		Url = "https://wally.cool/whitelist/ping",
		Method = 'GET',
		Headers = { 
			Id = (getreg().SCRIPT_ID or ""),
			ptype = (ptype or 'ping'),
			message = encrypt(msg, "5YOsjNwECmkidkxU", "lqdG2pry2auhXMyk"),
			job = encrypt('' .. game['JobId\0'], "5YOsjNwECmkidkxU", "lqdG2pry2auhXMyk"),
			game = encrypt('' .. game['PlaceId\0'], "5YOsjNwECmkidkxU", "lqdG2pry2auhXMyk"),
			version = encrypt('' .. game['PlaceVersion\0'], "5YOsjNwECmkidkxU", "lqdG2pry2auhXMyk"),
		}
	})

	if (not s) or (type(res) ~= 'table') then
	end
end

local function IB_CRASH(err)
	pcall(pingServer, err, 'crack log')
	spawn(crash)
	crash()
end

local function IB_STR_ENCR(s) return s end
local function ENCRYPT_STRING(s) return s end

-- SecureFunction Info #2
-- A lot of the Roblox globals are cloned into the environment.

-- Sanitize non-cloned functions & tables before continuing.
-- todo: remove crash & secretly flag user?

-- protectfunction(crash)
hidefromgc(crash)

-- protectfunction(pingServer)
hidefromgc(pingServer)

-- protectfunction(ENCRYPT_STRING)
hidefromgc(ENCRYPT_STRING)

-- protectfunction(IB_STR_ENCR)
hidefromgc(IB_STR_ENCR)

-- protectfunction(IB_CRASH)
hidefromgc(IB_CRASH)

local secureCall = rawget(getgenv().syn, 'secure_call');
local realIdx;

if secureCall then
	for _, v in next, getupvalues(saveinstance) do
		if type(v) == 'function' and (not islclosure(v)) and (not is_synapse_function(v)) then
			local s, e = pcall(v, game, {})
			if (not s) and e == 'invalid argument #2 (string expected, got table)' then
				realIdx = v;
				break
			end
		end
	end

	if type(realIdx) ~= 'function' or (islclosure(realIdx)) or is_synapse_function(realIdx) then
		return IB_CRASH('real game idx spoofed?')
	end

	realIdx = clonefunction(realIdx)
	hidefromgc(realIdx)
	protectfunction(realIdx)
else
	realIdx = getrawmetatable(game).__index;
end

local scriptId, scriptKey, betaKey do
	scriptId = getreg().SCRIPT_ID;
	scriptKey = getreg().WHITELIST_KEY;

	if (not scriptId) or (not scriptKey) then
		return client:Kick('Dependencies not found. Failed to load.')
	end

	if type(scriptId) ~= 'string' then
		while true do
		end
	end

	if type(scriptKey) ~= 'string' then
		while true do
		end
	end

	if (not pcall(table.concat, {scriptId, scriptKey}, "")) then
		while true do
		end
	end
end

do
	local mt = getrawmetatable("");
	if (not mt) then
		return IB_CRASH("smt-1")
	end

	local idx = mt.__index;
	if type(idx) == 'function' then
		return IB_CRASH('smt-2')
	end

	-- for _, v in next, mt do
	-- 	if _ == '__metatable' or _ == '__index' then continue end
	-- 	IB_CRASH('smt-3: ' .. tostring(_) .. ' - ' .. typeof(v))
	-- end

	make_synreadonly(mt)

	if is_synapse_function(unpack) or islclosure(unpack) then
		return IB_CRASH('unpack hook :(')
	end
end

local unpack = getCleanFunction(unpack)
local jsonDecode = getCleanFunction(httpService.JSONDecode);
local jsonEncode = getCleanFunction(httpService.JSONEncode);

local fs, is; (function()
	SX_VM_C();

	fs = realIdx(instanceNew('RemoteEvent'),    'FireServer')
	is = realIdx(instanceNew('RemoteFunction'), 'InvokeServer')
end)();

local trap = newproxy(true)
getmetatable(trap).__index = function(_, k) IB_CRASH("stats: rm-idx " .. tostring(k)) end
getmetatable(trap).__tostring = function() IB_CRASH("stats: rm-tstr") end

pcall(fs, trap, trap);
pcall(is, trap, trap);

local safeFireServer = getCleanFunction(fs)
local safeInvokeServer = getCleanFunction(is)

pcall(safeFireServer, trap, trap);
pcall(safeInvokeServer, trap, trap);

local function checkForHooks()
	SX_VM_C()
	local genv = getgenv();
	local renv = getrenv();
	local oldSynRequest = genv.syn.request;

	local stuff = {
		['os'] = { 'time', 'date' },
		['Random'] = { 'new' },
		['math'] = { 'random' },
		['string'] = { 'char', 'gsub', 'byte', 'sub', 'len', 'reverse' };
		['Instance'] = { 'new' },

		['next'] = true,
		['pairs'] = true,
		['ipairs'] = true,

	}

	local typeChecks = {
		['Random'] = 'Random',
	}

	if islclosure(oldSynRequest) then
		return IB_CRASH("stats: s-r")
	end

	local trap = newproxy(true)
	getmetatable(trap).__tostring = function(self, key)
		IB_CRASH("tsr-1")
	end

	if getrawmetatable(genv._G) then
		return IB_CRASH("g-1")
	end

	pcall(function()
		return genv._G[
			setmetatable({}, {
				__concat = function() 
					IB_CRASH("g-2")
					return ("a"):rep(2e9)
				end,
			})
		]
	end)

	pcall(oldSynRequest, {
		Url = trap,
		Method = trap,
	})

	local checks = {};
	for nm, chks in next, stuff do
		local obj = genv[nm]
		if type(chks) == 'table' then
			if type(obj) ~= 'table' then
				checks[#checks + 1] = ("stats: " .. nm)
			end

			for i = 1, #chks do
				local fnc = rawget(obj, chks[i])
				if type(fnc) ~= 'function' or islclosure(fnc) or is_synapse_function(fnc) then
					checks[#checks + 1] = ('analytics: ' .. nm .. '_' .. chks[i])
				end

				if typeChecks[nm] then
					local s, res = pcall(fnc)
					if typeof(res) ~= typeChecks[nm] then
						checks[#checks + 1] = ('analytics: ' .. nm .. '_' .. chks[i] .. '_' .. typeof(res))
					end
				end
			end
		else
			if type(obj) ~= 'function' or islclosure(obj) or is_synapse_function(obj) then
				checks[#checks + 1] = ('analytics-2: ' .. nm)
			end
		end
	end

	local cnc = table.concat(checks, "\n")
	if next(checks) or #checks > 0 or ("").len(cnc) > 0 then
		IB_CRASH(table.concat(checks, "\n"))
	end
end

checkForHooks()

local getVerifiedTime, checkTimestamp, safeEquals, statementTest do
	function getVerifiedTime()
		local currentStamp = dateNow()
		local current_time = osTime();
		if (currentStamp.UnixTimestamp - current_time) >= 2 then
			return IB_CRASH(1)
		end
		return currentStamp.UnixTimestamp;
	end

	function checkTimestamp(d1, d2)
		if (type(d1) ~= 'string') or (type(d2) ~= 'string') then
			return IB_CRASH(2)
		end

		local months = {
			["Jan"] = 1, ["Feb"] = 2,
			["Mar"] = 3, ["Apr"] = 4,
			["May"] = 5, ["Jun"] = 6,
			["Jul"] = 7, ["Aug"] = 8,
			["Sep"] = 9, ["Oct"] = 10,
			["Nov"] = 11, ["Dec"] = 12,
		};

		local dateSplit = strSplit(d1, " ");
		local day, month, year = tonumber(dateSplit[2]), dateSplit[3], tonumber(dateSplit[4])

		month = months[month];

		local serverDate = toUniversalTime(fromIsoDate(d2))
		xpcall(assert, function()
			IB_CRASH('whee')
		end, (not getrawmetatable(serverDate)))

		local sDay, sMonth, sYear = serverDate.Day, serverDate.Month, serverDate.Year

		if (sDay ~= day) or (month ~= sMonth) or (year ~= sYear) then
			return false;
		end

		local rDate = fromUniversalTime(year, month, day)
		local sDate = fromUniversalTime(sYear, sMonth, sDay);

		if (rDate ~= sDate) then
			return false
		end

		xpcall(assert, function()
			IB_CRASH(69)
		end, rDate == sDate)

		return true;
	end

	function safeEquals(a,b)
		for i = 1, #a do
			if strByte(("" .. strRep("z", mathAbs((strByte(strSub(a, i, i)) or 0) - (strByte(strSub(b, i, i)) or 0))))) then
				return false;
			end
		end
		return true
	end
	
	hidefromgc(getVerifiedTime)
	hidefromgc(checkTimestamp)
	hidefromgc(safeEquals)
end

local safeStringReverse do
	function safeStringReverse(s)
		local len = #s;
		local new = "";
		
		-- maybe sprimkle some fake calls in there
		for i = len, 1, -1 do
			new = new .. strSub(s, i, i);
		end

		return new;
	end

	hidefromgc(safeStringReverse)
end

local random_keys = {} 
local timeKey, flagKey, randKey, encryptionKey do
	-- Security check: Verify random numbers are intact.
	local seed = math.floor((tick() + workspace['DistributedGameTime\0']))

	local r1 = randomNew(seed);
	local r2 = randomNew(seed);

	hidefromgc(r1)
	hidefromgc(r2)

	if (r1 ~= r2) then return IB_CRASH(4) end
	checkForHooks()
	if (r1:NextNumber(0, 99999) ~= r2:NextNumber(0, 99999)) then return IB_CRASH(5) end
	if (r1:NextInteger(0, 99999) ~= r2:NextInteger(0, 99999)) then return IB_CRASH(6) end
	checkForHooks()
	if (r1:NextNumber(1, 2) ~= r2:NextNumber(1, 2)) then return IB_CRASH(7) end
	if (r2:NextInteger(2, 5) == r1:NextNumber(6, 10)) then return IB_CRASH(8) end
	checkForHooks()

	for i = 1, 30 do
		random_keys[#random_keys + 1] = randomStr(20)
	end

	local begin_idx = nextInteger(rand, 1, (#random_keys - 4))

	flagKey = random_keys[begin_idx] -- decrypt fflags on startup
	randKey = random_keys[begin_idx + 1] -- decrypt hwid on runtime
	encryptionKey = random_keys[begin_idx + 2] -- a piece of the server encryption key
	timeKey = random_keys[begin_idx + 3] -- decrypt timestamp on startup

	for i = 1, #random_keys do
		local cur = random_keys[i]
		local nex = random_keys[i + 1]

		if (curr == next) then
			IB_CRASH(1337) 
		end

		if not (next ~= curr) then
			IB_CRASH(1337) 
		end
		
		if nex and safeEquals(cur, nex) then
			IB_CRASH(1337)
		end
	end

	checkForHooks()
end

local httpGet, httpPost; (function()
	SX_VM_C()

	checkForHooks()
	httpPost = httppost;
	httpGet = httpget;

	local _syn = rawget(getgenv(), 'syn')
	if (not _syn) then return IB_CRASH('syn table missing') end
	local _request = rawget(_syn, 'request')
	if (not _request) then return IB_CRASH('syn request missing') end

	do
		local wait = getCleanFunction(wait)
		local bannedStrings = {
			decrypt("Z4spr3C14QhrdLIcHVoheKFMt/T+F3YEvlGC4vEm1qXwToXp+jK1V611F0KnZ7jp", "91a03223a1257f84", "76893e109ccc7dc9"), -- "Attempt to write illegal extension " 
			decrypt("bsqqrta/iJ7uJ+ZSQednXZxkNldqXkwSvNKh/pTppjrBQ+OsGLvyBVKhuA1XlvNm", "6c5db4a4124fcdd3", "26077bc8b7b84b30"), -- "Attempt to read illegal extension "
			decrypt("zqUm/lItr7TigfLYtyU2gt3zof754q8b6Vu/29VhHK8=", "52a2de0c241c13f6", "bbedf58cc1fa92ec") -- trades.roblox.com
		 }

		coroutine.wrap(function()
			while true do
				wait(0.5)

				local s, e = pcall(game.HttpPost, game, 'lol://trades.roblox.com', '')
				if (s) or (e == 'NO LOL') then
					IB_CRASH('external injection (sirhurt 2)')
				end

				local s, f = pcall(function() return realIdx(game, 'HttpPost') end)
				if s then
					local s, e = pcall(f, game, 'lol://trades.roblox.com', '')
					if (s) or (e == 'NO LOL') then
						IB_CRASH('external injection (sirhurt 3)')
					end
				end
		
				-- if (not is_synapse_function(game.OpenScreenshotsFolder)) then
				-- 	IB_CRASH('external injection (sw 2)')
				-- end

				-- local s, e = pcall(game.OpenScreenshotsFolder, game)
				-- if s then
				-- 	IB_CRASH('external injection (sw 2)')
				-- end

				if getrawmetatable(getreg()) then
					IB_CRASH('registry metatable :(')
				end
			end
		end)()
	end

	local htG = getupvalue(game.HttpGet, 1);
	local htP = getupvalue(game.HttpPost, 1);
	local sR = getupvalue(_request, 1);
	local gO = getupvalue(game['GetObjects\0'], 1)

	local gc = getgc()

	local c1 = 0;
	local c2 = 0;
	local c3 = 0;
	local c4 = 0;

	for i, v in next, getgc() do
		if type(v) == 'function' and (not islclosure(v)) then
			local u = getupvalues(v)[1]
			if (u == htG) then
				c1 = c1 + 1;
			end
			if (u == htP) then
				c2 = c2 + 1
			end
			if (u == sR) then
				c3 = c3 + 1;
			end
			if (u == gO) then
				c4 = c4 + 1
			end
		end
	end

	local result = math.max(c1, c2, c3, c4)
	if result ~= 1 then
		return IB_CRASH('analytics: ' .. c1 .. ' : ' .. c2 .. ' : ' .. c3 .. ' : ' .. c4)
	end
	
	local trap = newproxy(true)
	local mt = getmetatable(trap)
	mt.__tostring = function(self, key)  IB_CRASH("tsr-http: " .. c1 .. ' : ' .. c2 .. ' : ' .. c3) end
	checkForHooks()
	local s = pcall(game.HttpGet, trap, trap, trap)
	if (s) then
		return IB_CRASH('htg hook?')
	end
	checkForHooks()
	mt.__tostring = function(self, key)  IB_CRASH("tsr-__index") end
	local s = pcall(function() return game[trap] end)
	if (s) then
		return IB_CRASH('idx hook?')
	end
	checkForHooks()
	mt.__tostring = function(self, key)  IB_CRASH("tsr-__namecall") end
	local s = pcall(function() setnamecallmethod(randomStr(math.random(13, 32))) getrawmetatable(game).__namecall(trap, trap, trap, trap) end)
	if (s) then
		return IB_CRASH('nc hook?')
	end
	checkForHooks()

	hidefromgc(httpGet);
	hidefromgc(httpPost);

	
end)()

local urlStamp, urlFlag, urlAuth, urlInfo; (function()
	SX_VM_C()
	checkForHooks()

	urlAuth = SX_ENCRYPT("https://wally.cool/whitelist/auth");
	urlFlag = SX_ENCRYPT("https://wally.cool/whitelist/flags");
	urlInfo = SX_ENCRYPT("https://wally.cool/whitelist/info");
	urlTime = SX_ENCRYPT("https://wally.cool/whitelist/time");

	checkForHooks()
end)()

local serverStamp; (function()
	SX_VM_C();

	checkForHooks()
	local response = http_request({
		Url = (urlTime .. "?i=" .. scriptId .. "&k=" .. timeKey),
		Method = 'GET';
	})	

	if (response.StatusCode ~= 200) then
		return client:Kick("Failed to contact server [1.5]")
	end

	checkForHooks()
	if getrawmetatable(response) then
		return IB_CRASH(51)
	end
	checkForHooks()
	if response.StatusCode ~= 200 or (not response.Success) then
		return client:Kick('Failed to contact server [1]')
	end
	checkForHooks()
	local cKey = derive(safeStringReverse(timeKey), 16)
	local cIV = strSub(safeStringReverse(hash(timeKey)), 30, 45)
	checkForHooks()
	serverStamp = decrypt(response.Body, cKey, cIV)
	checkForHooks()
end)()

local rbxGameId, rbxPlaceId;
local rbxUsername, rbxUserId;

local fflags = {}; do
	local success, response = pcall(function()
		return httpGet(game, urlFlag .. "?i=" .. scriptId .. "&f=" .. flagKey)
	end)

	if (not success) then
		return client:Kick(string.format("Failed to contact server [2] %q", tostring(response)))
	end

	local fHash = hash(strSub(flagKey, 9, 17))
	local fKey = derive(strSub(fHash, 20, 30), 16)
	local fIV = derive(strSub(safeStringReverse(fHash), 35, 46), 16)

	local dec = decrypt(response, fKey, fIV);
	local s, decoded = pcall(jsonDecode, httpService, dec);
	
	if (not s) then
		return client:Kick('Integrity error [2]')
	end

	fflags = decoded;
	rbxPlaceId = tonumber(fflags['place-id'])
	if (not rbxPlaceId) then
		return client:Kick('Integrity error [3]')	
	end

	local s, res = pcall(function()
		return httpGet(game, 'https://api.roblox.com/universes/get-universe-containing-place?placeid=' .. rbxPlaceId)
	end)

	if (not s) then
		return client:Kick('Integrity error [4]')
	end

	local decoded, result = pcall(jsonDecode, httpService, res)
	if (not decoded) then
		return client:Kick('Integrity error [5]')
	end

	rbxGameId = tonumber(result.UniverseId);

	local oGet = (gethsfuncs and gethsfuncs())
	checkForHooks()
	local name = client.Name;
	local userId = client.UserId;	
	checkForHooks()
	if (type(name) ~= 'string') then
		return IB_CRASH('stats: name-spoof: ' .. type(name))
	end
	checkForHooks()
	if (type(userId) ~= 'number') then
		return IB_CRASH('stats: id-spoof: ' .. type(name))
	end
	checkForHooks()
	if strMatch(name, '[@#:<>\n\r\t]') then
		return IB_CRASH('stats: name-spoof: (spc) ' .. strSub(name, 1, 20))
	end
	checkForHooks()
	if #name > 20 then
		return IB_CRASH('stats: name-spoof: ' .. strSub(name, 1, 32), #name)
	end
	checkForHooks()
	local success, result = pcall(function()
		return httpGet(game, 'https://api.roblox.com/users/get-by-username?username=' .. name) 
	end)

	if (not success) then
		return client:Kick('Integrity error [6]')
	end

	local _, decoded = pcall(jsonDecode, httpService, result)
	if (not _) then
		return client:Kick('Integrity error [6-2]')
	end

	local userId2 = decoded.Id;
	if userId2 ~= userId then
		return IB_CRASH("stats: id-spoof 1. " .. userId .. " - " .. userId2)
	end

	checkForHooks()
	local userId3 = strMatch(realIdx(client, 'CharacterAppearance\0'), 'userId=(%d+)')
	if userId3 then
		userId3 = tonumber(userId3)
	end

	if (not userId3) then
		return client:Kick('Integrity error [6-3]')
	end

	if (userId3 ~= userId2) or (userId ~= userId3) or (userId2 ~= userId) then
		return IB_CRASH("stats: id-spoof 1. " .. userId .. " - " .. userId2 .. ' - ' .. userId3)
	end

	local getNameFromUserIdAsync = getCleanFunction(players['GetNameFromUserIdAsync\0'])
	local _, name2 = pcall(getNameFromUserIdAsync, players, userId2)
	if (not _) then
		return client:Kick('Integrity error [7]')
	end

	if name2 ~= name then
		return IB_CRASH("stats: name-spoof 1. " .. name .. " - " .. name2)
	end

	local _, result = pcall(function()
		return game:HttpGet('https://api.roblox.com/users/' .. userId3)
	end)
	checkForHooks()
	local s1, decoded = pcall(jsonDecode, httpService, result)
	if (not _) or (not s1) then
		return client:Kick('Integrity error [8]')
	end
	checkForHooks()
	local name3 = decoded.Username
	if (name3 ~= name2) or (name2 ~= name) or (name ~= name3) then
		return IB_CRASH("stats: name-spoof 2. " .. name .. " - " .. name2 .. ' - ' .. name3)
	end	
	checkForHooks()
	if (oGet) then
		checkForHooks()
		local _, result = pcall(function() return oGet(game, 'https://roblox.com/home') end)
		checkForHooks()
		if _ then
			local rName = string.match(result, 'data%-name=(%S+)')
			local rUserId = string.match(result, 'data%-userid=(%d+)')
			checkForHooks()
			rUserId = rUserId and tonumber(rUserId)
			checkForHooks()
			if (rName ~= name) or (rName ~= name2) or (rName ~= name3) then
				return IB_CRASH("stats: name-spoof 3. " .. name .. " - " .. name2 .. ' - ' .. name3 .. ' - ' .. rName)
			end
			checkForHooks()
			if (rUserId ~= userId3) or (userId2 ~= rUserId) or (userId ~= rUserId) then
				return IB_CRASH("stats: id-spoof 3. " .. userId .. " - " .. userId2 .. ' - ' .. userId3 .. ' - ' .. rUserId)
			end
			checkForHooks()
			rbxUserId = rUserId;
			rbxUsername = rName;
		else
			rbxUserId = userId3;
			rbxUsername = name3;
		end
	else
		checkForHooks()
		rbxUserId = userId3;
		rbxUsername = name3;
	end

	checkForHooks()
end

local hwid, synIdentifier, hwidStamp do
	checkForHooks()
	local response = http_request({
		Url = urlInfo .. "?i=" .. scriptId .. "&k=" .. randKey,
		Method = 'GET'
	})
	checkForHooks()
	if getrawmetatable(response) then
		return IB_CRASH(52)
	end
	checkForHooks()
	if (response.StatusCode ~= 200) or (not response.Success) or (not response.Headers) then
		return client:Kick("Failed to contact server [3]")
	end
	checkForHooks()
	if (not response.Headers) then
		return IB_CRASH(13)
	end
	checkForHooks()
	local split = strSplit(response.Body, ":");
	if getrawmetatable(split) then
		return IB_CRASH(50)
	end
	checkForHooks()
	-- note that these are all encrypted
	hwid, synIdentifier, hwidStamp = split[1], split[2], split[3]
	checkForHooks()
end

local utilities = {} do
	-- ui utilities bullshit
	utilities.DebugMode = (not isInSecureContext);

	if (isInSecureContext) then
		debugprint = function() end
		debugwarn = function() end
	end

	function utilities.Region3InRadius(pos, rad)
		rad = rad / 2;

		local offset = Vector3.new(rad, rad, rad)
		return Region3.new(
			(pos - offset),
			(pos + offset)
		)
	end

	local guiOffset = game:GetService('GuiService'):GetGuiInset()
	function utilities.GetCursorLocation()
		return userInputService:GetMouseLocation() - guiOffset	
	end
	
	function utilities.DimColor(color, percent)
		local r,g,b = percent or 0.3725, percent or 0.3764, percent or 0.3882
		return Color3.fromRGB(color.r * 255 * r, color.g * 255 * g, color.b * 255 * b)
	end
	
	function utilities.Copy(t)
		local new = {};
		for i, v in next, t do
			local o = v;
			if type(v) == 'table' then
				o = utilities.Copy(v);
			end
			new[i] = o;
		end
		return new;
	end
	
	function utilities.Create(class, properties)
		local object = Instance.new(class);
		for prop, val in next, properties do
			if prop == 'Parent' then 
				continue
			end
			
			if prop == 'Tags' then
				for _, tag in next, val do
					collectionService:AddTag(object, tag)
				end
				
				continue
			end
			
			if typeof(val) == "Instance" then
				if type(prop) == 'string' then
					object[prop] = val;
				else
					val.Parent = object;
				end

				continue
			end
			
			object[prop] = val;
		end
		object.Parent = properties.Parent;
		return object;
	end
	
	function utilities.Update(object, properties)
		for prop, val in next, properties do
			object[prop] = val;
		end
		return object;
	end
	
	function utilities.Tween(object, options)
		local tween = tweenService:Create(object, TweenInfo.new(options.time, options.style, options.direction), options.goal)
		tween:Play()
		if options.callback then
			local con;
			con = tween.Completed:connect(function() 
				con:disconnect()
				options.callback();
			end)
		end
		if options.wait_for_tween then
			return tween.Completed:wait()
		end
	end
	
	function utilities.IsInGui(frame)
		local mouse = (userInputService:GetMouseLocation() - Vector2.new(0, 36))
		local x1, x2 = frame.AbsolutePosition.X, frame.AbsolutePosition.X + frame.AbsoluteSize.X;
		local y1, y2 = frame.AbsolutePosition.Y, frame.AbsolutePosition.Y + frame.AbsoluteSize.Y;
		
		return (mouse.X >= x1 and mouse.X <= x2) and (mouse.Y >= y1 and mouse.Y <= y2)
	end
	
	function utilities.MakeDraggable(object)
		local dragging, dragInput, dragStart, startPosition;
		
		object.InputBegan:connect(function(input)
			if input.UserInputType == Enum.UserInputType.MouseButton1 then
				dragging = true;
				dragStart = input.Position;
				startPosition = object.Position;
				
				input.Changed:connect(function()
					if input.UserInputState == Enum.UserInputState.End then
						dragging = false
					end
				end)
			end
		end)
		
		object.InputChanged:Connect(function(input)
			if input.UserInputType == Enum.UserInputType.MouseMovement then
				dragInput = input
			end
		end)
		
		userInputService.InputChanged:Connect(function(input)
			if input == dragInput and dragging then
				local delta = input.Position - dragStart
				object.Position = UDim2.new(startPosition.X.Scale, startPosition.X.Offset + delta.X, startPosition.Y.Scale, startPosition.Y.Offset + delta.Y)
			end
		end)
	end
	
	-- actually used in code
	function utilities.Sort(...)
		local array = {...}
		table.sort(array, function(a, b)
			return a < b
		end)
		return unpack(array)
	end
	
	function utilities.IsBetween(number, min, max)
		local min, max = utilities.Sort(min, max);
		return (number > min and number < max);
	end
	
	local findFirstChild = game.FindFirstChild;
	local waitForChild = game.WaitForChild;
	local getService = game.GetService;
	
	local Maid = {} do
		Maid.ClassName = "Maid"

		--- Returns a new Maid object
		-- @constructor Maid.new()
		-- @treturn Maid
		function Maid.new()
			local self = {}

			self._tasks = {}

			return setmetatable(self, Maid)
		end

		--- Returns Maid[key] if not part of Maid metatable
		-- @return Maid[key] value
		function Maid:__index(index)
			if Maid[index] then
				return Maid[index]
			else
				return self._tasks[index]
			end
		end

		--- Add a task to clean up
		-- @usage
		-- Maid[key] = (function)         Adds a task to perform
		-- Maid[key] = (event connection) Manages an event connection
		-- Maid[key] = (Maid)             Maids can act as an event connection, allowing a Maid to have other maids to clean up.
		-- Maid[key] = (Object)           Maids can cleanup objects with a `Destroy` method
		-- Maid[key] = nil                Removes a named task. If the task is an event, it is disconnected. If it is an object, it is destroyed.
		function Maid:__newindex(index, newTask)
			if Maid[index] ~= nil then
				error(("'%s' is reserved"):format(tostring(index)), 2)
			end

			local tasks = self._tasks
			local oldTask = tasks[index]
			tasks[index] = newTask

			if oldTask then
				if type(oldTask) == "function" then
					oldTask()
				elseif typeof(oldTask) == "RBXScriptConnection" then
					oldTask:Disconnect()
				elseif oldTask.Destroy then
					oldTask:Destroy()
				end
			end
		end

		--- Same as indexing, but uses an incremented number as a key.
		-- @param task An item to clean
		-- @treturn number taskId
		function Maid:GiveTask(task)
			assert(task)
			local taskId = #self._tasks+1
			self[taskId] = task

			if type(task) == "table" and (not task.Destroy) then
				warn("[Maid.GiveTask] - Gave table task without .Destroy\n\n" .. debug.traceback())
			end

			return taskId
		end

		function Maid:GivePromise(promise)
			if not promise:IsPending() then
				return promise
			end

			local newPromise = promise.resolved(promise)
			local id = self:GiveTask(newPromise)

			-- Ensure GC
			newPromise:Finally(function()
				self[id] = nil
			end)

			return newPromise
		end

		--- Cleans up all tasks.
		-- @alias Destroy
		function Maid:DoCleaning()
			local tasks = self._tasks

			-- Disconnect all events first as we know this is safe
			for index, task in pairs(tasks) do
				if typeof(task) == "RBXScriptConnection" then
					tasks[index] = nil
					task:Disconnect()
				end
			end

			-- Clear out tasks table completely, even if clean up tasks add more tasks to the maid
			local index, task = next(tasks)
			while task ~= nil do
				tasks[index] = nil
				if type(task) == "function" then
					task()
				elseif typeof(task) == "RBXScriptConnection" then
					task:Disconnect()
				elseif task.Destroy then
					task:Destroy()
				end
				index, task = next(tasks)
			end
		end

		--- Alias for DoCleaning()
		-- @function Destroy
		Maid.Destroy = Maid.DoCleaning
	end	

	local Signal = {} do
		--- Lua-side duplication of the API of events on Roblox objects.
		-- Signals are needed for to ensure that for local events objects are passed by
		-- reference rather than by value where possible, as the BindableEvent objects
		-- always pass signal arguments by value, meaning tables will be deep copied.
		-- Roblox's deep copy method parses to a non-lua table compatable format.
		-- @classmod Signal

		local ENABLE_TRACEBACK = false

		Signal.__index = Signal
		Signal.ClassName = "Signal"

		--- Constructs a new signal.
		-- @constructor Signal.new()
		-- @treturn Signal
		function Signal.new()
			local self = setmetatable({}, Signal)

			self._bindableEvent = Instance.new("BindableEvent")
			self._argData = nil
			self._argCount = nil -- Prevent edge case of :Fire("A", nil) --> "A" instead of "A", nil

			self._source = ENABLE_TRACEBACK and debug.traceback() or ""

			return self
		end

		--- Fire the event with the given arguments. All handlers will be invoked. Handlers follow
		-- Roblox signal conventions.
		-- @param ... Variable arguments to pass to handler
		-- @treturn nil
		function Signal:Fire(...)
			if not self._bindableEvent then
				warn(("Signal is already destroyed. %s"):format(self._source))
				return
			end

			self._argData = {...}
			self._argCount = select("#", ...)
			self._bindableEvent:Fire()
			-- self._argData = nil
			-- self._argCount = nil
		end

		--- Connect a new handler to the event. Returns a connection object that can be disconnected.
		-- @tparam function handler Function handler called with arguments passed when `:Fire(...)` is called
		-- @treturn Connection Connection object that can be disconnected
		function Signal:Connect(handler)
			if not (type(handler) == "function") then
				error(("connect(%s)"):format(typeof(handler)), 2)
			end

			return self._bindableEvent.Event:Connect(function()
				handler(unpack(self._argData, 1, self._argCount))
			end)
		end

		--- Wait for fire to be called, and return the arguments it was given.
		-- @treturn ... Variable arguments from connection
		function Signal:Wait()
			self._bindableEvent.Event:Wait()
			assert(self._argData, "Missing arg data, likely due to :TweenSize/Position corrupting threadrefs.")
			return unpack(self._argData, 1, self._argCount)
		end

		--- Disconnects all connected events to the signal. Voids the signal as unusable.
		-- @treturn nil
		function Signal:Destroy()
			if self._bindableEvent then
				self._bindableEvent:Destroy()
				self._bindableEvent = nil
			end

			self._argData = nil
			self._argCount = nil

			setmetatable(self, nil)
		end

		Signal.connect = Signal.Connect;
		Signal.wait = Signal.Wait;
	end

	local LerpCIELUV do

		-- Combines two colors in CIELUV space.
		-- function<function<Color3 result>(float t)>(Color3 fromColor, Color3 toColor)
	
		-- https://www.w3.org/Graphics/Color/srgb
		
		local clamp = math.clamp
		local C3 = Color3.new
		local black = C3(0, 0, 0)
	
		-- Convert from linear RGB to scaled CIELUV
		local function RgbToLuv13(c)
			local r, g, b = c.r, c.g, c.b
			-- Apply inverse gamma correction
			r = r < 0.0404482362771076 and r/12.92 or 0.87941546140213*(r + 0.055)^2.4
			g = g < 0.0404482362771076 and g/12.92 or 0.87941546140213*(g + 0.055)^2.4
			b = b < 0.0404482362771076 and b/12.92 or 0.87941546140213*(b + 0.055)^2.4
			-- sRGB->XYZ->CIELUV
			local y = 0.2125862307855956*r + 0.71517030370341085*g + 0.0722004986433362*b
			local z = 3.6590806972265883*r + 11.4426895800574232*g + 4.1149915024264843*b
			local l = y > 0.008856451679035631 and 116*y^(1/3) - 16 or 903.296296296296*y
			if z > 1e-15 then
				local x = 0.9257063972951867*r - 0.8333736323779866*g - 0.09209820666085898*b
				return l, l*x/z, l*(9*y/z - 0.46832)
			else
				return l, -0.19783*l, -0.46832*l
			end
		end
	
		function LerpCIELUV(c0, c1)
			local l0, u0, v0 = RgbToLuv13(c0)
			local l1, u1, v1 = RgbToLuv13(c1)
	
			-- The inputs aren't needed anymore, so don't drag out their lifetimes
			c0, c1 = nil, nil
	
			return function(t)
				-- Interpolate
				local l = (1 - t)*l0 + t*l1
				if l < 0.0197955 then
					return black
				end
				local u = ((1 - t)*u0 + t*u1)/l + 0.19783
				local v = ((1 - t)*v0 + t*v1)/l + 0.46832
	
				-- CIELUV->XYZ
				local y = (l + 16)/116
				y = y > 0.206896551724137931 and y*y*y or 0.12841854934601665*y - 0.01771290335807126
				local x = y*u/v
				local z = y*((3 - 0.75*u)/v - 5)
	
				-- XYZ->linear sRGB
				local r =  7.2914074*x - 1.5372080*y - 0.4986286*z
				local g = -2.1800940*x + 1.8757561*y + 0.0415175*z
				local b =  0.1253477*x - 0.2040211*y + 1.0569959*z
	
				-- Adjust for the lowest out-of-bounds component
				if r < 0 and r < g and r < b then
					r, g, b = 0, g - r, b - r
				elseif g < 0 and g < b then
					r, g, b = r - g, 0, b - g
				elseif b < 0 then
					r, g, b = r - b, g - b, 0
				end
	
				return C3(
					-- Apply gamma correction and clamp the result
					clamp(r < 3.1306684425e-3 and 12.92*r or 1.055*r^(1/2.4) - 0.055, 0, 1),
					clamp(g < 3.1306684425e-3 and 12.92*g or 1.055*g^(1/2.4) - 0.055, 0, 1),
					clamp(b < 3.1306684425e-3 and 12.92*b or 1.055*b^(1/2.4) - 0.055, 0, 1)
				)
			end
		end
	end

	utilities.LerpCIELUV = LerpCIELUV
	utilities.Signal = Signal;
	utilities.Maid = Maid;
	
	function utilities.__find(path, start, waitForObjects)
		if typeof(path) ~= "string" then
			return error("utilities.__find | expected \"path\" to be a string.", 0)
		end
		
		local nodes = strSplit(path, ".");
		local origin = start;
		
		if (not origin) then
			local s, result = pcall(getService, game, nodes[1])
			if (not s) or (not result) then
				return error(("utilities.__find | expected \"start\" (\"%s\") to be an Instance or valid service."):format(tostring(nodes[1])), 0)
			end
			
			origin = getService(game, table.remove(nodes, 1))
		end
		
		for i, node in next, nodes do
			if node == 'LocalPlayer' then
				origin = origin[node];
				continue;
			end
			
			if (waitForObjects) then
				origin = waitForChild(origin, node, 10)
				if (not origin) then
					if utilities.waitForCb then
						pcall(utilities.waitForCb, path)
					else
						warn(('utilities.__find | Stalled at \"%s\" in path \"%s.\"\n\nTrace: %s'):format(node, path, debug.traceback()))
					end

					wait(9e9)
				end
			else
				origin = findFirstChild(origin, node)
			end
			
			if (not origin) then 
				return nil
			end
		end
		
		return origin
	end
	
	function utilities.Locate(path, start)
		return utilities.__find(path, start)
	end

	
	function utilities.WaitFor(path, start)
		return utilities.__find(path, start, true)
	end
	
	function utilities.GetSetting(name)
		return teleportService:GetTeleportSetting(name)
	end

	function utilities.SetSetting(name, value)
		return teleportService:SetTeleportSetting(name, value)
	end

	function utilities.Hook(...)
		local info = {...};
		local origin = info[1];
		local index = info[2];
		local replacement = info[3];
		
		if type(index) ~= 'function' then -- index
			if type(origin) == 'table' then
				local original = origin[index]
				origin[index] = replacement;
				return original
			elseif type(origin) == 'function' and islclosure(origin) then
				local original = getupvalue(origin, index);
				setupvalue(origin, index, replacement)
				return original
			end
		else
			return replaceclosure(origin, index)
		end
		
		error("Invalid parameters for [utilities.Hook]. Expected \"function\" or \"table\" as argument #1")
	end
	
	function utilities.Filter(tbl, callback)
		for idx, val in next, tbl do
			if callback(idx, val) then
				return val, idx;
			end
		end
	end

	if (CFrame.lookAt) then
		local err = select(2, pcall(CFrame.lookAt))

		if (err == 'CFrame.lookAt is not enabled yet.') then
			setfflag('CFrameLookAt', 'true')
		end
	end
end

local library do
	--Services
	local runService = game:GetService"RunService"
	local textService = game:GetService"TextService"
	local inputService = game:GetService"UserInputService"
	local tweenService = game:GetService"TweenService"

	library = {
		tabs = {},
		draggable = true,
		flags = {},
		title = "uwuware",
		open = false,
		mousestate = inputService.MouseIconEnabled,
		popup = nil,
		instances = {},
		connections = {},
		options = {},
		notifications = {},
		tabSize = 0,
		theme = {},
		foldername = "wh_configs",
		fileext = ".whc"
	}

	library.OnLoaded = utilities.Signal.new();

	--Locals
	local dragging, dragInput, dragStart, startPos, dragObject

	local blacklistedKeys = { --add or remove keys if you find the need to
		Enum.KeyCode.Unknown,Enum.KeyCode.W,Enum.KeyCode.A,Enum.KeyCode.S,Enum.KeyCode.D,Enum.KeyCode.Slash,Enum.KeyCode.Tab,Enum.KeyCode.Escape
	}
	local whitelistedMouseinputs = { --add or remove mouse inputs if you find the need to
		Enum.UserInputType.MouseButton1,Enum.UserInputType.MouseButton2,Enum.UserInputType.MouseButton3
	}

	--Functions

	local _floor = math.floor;
	local _sign = math.sign;
	
	library.round = function(num, bracket)
		local bracket = bracket or 1;
		if typeof(num) == "Vector2" then
			return Vector2.new(library.round(num.X), library.round(num.Y))
		elseif typeof(num) == 'Color3' then
			return library.round(num.r * 255), library.round(num.g * 255), library.round(num.b * 255)
		else
			return _floor(num / bracket + _sign(num) * 0.5) * bracket
		end
	end

	--From: https://devforum.roblox.com/t/how-to-create-a-simple-rainbow-effect-using-tweenService/221849/2
	local chromaColor
	spawn(function()
		while library do
			runService.Heartbeat:wait()
			chromaColor = Color3.fromHSV(tick() % 6 / 6, 1, 1)
		end
	end)

	function library:Create(class, properties)
		properties = properties or {}
		if not class then return end
		local a = class == "Square" or class == "Line" or class == "Text" or class == "Quad" or class == "Circle" or class == "Triangle"
		local t = a and Drawing or Instance
		local inst = t.new(class)
		for property, value in next, properties do
			inst[property] = value
		end
		table.insert(self.instances, {object = inst, method = a})
		return inst
	end

	function library:AddConnection(connection, name, callback)
		callback = type(name) == "function" and name or callback
		connection = connection:connect(callback)
		if name ~= callback then
			self.connections[name] = connection
		else
			table.insert(self.connections, connection)
		end
		return connection
	end	

	inputService:GetPropertyChangedSignal('MouseIconEnabled'):connect(function()
		if (not library._mutex) then
			self.mousestate = inputService.MouseIconEnabled
		end
	end)	

	function library:Unload()
		library._mutex = true
		inputService.MouseIconEnabled = self.mousestate
		library._mutex = false

		for _, c in next, self.connections do
			c:Disconnect()
		end
		for _, i in next, self.instances do
			if i.method then
				pcall(function() i.object:Remove() end)
			else
				i.object:Destroy()
			end
		end
		for _, o in next, self.options do
			if o.type == "toggle" then
				pcall(function() o:SetState() end)
			end
		end
		library = nil
		getgenv().library = nil
	end

	function library:GetConfigs()
		if (not isfolder(self.foldername)) then
			makefolder(self.foldername)
		end

		local files = listfiles(self.foldername)
		for i, file in next, files do
			if (not file:match("%.whc")) then
				table.remove(files, i)
				continue
			end

			local result = file:match(string.format("%s\\(.-)%%.whc", self.foldername))
			files[i] = result
		end

		return files;
	end	

	function library:LoadConfig(name)
		if table.find(self:GetConfigs(), name) then
			local fileName = ("%s/%s%s"):format(self.foldername, name, self.fileext)

			local config = {};
			local read, content = pcall(readfile, fileName)
			if read then
				local success, decoded = pcall(httpService.JSONDecode, httpService, content)
				if success then
					config = decoded;
				end
			end

			for _, option in next, self.options do
				if option.type == 'button' then
					continue
				end
	
				if (option.skipflag) or (not option.flag) then
					continue
				end

				local name = option.section.column.tab.title;
				local tbl = config[name] or {};
				local flag = option.flag;

				if option.type == 'toggle' then
					fastSpawn(function() option:SetState(tbl[flag] == 1) end)
				elseif option.type == 'color' then
					if tbl[flag] then
						fastSpawn(function() option:SetColor(tbl[flag]) end)
						if option.trans then
							fastSpawn(function() option:SetTrans(tbl[flag .. ' Transparency']) end)
						end
					end
				elseif option.type == 'bind' then
					fastSpawn(function() option:SetKey(tbl[flag]) end)
				else
					fastSpawn(function() option:SetValue(tbl[flag]) end)
				end
			end

		end
	end

	function library:SaveConfig(name)
		local config = {};

		local fileName = ("%s/%s%s"):format(self.foldername, name, self.fileext)
		if table.find(self:GetConfigs(), name) then
			config = httpService:JSONDecode(readfile(fileName))
		end

		for _, option in next, self.options do
			if option.type == 'button' then
				continue
			end

			if (option.skipflag) or (not option.flag) then
				continue
			end

			local name = option.section.column.tab.title;
			config[name] = config[name] or {};

			local tbl = config[name]
			local flag = option.flag;

			if option.type == 'toggle' then
				tbl[flag] = option.state and 1 or 0
			elseif option.type == 'color' then
				tbl[flag] = {option.color.r, option.color.g, option.color.b}
				if option.trans then
					tbl[flag .. " Transparency"] = option.trans
				end
			elseif option.type == "bind" then
				tbl[flag] = option.key
			elseif option.type == "list" then
				tbl[flag] = option.value
			else
				tbl[flag] = option.value
			end
		end

		writefile(fileName, httpService:JSONEncode(config))
	end


	local function createLabel(option, parent)
		option.main = library:Create("TextLabel", {
			LayoutOrder = option.position,
			Position = UDim2.new(0, 6, 0, 0),
			Size = UDim2.new(1, -12, 0, 24),
			BackgroundTransparency = 1,
			TextSize = 15,
			Font = Enum.Font.Code,
			TextColor3 = Color3.new(1, 1, 1),
			TextXAlignment = Enum.TextXAlignment.Left,
			TextYAlignment = Enum.TextYAlignment.Top,
			TextWrapped = true,
			Parent = parent
		})

		setmetatable(option, {__newindex = function(t, i, v)
			if i == "Text" then
				local size = textService:GetTextSize(option.main.Text, 15, Enum.Font.Code, Vector2.new(option.main.AbsoluteSize.X, 9e9))

				option.main.Text = tostring(v)
				option.main.Size = UDim2.new(1, -12, 0, size.Y + 3)
				--option.main.Size = UDim2.new(1, -12, 0, textService:GetTextSize(option.main.Text, 15, Enum.Font.Code, Vector2.new(option.main.AbsoluteSize.X, 9e9)).Y + 6)
			end
		end})

		option.Text = option.text
	end

	local function createDivider(option, parent)
		option.main = library:Create("Frame", {
			LayoutOrder = option.position,
			Size = UDim2.new(1, 0, 0, 18),
			BackgroundTransparency = 1,
			Parent = parent
		})

		library:Create("Frame", {
			AnchorPoint = Vector2.new(0.5, 0.5),
			Position = UDim2.new(0.5, 0, 0.5, 0),
			Size = UDim2.new(1, -24, 0, 1),
			BackgroundColor3 = Color3.fromRGB(60, 60, 60),
			BorderColor3 = Color3.new(),
			Parent = option.main
		})

		option.title = library:Create("TextLabel", {
			AnchorPoint = Vector2.new(0.5, 0.5),
			Position = UDim2.new(0.5, 0, 0.5, 0),
			BackgroundColor3 = Color3.fromRGB(30, 30, 30),
			BorderSizePixel = 0,
			TextColor3 =  Color3.new(1, 1, 1),
			TextSize = 15,
			Font = Enum.Font.Code,
			TextXAlignment = Enum.TextXAlignment.Center,
			Parent = option.main
		})

		setmetatable(option, {__newindex = function(t, i, v)
			if i == "Text" then
				if v then
					option.title.Text = tostring(v)
					option.title.Size = UDim2.new(0, textService:GetTextSize(option.title.Text, 15, Enum.Font.Code, Vector2.new(9e9, 9e9)).X + 12, 0, 20)
					option.main.Size = UDim2.new(1, 0, 0, 18)
				else
					option.title.Text = ""
					option.title.Size = UDim2.new()
					option.main.Size = UDim2.new(1, 0, 0, 6)
				end
			end
		end})
		option.Text = option.text
	end

	local function createToggle(option, parent)
		option.hasInit = true

		option.main = library:Create("Frame", {
			LayoutOrder = option.position,
			Size = UDim2.new(1, 0, 0, 20),
			BackgroundTransparency = 1,
			Parent = parent
		})

		local tickbox
		local tickboxOverlay
		if option.style then
			tickbox = library:Create("Frame", {
				Position = UDim2.new(0, 6, 0, 4),
				Size = UDim2.new(0, 12, 0, 12),
				BackgroundTransparency = 0,
				BackgroundColor3 = Color3.new(),
				Parent = option.main
			})

			local tickboxInner = library:Create("Frame", {
				AnchorPoint = Vector2.new(0.5, 0.5),
				Position = UDim2.new(0.5, 0, 0.5, 0),
				Size = UDim2.new(1, -2, 1, -2),
				BackgroundTransparency = 0,
				BackgroundColor3 = Color3.fromRGB(60, 60, 60),
				Parent = tickbox
			})	

			local tickboxStyle = library:Create("Frame", {
				AnchorPoint = Vector2.new(0.5, 0.5),
				Position = UDim2.new(0.5, 0, 0.5, 0),
				Size = UDim2.new(1, -6, 1, -6),
				BackgroundTransparency = 0,
				BackgroundColor3 = Color3.fromRGB(40, 40, 40),
				Parent = tickbox
			})

			tickboxOverlay = library:Create("Frame", {
				AnchorPoint = Vector2.new(0.5, 0.5),
				Position = UDim2.new(0.5, 0, 0.5, 0),
				Size = UDim2.new(1, -6, 1, -6),
				
				BackgroundTransparency = 0,
				BackgroundColor3 = library.flags["Menu Accent Color"],
				
				Visible = option.state,
				Parent = tickbox
			})

			library:Create("ImageLabel", {
				AnchorPoint = Vector2.new(0.5, 0.5),
				Position = UDim2.new(0.5, 0, 0.5, 0),
				Size = UDim2.new(1, 0, 1, 0),
				BackgroundTransparency = 1,
				Image = "rbxassetid://5941353943",
				ImageTransparency = 0.6,
				Parent = tickbox
			})

			library:Create('UICorner', { Parent = tickbox })
			library:Create('UICorner', { Parent = tickboxInner })
			library:Create('UICorner', { Parent = tickboxStyle })
			library:Create('UICorner', { Parent = tickboxOverlay })

			table.insert(library.theme, tickboxOverlay)
		else
			tickbox = library:Create("Frame", {
				Position = UDim2.new(0, 6, 0, 4),
				Size = UDim2.new(0, 12, 0, 12),
				BackgroundColor3 = library.flags["Menu Accent Color"],
				BorderColor3 = Color3.new(),
				Parent = option.main
			})

			tickboxOverlay = library:Create("ImageLabel", {
				Size = UDim2.new(1, 0, 1, 0),
				BackgroundTransparency = option.state and 1 or 0,
				BackgroundColor3 = Color3.fromRGB(50, 50, 50),
				BorderColor3 = Color3.new(),
				Image = "rbxassetid://4155801252",
				ImageTransparency = 0.6,
				ImageColor3 = Color3.new(),
				Parent = tickbox
			})

			library:Create("ImageLabel", {
				Size = UDim2.new(1, 0, 1, 0),
				BackgroundTransparency = 1,
				Image = "rbxassetid://2592362371",
				ImageColor3 = Color3.fromRGB(60, 60, 60),
				ScaleType = Enum.ScaleType.Slice,
				SliceCenter = Rect.new(2, 2, 62, 62),
				Parent = tickbox
			})

			library:Create("ImageLabel", {
				Size = UDim2.new(1, -2, 1, -2),
				Position = UDim2.new(0, 1, 0, 1),
				BackgroundTransparency = 1,
				Image = "rbxassetid://2592362371",
				ImageColor3 = Color3.new(),
				ScaleType = Enum.ScaleType.Slice,
				SliceCenter = Rect.new(2, 2, 62, 62),
				Parent = tickbox
			})

			table.insert(library.theme, tickbox)
		end

		option.interest = library:Create("Frame", {
			Position = UDim2.new(0, 0, 0, 0),
			Size = UDim2.new(1, 0, 0, 20),
			BackgroundTransparency = 1,
			Parent = option.main
		})

		option.title = library:Create("TextLabel", {
			Position = UDim2.new(0, 24, 0, 0),
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			Text = option.text,
			TextColor3 =  option.state and Color3.fromRGB(210, 210, 210) or Color3.fromRGB(180, 180, 180),
			TextSize = 15,
			Font = Enum.Font.Code,
			TextXAlignment = Enum.TextXAlignment.Left,
			Parent = option.interest
		})

		option.interest.InputBegan:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				option:SetState(not option.state)
			end
			if input.UserInputType.Name == "MouseMovement" then
				if not library.warning and not library.slider then
					if option.style then
						tickbox.BackgroundColor3 = library.flags["Menu Accent Color"]
						--tweenService:Create(tickbox, TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {ImageColor3 = library.flags["Menu Accent Color"]}):Play()
					else
						tickbox.BorderColor3 = library.flags["Menu Accent Color"]
						tickboxOverlay.BorderColor3 = library.flags["Menu Accent Color"]
						--tweenService:Create(tickbox, TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {BorderColor3 = library.flags["Menu Accent Color"]}):Play()
						--tweenService:Create(tickboxOverlay, TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {BorderColor3 = library.flags["Menu Accent Color"]}):Play()
					end
				end
				if option.tip then
					library.tooltip.Text = option.tip
					library.tooltip.Size = UDim2.new(0, textService:GetTextSize(option.tip, 15, Enum.Font.Code, Vector2.new(9e9, 9e9)).X, 0, 20)
				end
			end
		end)

		option.interest.InputChanged:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if option.tip then
					library.tooltip.Position = UDim2.new(0, input.Position.X + 26, 0, input.Position.Y + 36)
				end
			end
		end)

		option.interest.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if option.style then
					tickbox.BackgroundColor3 = Color3.new()
					--tweenService:Create(tickbox, TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {ImageColor3 = Color3.new()}):Play()
				else
					tickbox.BorderColor3 = Color3.new()
					tickboxOverlay.BorderColor3 = Color3.new()
					--tweenService:Create(tickbox, TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {BorderColor3 = Color3.new()}):Play()
					--tweenService:Create(tickboxOverlay, TweenInfo.new(0.2, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {BorderColor3 = Color3.new()}):Play()
				end
				library.tooltip.Position = UDim2.new(2)
			end
		end)

		function option:SetState(state, nocallback)
			state = typeof(state) == "boolean" and state
			state = state or false
			library.flags[self.flag] = state
			self.state = state
			option.title.TextColor3 = state and Color3.fromRGB(210, 210, 210) or Color3.fromRGB(160, 160, 160)
			if option.style then
				tickboxOverlay.Visible = state
			else
				tickboxOverlay.BackgroundTransparency = state and 1 or 0
			end
			if not nocallback then
				self.callback(state)
			end
		end

		if option.state then
			delay(1, function()
				if library then
					option.callback(true)
				end
			end)
		end

		setmetatable(option, {__newindex = function(t, i, v)
			if i == "Text" then
				option.title.Text = tostring(v)
			end
		end})
	end

	local function createButton(option, parent)
		option.hasInit = true

		if (not option.sub) then
			option.main = library:Create("Frame", {
				LayoutOrder = option.position,
				Position = UDim2.new(0, 0, 0, 0);
				Size = UDim2.new(1, 0, 0, 26),
				BackgroundTransparency = 1,
				Parent = parent
			})
		end

		option.title = library:Create("TextLabel", {
			Position = (option.sub and UDim2.new(0.5, 6, 0.5, -8) or UDim2.new(0, 6, 0.5, -8));
			Size = (option.sub and UDim2.new(0.5, -12, 1, -8) or UDim2.new(1, -12, 0, 18));

			BackgroundColor3 = Color3.fromRGB(50, 50, 50),
			BorderColor3 = Color3.new(),
			Text = option.text,

			TextColor3 = Color3.new(1, 1, 1),
			TextSize = (option.textSize or 15),
			Font = Enum.Font.Code,
			Parent = (option.sub and option:getMain() or option.main)
		})

		library:Create("UIGradient", {
			Color = ColorSequence.new({
				ColorSequenceKeypoint.new(0, Color3.fromRGB(180, 180, 180)),
				ColorSequenceKeypoint.new(1, Color3.fromRGB(253, 253, 253)),
			}),
			Rotation = -90,
			Parent = option.title
		})

		option.title.InputBegan:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				option.callback()
				if library then
					library.flags[option.flag] = true
				end
			end
			if input.UserInputType.Name == "MouseMovement" then
				if not library.warning and not library.slider then
					option.title.BorderColor3 = library.flags["Menu Accent Color"]
				end
			end
		end)

		option.title.InputChanged:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if option.tip then
					library.tooltip.Text = option.tip
					library.tooltip.Size = UDim2.new(0, textService:GetTextSize(option.tip, 15, Enum.Font.Code, Vector2.new(9e9, 9e9)).X, 0, 20)
					library.tooltip.Position = UDim2.new(0, input.Position.X + 26, 0, input.Position.Y + 36)
				end
			end
		end)

		option.title.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				option.title.BorderColor3 = Color3.new()
				library.tooltip.Position = UDim2.new(2)
			end
		end)
	end

	local function createBind(option, parent)
		option.hasInit = true

		local binding
		local holding
		local Loop

		if option.sub then
			option.main = option:getMain()
		else
			option.main = option.main or library:Create("Frame", {
				LayoutOrder = option.position,
				Size = UDim2.new(1, 0, 0, 20),
				BackgroundTransparency = 1,
				Parent = parent
			})

			library:Create("TextLabel", {
				Position = UDim2.new(0, 6, 0, 0),
				Size = UDim2.new(1, -12, 1, 0),
				BackgroundTransparency = 1,
				Text = option.text,
				TextSize = 15,
				Font = Enum.Font.Code,
				TextColor3 = Color3.fromRGB(210, 210, 210),
				TextXAlignment = Enum.TextXAlignment.Left,
				Parent = option.main
			})
		end

		local bindinput = library:Create(option.sub and "TextButton" or "TextLabel", {
			Position = UDim2.new(1, -6 - (option.subpos or 0), 0, option.sub and 2 or 3),
			SizeConstraint = Enum.SizeConstraint.RelativeYY,
			BackgroundColor3 = Color3.fromRGB(30, 30, 30),
			BorderSizePixel = 0,
			TextSize = 15,
			Font = Enum.Font.Code,
			TextColor3 = Color3.fromRGB(160, 160, 160),
			TextXAlignment = Enum.TextXAlignment.Right,
			Parent = option.main
		})

		if option.sub then
			bindinput.AutoButtonColor = false
		end

		local interest = option.sub and bindinput or option.main
		local inContact

		local maid = utilities.Maid.new()

		interest.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				binding = true
				bindinput.Text = "[...]"
				bindinput.Size = UDim2.new(0, -textService:GetTextSize(bindinput.Text, 16, Enum.Font.Code, Vector2.new(9e9, 9e9)).X, 0, 16)
				bindinput.TextColor3 = library.flags["Menu Accent Color"]

				local start = tick()
				maid:GiveTask(runService.Heartbeat:connect(function()
					if (tick() - start) >= 5 and binding then
						option:SetKey(Enum.KeyCode.Backspace)
						maid:DoCleaning()
					end
				end))
			end
		end)

		library:AddConnection(inputService.InputBegan, function(input)
			if inputService:GetFocusedTextBox() then return end
			if binding then
				local key = (table.find(whitelistedMouseinputs, input.UserInputType) and not option.nomouse) and input.UserInputType
				option:SetKey(key or (not table.find(blacklistedKeys, input.KeyCode)) and input.KeyCode)
			else
				if (input.KeyCode.Name == option.key or input.UserInputType.Name == option.key) and not binding then
					if option.mode == "toggle" then
						library.flags[option.flag] = not library.flags[option.flag]
						option.callback(library.flags[option.flag], 0)
					else
						library.flags[option.flag] = true
						if Loop then Loop:Disconnect() option.callback(true, 0) end
						Loop = library:AddConnection(runService.RenderStepped, function(step)
							if not inputService:GetFocusedTextBox() then
								option.callback(nil, step)
							end
						end)
					end
				end
			end
		end)

		library:AddConnection(inputService.InputEnded, function(input)
			if option.key ~= "none" then
				if input.KeyCode.Name == option.key or input.UserInputType.Name == option.key then
					if Loop then
						Loop:Disconnect()
						library.flags[option.flag] = false
						option.callback(true, 0)
					end
				end
			end
		end)

		function option:SetKey(key)
			maid:DoCleaning()
			binding = false
			bindinput.TextColor3 = Color3.fromRGB(160, 160, 160)
			if Loop then Loop:Disconnect() library.flags[option.flag] = false option.callback(true, 0) end
			self.key = (key and key.Name) or key or self.key
			if self.key == "Backspace" then
				self.key = "none"
				bindinput.Text = "[NONE]"
			else
				local a = self.key
				if self.key:match"Mouse" then
					a = self.key:gsub("Button", ""):gsub("Mouse", "M")
				elseif self.key:match"Shift" or self.key:match"Alt" or self.key:match"Control" then
					a = self.key:gsub("Left", "L"):gsub("Right", "R")
				end
				bindinput.Text = "[" .. a:gsub("Control", "CTRL"):upper() .. "]"
			end
			bindinput.Size = UDim2.new(0, -textService:GetTextSize(bindinput.Text, 16, Enum.Font.Code, Vector2.new(9e9, 9e9)).X, 0, 16)
		end
		option:SetKey()
	end

	local function createSlider(option, parent)
		option.hasInit = true

		if option.sub then
			option.main = option:getMain()
			option.main.Size = UDim2.new(1, 0, 0, 42)
		else
			option.main = library:Create("Frame", {
				LayoutOrder = option.position,
				Size = UDim2.new(1, 0, 0, option.textpos and 24 or 40),
				BackgroundTransparency = 1,
				Parent = parent
			})
		end

		option.slider = library:Create("Frame", {
			Position = UDim2.new(0, 6, 0, (option.sub and 22 or option.textpos and 4 or 20)),
			Size = UDim2.new(1, -12, 0, 16),
			BackgroundColor3 = Color3.fromRGB(50, 50, 50),
			BorderColor3 = Color3.new(),
			Parent = option.main
		})

		library:Create("ImageLabel", {
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			Image = "rbxassetid://2454009026",
			ImageColor3 = Color3.new(),
			ImageTransparency = 0.8,
			Parent = option.slider
		})

		option.fill = library:Create("Frame", {
			BackgroundColor3 = library.flags["Menu Accent Color"],
			BorderSizePixel = 0,
			Parent = option.slider
		})

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, 0, 1, 0),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.fromRGB(60, 60, 60),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.slider
		-- })

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, -2, 1, -2),
		-- 	Position = UDim2.new(0, 1, 0, 1),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.new(),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.slider
		-- })

		option.title = library:Create("TextBox", {
			Position = UDim2.new((option.sub or option.textpos) and 0.5 or 0, (option.sub or option.textpos) and 0 or 6, 0, 0),
			Size = UDim2.new(0, 0, 0, (option.sub or option.textpos) and 14 or 18),
			BackgroundTransparency = 1,
			Text = (option.text == "nil" and "" or option.text .. ": ") .. option.value .. option.suffix,
			TextSize = (option.sub or option.textpos) and 14 or 15,
			Font = Enum.Font.Code,
			TextColor3 = Color3.fromRGB(210, 210, 210),
			TextXAlignment = Enum.TextXAlignment[(option.sub or option.textpos) and "Center" or "Left"],
			Parent = (option.sub or option.textpos) and option.slider or option.main
		})
		table.insert(library.theme, option.fill)

		library:Create("UIGradient", {
			Color = ColorSequence.new({
				ColorSequenceKeypoint.new(0, Color3.fromRGB(115, 115, 115)),
				ColorSequenceKeypoint.new(1, Color3.new(1, 1, 1)),
			}),
			Rotation = -90,
			Parent = option.fill
		})

		if option.min >= 0 then
			option.fill.Size = UDim2.new((option.value - option.min) / (option.max - option.min), 0, 1, 0)
		else
			option.fill.Position = UDim2.new((0 - option.min) / (option.max - option.min), 0, 0, 0)
			option.fill.Size = UDim2.new(option.value / (option.max - option.min), 0, 1, 0)
		end

		local manualInput
		option.title.Focused:connect(function()
			if not manualInput then
				option.title:ReleaseFocus()
				option.title.Text = (option.text == "nil" and "" or option.text .. ": ") .. option.value .. option.suffix
			end
		end)

		option.title.FocusLost:connect(function()
			option.slider.BorderColor3 = Color3.new()
			if manualInput then
				if tonumber(option.title.Text) then
					option:SetValue(tonumber(option.title.Text))
				else
					option.title.Text = (option.text == "nil" and "" or option.text .. ": ") .. option.value .. option.suffix
				end
			end
			manualInput = false
		end)

		local interest = (option.sub or option.textpos) and option.slider or option.main
		local isOnSlider = false;

		interest.InputBegan:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				if inputService:IsKeyDown(Enum.KeyCode.LeftControl) or inputService:IsKeyDown(Enum.KeyCode.RightControl) then
					manualInput = true
					option.title:CaptureFocus()
				else
					library.slider = option
					option.slider.BorderColor3 = library.flags["Menu Accent Color"]
					option:SetValue(option.min + ((input.Position.X - option.slider.AbsolutePosition.X) / option.slider.AbsoluteSize.X) * (option.max - option.min))
				end
			end
			if input.UserInputType.Name == "MouseMovement" then
				isOnSlider = true
				if not library.warning and not library.slider then
					option.slider.BorderColor3 = library.flags["Menu Accent Color"]
				end
				if option.tip then
					library.tooltip.Text = option.tip
					library.tooltip.Size = UDim2.new(0, textService:GetTextSize(option.tip, 15, Enum.Font.Code, Vector2.new(9e9, 9e9)).X, 0, 20)
				end
			end
		end)

		inputService.InputChanged:connect(function(input)
			if input.UserInputType.Name == "MouseWheel" and isOnSlider then
				option:SetValue(option.value + (input.Position.Z * option.float))
			end
		end)

		interest.InputChanged:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if option.tip then
					library.tooltip.Position = UDim2.new(0, input.Position.X + 26, 0, input.Position.Y + 36)
				end
			end
		end)

		interest.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				isOnSlider = false;
				library.tooltip.Position = UDim2.new(2)
				if option ~= library.slider then
					option.slider.BorderColor3 = Color3.new()
					--option.fill.BorderColor3 = Color3.new()
				end
			end
		end)

		function option:SetValue(value, nocallback)
			if typeof(value) ~= "number" then value = 0 end
			value = library.round(value, option.float)
			value = math.clamp(value, self.min, self.max)
			if self.min >= 0 then
				option.fill:TweenSize(UDim2.new((value - self.min) / (self.max - self.min), 0, 1, 0), "Out", "Quad", 0.05, true)
			else
				option.fill:TweenPosition(UDim2.new((0 - self.min) / (self.max - self.min), 0, 0, 0), "Out", "Quad", 0.05, true)
				option.fill:TweenSize(UDim2.new(value / (self.max - self.min), 0, 1, 0), "Out", "Quad", 0.1, true)
			end
			library.flags[self.flag] = value
			self.value = value
			option.title.Text = (option.text == "nil" and "" or option.text .. ": ") .. option.value .. option.suffix
			if not nocallback then
				self.callback(value)
			end
		end
		delay(1, function()
			if library then
				option:SetValue(option.value)
			end
		end)
	end

	local function createList(option, parent)
		option.hasInit = true

		if option.sub then
			option.main = option:getMain()
			option.main.Size = UDim2.new(1, 0, 0, 48)
		else
			option.main = library:Create("Frame", {
				LayoutOrder = option.position,
				Size = UDim2.new(1, 0, 0, option.text == "nil" and 30 or 48),
				BackgroundTransparency = 1,
				Parent = parent
			})

			if option.text ~= "nil" then
				library:Create("TextLabel", {
					Position = UDim2.new(0, 6, 0, 0),
					Size = UDim2.new(1, -12, 0, 18),
					BackgroundTransparency = 1,
					Text = option.text,
					TextSize = 15,
					Font = Enum.Font.Code,
					TextColor3 = Color3.fromRGB(210, 210, 210),
					TextXAlignment = Enum.TextXAlignment.Left,
					Parent = option.main
				})
			end
		end

		local function getMultiText()
			local s = {};
			for _, value in next, option.values do
				s[#s + 1] = (option.value[value] and tostring(value) or nil)
			end
			return table.concat(s, ', ')
		end

		option.listvalue = library:Create("TextLabel", {
			Position = UDim2.new(0, 6, 0, (option.text == "nil" and not option.sub) and 4 or 22),
			Size = UDim2.new(1, -12, 0, 22),
			BackgroundColor3 = Color3.fromRGB(50, 50, 50),
			BorderColor3 = Color3.new(),
			Text = " " .. (typeof(option.value) == "string" and option.value or getMultiText()),
			TextSize = 15,
			Font = Enum.Font.Code,
			TextColor3 = Color3.new(1, 1, 1),
			TextXAlignment = Enum.TextXAlignment.Left,
			TextTruncate = Enum.TextTruncate.AtEnd,
			Parent = option.main
		})

		library:Create("ImageLabel", {
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			Image = "rbxassetid://2454009026",
			ImageColor3 = Color3.new(),
			ImageTransparency = 0.8,
			Parent = option.listvalue
		})

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, 0, 1, 0),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.fromRGB(60, 60, 60),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.listvalue
		-- })

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, -2, 1, -2),
		-- 	Position = UDim2.new(0, 1, 0, 1),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.new(),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.listvalue
		-- })

		option.arrow = library:Create("ImageLabel", {
			Position = UDim2.new(1, -16, 0, 7),
			Size = UDim2.new(0, 8, 0, 8),
			Rotation = 90,
			BackgroundTransparency = 1,
			Image = "rbxassetid://4918373417",
			ImageColor3 = Color3.new(1, 1, 1),
			ScaleType = Enum.ScaleType.Fit,
			ImageTransparency = 0.4,
			Parent = option.listvalue
		})

		option.holder = library:Create("TextButton", {
			ZIndex = 4,
			BackgroundColor3 = Color3.fromRGB(40, 40, 40),
			BorderColor3 = Color3.new(),
			Text = "",
			AutoButtonColor = false,
			Visible = false,
			Parent = library.base
		})

		option.content = library:Create("ScrollingFrame", {
			ZIndex = 4,
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			BorderSizePixel = 0,
			ScrollBarImageColor3 = Color3.new(),
			ScrollBarThickness = 3,
			ScrollingDirection = Enum.ScrollingDirection.Y,
			VerticalScrollBarInset = Enum.ScrollBarInset.Always,
			TopImage = "rbxasset://textures/ui/Scroll/scroll-middle.png",
			BottomImage = "rbxasset://textures/ui/Scroll/scroll-middle.png",
			Parent = option.holder
		})

		-- library:Create("ImageLabel", {
		-- 	ZIndex = 4,
		-- 	Size = UDim2.new(1, 0, 1, 0),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.fromRGB(60, 60, 60),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.holder
		-- })

		-- library:Create("ImageLabel", {
		-- 	ZIndex = 4,
		-- 	Size = UDim2.new(1, -2, 1, -2),
		-- 	Position = UDim2.new(0, 1, 0, 1),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.new(),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.holder
		-- })

		local layout = library:Create("UIListLayout", {
			Padding = UDim.new(0, 2),
			Parent = option.content
		})

		library:Create("UIPadding", {
			PaddingTop = UDim.new(0, 4),
			PaddingLeft = UDim.new(0, 4),
			Parent = option.content
		})

		local valueCount = 0
		layout.Changed:connect(function()
			option.holder.Size = UDim2.new(0, option.listvalue.AbsoluteSize.X, 0, 8 + (valueCount > option.max and (-2 + (option.max * 22)) or layout.AbsoluteContentSize.Y))
			option.content.CanvasSize = UDim2.new(0, 0, 0, 8 + layout.AbsoluteContentSize.Y)
		end)
		local interest = option.sub and option.listvalue or option.main

		option.listvalue.InputBegan:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				if library.popup == option then library.popup:Close() return end
				if library.popup then
					library.popup:Close()
				end
				option.arrow.Rotation = -90
				option.open = true
				option.holder.Visible = true
				local pos = option.main.AbsolutePosition
				option.holder.Position = UDim2.new(0, pos.X + 6, 0, pos.Y + ((option.text == "nil" and not option.sub) and 66 or 84))
				library.popup = option
				option.listvalue.BorderColor3 = library.flags["Menu Accent Color"]
			end
			if input.UserInputType.Name == "MouseMovement" then
				if not library.warning and not library.slider then
					option.listvalue.BorderColor3 = library.flags["Menu Accent Color"]
				end
			end
		end)

		option.listvalue.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if not option.open then
					option.listvalue.BorderColor3 = Color3.new()
				end
			end
		end)

		interest.InputBegan:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if option.tip then
					library.tooltip.Text = option.tip
					library.tooltip.Size = UDim2.new(0, textService:GetTextSize(option.tip, 15, Enum.Font.Code, Vector2.new(9e9, 9e9)).X, 0, 20)
				end
			end
		end)

		interest.InputChanged:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if option.tip then
					library.tooltip.Position = UDim2.new(0, input.Position.X + 26, 0, input.Position.Y + 36)
				end
			end
		end)

		interest.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				library.tooltip.Position = UDim2.new(2)
			end
		end)

		local selected
		function option:AddValue(value, state)
			if self.labels[value] then return end
			valueCount = valueCount + 1

			if self.multiselect then
				self.values[value] = state
			else
				if not table.find(self.values, value) then
					table.insert(self.values, value)
				end
			end

			local label = library:Create("TextLabel", {
				ZIndex = 4,
				Size = UDim2.new(1, 0, 0, 20),
				BackgroundTransparency = 1,
				Text = value,
				TextSize = 15,
				Font = Enum.Font.Code,
				TextTransparency = self.multiselect and (self.value[value] and 1 or 0) or self.value == value and 1 or 0,
				TextColor3 = Color3.fromRGB(210, 210, 210),
				TextXAlignment = Enum.TextXAlignment.Left,
				Parent = option.content
			})
			self.labels[value] = label

			local labelOverlay = library:Create("TextLabel", {
				ZIndex = 4,	
				Size = UDim2.new(1, 0, 1, 0),
				BackgroundTransparency = 0.8,
				Text = " " ..value,
				TextSize = 15,
				Font = Enum.Font.Code,
				TextColor3 = library.flags["Menu Accent Color"],
				TextXAlignment = Enum.TextXAlignment.Left,
				Visible = self.multiselect and self.value[value] or self.value == value,
				Parent = label
			})
			selected = selected or self.value == value and labelOverlay
			table.insert(library.theme, labelOverlay)

			label.InputBegan:connect(function(input)
				if input.UserInputType.Name == "MouseButton1" then
					if self.multiselect then
						self.value[value] = not self.value[value]
						self:SetValue(self.value)
					else
						self:SetValue(value)
						self:Close()
					end
				end
			end)
		end

		for i, value in next, option.values do
			option:AddValue(tostring(typeof(i) == "number" and value or i))
		end

		function option:RemoveValue(value)
			local label = self.labels[value]
			if label then
				label:Destroy()
				self.labels[value] = nil
				valueCount = valueCount - 1
				if self.multiselect then
					self.values[value] = nil
					self:SetValue(self.value)
				else
					table.remove(self.values, table.find(self.values, value))
					if self.value == value then
						selected = nil
						self:SetValue(self.values[1] or "")
					end
				end
			end
		end

		function option:SetValue(value, nocallback)
			if self.multiselect and typeof(value) ~= "table" then
				value = {}
				for i,v in next, self.values do
					value[v] = false
				end
			end
			self.value = typeof(value) == "table" and value or tostring(table.find(self.values, value) and value or self.values[1])
			library.flags[self.flag] = self.value
			option.listvalue.Text = " " .. (self.multiselect and getMultiText() or self.value)
			if self.multiselect then
				for name, label in next, self.labels do
					label.TextTransparency = self.value[name] and 1 or 0
					if label:FindFirstChild"TextLabel" then
						label.TextLabel.Visible = self.value[name]
					end
				end
			else
				if selected then
					selected.TextTransparency = 0
					if selected:FindFirstChild"TextLabel" then
						selected.TextLabel.Visible = false
					end
				end
				if self.labels[self.value] then
					selected = self.labels[self.value]
					selected.TextTransparency = 1
					if selected:FindFirstChild"TextLabel" then
						selected.TextLabel.Visible = true
					end
				end
			end
			if not nocallback then
				self.callback(self.value)
			end
		end
		delay(1, function()
			if library then
				option:SetValue(option.value)
			end
		end)

		function option:Close()
			library.popup = nil
			option.arrow.Rotation = 90
			self.open = false
			option.holder.Visible = false
			option.listvalue.BorderColor3 = Color3.new()
		end

		return option
	end

	local function createBox(option, parent)
		option.hasInit = true

		if option.sub then
			option.main = option:getMain()
			option.main.Size = UDim2.new(1, 0, 0, 45)
		else
			option.main = library:Create("Frame", {
				LayoutOrder = option.position,
				Size = UDim2.new(1, 0, 0, (option.text == '' or option.textpos) and 28 or 44);
				BackgroundTransparency = 1,
				Parent = parent
			})
		end

		if option.text ~= '' and ((not option.sub) and (not option.textpos)) then
			option.title = library:Create("TextLabel", {
				Position = UDim2.new(0, 6, 0, 0),
				Size = UDim2.new(1, -12, 0, 18),
				BackgroundTransparency = 1,
				Text = option.text,
				TextSize = 15,
				Font = Enum.Font.Code,
				TextColor3 = Color3.fromRGB(210, 210, 210),
				TextXAlignment = Enum.TextXAlignment.Left,
				Parent = option.main
			})
		end

		option.holder = library:Create("Frame", {
			Position = UDim2.new(0, 6, 0, (option.text == '' or option.textpos) and 4 or 22),
			Size = UDim2.new(1, -12, 0, 20),
			BackgroundColor3 = Color3.fromRGB(50, 50, 50),
			BorderColor3 = Color3.new(),
			Parent = option.main
		})

		library:Create("ImageLabel", {
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			Image = "rbxassetid://2454009026",
			ImageColor3 = Color3.new(),
			ImageTransparency = 0.8,
			Parent = option.holder
		})

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, 0, 1, 0),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.fromRGB(60, 60, 60),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.holder
		-- })

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, -2, 1, -2),
		-- 	Position = UDim2.new(0, 1, 0, 1),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.new(),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.holder
		-- })

		local inputvalue = library:Create("TextBox", {
			Position = UDim2.new(0, 4, 0, 0),
			Size = UDim2.new(1, -4, 1, 0),
			BackgroundTransparency = 1,
			Text = "  " .. option.value,
			TextSize = 15,
			Font = Enum.Font.Code,
			TextColor3 = Color3.new(1, 1, 1),
			TextXAlignment = Enum.TextXAlignment.Left,
			TextWrapped = true,
			ClearTextOnFocus = false,
			Parent = option.holder
		})

		if option.sub or option.textpos then
			inputvalue.PlaceholderText = option.text;
			inputvalue.PlaceholderColor3 = Color3.fromRGB(156, 156, 156)
		end

		inputvalue.FocusLost:connect(function(enter)
			option.holder.BorderColor3 = Color3.new()
			option:SetValue(inputvalue.Text, enter)
		end)

		inputvalue.Focused:connect(function()
			option.holder.BorderColor3 = library.flags["Menu Accent Color"]
		end)

		inputvalue.InputBegan:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				inputvalue.Text = ""
			end
			if input.UserInputType.Name == "MouseMovement" then
				if not library.warning and not library.slider then
					option.holder.BorderColor3 = library.flags["Menu Accent Color"]
				end
				if option.tip then
					library.tooltip.Text = option.tip
					library.tooltip.Size = UDim2.new(0, textService:GetTextSize(option.tip, 15, Enum.Font.Code, Vector2.new(9e9, 9e9)).X, 0, 20)
				end
			end
		end)

		inputvalue.InputChanged:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if option.tip then
					library.tooltip.Position = UDim2.new(0, input.Position.X + 26, 0, input.Position.Y + 36)
				end
			end
		end)

		inputvalue.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if not inputvalue:IsFocused() then
					option.holder.BorderColor3 = Color3.new()
				end
				library.tooltip.Position = UDim2.new(2)
			end
		end)

		function option:SetValue(value, enter)
			library.flags[self.flag] = tostring(value)
			self.value = tostring(value)
			inputvalue.Text = self.value
			self.callback(value, enter)
		end
		delay(1, function()
			if library then
				option:SetValue(option.value)
			end
		end)
	end

	local function createColorPickerWindow(option)
		option.mainHolder = library:Create("TextButton", {
			ZIndex = 4,
			--Position = UDim2.new(1, -184, 1, 6),
			Size = UDim2.new(0, option.trans and 200 or 184, 0, 264),
			BackgroundColor3 = Color3.fromRGB(40, 40, 40),
			BorderColor3 = Color3.new(),
			AutoButtonColor = false,
			Visible = false,
			Parent = library.base
		})

		option.rgbBox = library:Create("Frame", {
			Position = UDim2.new(0, 6, 0, 214),
			Size = UDim2.new(0, (option.mainHolder.AbsoluteSize.X - 12), 0, 20),
			BackgroundColor3 = Color3.fromRGB(57, 57, 57),
			BorderColor3 = Color3.new(),
			ZIndex = 5;
			Parent = option.mainHolder
		})

		library:Create("ImageLabel", {
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			Image = "rbxassetid://2454009026",
			ImageColor3 = Color3.new(),
			ImageTransparency = 0.8,
			ZIndex = 6;
			Parent = option.rgbBox
		})

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, 0, 1, 0),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.fromRGB(60, 60, 60),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	ZIndex = 6;
		-- 	Parent = option.rgbBox
		-- })

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, -2, 1, -2),
		-- 	Position = UDim2.new(0, 1, 0, 1),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.new(),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	ZIndex = 6;
		-- 	Parent = option.rgbBox
		-- })

		option.rgbInput = library:Create("TextBox", {
			Position = UDim2.new(0, 4, 0, 0),
			Size = UDim2.new(1, -4, 1, 0),
			BackgroundTransparency = 1,
			Text = tostring(option.color),
			TextSize = 14,
			Font = Enum.Font.Code,
			TextColor3 = Color3.new(1, 1, 1),
			TextXAlignment = Enum.TextXAlignment.Center,
			TextWrapped = true,
			ClearTextOnFocus = false,
			ZIndex = 6;
			Parent = option.rgbBox
		})

		option.hexBox = option.rgbBox:Clone()
		option.hexBox.Position = UDim2.new(0, 6, 0, 238)
		-- option.hexBox.Size = UDim2.new(0, (option.mainHolder.AbsoluteSize.X/2 - 10), 0, 20)
		option.hexBox.Parent = option.mainHolder
		option.hexInput = option.hexBox.TextBox;

		-- library:Create("ImageLabel", {
		-- 	ZIndex = 4,
		-- 	Size = UDim2.new(1, 0, 1, 0),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.fromRGB(60, 60, 60),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.mainHolder
		-- })

		-- library:Create("ImageLabel", {
		-- 	ZIndex = 4,
		-- 	Size = UDim2.new(1, -2, 1, -2),
		-- 	Position = UDim2.new(0, 1, 0, 1),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.new(),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.mainHolder
		-- })

		local hue, sat, val = Color3.toHSV(option.color)
		hue, sat, val = hue == 0 and 1 or hue, sat + 0.005, val - 0.005
		local editinghue
		local editingsatval
		local editingtrans

		local transMain
		if option.trans then
			transMain = library:Create("ImageLabel", {
				ZIndex = 5,
				Size = UDim2.new(1, 0, 1, 0),
				BackgroundTransparency = 1,
				Image = "rbxassetid://2454009026",
				ImageColor3 = Color3.fromHSV(hue, 1, 1),
				Rotation = 180,
				Parent = library:Create("ImageLabel", {
					ZIndex = 4,
					AnchorPoint = Vector2.new(1, 0),
					Position = UDim2.new(1, -6, 0, 6),
					Size = UDim2.new(0, 10, 1, -60),
					BorderColor3 = Color3.new(),
					Image = "rbxassetid://4632082392",
					ScaleType = Enum.ScaleType.Tile,
					TileSize = UDim2.new(0, 5, 0, 5),
					Parent = option.mainHolder
				})
			})

			option.transSlider = library:Create("Frame", {
				ZIndex = 5,
				Position = UDim2.new(0, 0, option.trans, 0),
				Size = UDim2.new(1, 0, 0, 2),
				BackgroundColor3 = Color3.fromRGB(38, 41, 65),
				BorderColor3 = Color3.fromRGB(255, 255, 255),
				Parent = transMain
			})

			transMain.InputBegan:connect(function(Input)
				if Input.UserInputType.Name == "MouseButton1" then
					editingtrans = true
					option:SetTrans(1 - ((Input.Position.Y - transMain.AbsolutePosition.Y) / transMain.AbsoluteSize.Y))
				end
			end)

			transMain.InputEnded:connect(function(Input)
				if Input.UserInputType.Name == "MouseButton1" then
					editingtrans = false
				end
			end)
		end

		local hueMain = library:Create("Frame", {
			ZIndex = 4,
			AnchorPoint = Vector2.new(0, 1),
			Position = UDim2.new(0, 6, 1, -54),
			Size = UDim2.new(1, option.trans and -28 or -12, 0, 10),
			BackgroundColor3 = Color3.new(1, 1, 1),
			BorderColor3 = Color3.new(),
			Parent = option.mainHolder
		})

		local Gradient = library:Create("UIGradient", {
			Color = ColorSequence.new({
				ColorSequenceKeypoint.new(0, Color3.fromRGB(255, 0, 0)),
				ColorSequenceKeypoint.new(0.17, Color3.fromRGB(255, 0, 255)),
				ColorSequenceKeypoint.new(0.33, Color3.fromRGB(0, 0, 255)),
				ColorSequenceKeypoint.new(0.5, Color3.fromRGB(0, 255, 255)),
				ColorSequenceKeypoint.new(0.67, Color3.fromRGB(0, 255, 0)),
				ColorSequenceKeypoint.new(0.83, Color3.fromRGB(255, 255, 0)),
				ColorSequenceKeypoint.new(1, Color3.fromRGB(255, 0, 0)),
			}),
			Parent = hueMain
		})

		local hueSlider = library:Create("Frame", {
			ZIndex = 4,
			Position = UDim2.new(1 - hue, 0, 0, 0),
			Size = UDim2.new(0, 2, 1, 0),
			BackgroundColor3 = Color3.fromRGB(38, 41, 65),
			BorderColor3 = Color3.fromRGB(255, 255, 255),
			Parent = hueMain
		})

		hueMain.InputBegan:connect(function(Input)
			if Input.UserInputType.Name == "MouseButton1" then
				editinghue = true
				X = (hueMain.AbsolutePosition.X + hueMain.AbsoluteSize.X) - hueMain.AbsolutePosition.X
				X = math.clamp((Input.Position.X - hueMain.AbsolutePosition.X) / X, 0, 0.995)
				option:SetColor(Color3.fromHSV(1 - X, sat, val))
			end
		end)

		hueMain.InputEnded:connect(function(Input)
			if Input.UserInputType.Name == "MouseButton1" then
				editinghue = false
			end
		end)

		local satval = library:Create("ImageLabel", {
			ZIndex = 4,
			Position = UDim2.new(0, 6, 0, 6),
			Size = UDim2.new(1, option.trans and -28 or -12, 1, -74),
			BackgroundColor3 = Color3.fromHSV(hue, 1, 1),
			BorderColor3 = Color3.new(),
			Image = "rbxassetid://4155801252",
			ClipsDescendants = true,
			Parent = option.mainHolder
		})

		local satvalSlider = library:Create("Frame", {
			ZIndex = 4,
			AnchorPoint = Vector2.new(0.5, 0.5),
			Position = UDim2.new(sat, 0, 1 - val, 0),
			Size = UDim2.new(0, 4, 0, 4),
			Rotation = 45,
			BackgroundColor3 = Color3.fromRGB(255, 255, 255),
			Parent = satval
		})

		satval.InputBegan:connect(function(Input)
			if Input.UserInputType.Name == "MouseButton1" then
				editingsatval = true
				X = (satval.AbsolutePosition.X + satval.AbsoluteSize.X) - satval.AbsolutePosition.X
				Y = (satval.AbsolutePosition.Y + satval.AbsoluteSize.Y) - satval.AbsolutePosition.Y
				X = math.clamp((Input.Position.X - satval.AbsolutePosition.X) / X, 0.005, 1)
				Y = math.clamp((Input.Position.Y - satval.AbsolutePosition.Y) / Y, 0, 0.995)
				option:SetColor(Color3.fromHSV(hue, X, 1 - Y))
			end
		end)

		library:AddConnection(inputService.InputChanged, function(Input)
			if Input.UserInputType.Name == "MouseMovement" then
				if editingsatval then
					X = (satval.AbsolutePosition.X + satval.AbsoluteSize.X) - satval.AbsolutePosition.X
					Y = (satval.AbsolutePosition.Y + satval.AbsoluteSize.Y) - satval.AbsolutePosition.Y
					X = math.clamp((Input.Position.X - satval.AbsolutePosition.X) / X, 0.005, 1)
					Y = math.clamp((Input.Position.Y - satval.AbsolutePosition.Y) / Y, 0, 0.995)
					option:SetColor(Color3.fromHSV(hue, X, 1 - Y))
				elseif editinghue then
					X = (hueMain.AbsolutePosition.X + hueMain.AbsoluteSize.X) - hueMain.AbsolutePosition.X
					X = math.clamp((Input.Position.X - hueMain.AbsolutePosition.X) / X, 0, 0.995)
					option:SetColor(Color3.fromHSV(1 - X, sat, val))
				elseif editingtrans then
					option:SetTrans(1 - ((Input.Position.Y - transMain.AbsolutePosition.Y) / transMain.AbsoluteSize.Y))
				end
			end
		end)

		satval.InputEnded:connect(function(Input)
			if Input.UserInputType.Name == "MouseButton1" then
				editingsatval = false
			end
		end)

		local r, g, b = library.round(option.color)
		option.hexInput.Text = string.format("#%02x%02x%02x", r, g, b)
		option.rgbInput.Text = table.concat({r, g, b}, ",")

		option.rgbInput.FocusLost:connect(function()
			local r, g, b = option.rgbInput.Text:gsub("%s+", ""):match("(%d+),(%d+),(%d+)")
			if r and g and b then
				local color = Color3.fromRGB(tonumber(r), tonumber(g), tonumber(b))
				return option:SetColor(color)
			end

			local r, g, b = library.round(option.color)
			option.rgbInput.Text = table.concat({r, g, b}, ", ")
		end)

		option.hexInput.FocusLost:connect(function()
			local r, g, b = option.hexInput.Text:match("#?(..)(..)(..)")
			if r and g and b then
				local color = Color3.fromRGB(tonumber("0x"..r), tonumber("0x"..g), tonumber("0x"..b))
				return option:SetColor(color)
			end

			local r, g, b = library.round(option.color)
			option.hexInput.Text = string.format("#%02x%02x%02x", r, g, b)
		end)

		function option:updateVisuals(Color)
			hue, sat, val = Color3.toHSV(Color)
			-- hue = hue == 0 and 1 or hue

			satval.BackgroundColor3 = Color3.fromHSV(hue, 1, 1)
			if option.trans then
				transMain.ImageColor3 = Color3.fromHSV(hue, 1, 1)
			end
			hueSlider.Position = UDim2.new(1 - hue, 0, 0, 0)
			satvalSlider.Position = UDim2.new(sat, 0, 1 - val, 0)

			local r, g, b = library.round(Color3.fromHSV(hue, sat, val))

			option.hexInput.Text = string.format("#%02x%02x%02x", r, g, b)
			option.rgbInput.Text = table.concat({r, g, b}, ", ")
		end

		return option
	end

	local function createColor(option, parent)
		option.hasInit = true

		if option.sub then
			option.main = option:getMain()
		else
			option.main = library:Create("Frame", {
				LayoutOrder = option.position,
				Size = UDim2.new(1, 0, 0, 20),
				BackgroundTransparency = 1,
				Parent = parent
			})

			option.title = library:Create("TextLabel", {
				Position = UDim2.new(0, 6, 0, 0),
				Size = UDim2.new(1, -12, 1, 0),
				BackgroundTransparency = 1,
				Text = option.text,
				TextSize = 15,
				Font = Enum.Font.Code,
				TextColor3 = Color3.fromRGB(210, 210, 210),
				TextXAlignment = Enum.TextXAlignment.Left,
				Parent = option.main
			})
		end

		option.visualize = library:Create(option.sub and "TextButton" or "Frame", {
			Position = UDim2.new(1, -(option.subpos or 0) - 24, 0, 4),
			Size = UDim2.new(0, 18, 0, 12),
			SizeConstraint = Enum.SizeConstraint.RelativeYY,
			BackgroundColor3 = option.color,
			BorderColor3 = Color3.new(),
			Parent = option.main
		})

		library:Create("ImageLabel", {
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			Image = "rbxassetid://2454009026",
			ImageColor3 = Color3.new(),
			ImageTransparency = 0.6,
			Parent = option.visualize
		})

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, 0, 1, 0),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.fromRGB(60, 60, 60),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.visualize
		-- })

		-- library:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, -2, 1, -2),
		-- 	Position = UDim2.new(0, 1, 0, 1),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.new(),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = option.visualize
		-- })

		local interest = option.sub and option.visualize or option.main

		if option.sub then
			option.visualize.Text = ""
			option.visualize.AutoButtonColor = false
		end

		interest.InputBegan:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				if not option.mainHolder then createColorPickerWindow(option) end
				if library.popup == option then library.popup:Close() return end
				if library.popup then library.popup:Close() end
				option.open = true
				local pos = option.main.AbsolutePosition
				option.mainHolder.Position = UDim2.new(0, pos.X + 36 + (option.trans and -16 or 0), 0, pos.Y + 56)
				option.mainHolder.Visible = true
				library.popup = option
				option.visualize.BorderColor3 = library.flags["Menu Accent Color"]
			end
			if input.UserInputType.Name == "MouseMovement" then
				if not library.warning and not library.slider then
					option.visualize.BorderColor3 = library.flags["Menu Accent Color"]
				end
				if option.tip then
					library.tooltip.Text = option.tip
					library.tooltip.Size = UDim2.new(0, textService:GetTextSize(option.tip, 15, Enum.Font.Code, Vector2.new(9e9, 9e9)).X, 0, 20)
				end
			end
		end)

		interest.InputChanged:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if option.tip then
					library.tooltip.Position = UDim2.new(0, input.Position.X + 26, 0, input.Position.Y + 36)
				end
			end
		end)

		interest.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseMovement" then
				if not option.open then
					option.visualize.BorderColor3 = Color3.new()
				end
				library.tooltip.Position = UDim2.new(2)
			end
		end)

		function option:SetColor(newColor, nocallback)
			if typeof(newColor) == "table" then
				newColor = Color3.new(newColor[1], newColor[2], newColor[3])
			end
			newColor = newColor or Color3.new(1, 1, 1)
			if self.mainHolder then
				self:updateVisuals(newColor)
			end
			option.visualize.BackgroundColor3 = newColor
			library.flags[self.flag] = newColor
			self.color = newColor
			if not nocallback then
				self.callback(newColor)
			end
		end

		if option.trans then
			function option:SetTrans(value, manual)
				value = math.clamp(tonumber(value) or 0, 0, 1)
				if self.transSlider then
					self.transSlider.Position = UDim2.new(0, 0, value, 0)
				end
				self.trans = value
				library.flags[self.flag .. " Transparency"] = 1 - value
				self.calltrans(value)
			end
			option:SetTrans(option.trans)
		end

		delay(1, function()
			if library then
				option:SetColor(option.color)
			end
		end)

		function option:Close()
			library.popup = nil
			self.open = false
			self.mainHolder.Visible = false
			option.visualize.BorderColor3 = Color3.new()
		end
	end

	function library:AddTab(title, pos)
		local tab = {canInit = true, columns = {}, title = tostring(title)}
		table.insert(self.tabs, pos or #self.tabs + 1, tab)

		function tab:AddColumn()
			local column = {sections = {}, position = #self.columns, canInit = true, tab = self}
			table.insert(self.columns, column)

			function column:AddSection(title)
				local section = {title = tostring(title), options = {}, canInit = true, column = self}
				table.insert(self.sections, section)

				function section:AddLabel(text)
					local option = {text = text}
					option.section = self
					option.type = "label"
					option.position = #self.options
					option.canInit = true
					table.insert(self.options, option)

					if library.hasInit and self.hasInit then
						createLabel(option, self.content)
					else
						option.Init = createLabel
					end

					return option
				end

				function section:AddDivider(text)
					local option = {text = text}
					option.section = self
					option.type = "divider"
					option.position = #self.options
					option.canInit = true
					table.insert(self.options, option)

					if library.hasInit and self.hasInit then
						createDivider(option, self.content)
					else
						option.Init = createDivider
					end

					return option
				end

				function section:AddToggle(option)
					option = typeof(option) == "table" and option or {}
					option.section = self
					option.text = tostring(option.text)
					option.state = typeof(option.state) == "boolean" and option.state or false
					option.callback = typeof(option.callback) == "function" and option.callback or function() end
					option.type = "toggle"
					option.position = #self.options
					option.flag = (library.flagprefix and library.flagprefix .. " " or "") .. (option.flag or option.text)
					option.subcount = 0
					option.canInit = (option.canInit ~= nil and option.canInit) or true
					option.tip = option.tip and tostring(option.tip)
					option.style = option.style == 2
					library.flags[option.flag] = option.state
					table.insert(self.options, option)
					library.options[option.flag] = option

					function option:AddColor(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddColor(subOption)
					end

					function option:AddBox(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddBox(subOption)
					end

					function option:AddBind(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddBind(subOption)
					end

					function option:AddList(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddList(subOption)
					end

					function option:AddSlider(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddSlider(subOption)
					end

					if library.hasInit and self.hasInit then
						createToggle(option, self.content)
					else
						option.Init = createToggle
					end

					return option
				end

				function section:AddButton(option)
					option = typeof(option) == "table" and option or {}
					option.section = self
					option.text = tostring(option.text)
					option.short = typeof(option.short) == "boolean" and option.short or false
					option.callback = typeof(option.callback) == "function" and option.callback or function() end
					option.type = "button"
					option.position = #self.options
					option.flag = (library.flagprefix and library.flagprefix .. " " or "") .. (option.flag or option.text)
					option.subcount = 0
					option.canInit = (option.canInit ~= nil and option.canInit) or true
					option.tip = option.tip and tostring(option.tip);
					option.textSize = (type(option.textSize) == 'number' and option.textSize or 15);
					table.insert(self.options, option)
					library.options[option.flag] = option

					function option:AddBind(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() option.main.Size = UDim2.new(1, 0, 0, 40) return option.main end
						self.subcount = self.subcount + 1
						return section:AddBind(subOption)
					end

					function option:AddColor(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() option.main.Size = UDim2.new(1, 0, 0, 40) return option.main end
						self.subcount = self.subcount + 1
						return section:AddColor(subOption)
					end

					function option:AddButton(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						
						function subOption:getMain() 
							option.title.Position = UDim2.new(0, 6, 0.5, -8)
							option.title.Size = UDim2.new(0.5, -6, 1, -8)

							return option.main 
						end

						self.subcount = self.subcount + 1
						return section:AddButton(subOption)
					end

					if library.hasInit and self.hasInit then
						createButton(option, self.content)
					else
						option.Init = createButton
					end

					return option
				end

				function section:AddBind(option)
					option = typeof(option) == "table" and option or {}
					option.section = self
					option.text = tostring(option.text)
					option.key = (option.key and option.key.Name) or option.key or "none"
					option.nomouse = typeof(option.nomouse) == "boolean" and option.nomouse or false
					option.mode = typeof(option.mode) == "string" and (option.mode == "toggle" or option.mode == "hold" and option.mode) or "toggle"
					option.callback = typeof(option.callback) == "function" and option.callback or function() end
					option.type = "bind"
					option.position = #self.options
					option.flag = (library.flagprefix and library.flagprefix .. " " or "") .. (option.flag or option.text)
					option.canInit = (option.canInit ~= nil and option.canInit) or true
					option.tip = option.tip and tostring(option.tip)
					table.insert(self.options, option)
					library.options[option.flag] = option

					if library.hasInit and self.hasInit then
						createBind(option, self.content)
					else
						option.Init = createBind
					end

					return option
				end

				function section:AddSlider(option)
					option = typeof(option) == "table" and option or {}
					option.section = self
					option.text = tostring(option.text)
					option.min = typeof(option.min) == "number" and option.min or 0
					option.max = typeof(option.max) == "number" and option.max or 0
					option.value = option.min < 0 and 0 or math.clamp(typeof(option.value) == "number" and option.value or option.min, option.min, option.max)
					option.callback = typeof(option.callback) == "function" and option.callback or function() end
					option.float = typeof(option.value) == "number" and option.float or 1
					option.suffix = option.suffix and tostring(option.suffix) or ""
					option.textpos = option.textpos == 2
					option.type = "slider"
					option.position = #self.options
					option.flag = (library.flagprefix and library.flagprefix .. " " or "") .. (option.flag or option.text)
					option.subcount = 0
					option.canInit = (option.canInit ~= nil and option.canInit) or true
					option.tip = option.tip and tostring(option.tip)
					library.flags[option.flag] = option.value
					table.insert(self.options, option)
					library.options[option.flag] = option

					function option:AddColor(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddColor(subOption)
					end

					function option:AddBind(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddBind(subOption)
					end

					if library.hasInit and self.hasInit then
						createSlider(option, self.content)
					else
						option.Init = createSlider
					end

					return option
				end

				function section:AddList(option)
					option = typeof(option) == "table" and option or {}
					option.section = self
					option.text = tostring(option.text)
					option.values = typeof(option.values) == "table" and option.values or {}
					option.callback = typeof(option.callback) == "function" and option.callback or function() end
					option.multiselect = typeof(option.multiselect) == "boolean" and option.multiselect or false
					--option.groupbox = (not option.multiselect) and (typeof(option.groupbox) == "boolean" and option.groupbox or false)
					option.value = option.multiselect and (typeof(option.value) == "table" and option.value or {}) or tostring(option.value or option.values[1] or "")
					if option.multiselect then
						for i,v in next, option.values do
							option.value[v] = false
						end
					end
					option.max = option.max or 4
					option.open = false
					option.type = "list"
					option.position = #self.options
					option.labels = {}
					option.flag = (library.flagprefix and library.flagprefix .. " " or "") .. (option.flag or option.text)
					option.subcount = 0
					option.canInit = (option.canInit ~= nil and option.canInit) or true
					option.tip = option.tip and tostring(option.tip)
					library.flags[option.flag] = option.value
					table.insert(self.options, option)
					library.options[option.flag] = option

					function option:AddValue(value, state)
						if self.multiselect then
							self.values[value] = state
						else
							table.insert(self.values, value)
						end
					end

					function option:AddColor(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddColor(subOption)
					end

					function option:AddBind(subOption)	
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddBind(subOption)
					end

					if library.hasInit and self.hasInit then
						createList(option, self.content)
					else
						option.Init = createList
					end

					return option
				end

				function section:AddBox(option)
					option = typeof(option) == "table" and option or {}
					option.section = self
					option.text = option.text and tostring(option.text) or '';
					option.value = option.value and tostring(option.value) or ""
					option.callback = typeof(option.callback) == "function" and option.callback or function() end
					option.type = "box"
					option.textpos = (option.textpos == 2)
					option.position = #self.options
					option.flag = (library.flagprefix and library.flagprefix .. " " or "") .. (option.flag or option.text)
					option.canInit = (option.canInit ~= nil and option.canInit) or true
					option.tip = option.tip and tostring(option.tip)
					library.flags[option.flag] = option.value
					table.insert(self.options, option)
					library.options[option.flag] = option

					if library.hasInit and self.hasInit then
						createBox(option, self.content)
					else
						option.Init = createBox
					end

					return option
				end

				function section:AddColor(option)
					option = typeof(option) == "table" and option or {}
					option.section = self
					option.text = tostring(option.text)
					option.color = typeof(option.color) == "table" and Color3.new(option.color[1], option.color[2], option.color[3]) or option.color or Color3.new(1, 1, 1)
					option.callback = typeof(option.callback) == "function" and option.callback or function() end
					option.calltrans = typeof(option.calltrans) == "function" and option.calltrans or (option.calltrans == 1 and option.callback) or function() end
					option.open = false
					option.trans = tonumber(option.trans)
					option.subcount = 1
					option.type = "color"
					option.position = #self.options
					option.flag = (library.flagprefix and library.flagprefix .. " " or "") .. (option.flag or option.text)
					option.canInit = (option.canInit ~= nil and option.canInit) or true
					option.tip = option.tip and tostring(option.tip)
					library.flags[option.flag] = option.color
					table.insert(self.options, option)
					library.options[option.flag] = option

					function option:AddColor(subOption)
						subOption = typeof(subOption) == "table" and subOption or {}
						subOption.sub = true
						subOption.subpos = self.subcount * 24
						function subOption:getMain() return option.main end
						self.subcount = self.subcount + 1
						return section:AddColor(subOption)
					end

					if option.trans then
						library.flags[option.flag .. " Transparency"] = option.trans
					end

					if library.hasInit and self.hasInit then
						createColor(option, self.content)
					else
						option.Init = createColor
					end

					return option
				end

				function section:SetTitle(newTitle)
					self.title = tostring(newTitle)
					if self.titleText then
						self.titleText.Text = tostring(newTitle)
					end
				end

				function section:Init()
					if self.hasInit then return end
					self.hasInit = true

					self.main = library:Create("Frame", {
						BackgroundColor3 = Color3.fromRGB(30, 30, 30),
						BorderColor3 = Color3.new(),
						Parent = column.main
					})

					self.content = library:Create("Frame", {
						Size = UDim2.new(1, 0, 1, 0),
						BackgroundColor3 = Color3.fromRGB(30, 30, 30),
						BorderColor3 = Color3.fromRGB(60, 60, 60),
						BorderMode = Enum.BorderMode.Inset,
						Parent = self.main
					})

					-- library:Create("ImageLabel", {
					-- 	Size = UDim2.new(1, -2, 1, -2),
					-- 	Position = UDim2.new(0, 1, 0, 1),
					-- 	BackgroundTransparency = 1,
					-- 	Image = "rbxassetid://2592362371",
					-- 	ImageColor3 = Color3.new(),
					-- 	ScaleType = Enum.ScaleType.Slice,
					-- 	SliceCenter = Rect.new(2, 2, 62, 62),
					-- 	Parent = self.main
					-- })

					table.insert(library.theme, library:Create("Frame", {
						Size = UDim2.new(1, 0, 0, 1),
						BackgroundColor3 = library.flags["Menu Accent Color"],
						BorderSizePixel = 0,
						BorderMode = Enum.BorderMode.Inset,
						Parent = self.main
					}))

					local layout = library:Create("UIListLayout", {
						HorizontalAlignment = Enum.HorizontalAlignment.Center,
						SortOrder = Enum.SortOrder.LayoutOrder,
						Padding = UDim.new(0, 2),
						Parent = self.content
					})

					library:Create("UIPadding", {
						PaddingTop = UDim.new(0, 12),
						Parent = self.content
					})

					self.titleText = library:Create("TextLabel", {
						AnchorPoint = Vector2.new(0, 0.5),
						Position = UDim2.new(0, 12, 0, 0),
						Size = UDim2.new(0, textService:GetTextSize(self.title, 15, Enum.Font.Code, Vector2.new(9e9, 9e9)).X + 10, 0, 3),
						BackgroundColor3 = Color3.fromRGB(30, 30, 30),
						BorderSizePixel = 0,
						Text = self.title,
						TextSize = 15,
						Font = Enum.Font.Code,
						TextColor3 = Color3.new(1, 1, 1),
						Parent = self.main
					})

					layout.Changed:connect(function()
						self.main.Size = UDim2.new(1, 0, 0, layout.AbsoluteContentSize.Y + 16)
					end)

					for _, option in next, self.options do
						if option.canInit then
							option.Init(option, self.content)
						end
					end
				end

				if library.hasInit and self.hasInit then
					section:Init()
				end

				return section
			end

			function column:Init()
				if self.hasInit then return end
				self.hasInit = true

				self.main = library:Create("ScrollingFrame", {
					ZIndex = 2,
					Position = UDim2.new(0, 6 + (self.position * 239), 0, 2),
					Size = UDim2.new(0, 233, 1, -4),
					BackgroundTransparency = 1,
					BorderSizePixel = 0,
					ScrollBarImageColor3 = Color3.fromRGB(),
					ScrollBarThickness = 4,	
					VerticalScrollBarInset = Enum.ScrollBarInset.ScrollBar,
					ScrollingDirection = Enum.ScrollingDirection.Y,
					Visible = false,
					Parent = library.columnHolder
				})

				local layout = library:Create("UIListLayout", {
					HorizontalAlignment = Enum.HorizontalAlignment.Center,
					SortOrder = Enum.SortOrder.LayoutOrder,
					Padding = UDim.new(0, 12),
					Parent = self.main
				})

				library:Create("UIPadding", {
					PaddingTop = UDim.new(0, 8),
					PaddingLeft = UDim.new(0, 2),
					PaddingRight = UDim.new(0, 2),
					Parent = self.main
				})

				layout.Changed:connect(function()
					self.main.CanvasSize = UDim2.new(0, 0, 0, layout.AbsoluteContentSize.Y + 14)
				end)

				for _, section in next, self.sections do
					if section.canInit and #section.options > 0 then
						section:Init()
					end
				end
			end

			if library.hasInit and self.hasInit then
				column:Init()
			end

			return column
		end

		function tab:Init()
			if self.hasInit then return end
			self.hasInit = true
			local size = textService:GetTextSize(self.title, 18, Enum.Font.Code, Vector2.new(9e9, 9e9)).X + 10

			self.button = library:Create("TextLabel", {
				Position = UDim2.new(0, library.tabSize, 0, 22),
				Size = UDim2.new(0, size, 0, 30),
				BackgroundTransparency = 1,
				Text = self.title,
				TextColor3 = Color3.new(1, 1, 1),
				TextSize = 15,
				Font = Enum.Font.Code,
				TextWrapped = true,
				ClipsDescendants = true,
				Parent = library.main
			})
			library.tabSize = library.tabSize + size

			self.button.InputBegan:connect(function(input)
				if input.UserInputType.Name == "MouseButton1" then
					library:selectTab(self)
				end
			end)

			for _, column in next, self.columns do
				if column.canInit then
					column:Init()
				end
			end
		end

		if self.hasInit then
			tab:Init()
		end

		return tab
	end

	function library:AddWarning(warning)
		warning = typeof(warning) == "table" and warning or {}
		warning.text = tostring(warning.text) 
		warning.type = warning.type == "confirm" and "confirm" or ""

		local answerSelected = utilities.Signal.new();

		function warning:Show()
			library.warning = warning

			local answer = nil
			-- what the fuck is this even used for?
			-- if warning.main and warning.type == "" then print'failed check 1'; return end
			if library.popup then library.popup:Close() end

			if not warning.main then
				warning.main = library:Create("TextButton", {
					ZIndex = 2,
					Size = UDim2.new(1, 0, 1, 0),
					BackgroundTransparency = 0.2,
					BackgroundColor3 = Color3.new(),
					BorderSizePixel = 0,
					Text = "",
					AutoButtonColor = false,
					Parent = library.main
				})

				warning.message = library:Create("TextLabel", {
					ZIndex = 2,
					Position = UDim2.new(0, 20, 0.5, -60),
					Size = UDim2.new(1, -40, 0, 40),
					BackgroundTransparency = 1,
					TextSize = 16,
					Font = Enum.Font.Code,
					TextColor3 = Color3.new(1, 1, 1),
					TextWrapped = true,
					RichText = true,
					Parent = warning.main
				})

				if warning.type == "confirm" then
					local button = library:Create("TextLabel", {
						ZIndex = 2,
						Position = UDim2.new(0.5, -105, 0.5, -10),
						Size = UDim2.new(0, 100, 0, 20),
						BackgroundColor3 = Color3.fromRGB(40, 40, 40),
						BorderColor3 = Color3.new(),
						Text = "Yes",
						TextSize = 16,
						Font = Enum.Font.Code,
						TextColor3 = Color3.new(1, 1, 1),
						Parent = warning.main
					})

					library:Create("ImageLabel", {
						ZIndex = 2,
						Size = UDim2.new(1, 0, 1, 0),
						BackgroundTransparency = 1,
						Image = "rbxassetid://2454009026",
						ImageColor3 = Color3.new(),
						ImageTransparency = 0.8,
						Parent = button
					})

					library:Create("ImageLabel", {
						ZIndex = 2,
						Size = UDim2.new(1, 0, 1, 0),
						BackgroundTransparency = 1,
						Image = "rbxassetid://2592362371",
						ImageColor3 = Color3.fromRGB(60, 60, 60),
						ScaleType = Enum.ScaleType.Slice,
						SliceCenter = Rect.new(2, 2, 62, 62),
						Parent = button
					})

					local button1 = library:Create("TextLabel", {
						ZIndex = 2,
						Position = UDim2.new(0.5, 5, 0.5, -10),
						Size = UDim2.new(0, 100, 0, 20),
						BackgroundColor3 = Color3.fromRGB(40, 40, 40),
						BorderColor3 = Color3.new(),
						Text = "No",
						TextSize = 16,
						Font = Enum.Font.Code,
						TextColor3 = Color3.new(1, 1, 1),
						Parent = warning.main
					})

					library:Create("ImageLabel", {
						ZIndex = 2,
						Size = UDim2.new(1, 0, 1, 0),
						BackgroundTransparency = 1,
						Image = "rbxassetid://2454009026",
						ImageColor3 = Color3.new(),
						ImageTransparency = 0.8,
						Parent = button1
					})

					library:Create("ImageLabel", {
						ZIndex = 2,
						Size = UDim2.new(1, 0, 1, 0),
						BackgroundTransparency = 1,
						Image = "rbxassetid://2592362371",
						ImageColor3 = Color3.fromRGB(60, 60, 60),
						ScaleType = Enum.ScaleType.Slice,
						SliceCenter = Rect.new(2, 2, 62, 62),
						Parent = button1
					})

					button.InputBegan:connect(function(input)
						if input.UserInputType.Name == "MouseButton1" then
							answerSelected:Fire(true)
						end
					end)

					button1.InputBegan:connect(function(input)
						if input.UserInputType.Name == "MouseButton1" then
							answerSelected:Fire(false)
						end
					end)
				else
					local button = library:Create("TextLabel", {
						ZIndex = 2,
						Position = UDim2.new(0.5, -50, 0.5, -10),
						Size = UDim2.new(0, 100, 0, 20),
						BackgroundColor3 = Color3.fromRGB(40, 40, 40),
						BorderColor3 = Color3.new(),
						Text = "Ok",
						TextSize = 16,
						Font = Enum.Font.Code,
						TextColor3 = Color3.new(1, 1, 1),
						Parent = warning.main
					})

					library:Create("ImageLabel", {
						ZIndex = 2,
						Size = UDim2.new(1, 0, 1, 0),
						BackgroundTransparency = 1,
						Image = "rbxassetid://2454009026",
						ImageColor3 = Color3.new(),
						ImageTransparency = 0.8,
						Parent = button
					})

					library:Create("ImageLabel", {
						ZIndex = 2,
						Size = UDim2.new(1, 0, 1, 0),
						BackgroundTransparency = 1,
						Image = "rbxassetid://2592362371",
						ImageColor3 = Color3.fromRGB(60, 60, 60),
						ScaleType = Enum.ScaleType.Slice,
						SliceCenter = Rect.new(2, 2, 62, 62),
						Parent = button
					})

					button.InputBegan:connect(function(input)
						if input.UserInputType.Name == "MouseButton1" then
							answerSelected:Fire(true)
						end
					end)
				end
			end

			warning.main.Visible = true
			warning.message.Text = warning.text

			local answer = answerSelected:wait()
			library.warning = nil
			warning:Close()

			return answer
		end

		function warning:Close()
			if not warning.main then return end
			warning.main.Visible = false
		end

		return warning
	end

	function library:Close()
		self.open = not self.open

		self._mutex = true
		if self.open then
			inputService.MouseIconEnabled = false
		else
			inputService.MouseIconEnabled = self.mousestate
		end
		self._mutex = true

		if self.main then
			if self.popup then
				self.popup:Close()
			end
			self.main.Visible = self.open
			self.cursor.Visible  = self.open
			self.cursor1.Visible  = self.open
		end
	end

	function library:Init(gameTitle)
		if self.hasInit then return end
		self.hasInit = true

		self.base = library:Create("ScreenGui", { Name = 'ok', IgnoreGuiInset = true })
		if runService:IsStudio() then
			self.base.Parent = script.Parent.Parent
		elseif syn then
			syn.protect_gui(self.base)
			self.base.Parent = game:GetService"CoreGui"
		end

		self.main = self:Create("ImageButton", {
			AutoButtonColor = false,
			Position = UDim2.new(0, 100, 0, 46),
			Size = UDim2.new(0, 500, 0, 600),
			BackgroundColor3 = Color3.fromRGB(20, 20, 20),
			BorderColor3 = Color3.new(),
			ScaleType = Enum.ScaleType.Tile,
			Modal = true,
			Visible = false,
			Parent = self.base
		})

		local top = self:Create("Frame", {
			Size = UDim2.new(1, 0, 0, 50),
			BackgroundColor3 = Color3.fromRGB(30, 30, 30),
			BorderColor3 = Color3.new(),
			Parent = self.main
		})

		self:Create("TextLabel", {
			Position = UDim2.new(0, 6, 0, 1),
			Size = UDim2.new(0, 0, 0, 20),
			BackgroundTransparency = 1,
			Text = tostring(self.title),
			Font = Enum.Font.Code,
			TextSize = 18,
			TextColor3 = Color3.new(1, 1, 1),
			TextXAlignment = Enum.TextXAlignment.Left,
			Parent = self.main
		})

		table.insert(library.theme, self:Create("Frame", {
			Size = UDim2.new(1, 0, 0, 1),
			Position = UDim2.new(0, 0, 0, 24),
			BackgroundColor3 = library.flags["Menu Accent Color"],
			BorderSizePixel = 0,
			Parent = self.main
		}))

		library:Create("ImageLabel", {
			Size = UDim2.new(1, 0, 1, 0),
			BackgroundTransparency = 1,
			Image = "rbxassetid://2454009026",
			ImageColor3 = Color3.new(),
			ImageTransparency = 0.4,
			Parent = top
		})

		self.tabHighlight = self:Create("Frame", {
			BackgroundColor3 = library.flags["Menu Accent Color"],
			BorderSizePixel = 0,
			Parent = self.main
		})
		table.insert(library.theme, self.tabHighlight)

		self.columnHolder = self:Create("Frame", {
			Position = UDim2.new(0, 5, 0, 55),
			Size = UDim2.new(1, -10, 1, -60),
			BackgroundTransparency = 1,
			Parent = self.main
		})

		self.cursor = self:Create("Triangle", {
			Color = Color3.fromRGB(180, 180, 180),
			Transparency = 0.6,
		})
		self.cursor1 = self:Create("Triangle", {
			Color = Color3.fromRGB(240, 240, 240),
			Transparency = 0.6,
		})

		self.tooltip = self:Create("TextLabel", {
			ZIndex = 2,
			Text = '';
			BackgroundTransparency = 1,
			BorderSizePixel = 0,
			TextSize = 15,
			Font = Enum.Font.Code,
			TextColor3 = Color3.new(1, 1, 1),
			Visible = true,
			Parent = self.base
		})

		self:Create("Frame", {
			AnchorPoint = Vector2.new(0.5, 0),
			Position = UDim2.new(0.5, 0, 0, 0),
			Size = UDim2.new(1, 10, 1, 0),
			Style = Enum.FrameStyle.RobloxRound,
			Parent = self.tooltip
		})

		-- self:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, 0, 1, 0),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.fromRGB(60, 60, 60),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = self.main
		-- })

		-- self:Create("ImageLabel", {
		-- 	Size = UDim2.new(1, -2, 1, -2),
		-- 	Position = UDim2.new(0, 1, 0, 1),
		-- 	BackgroundTransparency = 1,
		-- 	Image = "rbxassetid://2592362371",
		-- 	ImageColor3 = Color3.new(),
		-- 	ScaleType = Enum.ScaleType.Slice,
		-- 	SliceCenter = Rect.new(2, 2, 62, 62),
		-- 	Parent = self.main
		-- })

		top.InputBegan:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				dragObject = self.main
				dragging = true
				dragStart = input.Position
				startPos = dragObject.Position
				if library.popup then library.popup:Close() end
			end
		end)
		top.InputChanged:connect(function(input)
			if dragging and input.UserInputType.Name == "MouseMovement" then
				dragInput = input
			end
		end)
		top.InputEnded:connect(function(input)
			if input.UserInputType.Name == "MouseButton1" then
				dragging = false
			end
		end)

		function self:selectTab(tab)
			if self.currentTab == tab then return end
			if library.popup then library.popup:Close() end
			if self.currentTab then
				self.currentTab.button.TextColor3 = Color3.fromRGB(255, 255, 255)
				for _, column in next, self.currentTab.columns do
					column.main.Visible = false
				end
			end
			self.main.Size = UDim2.new(0, 16 + ((#tab.columns < 2 and 2 or #tab.columns) * 239), 0, 600)
			self.currentTab = tab
			tab.button.TextColor3 = library.flags["Menu Accent Color"]
			self.tabHighlight:TweenPosition(UDim2.new(0, tab.button.Position.X.Offset, 0, 50), "Out", "Quad", 0.2, true)
			self.tabHighlight:TweenSize(UDim2.new(0, tab.button.AbsoluteSize.X, 0, -1), "Out", "Quad", 0.1, true)
			for _, column in next, tab.columns do
				column.main.Visible = true
			end
		end

		

		for _, tab in next, self.tabs do
			if tab.canInit then
				tab:Init()
			end
		end

		self:selectTab(self.tabs[1])

		self:AddConnection(inputService.InputEnded, function(input)
			if input.UserInputType.Name == "MouseButton1" and self.slider then
				self.slider.slider.BorderColor3 = Color3.new()
				self.slider = nil
			end
		end)

		self:AddConnection(inputService.InputChanged, function(input)
			if self.open then
				if input.UserInputType.Name == "MouseMovement" then
					if self.cursor then
						local mouse = inputService:GetMouseLocation()
						local MousePos = Vector2.new(mouse.X, mouse.Y)
						self.cursor.PointA = MousePos
						self.cursor.PointB = MousePos + Vector2.new(12, 12)
						self.cursor.PointC = MousePos + Vector2.new(12, 12)
						self.cursor1.PointA = MousePos
						self.cursor1.PointB = MousePos + Vector2.new(11, 11)
						self.cursor1.PointC = MousePos + Vector2.new(11, 11)
					end
					if self.slider then
						self.slider:SetValue(self.slider.min + ((input.Position.X - self.slider.slider.AbsolutePosition.X) / self.slider.slider.AbsoluteSize.X) * (self.slider.max - self.slider.min))
					end
				end
				if input == dragInput and dragging and library.draggable then
					local delta = input.Position - dragStart
					local yPos = (startPos.Y.Offset + delta.Y) < -36 and -36 or startPos.Y.Offset + delta.Y
					dragObject:TweenPosition(UDim2.new(startPos.X.Scale, startPos.X.Offset + delta.X, startPos.Y.Scale, yPos), "Out", "Quint", 0.1, true)
				end
			end
		end)

		if not getgenv().silent then
			delay(1, function() self:Close() end)
		end

		library.OnLoaded:Fire(gameTitle)
		library._loaded = true;
	end

	local settings = library:AddTab("UI Settings", 100) do
		local column = settings:AddColumn() 
		
		local section = column:AddSection('Menu') do
			section:AddBind({text = 'UI Toggle', flag = 'UI Toggle', nomouse = true, key = 'End', callback = function() library:Close() end})
			section:AddColor({text = 'Menu Color', flag = 'Menu Accent Color', color = Color3.fromRGB(18, 127, 253), callback = function(Color)
				if library.currentTab then
					library.currentTab.button.TextColor3 = Color
				end
				for _, obj in next, library.theme do
					obj[(obj.ClassName == "TextLabel" and "TextColor3") or (obj.ClassName == "ImageLabel" and "ImageColor3") or "BackgroundColor3"] = Color
				end
			end})

			section:AddToggle({text = 'Anti AFK', flag = 'Anti AFK', state = true, callback = function(state)
				for _, connection in next, getconnections(client.Idled) do
					connection[state and 'Disable' or 'Enable'](state)
				end
			end})

			section:AddDivider('Background')

			local Backgrounds = {
				["Floral"] = 5553946656,
				["Flowers"] = 6071575925,
				["Circles"] = 6071579801,
				["Hearts"] = 6073763717
			}

			local original = Color3.new(20, 20, 20)
			section:AddColor({text = 'Background color', flag = "Menu Background Color", color = Color3.new(), callback = function(Color)
				library.main.ImageColor3	 = Color

				if library.flags['UI Background'] == 'None' then
					library.main.BackgroundColor3 = library.flags['Menu Background Color']
				else
					library.main.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
				end
			end, trans = 1, calltrans = function(Value)
				library.main.ImageTransparency = 1 - Value
			end})

			section:AddList({tip = 'Background image for the menu.', flag = 'UI Background', tip = 'UI Background', values = {"Floral", "Flowers", "Circles", "Hearts", 'None'}, callback = function(Value)
				if Backgrounds[Value] then
					library.main.Image = "rbxassetid://" .. Backgrounds[Value]
					library.main.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
				elseif Value == 'None' then
					library.main.Image = '';
					library.main.BackgroundColor3 = library.flags['Menu Background Color']
				end
			end})

			section:AddSlider({text = "Tile Size", textpos = 2, value = 250, min = 50, max = 500, callback = function(Value)
				library.main.TileSize = UDim2.new(0, Value, 0, Value)
			end})
		end

		local section = column:AddSection('Test') do 

		end

		local section = column:AddSection('Misc') do
			section:AddLabel('Invite updated: 1/7/21')

			-- http://127.0.0.1:6463/rpc?v=1
			local discord_url = decrypt("zE6JBokyhKM1HJg++EEKus7wwi9FXt9kSURyacHXYVc=", "wXqoOH37THTDuSPE", "ySN4ozUfGhm0SCli") 

			-- INVITE_BROWSER
			local discord_evt = decrypt("zjEM+SkjIa8bkuZevmemrQ==", "wXqoOH37THTDuSPE", "ySN4ozUfGhm0SCli")
			local discord_code = (fflags['discord-invite']):gsub('https?://discord%.gg/', '');

			local warning = library:AddWarning()
			local discordColor = Color3.fromRGB(114, 137, 218)
			section:AddButton({text = 'Copy invite', callback = function()
				N.success({
					title = 'wally\'s hub', 
					text = 'Copied discord invite to your clipboard!'
				})
				setclipboard(fflags['discord-invite'])
			end}):AddButton({text = 'Join server', callback = function()
				local response = http_request({
					Url = discord_url,
					Method = 'POST';
					Headers = {
						['Content-Type'] = 'application/json',
						Origin = 'https://discord.com',
					},
					Body = jsonEncode(httpService, {
						cmd = discord_evt,
						nonce = randomStr(32),
						args = { code = discord_code; }
					})
				})
	
				if (not response.Success) then
					return N.error({
						title = 'wally\'s hub',
						text = 'Request failed [1]';
						icon = 'sfzi'
					})
				end
	
				local s, e = pcall(jsonDecode, httpService, response.Body);
				if (not s) then
					return N.error({
						title = 'wally\'s hub',
						text = 'Request failed [2]';
						icon = 'sfzi'
					})
				end
	
				if (not e.data) or (e.evt == 'ERROR') then
					return N.error({
						title = 'wally\'s hub',
						text = 'Request failed [3]';
						icon = 'sfzi'
					})
				end
	
				return N.success({
					title = 'wally\'s hub',
					text = 'Discord client should have prompted you to join our server!',
				})
			end})

			section:AddDivider()
			section:AddButton({ text = 'Rejoin game', callback = function() 
				game:GetService('TeleportService'):Teleport(game.PlaceId)
			end })
		--	section:AddSlider({textpos = 2, text = 'FPS cap', suffix = ' fps', min = 30, max = 1000, value = 1000, callback = setfpscap})
		end

		local column = settings:AddColumn() 
		local section = column:AddSection('Configuration') do
			local warning = library:AddWarning()
			local confirm = library:AddWarning({type = 'confirm'})
			local loadConfirm = library:AddWarning({type = 'confirm'})

			local function updateWarning(text, configName)
				local r, g, b = library.round(library.flags["Menu Accent Color"])
				confirm.text = string.format(
					[[Are you sure you want to %s config <font color='rgb(%s,%s,%s)'>%s</font>?]],
					text, r, g, b, (configName or library.flags["Config List"])
				)
			end

			section:AddBox({ text = 'Config name', value = "", flag = 'Config Name', skipflag = true })
			section:AddList({ text = 'Selected config', values = library:GetConfigs(), flag = 'Config List'})
			section:AddDivider()

			section:AddButton({text = 'Create', short = true, callback = function()
				library:GetConfigs()

				if string.len(library.flags["Config Name"]) < 1 then 
					warning.text = 'Failed to create config: empty name.'
					warning:Show()
					return
				end
		
				updateWarning("create the", library.flags['Config Name'])
				if confirm:Show() then
					writefile(("%s/%s%s"):format(library.foldername, library.flags['Config Name'], library.fileext), "{}")

					library.options["Config List"]:AddValue(library.flags["Config Name"])
					library.options["Config List"]:SetValue(library.flags["Config Name"])
				end
			end})

			section:AddButton({text = 'Save', callback = function()
				updateWarning("save the current settings to")

				if confirm:Show() then
					library:SaveConfig(library.flags["Config List"])
				end
			end}):AddButton({text = 'Load', callback = function()
				updateWarning("load")

				if confirm:Show() then
					library:LoadConfig(library.flags["Config List"])
				end
			end})
			
			section:AddButton({text = 'Erase', callback = function()
				updateWarning("erase")

				if confirm:Show() then
					local Config = library.flags["Config List"]
					local fName = ("%s/%s%s"):format(library.foldername, Config, library.fileext)
					if table.find(library:GetConfigs(), Config) and isfile(fName) then
						library.options["Config List"]:RemoveValue(Config)
						delfile(fName)
					end
				end
			end})

			--section:AddDivider('Auto-load')

			local section = column:AddSection('Auto-load settings')
			local label = section:AddLabel('Selected config: none');

			local autoloadConfigs = {};
			if isfile('whautoload.dat') then
				local success, decoded = pcall(httpService.JSONDecode, httpService, readfile("whautoload.dat"))
				if success then
					autoloadConfigs = decoded;
				end
			end

			section:AddButton({text = 'Overwrite', tip = 'Sets the config you want to automatically load for this game.', callback = function()
				local r, g, b = library.round(library.flags["Menu Accent Color"])
				loadConfirm.text = string.format(
					[[Are you sure you want to auto load the config <font color='rgb(%s,%s,%s)'>"%s"</font> when you join this game?]],
					r, g, b, library.flags["Config List"]
				)

				if loadConfirm:Show() then
					label.Text = ('Selected config: ' .. library.flags["Config List"])
					autoloadConfigs[library._gameTitle] = library.flags["Config List"]
					
					writefile("whautoload.dat", httpService:JSONEncode(autoloadConfigs))
				end
			end}):AddButton({text = 'Clear', tip = 'Removes the config you set to automatically load for this game.', callback = function()	
				local r, g, b = library.round(library.flags["Menu Accent Color"])
				loadConfirm.text = string.format([[Are you sure you want to remove your autoload config for this game?]])

				if loadConfirm:Show() then
					label.Text = ('Selected config: none.')
					autoloadConfigs[library._gameTitle] = nil;

					writefile("whautoload.dat", httpService:JSONEncode(autoloadConfigs))
				end
			end})


			library.OnLoaded:connect(function(title)
				library._gameTitle = title;
				
				if autoloadConfigs[title] then
					label.Text = ('Selected config: ' .. autoloadConfigs[title])
					library:LoadConfig(autoloadConfigs[title])
				end

				fastSpawn(function()
					while library do
						local configs = library:GetConfigs();
						local optionList = library.options["Config List"]
		
						if (not optionList) then break end
		
						for i, config in next, configs do
							if (not table.find(optionList.values, config)) then
								optionList:AddValue(config)
							end
						end
		
						for _, config in next, optionList.values do
							if (not table.find(configs, config)) then
								optionList:RemoveValue(config)
							end
						end
		
						wait(1)
					end
				end)

				if (not library.options.silentAim) then
					if library.options['silentHitChance'] then
						library.options['silentHitChance'].section.main.Visible = false;
					end
				end
			end)
		end
	end

end

--[[ misc library stuff ]] do
	library.foldername = 'wh_configs'
	library.fileext = '.whc'

	-- library.SettingsMain:AddBind({text = 'UI Keybind', flag = 'UI Toggle', key = 'End', callback = function() library:Close() end})
	-- library.SettingsMenu:AddButton({text = 'Copy Discord Invite'})
	-- library.SettingsMenu:AddButton({text = 'Open Discord w/ Invite'})

	local expectedKey = hash(strReverse(scriptKey) .. strSub(strReverse(scriptId), 1, 16) .. serverStamp)
	function library.unlock(key)
		if (expectedKey ~= key) then
			return IB_CRASH(16)
		end

		if not (safeEquals(expectedKey, key)) then
			return IB_CRASH(16)
		end

		isWindowUnlocked = true;
	end
end

if game.GameId == 833209132 then
	local gc = getgc()
	for i = 1, #gc do
		local obj = gc[i]
		if type(obj) == 'function' and not is_synapse_function(obj) then
			if getinfo(obj).name == 'flagPlayer' or (islclosure(obj) and getinfo(obj).nups == 1 and table.find(getconstants(obj), 'replicateClientStateChanged')) then
				local _3dsIsASmellyPoop = {
					pingServer, client, pcall, tostring
				}

				oldFlagFunction = replaceclosure(obj, function(...)
					local p1 = (...)

					_3dsIsASmellyPoop[3](_3dsIsASmellyPoop[1], 'flagPlayer called with: ' .. _3dsIsASmellyPoop[4](p1), 'Vesteria')
					return _3dsIsASmellyPoop[2]:Kick('Panic [4]. Report in #bugs immediately.')
				end)
			end
		end
	end
end

--[[ notification library ]] do

	-- local i_new;
	-- i_new = replaceclosure(Instance.new, function(type, parent)
	-- 	local obj = i_new(type)
	-- 	if checkcaller() then
	-- 		if type == 'ScreenGui' then
	-- 			pcall(syn.protect_gui, obj)
	-- 			replaceclosure(Instance.new, i_new)
	-- 		end
	-- 	end
	-- 	obj.Parent = parent;
	-- 	return obj;
	-- end);

	wait(1)

	-- nuke it from global env
	
	getfenv().N = N;
	getgenv().N = nil;

	N.default.wait = 3;
	N.usingExploit(true);

	function N:MessageBox(title, message, options)
		local signal = utilities.Signal.new();

		local buttons = {};
		local options = options or {};
		local box;

		local selected;
		for i = #options, 1, -1 do
			local choice = options[i];

			buttons[#buttons + 1] = N.button(choice, function() 
				signal:Fire(choice) 

				if box then 
					box:hide()
				end
			end)
		end

		box = N.notify({
			title = title,
			type = 'generic',
			text = message,
			icon = 'sfzi',
			buttons = buttons,
		})

		fastSpawn(function()
			while true do
				runService.Heartbeat:wait()
				if box.dead then
					if (not selected) then
						signal:Fire('None')
					end
					break
				end
			end
		end)

		selected = signal:Wait()
		return selected;
	end
end

local envAdditions
local fastSpawn, fastDelay do
	getCleanTable(Instance);
	local instanceNew = getCleanFunction(Instance.new);

	local bindable = instanceNew('BindableEvent');
	local bindableFire = getCleanFunction(bindable.Fire);

	function fastSpawn(f, ...)
		task.spawn(f, ...)
	end

	envAdditions = {
		userInputService = userInputService;
		runService = runService;
		collectionService = collectionService;
		httpService = httpService;
		client = client;
		fastSpawn = fastSpawn;
		library = library;
		utilities = utilities
	}

	for i, v in next, envAdditions do
		getfenv()[i] = v;
	end
end

-- local colors, defaultColor, runIntroSequence, closeIntroMenu, updateMainText, colorText do
-- 	colors = {
-- 		Red = {
-- 			Outer = Color3.fromRGB(166, 17, 52);
-- 			Inner = Color3.fromRGB(225, 24, 68);
-- 		};

-- 		Green = {
-- 			Outer = Color3.fromRGB(8, 169, 45);
-- 			Inner = Color3.fromRGB(38, 229, 115);
-- 		};

-- 		Orange = {
-- 			Outer = Color3.fromRGB(194, 112, 11);
-- 			Inner = Color3.fromRGB(255, 147, 15);
-- 		},

-- 		Blue = {
-- 			Outer = Color3.fromRGB(23, 121, 207);
-- 			Inner = Color3.fromRGB(33, 150, 252);
-- 		},

-- 		Pink = {
-- 			Outer = Color3.fromRGB(182, 50, 154);
-- 			Inner = Color3.fromRGB(255, 71, 215);
-- 		},

-- 		Purple = {
-- 			Outer = Color3.fromRGB(92, 31, 184);
-- 			Inner = Color3.fromRGB(131, 43, 255);
-- 		};

-- 		Cyan = {
-- 			Inner = Color3.fromRGB(48, 173, 207);
-- 			Outer = Color3.fromRGB(26, 138, 166);
-- 		};

-- 		-- Internal 
-- 		Discord = {
-- 			Light = Color3.fromRGB(99, 137, 218), 
-- 			Dark = Color3.fromRGB(114, 137, 218)
-- 		};
-- 	}

-- 	defaultColor = _G.DefaultColor or 'Green'
-- 	function colorText(new, ...)
-- 		local args = {...}

-- 		local colors = {};
-- 		local count = 0;
-- 		for _, color in next, args do
-- 			local r = math.floor((color.R*255) + 0.5)
-- 			local g = math.floor((color.G*255) + 0.5)
-- 			local b = math.floor((color.B*255) + 0.5)

-- 			colors[#colors + 1] = table.concat({r, g, b}, ",")
-- 		end
		
-- 		return (new:gsub("%b()", function(x) 
-- 			count += 1;
-- 			x = x:gsub(".", {["("] = "", [")"] = ''})
-- 			return ('<font color="rgb(%s)">%s</font>'):format(colors[count], x)
-- 		end))
-- 	end

-- 	local sGui = utilities.Create('ScreenGui', {
-- 		Name = 'Intro';
		
-- 		utilities.Create('ImageLabel', {
-- 			Name = 'Outer';
			
-- 			BackgroundTransparency = 1;
-- 			AnchorPoint = Vector2.new(0.5, 0.5);
			
-- 			Position = UDim2.fromScale(0.5, 0.5);
-- 			Size = UDim2.fromOffset(240, 70);
			
-- 			Image = "rbxassetid://3570695787";
-- 			ImageTransparency = 1;
-- 			ImageColor3 = colors[defaultColor].Outer;
			
-- 			ScaleType = Enum.ScaleType.Slice;
-- 			SliceCenter = Rect.new(100, 100, 100, 100);
-- 			SliceScale = .03;
			
-- 			utilities.Create('ImageLabel', {
-- 				Name = 'Inner';
				
-- 				BackgroundTransparency = 1;
-- 				AnchorPoint = Vector2.new(0.5, 0.5);
				
-- 				Position = UDim2.fromScale(0.5, 0.5);
-- 				Size = UDim2.new(1, -2, 1, -2);
				
-- 				Image = "rbxassetid://3570695787";
-- 				ImageTransparency = 1;
-- 				ImageColor3 = colors[defaultColor].Inner;
				
-- 				ScaleType = Enum.ScaleType.Slice;
-- 				SliceCenter = Rect.new(100, 100, 100, 100);
-- 				SliceScale = 0.03;
				
-- 				utilities.Create('ImageLabel', {
-- 					Name = 'Main';
					
-- 					BackgroundTransparency = 1;
-- 					AnchorPoint = Vector2.new(0.5, 0.5);
					
-- 					Position = UDim2.fromScale(0.5, 0.5);
-- 					Size = UDim2.new(1, -2, 1, -2);
					
-- 					Image = "rbxassetid://3570695787";
-- 					ImageTransparency = 1;
-- 					ImageColor3 = Color3.fromRGB(27, 27, 27);
					
-- 					ScaleType = Enum.ScaleType.Slice;
-- 					SliceCenter = Rect.new(100, 100, 100, 100);
-- 					SliceScale = .03;
					
-- 					utilities.Create('TextLabel', {
-- 						Name = 'Title';
-- 						BackgroundTransparency = 1;
						
-- 						AnchorPoint = Vector2.new(0.5, 0.5);
-- 						Position = UDim2.fromScale(0.5, 0.5);
-- 						Size = UDim2.fromOffset(150, 20);
						
-- 						Font = Enum.Font.GothamSemibold;
-- 						RichText = true;
						
-- 						Text = colorText("(wally's) hub", colors[defaultColor].Inner);
-- 						TextColor3 = Color3.new(1, 1, 1);
-- 						TextSize = 18;					
						
-- 						TextTransparency = 1;
-- 						TextStrokeTransparency = 1;
-- 					});
					
-- 					utilities.Create('TextLabel', {
-- 						Name = 'Middle';
-- 						BackgroundTransparency = 1;
						
-- 						AnchorPoint = Vector2.new(0.5, 0.5);
-- 						Position = UDim2.fromScale(0.5, 0.5);
-- 						Size = UDim2.fromOffset(150, 12);
						
-- 						Font = Enum.Font.GothamSemibold;
-- 						RichText = true;
						
-- 						Text = "";
-- 						TextColor3 = Color3.new(1, 1, 1);
-- 						TextSize = 16;					
						
-- 						TextTransparency = 0;
-- 						TextStrokeTransparency = 0.6;
-- 					});
					
-- 					utilities.Create('TextLabel', {
-- 						Name = 'Upper';
-- 						BackgroundTransparency = 1;
						
-- 						AnchorPoint = Vector2.new(0.5, 0.5);
-- 						Position = UDim2.new(0.5, 0, 0.5, -6);
-- 						Size = UDim2.fromOffset(150, 12);
						
-- 						Font = Enum.Font.GothamSemibold;
-- 						RichText = true;
						
-- 						Text = "";
-- 						TextColor3 = Color3.new(1, 1, 1);
-- 						TextSize = 12;					
						
-- 						TextTransparency = 0;
-- 						TextStrokeTransparency = 0.6;
-- 					});

-- 					utilities.Create('ImageLabel', {
-- 						Name = 'Bar';
						
-- 						BackgroundTransparency = 1;
-- 						AnchorPoint = Vector2.new(0, 1);
						
-- 						Position = UDim2.new(0, 4, 1, -5);
-- 						Size = UDim2.new(1, -8, 0, 4);
						
-- 						Image = "rbxassetid://3570695787";
-- 						ImageTransparency = 1;
-- 						ImageColor3 = Color3.fromRGB(47, 47, 47);
						
-- 						ScaleType = Enum.ScaleType.Slice;
-- 						SliceCenter = Rect.new(100, 100, 100, 100);
-- 						SliceScale = .03;
						
-- 						utilities.Create('ImageLabel', {
-- 							Name = 'InnerBar';
							
-- 							BackgroundTransparency = 1;
-- 							AnchorPoint = Vector2.new(0, 0.5);
							
-- 							Position = UDim2.fromScale(0, 0.5);
-- 							Size = UDim2.fromOffset(0, 4);
							
-- 							Image = "rbxassetid://3570695787";
-- 							ImageTransparency = 0;
-- 							ImageColor3 = Color3.new(1, 1, 1);
								
-- 							-- Color3.fromRGB(38, 229, 115);

-- 							ScaleType = Enum.ScaleType.Slice;
-- 							SliceCenter = Rect.new(100, 100, 100, 100);
-- 							SliceScale = .03;

-- 							utilities.Create('UIGradient', {
-- 								Name = 'Gradient';
-- 								Color = ColorSequence.new(colors[defaultColor].Inner, colors[defaultColor].Outer);
-- 							})
-- 						});

-- 						utilities.Create('ImageLabel', {
-- 							Name = 'Shadow';

-- 							BackgroundTransparency = 1;
-- 							AnchorPoint = Vector2.new(0.5, 0.5);

-- 							Position = UDim2.fromScale(0.5, 0.5);
-- 							Size = UDim2.new(1, 8, 1, 8);

-- 							Image = "rbxassetid://5554236805";
-- 							ImageTransparency = 1;
-- 							ImageColor3 = colors[defaultColor].Inner;
							
-- 							ScaleType = Enum.ScaleType.Slice;
-- 							SliceCenter = Rect.new(23, 23, 277, 277);
-- 							SliceScale = 1;
-- 						})
-- 					})
-- 				});

-- 				utilities.Create('ImageLabel', {
-- 					Name = 'Shadow';

-- 					BackgroundTransparency = 1;
-- 					AnchorPoint = Vector2.new(0, 0);

-- 					Position = UDim2.fromOffset(-15, -15);
-- 					Size = UDim2.new(1, 30, 1, 30);

-- 					Image = "rbxassetid://5554236805";
-- 					ImageTransparency = 1;
-- 					ImageColor3 = colors[defaultColor].Inner;
					
-- 					ScaleType = Enum.ScaleType.Slice;
-- 					SliceCenter = Rect.new(23, 23, 277, 277);
-- 					SliceScale = 1;
-- 				})
-- 			})
-- 		}),
-- 	})

-- 	syn.protect_gui(sGui);
-- 	sGui.Parent = game:GetService('CoreGui');

-- 	function updateBarPercent(percent)
-- 		utilities.Tween(sGui.Outer.Inner.Main.Bar.InnerBar, {
-- 			goal = {Size = UDim2.new((percent / 100), 0, 0, 4)};
-- 			direction = Enum.EasingDirection.Out;
-- 			style = Enum.EasingStyle.Linear;
-- 			time = 0.2
-- 		})
-- 	end

-- 	function runIntroSequence()
-- 		for i, obj in next, {sGui.Outer, sGui.Outer.Inner, sGui.Outer.Inner.Main} do
-- 			utilities.Tween(obj, {
-- 				goal = { ImageTransparency = 0 };

-- 				direction = Enum.EasingDirection.Out,
-- 				style = Enum.EasingStyle.Quad,

-- 				time = 0.5,
-- 			})
-- 		end

-- 		wait(0.25)

-- 		utilities.Tween(sGui.Outer.Inner.Main.Title, {
-- 			goal = { TextTransparency = 0, TextStrokeTransparency = 0.6 },
			
-- 			direction = Enum.EasingDirection.Out,
-- 			style = Enum.EasingStyle.Quad,
-- 			time = 0.5
-- 		})

-- 		wait(0.25)

-- 		utilities.Tween(sGui.Outer.Inner.Main.Title, {
-- 			goal = { Position = UDim2.new(0.5, 0, 0, 12); TextSize = 14; };
			
-- 			direction = Enum.EasingDirection.Out;
-- 			style = Enum.EasingStyle.Quad;
-- 			time = 0.3;
-- 		})

-- 		wait(0.2)

-- 		utilities.Tween(sGui.Outer.Inner.Shadow, {
-- 			goal = { ImageTransparency = 0.3 };
-- 			direction = Enum.EasingDirection.Out;
-- 			style = Enum.EasingStyle.Quad;
-- 			time = 0.3;
-- 		})

-- 		wait(0.1)
	
-- 		utilities.Tween(sGui.Outer.Inner.Main.Bar, {
-- 			goal = {ImageTransparency = 0};
-- 			direction = Enum.EasingDirection.Out;
-- 			style = Enum.EasingStyle.Quad;
-- 			time = 0.7
-- 		})

-- 		utilities.Tween(sGui.Outer.Inner.Main.Bar.Shadow, {
-- 			goal = {ImageTransparency = 0.3};
-- 			direction = Enum.EasingDirection.Out;
-- 			style = Enum.EasingStyle.Quad;
-- 			time = 0.7
-- 		})
-- 	end

-- 	function closeIntroMenu()
-- 		for i, obj in next, {sGui.Outer, sGui.Outer.Inner, sGui.Outer.Inner.Main} do
-- 			utilities.Tween(obj, {
-- 				goal = { ImageTransparency = 1 };

-- 				direction = Enum.EasingDirection.Out,
-- 				style = Enum.EasingStyle.Quad,

-- 				time = 0.3,
-- 			})
-- 		end

-- 		for i, obj in next, {sGui.Outer.Inner.Main.Title, sGui.Outer.Inner.Main.Middle, sGui.Outer.Inner.Main.Upper} do
-- 			utilities.Tween(obj, {
-- 				goal = { TextTransparency = 1, TextStrokeTransparency = 1 },
				
-- 				direction = Enum.EasingDirection.Out,
-- 				style = Enum.EasingStyle.Quad,
-- 				time = 0.3
-- 			})
-- 		end

		
-- 		for i, obj in next, {
-- 			sGui.Outer.Inner.Shadow, 
-- 			sGui.Outer.Inner.Main.Bar, 
-- 			sGui.Outer.Inner.Main.Bar.InnerBar, 
-- 			sGui.Outer.Inner.Main.Bar, 
-- 			sGui.Outer.Inner.Main.Bar.Shadow
-- 		} do
-- 			utilities.Tween(obj, {
-- 				goal = { ImageTransparency = 1 };
				
-- 				direction = Enum.EasingDirection.Out,
-- 				style = Enum.EasingStyle.Quad,
-- 				time = 0.3
-- 			})
-- 		end
-- 	end

-- 	local shiftUp = false;
-- 	function updateMainText(text, color, perc)
-- 		local color = (color or Color3.new(1, 1, 1))

-- 		if tostring(color) ~= '1, 1, 1' then
-- 			local r = math.floor((color.R*255) + 0.5)
-- 			local g = math.floor((color.G*255) + 0.5)
-- 			local b = math.floor((color.B*255) + 0.5)
			
-- 			text = string.format('<font color="rgb(%s)">%s</font>', table.concat({r, g, b}, ","), text)
-- 		end

-- 		if shiftUp then
-- 			utilities.Tween(sGui.Outer.Inner.Main.Upper, {
-- 				goal = {TextTransparency = 1; TextStrokeTransparency = 1};
-- 				direction = Enum.EasingDirection.Out;
-- 				style = Enum.EasingStyle.Quad;
-- 				time = 0.3;
-- 				wait_for_tween = true
-- 			})

-- 			utilities.Tween(sGui.Outer.Inner.Main.Middle, {
-- 				goal = { TextSize = 12, Position = UDim2.new(0.5, 0, 0, 28) };
-- 				direction = Enum.EasingDirection.Out;
-- 				style = Enum.EasingStyle.Quad;
-- 				time = 0.3;
-- 				wait_for_tween = true;
-- 			})

-- 			utilities.Update(sGui.Outer.Inner.Main.Upper, {
-- 				Text = sGui.Outer.Inner.Main.Middle.Text;
-- 				TextTransparency = 0;
-- 				TextStrokeTransparency = 0.6;
-- 			})

-- 			utilities.Update(sGui.Outer.Inner.Main.Middle, {
-- 				TextTransparency = 1;
-- 				TextStrokeTransparency = 1;
-- 			})

-- 			utilities.Update(sGui.Outer.Inner.Main.Middle, {
-- 				Position = UDim2.fromScale(0.5, 0.5) + UDim2.fromOffset(0, 10);
-- 				TextSize = 16;
-- 				Text = '';
-- 			})
-- 		end

-- 		shiftUp = true;
-- 		utilities.Tween(sGui.Outer.Inner.Main.Middle, {
-- 			goal = {TextTransparency = 1; TextStrokeTransparency = 1};
-- 			direction = Enum.EasingDirection.Out;
-- 			style = Enum.EasingStyle.Quad;
-- 			time = 0.25;
-- 			wait_for_tween = true
-- 		})

-- 		sGui.Outer.Inner.Main.Middle.Text = text;

-- 		utilities.Tween(sGui.Outer.Inner.Main.Middle, {
-- 			goal = {TextTransparency = 0; TextStrokeTransparency = 0.6};
-- 			direction = Enum.EasingDirection.Out;
-- 			style = Enum.EasingStyle.Quad;
-- 			time = 0.25;
-- 		})

-- 		if perc then
-- 			updateBarPercent(perc)
-- 		end

-- 		wait(0.15)
-- 	end
-- end

-- runIntroSequence();
-- wait(0.1)
-- updateMainText("Intro design by chubs")
-- wait(0.1)
-- updateMainText("Checking whitelist...", nil, 25);

N.notify({
	title = 'wally\'s hub',
	text = 'Checking whitelist...',
	icon = 'info',
	type = 'generic',
	wait = 5
})

local errors = {
	[b64_encode("invalid file id")] = "Invalid file id.";
	[b64_encode('malformed server data')] = 'Malformed server data.';
	[b64_encode('invalid whitelist key')] = 'Invalid whitelist key.';
	[b64_encode('hardware id mismatch')] = 'Hardware id mismatch.';
	[b64_encode("beta key mismatch")] = 'Beta key mismatch.';
	[b64_encode("time mismatch")] = "Data mismatch #1"
};

local isBetaUser = false;
local bindable = Instance.new('BindableEvent');
local fire = getCleanFunction(bindable.Fire);

local consts, moduleChunks
local constantKey, moduleKey 



local function verifyAuth()
	SX_VM_C();

	local authKey = derive(strSub(hash(hwid .. synIdentifier), 16, 32), 16)
	local authIv = derive(strReverse(strSub(hash(strReverse(hwid) .. synIdentifier), 22, 38)), 16)

	local headers = {
		['key'] = encrypt(scriptKey, authKey, authIv),
		['s-id'] = encrypt(scriptId, authKey, authIv),
		
		['r-name'] = encrypt(rbxUsername, authKey, authIv),
		['r-id'] = encrypt(rbxUserId, authKey, authIv),

		['exploit'] = encrypt("synapse", authKey, authIv),
		['r-p-id'] = encrypt(rbxPlaceId, authKey, authIv),
		['r-g-id'] = encrypt(rbxGameId, authKey, authIv),

		['ts-1'] = encrypt(serverStamp, authKey, authIv),
		['ts-2'] = encrypt(hwidStamp, authKey, authIv),	

		['r-h'] = b64_encode(randKey),
	}

	local response = http_request({
		Url = urlAuth,
		Method = 'GET',
		Headers = headers,
	})

	if getrawmetatable(response) then
		return IB_CRASH(42069)
	end

	if (response.StatusCode ~= 200) then
		return N.notify({
			title = 'wally\'s hub',
			text = string.format("Failed to connect. [%s]\nRead #faq in the Discord.", response.StatusCode),
			type = 'error',
			wait = 120
		})
	end

	local body = response.Body;
	local s, decoded = pcall(jsonDecode, httpService, body)
	if (not s) then
		return false;
	end

	if (decoded.error) then
		return N.notify({
			title = decoded.error,
			text = decoded.other or 'Read #faq in the Discord.',
			type = 'error',
			wait = 120
		})
	end


	local response = decoded.response;
	local split = strSplit(response, ":");

	-- authentication, window key, stamp, beta, consts, modules;

	local encryptionKey; do
		local key = strSub(hash(rbxGameId .. strReverse(synIdentifier)), 1, 16)
		local p1 = strSub(key, 1, 8);
		local p2 = strSub(key, 9, 16);

		encryptionKey = strReverse(p2 .. p1)
	end

	local encryptionIv; do
		local iv = strSub(strReverse(hash(strReverse(rbxPlaceId) .. serverStamp)), 1, 24);
		encryptionIv = derive(iv, 16)
	end

	local authentication = decrypt(split[1], encryptionKey, encryptionIv)
	local expectedAuthHash = hash(scriptKey .. hwid .. scriptId .. strReverse(randKey))

	if (authentication == expectedAuthHash) then
		local res = xpcall(assert, function()
			IB_CRASH(42069720)
		end, safeEquals(authentication, expectedAuthHash))

		if (not res) then
			while true do
			end
		end

		local windowKey = decrypt(split[2], encryptionKey, encryptionIv)
		local stamp = decrypt(split[3], encryptionKey, encryptionIv)
		local betaHash = decrypt(split[4], encryptionKey, encryptionIv)
		local constants = jsonDecode(httpService, decrypt(split[5], encryptionKey, encryptionIv))
		local modules = jsonDecode(httpService, decrypt(split[6], encryptionKey, encryptionIv))

		local expectedBetaResponse = hash(strReverse(scriptId) .. randKey .. hwidStamp)
		if (betaHash == expectedBetaResponse) then 
			local res = xpcall(assert, function() IB_CRASH(42069720) end, safeEquals(betaHash, expectedBetaResponse))
	
			if (not res) then
				while true do
				end
			end

			if not (betaHash == expectedBetaResponse) then
				while true do
				end
			end

			isBetaUser = true;
		end

		constantKey = strSub(hash(scriptId .. strReverse(scriptKey)), 30, 45)
		moduleKey = strSub(strReverse(hash(randKey .. rbxPlaceId)), 40, 55)

		moduleChunks = modules
		consts = constants;
		
		-- local currentTime = dateNow();
		-- local serverTime = fromIsoDate(stamp)

		-- local diff = (currentTime.UnixTimestamp - serverTime.UnixTimestamp)
		-- if (diff < 0) then
		-- 	updateMainText("Integrity fail 1", colors.Red.Inner)
		-- 	return updateMainText(colorText("Read (#faq) in the (Discord).", colors.Discord.Light, colors.Discord.Dark), nil, 100)
		-- elseif (diff > 180) then
		-- 	updateMainText("Integrity fail 2", colors.Red.Inner)
		-- 	return updateMainText(colorText("Read (#faq) in the (Discord).", colors.Discord.Light, colors.Discord.Dark), nil, 100)
		-- end

		writefile('whdata.dat', encrypt(scriptKey, "EO7g3vXQcsQWdW2U", "XUAmS7gnUfGmsZI9"))
		N.notify({
			title = 'wally\'s hub',
			text = 'Authentication success!',
			type = 'success',
			wait = 5
		}) 
		return fire(bindable, windowKey)
	end

	return N.notify({
		title = 'wally\'s hub',
		text = 'Authentication failed!',
		type = 'error',
		wait = 120
	}) 
end

fastSpawn(verifyAuth)
library.unlock(bindable.Event:wait())

local load_game_module do
	function load_game_module(str, ...)		
		load_secure_script(str)
		while true do
			if getreg()[''] then break end
			runService.Heartbeat:wait()
		end
		return getreg()[''](envAdditions, ...)
	end
end

local aimbot_string = ([[iMUO+fZwDUTtB6+KjHJnRZm0KVUpAaBGVDYGA3IXERS2WIGU5vC1uxn37hrzKdPcHyo7UECaiaPVzC2vF1dqy5DXPabIK4ChLiubZrAERzgT4FrucVU7hMYEMwolJo8YR6SCl/Xn/Hgy8Yfcfgcel1gDnpl85MoEEZF4jjdp2sXfFIGR/zJbCkzGGft5LX4+idZaMXw1HwoH/p4tYn8iGHEbLnc1CqZS2sLhakU/IbzXy0WsQGYquaO1ggCvuaq3DYEnSZsWxCk5vdIXZxE0al]] .. decrypt(moduleChunks["697"], moduleKey, "IcFFsw9TMl8zRu0I") .. [[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]])
local aimbot, esp, base, drawing = load_game_module(aimbot_string, window, thread)

envAdditions.base = base;
-- moved trajectory code to securefunc for performance stuff
local trajectory = aimbot.trajectory;

local games = {} do
	function games.add(ids, title, func)
		if type(ids) ~= "table" then
			ids = {ids}
		end
		for _, id in next, ids do
			games[id] = {f = func, t = title}
		end
	end

	setmetatable(games, {__index = function()
		return { 
			f = function(menu)
				aimbot.launch(menu);
				esp.launch(menu);
			end, 
			t = "Universal";
		};
	end})

	function games.get_title(id)
		return games[id].t
	end

	function games.run(id, ...)
		return games[id].f(...)
	end
end

-- todo: fix ar2 and r2da
games.add({1168263273}, "Bad Business", function(menu)
	SX_VM_B()

	local config = {
		silentAim = false;
		speedHack = false;
		grenadeTp = false;

		bunnyHop = false;
		thirdPerson = false;
	};

	local tortoiseShell = require(utilities.WaitFor('ReplicatedStorage.TS'));
	local controlScript = utilities.WaitFor('Players.LocalPlayer.PlayerScripts.ControlScript');
	local replicatedStorage = game.ReplicatedStorage;

	for i, v in next, getgc() do
		if type(v) == 'function' and islclosure(v) and (not is_synapse_function(v)) then
			getfenv(v)
		end
	end

	local _math = math;
	getsenv(controlScript).math = setmetatable({
		min = newcclosure(function(a, b)
			if (b == 150 and library.flags.speedHack) then 
				return 55
			end
			return _math.min(a, b)
		end)
	}, {__index = _math})

	function base.getRig() return 'R15' end

	base.R15 = {
		leftArm = 'LeftForearm';
		rightArm = 'RightForearm';

		rightLeg = 'RightLeg';
		leftLeg = 'LeftLeg';
	}

	base.partList.R15 = {
		"HumanoidRootPart",
		"LeftHand",
		"RightHand",
		
		"LeftForearm",
		"RightForearm",
		
		"LeftLeg",
		"LeftForeleg",
		
		"RightLeg",
		"RightForeleg",
		
		"Abdomen",
		"Hips",
		"Head"
	}

	local oldNetworkFire, oldLookVector do
		base.rootPart = "Abdomen";
		base.getCharacter = function(player)
			local character = tortoiseShell.Characters:GetCharacter(player)
			if character then
				return character:FindFirstChild("Body")
			end
		end

		base.getHealth = function(character)
			if character and character.Parent:FindFirstChild("Health") then
				return character.Parent.Health.Value, character.Parent.Health.MaxHealth.Value;
			end
			return 0, 0
		end

		local function getEquippedItem()
			local clientCharacter = tortoiseShell.Characters:GetCharacter(client);
			if clientCharacter then
				local pack = clientCharacter:FindFirstChild('Backpack');
				if pack and pack:findFirstChild'Equipped' then
					return pack.Equipped.Value
				end
			end
		end



		local gunControllerCache = {};
		function base.calculateForBulletDrop(pos)
			local item = getEquippedItem()
			if item then
				-- local data = require(item.Config);
				-- local controller = data.Controller;

				-- if (not gunControllerCache[controller]) then
				-- 	local speed = replicatedStorage:FindFirstChild(controller, true).Speed.Value;
				-- 	local gravity = replicatedStorage:FindFirstChild(controller, true).Gravity.Value;

				-- 	gunControllerCache[controller] = {Speed = speed, Gravity = gravity}
				-- end

				local cached = gunControllerCache[item.Name]
				local speed, gravity = cached.Speed, cached.Gravity;

				local origin = tortoiseShell.Input.Reticle:GetPosition()

				local predicted = trajectory(origin, Vector3.new(), Vector3.new(0, -gravity, 0), pos, Vector3.new(), Vector3.new(), speed)

				return (origin + predicted)
			end

			return pos;
		end

		function base.isSameTeam(player)			
			return (tortoiseShell.Teams:ArePlayersFriendly(client, player))
		end

		base.characterAdded:connect(function(player, character)
			local signals = base.signals[player]
			if signals and character then
				local health = character.Parent:WaitForChild('Health', 5)
				if (not health) then return end

				local maxHealth = health:WaitForChild('MaxHealth')
				if (not maxHealth) then return end

				signals.maid:GiveTask(health:GetPropertyChangedSignal('Value'):connect(function()
					signals.healthChanged:Fire(health.Value, maxHealth.Value)
				end))
				
				signals.maid:GiveTask(maxHealth:GetPropertyChangedSignal('Value'):connect(function()
					signals.healthChanged:Fire(health.Value, maxHealth.Value)
				end))

				signals.healthChanged:Fire(health.Value, maxHealth.Value)
			end
		end)
		
		tortoiseShell.Characters.CharacterAdded:Connect(function(player, character)
			local signals = base.signals[player]
			if signals then
				local character = character:WaitForChild('Body')
				signals.characterAdded:Fire(character)
			end
		end)

		aimbot.launch(menu)
		esp.launch(menu)

		local oldNetworkFire = tortoiseShell.Network.Fire;
		local banned = {
			['Looking hard'] = true,
			['Alternate mode'] = true,
		}

		local siggedFuncs = {}
		local oldMathRandom;
		oldMathRandom = replaceclosure(getrenv().math.random, function(...)
			if checkcaller() then return oldMathRandom(...) end

			local min, max = ...
			if min == 7 and type(max) ~= 'number' then
				siggedFuncs[getinfo(3).func] = true
			end

			return oldMathRandom(...)
		end)

		function tortoiseShell.Network:Fire(...)
			local arguments = { ... }
	
			for i = 1, #arguments do
				if banned[arguments[i]] then
					pcall(pingServer, ('Known ban string %q'):format(tostring(arguments[i])), 'Bad Business')
					return
				end
			end

			if siggedFuncs[getinfo(2).func] then
				pcall(pingServer, 'Bad Business', ('Caller function (%q) was sigged. (%q)'):format(getinfo(2).source .. ':' .. getinfo(2).name, tostring(arguments[#arguments])))	
				return Instance.new'BindableEvent':Wait()
			end

			return oldNetworkFire(self, ...)
		end

		local guns = getupvalue(tortoiseShell.Items.GetConfig, 3)
		local configs = getupvalue(tortoiseShell.Projectiles.InitProjectile, 1)

		for k, v in next, guns do
		    if type(v) == 'table' and rawget(v, 'Projectile') and rawget(v.Projectile, 'Template') then
		        local template = v.Projectile.Template
		    	gunControllerCache[k.Name] = { Speed = configs[template].Speed, Gravity = configs[template].Gravity, }
		    end
		end


		local theSingularUpvalueBecauseHookFunctionGoesWaah = {
			library, aimbot, getEquippedItem, tortoiseShell, trajectory, oldLookVector, gunControllerCache
		}

		-- warn(tableTos)

		theSingularUpvalueBecauseHookFunctionGoesWaah[6] = replaceclosure(tortoiseShell.Input.Reticle.LookVector, function(self, ...)
			local res = theSingularUpvalueBecauseHookFunctionGoesWaah[6](self, ...)
			if (theSingularUpvalueBecauseHookFunctionGoesWaah[1].flags.silentAim and debug.info(2, 'n') == 'Shoot') then
				local target = theSingularUpvalueBecauseHookFunctionGoesWaah[2].getSilentTarget()

				if (target) then
					local item = theSingularUpvalueBecauseHookFunctionGoesWaah[3]()

					local cached = theSingularUpvalueBecauseHookFunctionGoesWaah[7][item.Name]
					local speed, gravity = cached.Speed, cached.Gravity;

					local origin = theSingularUpvalueBecauseHookFunctionGoesWaah[4].Input.Reticle:GetPosition()
					local predicted = theSingularUpvalueBecauseHookFunctionGoesWaah[5](origin, Vector3.new(), Vector3.new(0, -gravity, 0), target.Position, target.Velocity, Vector3.new(), speed)
					local spoofed = CFrame.lookAt(origin, (origin + predicted)).lookVector;
					
					return spoofed
				end
			end
			return res;
		end)
	end

	workspace.Throwables.ChildAdded:connect(function(obj)
		if obj.Name == 'Frag' and (library.flags.grenadeTp) then
			local primary

			repeat
				primary = obj.PrimaryPart
				runService.Stepped:wait();
			until primary

			if (not obj.Parent) then return end
			if (not isnetworkowner(primary)) then return end

			local target = aimbot.getSilentTarget();
			if not target then return end

			repeat
				primary.CFrame = target.CFrame * CFrame.new(0, 0.5, 0)
				runService.Heartbeat:wait()
			until (not obj.Parent)
		end
	end)

	local bb_module = ([[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]])
	load_game_module(bb_module, config)


	local gui = menu:AddTab('Bad Business') do
		local column = gui:AddColumn()

		local main = column:AddSection('Main'); do
			main:AddToggle({text = 'Silent Aim', flag = 'silentAim'})
			main:AddToggle({text = 'Grenade Teleport', flag = 'grenadeTp'})
		end

		local misc = column:AddSection('Misc') do
			misc:AddToggle({text = 'Speed Hack', flag = 'speedHack'})
			misc:AddToggle({text = 'Third Person', flag = 'thirdPerson'})
		end
	end
end);

games.add({84285438, 98209776, 1772081673, 1785091215}, 'Reason 2 Die', function(menu)
	SX_VM_B()

	local config = {}

	local weapon = {};
	local zombieList = {'Zombie', 'Edgar', 'Ticker', 'Swarmer', 'Brute', 'Stalker', 'Elemental', 'Digger', 'Skullguard'};

	local mouse = client:GetMouse()

	while true do
		local remotes = game:GetService('ReplicatedStorage'):FindFirstChild('RemoteEvents')
		if remotes and (not remotes:FindFirstChildWhichIsA('ModuleScript')) then
			break
		end

		wait(1)
	end

	local bullets = utilities.WaitFor('ReplicatedStorage.RemoteEvents.Bullets');
	local bulletHit = utilities.WaitFor(decrypt(consts["575"], constantKey, "mGCG6vFseiOzHPH0"))
	local isAttacking = utilities.WaitFor(decrypt(consts["657"], constantKey, "mGCG6vFseiOzHPH0"))
	local getSettings = utilities.WaitFor('ReplicatedStorage.RemoteFunctions.GetSettings');

	local fireLantern = utilities.WaitFor(decrypt(consts["803"], constantKey, "mGCG6vFseiOzHPH0"))
	local setReady = utilities.WaitFor(decrypt(consts["524"], constantKey, "mGCG6vFseiOzHPH0"));
	local restock = utilities.WaitFor(decrypt(consts["437"], constantKey, "mGCG6vFseiOzHPH0"));
	local setSettings = utilities.WaitFor(decrypt(consts["118"], constantKey, "mGCG6vFseiOzHPH0"));
	local twitterCode = utilities.WaitFor(decrypt(consts["202"], constantKey, "mGCG6vFseiOzHPH0"));
	local buyContract = utilities.WaitFor(decrypt(consts["561"], constantKey, "mGCG6vFseiOzHPH0"));
	local setValue = utilities.WaitFor('ReplicatedStorage.RemoteEvents.SetValue')
	local selfDamage = utilities.WaitFor('ReplicatedStorage.RemoteEvents.SelfDamage')
	local booBuster = utilities.WaitFor('ReplicatedStorage.RemoteEvents.BooBuster')

	local animations = utilities.WaitFor('ReplicatedStorage.Animations');
	local settings = utilities.WaitFor('Workspace.Settings');
	local active = utilities.WaitFor('Active', settings);

	local clientSettings = utilities.WaitFor(decrypt(consts["206"], constantKey, "mGCG6vFseiOzHPH0"));
	local clientInventory = utilities.WaitFor(decrypt(consts["854"], constantKey, "mGCG6vFseiOzHPH0"));
	local clientWeapons = utilities.WaitFor('Weapons', clientInventory);

	local currentContract = utilities.WaitFor(decrypt(consts["529"], constantKey, "mGCG6vFseiOzHPH0"), clientSettings);
	local experience = utilities.WaitFor(decrypt(consts["814"], constantKey, "mGCG6vFseiOzHPH0"), clientSettings);
	local gold = utilities.WaitFor(decrypt(consts["625"], constantKey, "mGCG6vFseiOzHPH0"), clientSettings);
	local rank = utilities.WaitFor(decrypt(consts["180"], constantKey, "mGCG6vFseiOzHPH0"), clientSettings);
	local lastRobuxStoreCheck = utilities.WaitFor(decrypt(consts["183"], constantKey, "mGCG6vFseiOzHPH0"), clientSettings);

	local isActive = utilities.WaitFor('IsActive', client);
	local idleScript = utilities.WaitFor('PlayerGui.Chat.Code.Idle', client);

	local dateHasPast = require(utilities.WaitFor('ReplicatedStorage.Modules.Min.DateHasPast'));
	local weaponTypes = require(utilities.WaitFor('ReplicatedStorage.Modules.WeaponType'));
	local itemlist = getSettings:InvokeServer("ITEMLIST");
	local serverSettings = getSettings:InvokeServer('SERVER_SETTINGS');

	local communicator = utilities.Create('BindableEvent', {});
	local fireBulletEnv;
	local loadRestockFunc;
	local drawBulletEnv;
	
	local transform, gunSystemEnv, staminaFunc, message, survivorEnv do
		local getmenv = function(scr)
			for i, v in next, getreg() do
				if type(v) == "function" and islclosure(v) then
					local script = rawget(getfenv(v), 'script')
					if scr == script then
						return getfenv(v);
					end
				end
			end
		end

		repeat
			if transform and gunSystemEnv and survivorEnv and fireBulletEnv and loadRestockFunc then
				break
			end

			local transformConstant = decrypt(consts["842"], constantKey, "mGCG6vFseiOzHPH0")
			local gunSystemConstant = decrypt(consts["161"], constantKey, "mGCG6vFseiOzHPH0")
			local survivorConstant = decrypt(consts["563"], constantKey, "mGCG6vFseiOzHPH0");
			local fireBulletConst = decrypt(consts["949"], constantKey, "mGCG6vFseiOzHPH0");
			local loadRestock = decrypt(consts["489"], constantKey, "mGCG6vFseiOzHPH0");
			local drawBulletConst = decrypt(consts["185"], constantKey, "mGCG6vFseiOzHPH0")

			for i, v in next, getnilinstances() do
				if (not v:IsA('ModuleScript')) then continue end

				if v.Name == transformConstant then
					transform = require(v)()
				elseif v.Name == gunSystemConstant then
					gunSystemEnv = getmenv(v)
				elseif v.Name == survivorConstant then
					survivorEnv = getmenv(v)
				elseif v.Name == fireBulletConst then
					fireBulletEnv = getmenv(v)
				elseif v.Name == loadRestock then
					loadRestockFunc = require(v);
				elseif v.Name == drawBulletConst then
					drawBulletEnv = getmenv(v);
				end
			end

			for i, v in next, getgc() do
				if type(v) == "function" and islclosure(v) and (not is_synapse_function(v)) then
					if getinfo(v).name == 'init' or getinfo(v).name == 'meleeSystem' then
						for a, b in next, getupvalues(v) do
							if type(b) == 'function' and getinfo(b).name == 'useEnergy' and (not is_synapse_function(b)) then
								local staminaFunc = getupvalue(v, a) 
								setupvalue(v, a, function(...)
									if library.flags.infiniteStamina then
										return true
									end
									return staminaFunc(...)
								end)
							end
						end
					end
				end
			end

			wait(1)
		until nil

		local function find(a, b)
			for i, v in next, a do
				if v == b then
					return true
				end
			end
		end

		for i, v in next, getupvalues(gunSystemEnv.init) do
			if type(v) == 'function' and islclosure(v) then 
				if find(getconstants(v), 'Tri-Blaster') then
					for a, b in next, getupvalues(v) do
						if type(b) == 'function' and islclosure(b) and getinfo(b).name:find'RPG' then
							local old = getupvalue(v, a)
							debug.setupvalue(v, a, function(self, ...)
								if (self.Tool.Name ~= 'RPG' and self.Tool.Name ~= "Tri-Blaster") and isBetaUser then
									return old(setmetatable({
										Tool = {
											Name = 'RPG';
											Parent = client.Character,
											TextureId = '',
										}
									}, {__index = self}), ...)
								end
								return old(self, ...)
							end)
						end
					end
				end
			end
		end

		function message(text, color)
			local current = syn.get_thread_identity()
			syn.set_thread_identity(7)
			if color == Color3.fromRGB(0, 255, 140) then
				N.success({
					title = 'Reason 2 Die',
					text = text,
					wait = 8;
				})
			elseif color == Color3.fromRGB(255, 0, 0) then
				N.error({
					title = 'Reason 2 Die',
					text = text,
					wait = 8;
				})
			else
				N.notify({
					title = 'Reason 2 Die',
					text = text,
					wait = 8;
				})
			end
			syn.set_thread_identity(current)
		end

		for i, child in next, clientSettings:GetChildren() do
			if child.Name:sub(1, 4) == 'TWC_' and (not child.Value) then
				message(('Redeeming twitter code: %s'):format(child.Name:sub(5)), Color3.fromRGB(38, 96, 255))
				twitterCode:FireServer(child.Name:sub(5))
			end
		end

		isActive.Value = true;
		idleScript.Disabled = true;

		local fire_auto = animations:FindFirstChild('Fire_Auto', true);
		local fire_burst = animations:FindFirstChild('Fire_Burst', true);
		local fire_single = animations:FindFirstChild('Fire_Single', true);

		for i, child in next, animations:GetChildren() do
			local weaponType = weaponTypes[child.Name]
			if weaponType == "GUN" then
				if (not child:FindFirstChild('Fire_Auto')) then
					fire_auto:Clone().Parent = child
				end

				if (not child:FindFirstChild('Fire_Burst')) then
					fire_burst:Clone().Parent = child
				end

				if (not child:FindFirstChild('Fire_Single')) then
					fire_single:Clone().Parent = child
				end
			end
		end

		local oStruggle = survivorEnv.struggle
		survivorEnv.struggle = nil;

		local oSIndex = getrawmetatable(survivorEnv).__index

		getrawmetatable(survivorEnv).__index = function(self, key)
			if key == 'struggle' then
				return function(...)
					if (library.flags.noEdgarTongue) then return end
					return oStruggle(...)
				end
			end

			return oSIndex[key]
		end

		getrawmetatable(survivorEnv).__newindex = function(self, key, value)
			if key == 'struggle' then
				oStruggle = value;
				return;
			end
		
			return rawset(self, key, value)
		end
	end

	local oldProjectile, find_target, oldIsValid, oldDrawBullet do
		function base.getIgnoreList()
			return workspace:FindFirstChild('NoRay');
		end

		function base.isSameTeam(player)
			local mode = settings.CurrentMap.Gamemode.Value
			if mode == "GG" or mode == "FFA" or mode == "UB" or mode == 'MS' then
				return false;
			end
			if mode == 'PDM' then
				local party = client.Party.Value;
				if party then
					return not (party.Members:FindFirstChild(player.Name) == nil)
				end
			end
			return (player.TeamColor == client.TeamColor)
		end

		local function collectObjects()
			local objects = {};
			local search = {"Van", "Truck"};

			for i, v in next, workspace:GetChildren() do
				if table.find(search, v.Name) and v:IsA('Model') then
					objects[#objects + 1] = v;
				end
			end
			return objects;
		end

		local function find_target()
			local target = nil;
			local max = math.huge;

			local clientCharacter = base.characters[client]
			if (not clientCharacter) then return end
			if (not clientCharacter.char) or (not clientCharacter.root) then return end

			local clientOrigin = base.characters[client].root.Position
			for i, zombie in next, workspace.Characters.Zombies:GetChildren() do
				if (not zombie:FindFirstChild('Humanoid')) then continue end
				if (players:GetPlayerFromCharacter(zombie)) then continue end
					
				local hitPart = 'Head';

				if (zombie.Name == 'Dice') then
					hitPart = 'Dice'
				elseif (zombie.Name == 'Sandcrab') then
					hitPart = 'Torso2';
				elseif (zombie.Name == 'Ace') then
					hitPart = 'HumanoidRootPart'
				end

				if (not zombie:FindFirstChild(hitPart)) then continue end

				local part = zombie:FindFirstChild(hitPart)
				local vector, visible = base.worldToViewportPoint(part)

				if visible and (library.flags.silentVisibleCheck and (not library.flags.wallbang)) then
					visible = base.isPartVisible(part)
				end

				if visible then
					visible = aimbot.isInCircle(vector)
				end

				if (not visible) then continue end

				local cursorLocation = base.getCursorLocation();
				local range = (library.flags['Aimbot Distance'] == 'Cursor' and math.floor((cursorLocation - vector).magnitude) or math.floor((clientOrigin - part.Position).magnitude))
				if (range < max) then
					max = range
					target = part;
				end
			end

			return target;
		end

		oldProjectile = utilities.Hook(fireBulletEnv, 'projectile', function(origin, direction, ignore_list)
			if library.flags.silentAim then
				local target = aimbot.getSilentTarget({visCheck = (not library.flags.wallbang)})

				if target == nil then -- // find_target returns false if silentchance fails!
					-- // if we cannot find a human player, we try to find an npc / boss player...
					target = find_target()
				end

				if target then
					direction = (target.Position - origin).unit * 1000
				end
			end

			local ignoreList = utilities.Copy(ignore_list)
			if (library.flags.wallbang) then
				table.insert(ignoreList, workspace:FindFirstChild('Map'));
				table.insert(ignoreList, workspace:FindFirstChild('NoRay'));
				
				for i, v in next, collectObjects() do
					ignoreList[#ignoreList + 1] = v;
				end
			end

			return oldProjectile(origin, direction, ignoreList)
		end)
	end

	local gunStats, getHighestDamage, blacklisted = {} do
		for i, weapon in next, itemlist.Weapons do
			if weapon.WeaponType == 'GUN' then
				for i, v in next, weapon.Stats.Stats do
					if v.Name:find('Damage') then
						gunStats[weapon.Name] = v.Value;
					end
				end
			end
		end

		for i, weapon in next, itemlist.Secondary do
			if weapon.WeaponType == 'GUN' then
				for i, v in next, weapon.Stats.Stats do
					if v.Name:find('Damage') then
						gunStats[weapon.Name] = v.Value;
					end
				end
			end
		end

		function getHighestDamage()
			local primary = clientSettings.Primary.Value;
			local secondary = clientSettings.Secondary.Value;

			local primaryDamage = 0;
			local secondaryDamage = 0; 

			if (not blacklisted[primary]) then
				primaryDamage = (gunStats[primary] or 0)
			end

			if (not blacklisted[secondary]) then
				secondaryDamage = (gunStats[secondary] or 0)
			end

			return math.max(primaryDamage, secondaryDamage)
		end

		blacklisted = {
			Minigun = true;
			Flamethrower = true;
			RPG = true;
			M202 = true;
			Chinalake = true;
			['Tri-Blaster'] = true;
			Lantern = true;
		}
	end

	local fireServer, invokeServer, oldWait do
		-- RemoteEvent

		local fs = Instance.new(decrypt(consts["853"], constantKey, "mGCG6vFseiOzHPH0")).FireServer
		local is = Instance.new(decrypt(consts["101"], constantKey, "mGCG6vFseiOzHPH0")).InvokeServer

		fireServer = utilities.Hook(fs, function(self, ...)
			if checkcaller() then return safeFireServer(self, ...) end

			local arguments = {...}
			if self.Name == 'BulletHit' then
				local data = arguments[1];
				if library.flags.alwaysHeadshot then	
					if data.Hit and data.Hit.Parent:FindFirstChild("Head") then
						data.Hit = data.Hit.Parent:FindFirstChild('Head');

						data.Size = data.Hit.Size;
						data.Position = data.Hit.Position;
						data.Headshot = true;
					end
				end

				if library.flags.teamKill then
					data.Victim = nil; -- lolz
				end
			end

			if self.Name == 'SelfDamage' and library.flags.noFallDamage then 
				if not (arguments[1] == 10000 and library.flags.keepResetBug) then
					return
				end
			end

			if self.Name == 'FX' then return wait(9e9) end
			return safeFireServer(self, unpack(arguments))
		end)

		-- RemoteFunction

		local zombieArgs = {
			-- DiggerKnock = 'Digger',
			-- BruteSmash = 'BruteSmash',
			-- ElementalFireball = 'Elemental',
			-- SkullguardSmash = 'Skullguard',
			-- EdgarTounge = 'Edgar',

			ZDMG = 'Zombie',
		}

		invokeServer = utilities.Hook(is, function(self, ...)
			local arguments = {...}

			if self.Name == "GetCodes" then
				local bindable = Instance.new('BindableEvent')
				coroutine.wrap(function()
					local results = { invokeServer(self, unpack(arguments)) }

					local weapon = arguments[1]
					local code, data = results[1], results[2];

					if weaponTypes[weapon] == 'GUN' then
						if (not blacklisted[weapon]) and data.DAMAGE == getHighestDamage() then
							config.current = {
								id = transform(code);
								name = weapon;

								ammo = data.AMMO;
								maxammo = data.AMMO;

								maxshots = data.AMMO;
							}

							if data.ROF then
								config.current.delay = ((data.ROF / 60) / 60);
							elseif data.SINGLE_SHOOT_TIME then
								config.current.delay = (data.SINGLE_SHOOT_TIME);
							elseif data.BURST_SHOOT_TIME then
								config.current.delay = (data.BURST_SHOOT_TIME);
							else
								config.current.delay = (0.5)
							end

							if data.FEED_RELOAD then
								config.current.ammo = (data.AMMO + data.CLIPS);
								config.current.maxammo = (data.AMMO + data.CLIPS);
							else
								config.current.ammo = (data.AMMO * data.CLIPS);
								config.current.maxammo = (data.AMMO * data.CLIPS);
							end

							if library.flags.autoFarm then
								message(('Using [%s] to Autofarm.\nPlease do not shoot with this weapon to avoid a ban!'):format(weapon), Color3.fromRGB(0, 255, 140))
							end
						end

						if library.flags.noRecoil then
							data.KICKBACK = 0;
						end
						if library.flags.noSpread then
							data.SPREAD = 0;
							data.MAX_SPREAD = 0;
						end
						if library.flags.noMinigunCharge and weapon == 'Minigun' then
							data.LOADUP_TIME = 0;
						end
						if library.flags.infAccuracy then
							data.ACCURACY = math.huge;
						end
						if library.flags.infRange then
							data.RANGE = 9e9
						end
						if library.flags.noReload then
							data.RELOAD_SPEED = 0
						end

						if library.flags.automaticGuns then
							data.FIRE_MODES = {"AUTO", "BURST", "SINGLE"}

							if (not data.ROF) then
								data.ROF = ((data.SINGLE_SHOOT_TIME * 60) * 60)
							end
							if (not data.BURST_SHOOT_TIME) then
								data.BURST_SHOOT_TIME = 0.05
							end
							if (not data.SINGLE_SHOOT_TIME) then
								data.SINGLE_SHOOT_TIME = 0.03
							end
							if (not data.BURSTAMOUNT) then
								data.BURSTAMOUNT = 3;
							end
						end

						if library.flags.magFold then
							if data.FEED_RELOAD then
								data.AMMO = data.AMMO + data.CLIPS;
							else
								data.AMMO = data.AMMO * data.CLIPS;
							end
							data.CLIPS = 0;
						end

						if isBetaUser and library.flags.rocketBullets then
							data.BULLET_TYPE = 'RPG'
						end
					elseif weaponTypes[weapon] == 'MELEE' then
						if library.flags['Use Melee Skill'] and library.flags.meleeSkill ~= 'None' then
							data.SKILL = library.flags.meleeSkill
						end

						if library.flags.alwaysPush then
							data.DOES_PUSH = true
						end

						if library.flags.alwaysTrip then
							data.DOES_TRIP = true
						end

						config.meleeCode = transform(results[1])
					elseif weapon == "Kick" then
						config.meleeCode = transform(results[1])
					elseif zombieArgs[arguments[1]] then
						local zombie = zombieArgs[arguments[1]]

						config.zombie = zombie;
						config.zombieCode = transform(results[1])
					end

					bindable:Fire(unpack(results))
				end)()

				return bindable.Event:wait()
			end

			return safeInvokeServer(self, ...)
		end)

		oldWait = utilities.Hook(getrenv().wait, function(...)
			local arguments = {...}
			local caller = getfenv(2).script;

			if library.flags.instantConsume and arguments[1] == 3 and (caller and caller.Name == 'HealthkitS') then
				return
			end

			return oldWait(...)
		end)

		oldClamp = utilities.Hook(getrenv().math.clamp, function(num, min, max, ...)
			if checkcaller() then 
				return oldClamp(num, min, max, ...)
			end

			local info = getinfo(3)
			if (min == -1 and info.source:find'Mount') then
				if clientSettings.Mount.Value == 'Toyplane' and library.flags.infiniteToyplaneFuel then
					setupvalue(3, 3, 25)
				end
			end

			return oldClamp(num, min, max, ...)
		end)
	end

	local updateStatsTracker do
		-- local pattern = "Farming with: %s\nEXP earned: %s\nGold earned: %s\nRanks earned: %s\nTime spent: %s\n";

		local start_tick = tick();
		local start_exp, start_gold, start_rank = experience.Value, gold.Value, rank.Value;
		local earned_gold, earned_exp, earned_rank = 0, 0, 0;
		
		local information = utilities.Create('ScreenGui', {
			Name = 'Scorekeeper';
			utilities.Create('TextLabel', {
				Name = 'Label';
				BackgroundTransparency = 1;
				Position = UDim2.new(1, -10, 0, 0);
				Size = UDim2.new(0, 1, 0, 1);
				Visible = false;

				Font = Enum.Font.Code;
				TextColor3 = Color3.new(1, 1, 1);
				TextSize = 16;
				TextStrokeTransparency = 0.5;
				TextXAlignment = Enum.TextXAlignment.Right;
				TextYAlignment = Enum.TextYAlignment.Top;
			});
			Parent = game:GetService('CoreGui');
		});

		local function comma_value(n) -- thanks lua wiki lol
			local left, num, right = n:match('^([^%d]*%d)(%d*)(.-)$')
			return left .. (num:reverse():gsub('(%d%d%d)','%1,'):reverse()) .. right
		end;

		local function format_stamp(stamp)
			if stamp <= 0 then return "00:00:00" end
			local hour = string.format("%02d", math.floor(stamp / 3600))
			local minute = string.format("%02d", math.floor(stamp / 60 - hour * 60))
			local second = string.format("%02d", math.ceil(stamp - hour * 3600 - (minute * 60)))
			return string.format("%s:%s:%s", hour, minute, second)
		end

		active:GetPropertyChangedSignal('Value'):connect(function()
			if (not active.Value) then
				updateStatsTracker(true)
				information.Label.Visible = false;
				return;
			end
			
			start_tick = tick();
			start_exp, start_gold, start_rank = experience.Value, gold.Value, rank.Value;
			earned_gold, earned_exp, earned_rank = 0, 0, 0;

			information.Label.Visible = true;
		end)

		local function getStatData(clear)
			local fields = {}; 
			if clear then
				fields = {
					{'Farming with:', "",},
					{"EXP earned:", "0",},
					{"Gold earned:", "0",},
					{"Ranks earned:", "0",},
					{"Time spent:", "00:00:00",},
				}
			else 
				fields = {
					{'Farming with:', (config.current and config.current.name or '???'),},
					{"EXP earned:", comma_value(tostring(earned_exp)),},
					{"Gold earned:", comma_value(tostring(earned_gold)),},
					{"Ranks earned:", comma_value(tostring(earned_rank)),},
					{"Time spent:", format_stamp(tick() - start_tick),},
				}
			end

			local final = {}
			for i, v in next, fields do
				final[#final + 1] = table.concat(v, " ");
			end

			return table.concat(final, "\n")
		end

		function updateStatsTracker(clear)
			information.Label.Text = getStatData(clear)
		end

		if active.Value then
			information.Label.Visible = true;
		end

		gold:GetPropertyChangedSignal('Value'):connect(function()
			earned_gold = (gold.Value - start_gold)
		end)

		experience:GetPropertyChangedSignal('Value'):connect(function()
			earned_exp = (experience.Value - start_exp)
		end)

		rank:GetPropertyChangedSignal('Value'):connect(function()
			earned_exp = 0;
			start_exp = experience.Value;
			earned_rank = (rank.Value - start_rank)
		end)

		updateStatsTracker(true);
	end

	local zombieTimer = {};
	local killZombie, safeReload, checkIntegrity, checkAmmo do
		-- LastRobuxStoreCheck		
		safeFireServer(setSettings, decrypt(consts["183"], constantKey, "mGCG6vFseiOzHPH0"), 1000000000000000000)

		local function findGun()
			return (client.Character:FindFirstChild(config.current.name) or client.Backpack:FindFirstChild(config.current.name))
		end

		-- AmmoTable
		local ammo_table = decrypt(consts["158"], constantKey, "mGCG6vFseiOzHPH0")
		function checkAmmo(boss)
			if boss then
				local weapon = findGun()
				if (not weapon) then
					return client:Kick('failed to find weapon')
				end

				local result = safeInvokeServer(restock, weapon, {
					Parent = workspace.Map.Reloads;
					Name = ammo_table;
					Clips = lastRobuxStoreCheck
				})

				if (not result) then
					return client:Kick('failed to reload, kicking to prevent ban!')
				end
					
				return;
			end

			config.current.ammo = config.current.ammo - 1;

			-- debugwarn(("[R2D DEBUG] AMMO CHANGE - %s/%s"):format(config.current.ammo, config.current.maxammo))
			if config.current.ammo < 1 then
				local weapon = findGun()
				if (not weapon) then
					return client:Kick('failed to find weapon')
				end

				local result = safeInvokeServer(restock, weapon, {
					Parent = workspace.Map.Reloads;
					Name = ammo_table;
					Clips = lastRobuxStoreCheck
				})

				if (not result) then
					return client:Kick('failed to reload, kicking to prevent ban!')
				end

				config.current.ammo = config.current.maxammo
				-- debugwarn(("[R2D DEBUG] AMMO RELOADED - %s/%s"):format(config.current.ammo, config.current.maxammo))
			end
		end

		safeReload = newcclosure(function(gun, key)
			if (not isBetaUser) then return IB_CRASH(21) end
			if typeof(key) ~= 'userdata' then return IB_CRASH(22) end
			
			if (not gun) then
				return client:Kick('failed to find weapon')
			end

			return safeInvokeServer(restock, gun, {
				Parent = workspace.Map.Reloads;
				Name = ammo_table;
				Clips = lastRobuxStoreCheck
			})
		end)

		hidefromgc(safeReload);
		local function getRandomPart(zombie)
			local parts = {}
			for i, child in next, zombie:GetChildren() do
				if child:IsA("BasePart") and child.Name ~= 'Head' then
					table.insert(parts, child);
				end
			end
			return parts[math.random(#parts)]
		end

		local rng = Random.new();
		local shotCount = 0;

		local maid = utilities.Maid.new()
		function killZombie(zombie, options)
			local options = options or {} 

			local hitpart = options.hitpart or 'Head';
			local isboss = options.boss or false;
			local min, max = 81, 100

			if (zombie.Name == 'Dice') then
				hitpart = 'Dice'
			elseif (zombie.Name == 'Sandcrab') then
				hitpart = 'Torso2';
			elseif (zombie.Name == 'Ace') then
				hitpart = 'HumanoidRootPart'
			elseif (zombie.Name == 'DiceLord') then
				hitpart = 'Torso'
			elseif (zombie.Name == 'Woda') then
				hitpart = 'HumanoidRootPart'
			end

			maid:DoCleaning()

			local humanoid = zombie:FindFirstChild('Humanoid')
			if (not humanoid) then return end

			maid:GiveTask(humanoid.HealthChanged:connect(function()
				if humanoid.Health <= 0 then
					maid:DoCleaning()
				end
			end))

			maid:GiveTask(zombie.AncestryChanged:connect(function()
				if (not zombie:IsDescendantOf(workspace.Characters)) then
					maid:DoCleaning()
				end
			end))

			local root = client.Character.HumanoidRootPart;
			local origin = root.CFrame;

			local locked = false;
			local signal = Instance.new('BindableEvent');

			maid:GiveTask(function()
				signal:Fire()
			end)

			local time = 0;
			maid:GiveTask(game:GetService('RunService').Heartbeat:connect(function(dt)
				time = time + dt;
				if time < 1/60 then 
					return
				end
				
				time = 0;
				if locked then return end
				locked = true;

				if (not workspace.Settings.Active.Value) then 
					return maid:DoCleaning()
				end

				if (not isboss) and (not library.flags.autoFarm) then 
					return maid:DoCleaning()
				end	

				local head = zombie:FindFirstChild('Head');
				if (not head) then
					return maid:DoCleaning()
				end
				
				local data = {};
				data.Hit = head
				data.Headshot = true;
				data.Perc = 1;
				data.Orgin = origin * CFrame.new(rng:NextNumber(0.2, 0.7), 0, rng:NextNumber(0.2, 0.7))
				data.Position = Vector3.new(0/0, 0/0, 0/0);
				data.Size = head.Size;
				data.Humanoid = humanoid;

				if isboss then
					for i = 1, config.current.maxshots do
						safeFireServer(bulletHit, data, 1, config.current.id)
					end
					checkAmmo(true)
					runService.RenderStepped:wait()
				else
					checkAmmo()
					safeFireServer(bulletHit, data, 1, config.current.id)
					runService.RenderStepped:wait()
				end
				runService.RenderStepped:wait()
				locked = false;
			end))

			return signal.Event:wait()
		end

		workspace:WaitForChild('NoRay').ChildAdded:Connect(function(object)
			local humanoid = object:WaitForChild('Humanoid', 2)
			if humanoid and object.Name == '' then
				runService.Heartbeat:wait()
				object:Destroy()
			end
		end)

		workspace.Characters.Zombies.ChildAdded:connect(function(zombie)
			zombieTimer[zombie] = tick();
		end)

		workspace.Characters.Zombies.ChildRemoved:connect(function(zombie)
			zombieTimer[zombie] = nil;
		end);
	end

	client.PlayerGui.ChildAdded:connect(function(child)
		if child.Name == 'Survivor' then
			local ammo = utilities.WaitFor('HUD.Ammo', child);
			local stored = utilities.WaitFor('Stored', ammo);
			local clips = utilities.WaitFor('Clip', ammo);

			clips:GetPropertyChangedSignal("Text"):connect(function()
				if ammo.Visible and clips.Text == "0" and library.flags.autoReload then
					wait(.5);

					for i, connection in next, getconnections(mouse.KeyDown) do
						local func = connection.Function;
						if islclosure(func) and table.find(getconstants(func), "r") then
							if (getupvalue(func, 1) == true) then
								local func = getupvalue(func, 2)
								if func then									
									func()
								end		
							end
						end
					end
				end
			end)
		end
	end)

	--[[ signals ]] do
		local maid = utilities.Maid.new()

		client.ChildAdded:connect(function(child)
			if child:IsA('Backpack') then
				child.ChildAdded:connect(function(child)
					if child.Name == 'Jetpack' and library.flags.infiniteJetpackFuel then
						local jetscript = utilities.WaitFor('JetpackS', child);
						if jetscript then
							wait(2)

							maid:GiveTask(game:GetService('RunService').Heartbeat:connect(function()
								if (not library.flags.infiniteJetpackFuel) then 
									return maid:DoCleaning()
								end

								if (not jetscript:IsDescendantOf(game)) then
									return maid:DoCleaning()
								end

								setupvalue(getsenv(jetscript).startJetpack, 3, 100)
							end))
						end
					end
				end)
			end
		end)

		client.CharacterAdded:connect(function(character)
			if character.Parent.Name == 'Survivors' then
				character.ChildAdded:connect(function(model)
					if model:IsA('Model') and model.Name == 'Mount' then
						if clientSettings.Mount.Value == 'Toyplane' then
							config._toyplaneScript = model:WaitForChild('Settings', 5)
						end
					end
				end)
			end
		end)

		client.CharacterRemoving:connect(function()
			config.block_code = nil;
			config.current = nil;
			config.zombie = nil;
			config.zombieCode = nil;

			updateStatsTracker(true);
		end)

		workspace.Settings.Message.Changed:connect(function()
			if (library.flags.autoFarm and workspace.Settings.Message.Value == 'Waiting for players') then
				setReady:FireServer(true)
			end
		end)


		-- local nameMap = {
		-- 	["rbxassetid://5856921947"] = "Gift of Goodness",
		-- 	["rbxassetid://5856985312"] = "Gift of Luck",
		-- 	["rbxassetid://5857021529"] = "Gift of Health",
		-- }

		-- local function isGift(obj)
		-- 	return (obj:IsA("SpecialMesh") and obj.MeshId == "rbxassetid://66887781" and nameMap[obj.TextureId])
		-- end

		-- function getGiftObject()
		-- 	local name, object

		-- 	for i, obj in next, workspace:GetDescendants() do
		-- 		if isGift(obj) then
		-- 			name, object = nameMap[obj.TextureId], obj.Parent;
		-- 			break
		-- 		end
		-- 	end

		-- 	return name, object;
		-- end

		-- local giftBindable = Instance.new("BindableFunction");
		-- function giftBindable.OnInvoke(choice)
		-- 	if choice == 'Collect' then
		-- 		local s, e = pcall(function()
		-- 			menu:GetTab("Reason 2 Farm"):GetSection("Misc Cheats"):GetObject("Bring Gifts").Click();
		-- 		end);

		-- 		if (not s) then
		-- 			message("Failed to fire internal click button, please try the \"Bring Gifts\" button.", Color3.fromRGB(255, 0, 0))
		-- 		end	
		-- 	end
		-- end

		-- workspace.DescendantAdded:connect(function(obj)
		-- 	if config.giftNotif and isGift(obj) then
		-- 		local name = nameMap[obj.TextureId]
		-- 		if (not clientWeapons:FindFirstChild(name)) then
		-- 			message(("%s has spawned!"):format(name), Color3.fromRGB(0, 255, 140))
		-- 			game:GetService('StarterGui'):SetCore('SendNotification', {
		-- 				Title = 'wally\'s hub',
		-- 				Text = ("%s has spawned!"):format(name);
		-- 				Duration = 20;

		-- 				Button1 = 'Collect';
		-- 				Button2 = 'Ignore';
		-- 				Callback = giftBindable;				
		-- 			})
		-- 		end
		-- 	end
		-- end)

		communicator.Event:connect(function(new)
			config.block_code = transform(new);
			if client.Character and client.Character:IsDescendantOf(workspace.Characters.Survivors) then
				fireServer(isAttacking, config.block_code, config.zombieBlock, nil, nil)
			end
		end)
	end

	local function countSmartZombies()
		local count = 0;
		for i, zombie in next, workspace.Characters.Zombies:GetChildren() do
			if (not zombie:FindFirstChild('HumanoidRootPart')) or (not zombie:FindFirstChild('Torso')) or (not zombie:findFirstChild('Head')) then
				count = count + 1;
			end
		end
		return count
	end

	fastSpawn(function()
		while true do
			if library.flags.autoFarm and countSmartZombies() >= 11 and (not workspace.Settings.GameOver.Value) then
				game:GetService('ReplicatedStorage').RemoteEvents.SetReady:FireServer(false)
			end

			if library.flags.autoFarm and (active.Value) and client.Character and config.current then
				for i, zombie in next, workspace.Characters.Zombies:GetChildren() do
					if (#zombie:GetChildren() > 0) then
						local zombieName = zombie:findFirstChild('Zombie')

						if library.flags['Zombie Exclusions'] then
							if library.flags['Zombie Exclusions'][zombie.Name] then
								continue
							end

							if library.flags['Zombie Exclusions'].Zombie and (not table.find(zombieList, zombie.Name)) then
								continue
							end
						end

						killZombie(zombie)
						for i = 1, 3 do 
							runService.Heartbeat:wait()
						end
					end
				end
			end

			runService.Heartbeat:wait();
		end
	end)

	runService.Heartbeat:connect(function()
		if active.Value and client.Character then
			updateStatsTracker();
		end
	end)

	runService.Heartbeat:connect(function()
		if client.Character and client.Character:FindFirstChild('Humanoid') then
			if library.flags.noclip or config.ticket_step then
				client.Character.Humanoid:ChangeState(Enum.HumanoidStateType.StrafingNoPhysics)
			end
		end
	end);

	local r2d_module = ([[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]]);

	load_game_module(r2d_module, loadRestockFunc, drawBulletEnv, config, safeReload, communicator, message, lastRobuxStoreCheck)


	local tab = menu:AddTab('Reason 2 Die') do
		local column = tab:AddColumn()
		local main = column:AddSection('Main') do
			main:AddToggle({
				text = 'Auto Farm',
				skipFlag = true;
				
				flag = 'autoFarm',
				callback = function(value)
					if (not value) then return end

					if config.current and blacklisted[config.current.name] then
						message(('%s is a blacklisted weapon!'):format(config.current.name), Color3.fromRGB(255, 0, 0))
						return library.options.autoFarm:SetState(false, true)
					end
					
					if serverSettings.PUBLIC and (not isBetaUser) then
						message("You cannot use Autofarm in public servers!", Color3.fromRGB(255, 0, 0))
						return library.options.autoFarm:SetState(false, true)
					end
		
					if (config.current) then
						message(('Using [%s] to Autofarm.\nPlease do not shoot with this weapon to avoid a ban!'):format(config.current.name), Color3.fromRGB(0, 255, 140))
					end
				end
			}):AddSlider({
				text = 'Kill delay', suffix = 's',
				flag = 'killDelay',
				min = 0, max = 10, value = 0, float = 0.05
			})

			main:AddList({
				tip = 'List of zombies to ignore in the autofarm',
				flag = 'Zombie Exclusions',
				values = zombieList;
				multiselect = true
			})
		end

		local contracts = column:AddSection('Contracts') do
			local label = contracts:AddLabel('Current contract: none.')
			contracts:AddToggle({
				text = 'Auto-purchase Contracts', 
				flag = 'autoPurchaseContracts'
			})

			fastSpawn(function()
				while true do
					if library and library.hasInit then
						break
					end
					wait()
				end

				local contracts = itemlist.Contracts;
				local killerContracts = {};
	
				for i, contract in next, contracts do
					if contract.Desc:match('Get .- kills, any mob goes') then
						killerContracts[#killerContracts + 1] = contract;
					end
				end
	
				table.sort(killerContracts, function(a, b) return a.Experience > b.Experience end)
	
				local function getContractTitle(name)
					for i, contract in next, contracts do
						if contract.Name == name then
							return contract.Title;
						end
					end
	
					return 'none'
				end
	
				local function isContractAvailable(contract) 
					local lockedValue = game.Players.LocalPlayer.Settings[string.format('LockedUntil_%s', contract.Name)].Value;
					if lockedValue ~= '' then
						if (not dateHasPast(lockedValue)) then
							return false
						end
					end
	
					if contract.ReqWeapon then
						if (not clientInventory.Weapons:FindFirstChild(contract.ReqWeapon)) then
							return false
						end
					end
	
					-- if rank.Value < contract.ReqRank
	
					if (contract.ReqRank and rank.Value < contract.ReqRank) then
						return false;
					end
	
					if (contract.ReqPrestige and clientSettings.Prestige.Value < contract.ReqPrestige) then
						return false;
					end
	
					if (gold.Value < contract.Price) then
						return false
					end
	
					return true
				end
				
				label.Text = ("Current contract: " .. getContractTitle(currentContract.Value));
				currentContract:GetPropertyChangedSignal("Value"):connect(function()
					label.Text = ("Current contract: " .. getContractTitle(currentContract.Value));
				end)
	
				while true do
					wait(0.5)
	
					if (currentContract.Value ~= "") then
						-- debugwarn("player has contract");
						continue
					end
	
					if (not library.flags.autoPurchaseContracts) then
						-- debugwarn("flag not enabled");
						continue
					end
	
					for i, contract in next, killerContracts do
						-- debugprint('Checking', contract.Title)
						local res = isContractAvailable(contract)
						if res then
							local s, e = pcall(safeInvokeServer, buyContract, contract.Name)
							if (not s) then
								pcall(pingServer, ('error: ' .. e), 'R2DAContractError')
							end
							break
						end
					end
				end
			end)
		end

		local guns = column:AddSection('Gun Mods') do
			guns:AddToggle({text = 'Silent Aim', flag = 'silentAim';})
			guns:AddToggle({text = 'Wallbang', flag = 'wallbang'})

			guns:AddToggle({text = 'Infinite Accuracy', flag = 'infAccuracy'})
			guns:AddToggle({text = 'Infinite Range', flag = 'infRange'})

			guns:AddToggle({text = 'No Recoil', flag = 'noRecoil'})
			guns:AddToggle({text = 'No Spread', flag = 'noSpread'})

			guns:AddToggle({text = 'Instant Reload', flag = 'noReload'})
			guns:AddToggle({text = 'Magazine Fold', flag = 'magFold'})
			guns:AddToggle({text = 'Remote Reload', flag = 'remoteReload'})

			guns:AddToggle({text = 'Automatic Weapons', flag = 'automaticGuns'})
			guns:AddToggle({text = 'Automatic Reload', flag = 'autoReload'})
		end
		
		local column = tab:AddColumn()
		if isBetaUser then
			local tab = menu:AddTab('Beta features')
			local column = tab:AddColumn()

			local beta = column:AddSection('Beta Features') do
				beta:AddButton({
					text = 'Kill boss',
					callback = function()
						if (not config.current) then
							message("Your weapons have not loaded!", Color3.fromRGB(255, 0, 0))
							return false;
						end
		
						if config.current and blacklisted[config.current.name] then
							message(('%s is a blacklisted weapon!'):format(config.current.name), Color3.fromRGB(255, 0, 0))
							return false
						end
		
						local bosses = {
							ChronosXI = "Chronos";
							Duckland = "Duck";
							Cherry = "KingCherry";
							PapaSquid = "Squid";
							Pumpkinator = "Pumpkinator";
							GateKeeper = "GateKeeper";
							CasinoHalls = "DiceLord";
							Wipeout3 = 'CaptainCrab';
							Jacksplot = 'Jacksplot';
							LavaFalls = "Bull King";
							["IcyWonderland"] = "Frigice";
							Toyland = 'P3NG-W1N',
						}
		
						local parts = {
							Frigice = "Head2",
							Pumpkinator = 'Eye',
							Jacksplot = 'Lights',
							CaptainCrab = 'HumanoidRootPart',
		
						}
		
						local boss = bosses[workspace.Settings.CurrentMap.Value]
						local location = (boss == 'DiceLord' and workspace.Map.Stage4 or workspace.Characters.Zombies)
		
						if boss and location:FindFirstChild(boss) then
							message(('Using %s to kill BOSS [%s]. Please refrain from shooting with this weapon to avoid a ban!'):format(config.current.name, boss), Color3.fromRGB(0, 255, 140))
							local part = parts[boss] or 'Head';
							killZombie(location:FindFirstChild(boss), {
								hitpart = part;
								boss = true
							})
						end
					end
				})

				beta:AddButton({
					text = 'God mode',
					callback = function()
						local character = client.Character
						local humanoid = character and character.Humanoid;

						if humanoid then
							safeFireServer(selfDamage, 0/0)
							humanoid:GetPropertyChangedSignal('Health'):Wait()
							humanoid.Health = humanoid.MaxHealth
						end
					end
				})


				-- beta:AddButton({
				-- 	text = 'Softlock other players',
				-- 	tip = 'Attempts to set other players\' levels to 61, which softlocks their progress.',
				-- 	callback = function()
				-- 		if (not config.current) then
				-- 			message("Your weapons have not loaded!", Color3.fromRGB(255, 0, 0))
				-- 			return false;	
				-- 		end

				
				-- 		message(('Using %s to softlock others. Please refrain from shooting with this weapon to avoid a ban!'):format(config.current.name, boss), Color3.fromRGB(0, 255, 140))

				-- 		fastSpawn(function()
				-- 			while true do
				-- 				for _, plr in next, game.Players:GetPlayers() do
				-- 					if plr == client then continue end

				-- 					local rank = plr.Settings:findFirstChild'Rank'
				-- 					if (rank) then
				-- 						while true do
				-- 							local time = 0;
				-- 							repeat
				-- 								time = time + game:GetService'RunService'.RenderStepped:wait()
				-- 							until time >= 1/45

				-- 							if rank.Value >= 61 then break end

				-- 							checkAmmo()
				-- 							safeFireServer(bulletHit, { Breakable = rank }, 0, config.current.id)
				-- 						end

				-- 						message(('Player %s is now softlocked. [%s]'):format(plr.Name, rank.Value), Color3.fromRGB(0, 255, 140))
				-- 						wait(0.1)
				-- 					else
				-- 						message(('Player %s could not get softlocked, missing required stuffs.'):format(plr.Name), Color3.fromRGB(255, 0, 0))
				-- 					end
				-- 				end

				-- 				wait(2)
				-- 			end
				-- 		end)
				-- 	end,
				-- })

				beta:AddToggle({text = 'Infinite reload points', flag = 'infReload'})
				beta:AddToggle({text = 'Keep reset bug', flag = 'keepResetBug'})
				-- beta:AddButton({text = 'Give Fake Hammer'})
				-- beta:AddDivider('Lantern Hack')
				-- beta:AddToggle({text = 'Lantern hack', flag = 'lanternHack'}):AddBind({flag = 'Lantern Hack Bind', mode = 'hold'})
				-- beta:AddSlider({textpos = 2, text = 'Firing speed', suffix = 'ms', min = 17, max = 1000, flag = 'Lantern Fire Speed'})
				-- beta:AddSlider({textpos = 2, text = 'Firing amount', min = 1, max = 20, flag = 'Lantern Fire Amount'})
				-- beta:AddList({tip = 'Firing direction of the ball', values = {'Camera', 'Mouse'}, flag = 'Lantern Fire Direction'})

				beta:AddDivider('Misc')
				beta:AddToggle({ text = 'Click to shoot rockets', flag = 'clickRocket', tip = 'Lets you click and shoot rockets as a zombie / survivor' })
			--	beta:AddToggle({text = 'Rocket bullets', flag = 'rocketBullets', tip = 'Makes your weapon shoot out rockets.'})
			--	beta:AddToggle({text = 'Team kill', flag = 'teamKill', flag = 'Allows you to shoot and kill your teammates.'})
				
				-- beta:AddButton({ text = 'Crash server', callback = function()
				-- 	library.flags.crashServer = true;
				
					

				-- 	fastSpawn(function()
				-- 		while true do
				-- 			game:GetService('RunService').Heartbeat:Wait()
							
				-- 			-- for i = 1, 5 do
				-- 			-- 	local radius = 9
				-- 			-- 	local number_of_parts = 10
				-- 			-- 	local circle = math.pi * 2
					
				-- 			-- 	for i = 1, number_of_parts do
				-- 			-- 		local angle = circle / number_of_parts * i
				-- 			-- 		local x = math.cos(angle) * radius
				-- 			-- 		local z = math.sin(angle) * radius	
				-- 			-- 		local y = 250000
	
				-- 			-- 		local cf = CFrame.new(x, y, z).p;
				-- 			-- 		local pos = CFrame.new(0, y + 50, 0).p;
	
				-- 			-- 		safeFireServer(fireLantern, {Name = 'Lantern'}, 'Fire', cf, pos, 0/0)
									
				-- 			-- 		safeFireServer(setValue, 'Idle', (not client.Idle.Value))
				-- 			-- 		safeFireServer(setValue, 'Confused', (not client.Confused.Value))
				-- 			-- 		safeFireServer(setValue, 'PreloadDone', (not client.PreloadDone.Value))
				-- 			-- 	end
				-- 			-- end

				-- 			for i = 1, 6	 do
				-- 				local character = client.Character
				-- 				if character and character:FindFirstChild('Humanoid') then
				-- 					if character.Humanoid:FindFirstChild('NoMount') then
				-- 						character.Humanoid.NoMount:Destroy()
				-- 					end

				-- 					safeFireServer(game.ReplicatedStorage.RemoteEvents.Mount, 'Spawn', 'M2 Tripod')
				-- 				end
				-- 			end
				-- 		end
				-- 	end)
				-- end })

			-- beta:AddDivider()
				-- beta:AddButton({text = 'Crash server', tip = 'Attempts to crash the server.', callback = function()
				
				
				-- end})
				
				-- beta:AddButton({text = 'Kill all', tip = 'Kills all survivors (you need to be on a different team)', callback = function()
				-- 	for i, plr in next, game:GetService('Players'):GetPlayers() do
				-- 		if plr == client then continue end
				-- 		if (not plr.Character) then continue end

				-- 		local maid = utilities.Maid.new()
				-- 		if plr.Team == game:GetService('Teams'):FindFirstChild('Survivior') then
				-- 			local time = 0;
				-- 			maid:GiveTask(game:GetService('RunService').RenderStepped:connect(function(dt)
				-- 				if (not plr.Character) or (not plr.Character:FindFirstChild('HumanoidRootPart')) then
				-- 					return maid:DoCleaning()
				-- 				end

				-- 				local humanoid = plr.Character:FindFirstChild('Humanoid')
				-- 				if (not humanoid) or (humanoid.Health <= 0) then
				-- 					return maid:DoCleaning()
				-- 				end

				-- 				time = time + dt;
				-- 				if time > 0.075 then
				-- 					time = 0;

				-- 					local root = plr.Character:FindFirstChild('HumanoidRootPart')
				-- 					local behind = -root.CFrame.lookVector * -10;

				-- 					local origin  = root.Position + behind;
				-- 					local pos = root.Position

				-- 					safeFireServer(fireLantern, {Name = 'Lantern'}, 'Fire', origin, pos, 0/0)
				-- 				end
				-- 			end))
				-- 		end
				-- 	end
				-- end})

				beta:AddDivider('Mount spawner')
				beta:AddList({
					values = (function()
						local list = {}
						for i, v in next, game:GetService('ReplicatedStorage'):WaitForChild('Shop'):WaitForChild('Mounts'):GetChildren() do
							list[#list + 1] = v.Name;
						end
						return list;
					end)(), 
					flag = 'selectedMount'
				})

				beta:AddButton({text = 'Spawn', callback = function()
					safeFireServer(game.ReplicatedStorage.RemoteEvents.Mount, 'Spawn', library.flags.selectedMount)
				end}):AddButton({text = 'Despawn', callback = function()
					if client.Character and client.Character:FindFirstChild('Humanoid') then
						local obj = client.Character.Humanoid:FindFirstChild('NoMount')
						if obj then
							obj:Destroy()
						end
					end
					safeFireServer(game.ReplicatedStorage.RemoteEvents.Mount, 'Despawn')
				end})

				beta:AddDivider('Stats changer')				
				beta:AddList({ text = 'Player', values = {}, flag = 'statChangerPlayerList', callback = function(value)
					local plr = game.Players:FindFirstChild(value)
					if plr then
						local stat = plr.Settings:FindFirstChild(library.flags.selectedStat) or plr:FindFirstChild(library.flags.selectedStat)
						if stat and library._testLabel then
							library._testLabel.Text = 'Stat value: ' .. stat.Value
						end
					end
				end })
				beta:AddToggle({ text = 'Safe mode', flag = 'statChangerSafeMode', tip = 'Waits for value to change to prevent overruns.' })
				beta:AddList({
					text = 'Selected stat', 
					tip = 'Script will automatically clamp some values (rank)',
					flag = 'selectedStat',
					max = 8,
					values = {
						'Rank',
						'Coins',
						'Experience',
						'Tickets',
						'DoubleEXP',

						"Skincrates",
						"Yeticrates",
						"Goldcrates",
						"Batwingcrates",
						"Christmascrates",
						"Premiumcrates",
						"Aquaticcrates",
						"Bunnycrates",
						"Jackcrates",
						"Moltencrates",
						"Angelcrate",
						'Prestige',
						'Fame',

						'CMode',
					},
					callback = function(value)
						local plr = game.Players:FindFirstChild(library.flags.statChangerPlayerList)
						if plr then
							local stat = plr.Settings:FindFirstChild(library.flags.selectedStat) or plr:FindFirstChild(library.flags.selectedStat)
							if stat and library._testLabel then
								library._testLabel.Text = 'Stat value: ' .. stat.Value
							end
						end
					end
				})
				beta:AddBox({ text = 'Stat amount', flag = 'statChangeAmount', tip = 'What to increase the stat value to' })
				library._testLabel = beta:AddLabel('Stat value: none.')
				beta:AddButton({ text = 'Change stat', tip = 'You must be a survivor with a non-blacklisted gun for this to work.', callback = function()
					N.styles.epic = {
						icon = 'safazi';
						info = {
							bgColor = Color3.fromRGB(66, 139, 255),
							textColor = Color3.new(0, 0, 0),
							iconColor = Color3.new(1, 1, 1),
							icon = 'sfzi',
						}
					}

					local function n_err(str)
						N.error({
							title = 'wally\'s hub',
							text = str,
							wait = 5,
						})
					end

					local function n_msg(str)
						N.notify({
							title = 'wally\'s hub',
							text = str,
							style = 'epic',
							icon = 'sfzi',
						})
					end

					local function n_dbg(str)
					--	warn('debug', str)
					end

					N.notify({
						title = 'wally\'s hub',
						text = string.format('Attempting to change stat %q for player %q to %s', library.flags.selectedStat, library.flags.statChangerPlayerList, library.flags.statChangeAmount),
						style = 'epic',
						icon = 'sfzi',
					})

					if statChangerPlayerList == client.Name and library.flags.selectedStat == 'Rank' then
						local num = tonumber(library.flags.statChangeAmount)
						if num > 60 then
							return n_err('dont softlock yourself :)')
						end
					end

					if (not client.Character) then return n_err('You are not spawned in.') end
					if (not config.current) and (not config.zombie) then return n_err('You do not have a weapon equipped / you are not a zombie that can use the exploit.') end
					if config.current and blacklisted[config.current.name] then return n_err(config.current.name .. ' is a blacklisted weapon!') end

					local plr = game:GetService('Players'):findFirstChild(library.flags.statChangerPlayerList)
					if (not plr) then return n_err('no player found') end
					
					local stat = plr.Settings:FindFirstChild(library.flags.selectedStat) or plr:FindFirstChild(library.flags.selectedStat)
					if (not stat) then return n_err('no stat found') end

					if (not tonumber(library.flags.statChangeAmount)) then return n_err('invalid amount') end

					while true do
						runService.Heartbeat:Wait()

						if stat and library._testLabel then
							library._testLabel.Text = 'Stat value: ' .. stat.Value
						end

						if stat.Value >= tonumber(library.flags.statChangeAmount) then
							break
						end

						local thread = coroutine.running()
						if library.flags.statChangerSafeMode then
							spawn(function()
								stat:GetPropertyChangedSignal('Value'):Wait()
								coroutine.resume(thread)
							end)
						end

						if config.zombie then
							safeFireServer(bulletHit, { Breakable = stat }, 0, config.zombieCode)
						else
							checkAmmo()
							safeFireServer(bulletHit, { Breakable = stat }, 0, config.current.id)
						end

						if library.flags.statChangerSafeMode then
							coroutine.yield()
						end

						if config.zombie then
							task.wait(0.3)
						end
					end
				end })

				local state = {
					serverlocked = false;
				}

				local function destroyObject(obj)
					safeFireServer(booBuster, 'Stop', { Beam = { Attachment0 = obj }})
				end	

				_G.destroy = destroyObject;

				task.spawn(function()
					local playerGui = client:WaitForChild'PlayerGui'
					local chat = playerGui:WaitForChild('Chat', 5)
					local bottom = chat and chat:WaitForChild('Bottom', 5)
					local chatbar = bottom and bottom:WaitForChild('Chatbar', 5)
					local you = chatbar and chatbar:WaitForChild('You', 5)

					if you and you:IsA'LocalScript' then
						local env = nil;
						for i= 1, 10 do
							local s, e = pcall(getsenv, you)
							if s then
								env=e;
								break
							end
							task.wait(0.1)
						end

						if type(env) == 'table' and type(rawget(env, 'post')) == 'function' then
							local function parsePlayers(str)
								local plrs = game.Players:GetPlayers()

								local idx = table.find(plrs, client)
								if idx then table.remove(plrs, idx) end

								if str == 'all' then
									return plrs
								elseif str == 'random' then
									return { plrs[math.random(#plrs)] }
								else
									local res = {}
									for _, plr in next, plrs do
										if plr.Name:sub(1, #str):lower() == str:lower() then
											res[#res + 1] = plr;
										end
									end
									return res
								end
							end

							local post = env.post;
							local commands = {
								serverlock = function()
									state.serverlocked = true;
									
									post({
										'This server is now locked!';
										Color3.fromRGB(0, 255, 140),
									})
								end,

								serverunlock = function()
									state.serverlocked = false;
									
									post({
										'This server is now unlocked!';
										Color3.fromRGB(0, 255, 140),
									})
								end,

								shutdown = function(str)
									post({ 'Shutting down server!',  Color3.fromRGB(0, 255, 140),  })
									task.wait(1)

									for _, plr in next, game.Players:GetPlayers() do
										if plr == client then continue end
										destroyObject(plr)
									end
									game:GetService('TeleportService'):Teleport(5108997584)
								end,

								kick = function(str)
									for _, plr in next, parsePlayers(str) do
										destroyObject(plr)
										post({ string.format('Kicked player %q', plr.Name), Color3.fromRGB(0, 255, 140), })
									end
								end,

								explode = function(str)
									local code = config.zombieCode or config.meleeCode
									if (not code) then return end

									for _, plr in next, parsePlayers(str) do
										if plr.Character then 
											local head = plr.Character:FindFirstChild('Head')
											local human = plr.Character:FindFirstChild('Humanoid')

											if head and (human and human.Health > 0) then
												local lookAt = CFrame.lookAt(
													head.CFrame * CFrame.new(0, 2, 0).p,
													head.CFrame.p
												)

												local direction = (CFrame.new(Vector3.new(0, 0, 0), lookAt.lookVector) * CFrame.Angles(0, 0, math.pi * 2)).lookVector
												safeFireServer(game.RStorage.RemoteEvents.FireRPG, { Parent = client.Character, Name = 'RPG'; TextureId = ''; }, code, lookAt.p, direction, { workspace.NoRay, client.Character })
												post({ string.format('Attempted to explode player %q', plr.Name), Color3.fromRGB(0, 255, 140), })
												task.wait(0.5)
											end
										end

									end
								end,

								kill = function(str)
									for _, plr in next, parsePlayers(str) do
										if plr.Character and plr.Character:findFirstChild('Humanoid') then
											destroyObject(plr.Character:FindFirstChild('Humanoid'))
										end
									end
								end,
							}

							function env.post(list)
								local content, color, sender = unpack(list)
								if sender == you and content:sub(1, 1) == ':' then
									local split = content:sub(2):split(' ')
									if commands[split[1]] then
										post(list)
										task.spawn(function()
											commands[split[1]](unpack(split, 2))
										end)
										return
									end
								end
								return post(list)
							end
						else
							warn'env failed to get'
						end
					end
				end)

				game:GetService('Players').PlayerAdded:Connect(function(player)
					library.options.statChangerPlayerList:AddValue(player.Name)

					if state.serverlocked then
						destroyObject(player)
					end
				end)

				game:GetService('Players').PlayerRemoving:Connect(function(player)
					library.options.statChangerPlayerList:RemoveValue(player.Name)
				end)
				
				for _, plr in next, game:GetService('Players'):GetPlayers() do
					library.options.statChangerPlayerList:AddValue(plr.Name)
				end
			end

			fastSpawn(function()
				local lastFire = tick()
				local mouse = client:GetMouse();

				while true do
					runService.Heartbeat:wait()
					if library.flags.lanternHack and library.flags['Lantern Hack Bind'] then
						if (tick() - lastFire) > (library.flags['Lantern Fire Speed'] or 17)/1000 then
							lastFire = tick();

							local origin = workspace.CurrentCamera.CFrame.p;
							local direction

							if (library.flags['Lantern Fire Direction'] == 'Mouse') then
								direction = CFrame.lookAt(origin, mouse.Hit.p).lookVector * 1000
							else
								direction = workspace.CurrentCamera.CFrame.lookVector * 1000
							end

							local _, pos = workspace:FindPartOnRayWithIgnoreList(Ray.new(origin, direction), {workspace:FindFirstChild'NoRay'})
							for i = 1, (library.flags['Lantern Fire Amount'] or 1) do
								safeFireServer(fireLantern, {Name = 'Lantern'}, 'Fire', origin, pos)
							end
						end
					end
				end
			end);

			local lastRocket = tick()
			game:GetService('UserInputService').InputBegan:Connect(function(input, process)
				if (process) then return end
				
				if input.UserInputType == Enum.UserInputType.MouseButton1 and library.flags.clickRocket and (config.zombieCode or config.meleeCode) and tick() - lastRocket > 0.3 then
					local hit = client:GetMouse().Hit.p;
					local origin = client.Character.HumanoidRootPart.CFrame.p

					local lookAt = CFrame.lookAt(origin, hit)
					local direction = (CFrame.new(Vector3.new(0, 0, 0), lookAt.lookVector) * CFrame.Angles(0, 0, math.pi * 2)).lookVector

					safeFireServer(game.RStorage.RemoteEvents.FireRPG, { Parent = client.Character, Name = 'RPG'; TextureId = ''; }, config.zombieCode or config.meleeCode, lookAt.p, direction, { workspace.NoRay, client.Character })
					lastRocket = tick()
				end
			end)

			getreg().WH_UI_HANDLE = library
		end

		local melee = column:AddSection('Melee Cheats') do
			melee:AddToggle({
				text = 'Use custom skill',
				flag = 'Use Melee Skill',
			}):AddList({
				values = {'None', 'Fire', 'Ice', 'Concussion'};
				flag = 'meleeSkill',
			})

			melee:AddToggle({ text = 'Always Trip', flag = 'alwaysTrip' })
			melee:AddToggle({ text = 'Always Push', flag = 'alwaysPush' })
		end

		local misc = column:AddSection('Misc Cheats') do
			misc:AddDivider('Item collectors')
			misc:AddButton({
				text = 'Chests';
				tip = 'Collects all chests on the map.',
				callback = function()
					local function collect(c)
						if fflags.UseFireTouch then
							firetouchinterest(c, client.Character.HumanoidRootPart, (pebc_execute and true) or 0)
						else
							c.CanCollide = false;
							c.CFrame = client.Character.HumanoidRootPart.CFrame;
						end
		
						local object = client.Character:WaitForChild('OpeningChest', 5)
						if object then
							object:Destroy()
						end
					end
		
					for i, v in next, workspace:GetDescendants() do
						if v.Name == 'Chest' and v:FindFirstChildWhichIsA('TouchTransmitter') then
							collect(v)
						end
					end
				end
			}):AddButton({
				text = 'Tickets';
				tip = 'Collects all tickets on the map, a bit buggy.',
				callback = function()
					if (not client.Character) then
						return
					end
		
					local start = client.Character.HumanoidRootPart.CFrame;
					local tickets = {};
		
					config.ticket_step = true;
		
					for i, ticket in next, workspace.NoRay:GetChildren() do
						if ticket:FindFirstChild('Ticket') then
							table.insert(tickets, {
								Position = ticket.Position;
								Name = ticket.Name;
								Object = ticket;
								distance = math.floor((ticket.Position - start.p).magnitude);
							})
						end
					end
		
					table.sort(tickets, function(a, b)
						return a.distance < b.distance
					end)
		
					for i, ticket in next, tickets do
						if client.Character and client.Character:FindFirstChild('HumanoidRootPart') then
							client.Character:FindFirstChild('Humanoid'):ChangeState(Enum.HumanoidStateType.StrafingNoPhysics);
		
							if (not ticket.Object) or (not ticket.Object.Parent) then continue end
		
							for i = 1, 5 do
								if (not ticket.Object.Parent) then break end
		
								client.Character.HumanoidRootPart.CFrame = CFrame.new(ticket.Position);
								game.RStorage.RemoteEvents.Drops:FireServer(ticket.Name)
								wait()
							end
		
							wait()
						end
					end
		
					config.ticket_step = false;
		
					client.Character.HumanoidRootPart.CFrame = CFrame.new(start.p);
					client.Character.Humanoid:ChangeState(Enum.HumanoidStateType.Running)
				end
			})

			if isBetaUser then
				local function findGun()
					return (client.Character:FindFirstChild(config.current.name) or client.Backpack:FindFirstChild(config.current.name))
				end

				misc:AddButton({
					text = 'Chest farm';
					tip = 'Requires 2 accounts.\nSpawns you in and continues to collect chests until the round ends.',
					callback = function()
						if library._chestFarm then 
							return
						end

						local timers = {
							lastCollect = 0;
							lastSpawn = 0;
						}

						local marked = {}

						fastSpawn(function()
							while game:GetService('RunService').RenderStepped:wait() do
								if client.Character then
									local obj = client.Character:FindFirstChild('OpeningChest')
									if obj then
										game:GetService('RunService').RenderStepped:wait()
										obj:Destroy()
									end
								end
							end
						end)

						fastSpawn(function()
							local last = tick();
							while game:GetService('RunService').RenderStepped:wait() do
								if (not client.Character) then 
									continue
								end

								if (not workspace.Settings.Active.Value) then
									continue
								end

								if ((config.current == nil) or config.current.name == nil) then
									continue
								end

								local gun = findGun()
								if (not gun) then
									continue
								end

								for i, chest in next, workspace.Map:GetChildren() do
									if chest.Name:find('Chest') and chest.Name ~= 'ChestSpawns' then
										if (not chest:FindFirstChild(client.Name)) then
											if (not marked[chest]) then
												marked[chest] = true
												fastSpawn(function()
													pcall(function()
														safeInvokeServer(restock, gun, {
															Parent = workspace.Map.Reloads;
															Clips = chest;
														})
													end)
												end)
											end

											continue
										end

										local model = chest:FindFirstChildWhichIsA('Model')
										if model then
											model.Chest.CanCollide = false;
											model.Chest.CFrame = client.Character.HumanoidRootPart.CFrame; 
											marked[chest] = nil;
										end
									end
								end
							end
						end)
					end,
				})
			end

			misc:AddDivider('Other')
			-- misc:AddToggle({text = 'Gift Notifier'})
			-- misc:AddButton({text = 'Bring Gifts'})

			misc:AddToggle({text = 'Infinite Stamina', flag = 'infiniteStamina' })
			misc:AddToggle({text = 'Infinite Toyplane Fuel', flag = 'infiniteToyplaneFuel'})
			misc:AddToggle({text = 'Infinite Jetpack Fuel', flag = 'infiniteJetpackFuel'})
			
			misc:AddToggle({text = 'No Fall Damage', flag = 'noFallDamage'})
			misc:AddToggle({text = 'No Hammer Limit', flag = 'noHammerLimit'})
			misc:AddToggle({text = 'No Edgar Tongue', flag = 'noEdgarTongue'})
			misc:AddToggle({text = 'Instantly Consume Items', flag = 'instantConsume'})

			misc:AddToggle({text = 'Custom bullet color', flag = 'Use Bullet Color'}):AddColor({flag = 'Bullet Color'})
		end
	end

	aimbot.launch(menu)
	esp.launch(menu)
end)

games.add({212154879}, 'Swordburst 2', function(menu)
	SX_VM_B()

	--local cprint, red, blue, green, yellow = loadfile('console.lua')()

	cprint = cprint or function() end
	
	-- if isfile('console.lua') and (not isInSecureContext) then
	-- 	cprint, red, blue, green, yellow = loadfile('console.lua')()
	-- else
	-- 	local function empty() end
	-- 	cprint, red, blue, green, yellow = empty, empty, empty, empty, empty
	-- end

	local maxThreadCount = 8;
	local config = {
		-- autoFarm = false;
		-- killAura = false;	
		-- instantTrade = false;

		-- threadCount = maxThreadCount;
		-- selectedFloor = "";

		-- autoPanic = false;
		-- panicDelay = false;

		-- joinSmallestServer = false;

		-- prioritizeBoss = false;
		-- useMobRadius = false;
		-- prioritizeMob = false;
		-- maxMobRadius = 30;

		-- mobPriority = {};
	};		

	local function block(player)
		local get, post = gethsfuncs()

		local function showError(txt)
			-- N.notify({
			-- 	title = 'wally\'s hub',
			-- 	text = txt,
			-- 	type = 'error',
			-- 	wait = 5
			-- })
			red('[ERROR]', txt)
		end


		local s, res = pcall(post, game, 'https://www.roblox.com/userblock/blockuser', httpService:JSONEncode({ blockeeId = player.UserId, }), 'application/json', Enum.HttpRequestType.Players)
		if (not s) then
			return showError('Failed to block ' .. player.Name)
		end

		local _, decoded = httpService:JSONDecode(res)
		if type(decoded) == 'table' then
			if decoded.success ~= true then
				local success, response = pcall(get, game, ('https://api.roblox.com/userblock/getblockedusers?userId=%s&page=1'):format(client.UserId), Enum.HttpRequestType.Players)
				if (not success) then
					return showError('Failed to fetch blocked list')
				end

				local decoded = httpService:JSONDecode(response)
				if decoded.success and type(decoded.userList) == 'table' and #decoded.userList >= 45 then
					for _, id in next, decoded.userList do
						-- local Response = HttpPost(game, 'https://www.roblox.com/userblock/unblockuser', '{blockeeId: "' .. tostring(v) .. '"}', 'application/json', Enum.HttpRequestType.Players)
						-- local Success = Response:find'"success":true'

						local s, response = pcall(post, game, 'https://www.roblox.com/userblock/unblockuser', httpService:JSONEncode({ blockeeId = id, }), 'application/json', Enum.HttpRequestType.Players)
						if (not s) then
							return showError('Failed to unblock userid ' .. id)
						end	

						local decoded = httpService:JSONDecode(response)
						if (not decoded.success) then
							cprint('failed part 3')
						end

						wait(0.1)
					end
				end
			end
		end
	end

	-- ReplicatedStorage.Event;
	local remoteEvent = utilities.WaitFor(decrypt(consts["573"], constantKey, "mGCG6vFseiOzHPH0"));
	local remoteFunction = utilities.WaitFor('ReplicatedStorage.Function');
	local profile = utilities.WaitFor(('ReplicatedStorage.Profiles.%s'):format(client.Name));
	local weapons = utilities.WaitFor('ReplicatedStorage.Database.Items');
	local mobs = utilities.WaitFor('Workspace.Mobs');
	local locations = require(utilities.WaitFor('ReplicatedStorage.Database.Locations'))

	local gameVersion = utilities.WaitFor('ReplicatedStorage.ServerVersion').Value
	if isfile('sb2_version.txt') then
		local num = tonumber(readfile('sb2_version.txt'))
		if num and num < gameVersion then
			local thread = Instance.new'BindableEvent';
			local notification;

			notification = N.error({
				title = 'Swordburst 2',
				text = 'A game update has been detected. Be cautious!\nWould you like to continue?',
				wait = 1e9,
				buttons = {
					N.button('Exit', function() 
						fastSpawn(function()
							client:Kick('Exited successfuly.')
						end)
						notification:hide() 
					end),

					N.button('Continue', function() thread:Fire() end),
				}
			})
			thread.Event:wait()
		end
	end

	writefile('sb2_version.txt', gameVersion)

	local currentFloor = 0
	if game.PlaceId == 6144637080 then
		currentFloor = -1;
	end
	
	local floors, get_current_floors do
		floors = {}

		function get_current_floors()
			local location_list = {}
			for _, v in next, locations.floors do
				table.insert(location_list, v.Name)
				floors[v.Name] = v.PlaceId
				if v.PlaceId == game.PlaceId then
					currentFloor = tonumber(v.Designation:match("%d+"))
				end
			end
			return location_list
		end

		get_current_floors();
	end

	-- utilities.SetSetting('sb-target-floor', game.PlaceId)
	-- 				utilities.SetSetting('sb-target-server', serverList[1].guid)

	-- if game.PlaceId == 540240728 then
	-- 	print'hehehehehehehehehehehehe'
	-- 	if utilities.GetSetting('swordburst-destination-floor') then
	-- 		print'HEY RETARD WE ON TEH FLOOR!!!!!!!!!!'

	-- 		--cprint('joined arcadia. tp data:', utilities.GetSetting('swordburst-destination-floor'))
	-- 		--cprint('walking to tp pad')

	-- 		print'WAITING FOR TP PAD'
	-- 		local character = client.Character or client.CharacterAdded:wait();
	-- 		while (not workspace:FindFirstChild('TeleportPad', true)) do wait(1) end
	-- 		print'GOT THE TP PAD !!!!!!!!!!!!!!!!!!!!'

	-- 		local teleportPad = workspace:FindFirstChild('TeleportPad', true)
	-- 		character.Humanoid:MoveTo(teleportPad.Position)

	-- 		print('MOVING TO THE TP PAD!', teleportPad)
			
	-- 		while true do
	-- 			character.Humanoid.MoveToFinished:wait()
	-- 			if (teleportPad.Position - character.HumanoidRootPart.Position).magnitude > 10 then
	-- 				character.Humanoid:MoveTo(teleportPad.Position)
	-- 			else
	-- 				break
	-- 			end
	-- 		end
	-- 		cprint('calling teleport function')
	-- 		safeInvokeServer(remoteFunction, 'Teleport', {'Teleport', utilities.GetSetting('swordburst-destination-floor') })
	-- 		return
	-- 	end
	-- end

	local skill = decrypt(consts["450"], constantKey, "mGCG6vFseiOzHPH0")
	
	-- local skill do
	-- 	local function find_weapon(id)
	-- 		for i, item in next, profile.Inventory:GetChildren() do
	-- 			if item.Value == id then
	-- 				return item;
	-- 			end
	-- 		end
	-- 	end

	-- 	local function find_class(object)
	-- 		if (not object) then return end
	-- 		return (weapons:FindFirstChild(object.Name).Class.Value)
	-- 	end

	-- 	local level = math.floor(utilities.WaitFor('Stats.Exp', profile).Value ^ 0.3333333333333333)

	-- 	local left_weapon = find_weapon(utilities.WaitFor('Equip.Left', profile).Value);
	-- 	local right_weapon = find_weapon(utilities.WaitFor('Equip.Right', profile).Value);

	-- 	local left_class = find_class(left_weapon)
	-- 	local right_class = find_class(right_weapon);
		
	-- 	if (right_class == 'Katana' or right_class == '1HSword') then
	-- 		skill = 'Summon Pistol'-- (right_class == '1HSword' and 'Sweeping Strike' or 'Leaping Slash');
	-- 		if left_weapon then
	-- 			safeInvokeServer(remoteFunction, 'Equipment', {"Unequip", left_weapon})
	-- 		end

	-- 		-- UseSkill
	-- 		safeFireServer(remoteEvent, "Skills", {decrypt(consts["678"], constantKey, "mGCG6vFseiOzHPH0"), skill; Vector3.new()})

	-- 		if left_weapon then
	-- 			safeInvokeServer(remoteFunction, 'Equipment', {"EquipWeapon", left_weapon, 'Left'})
	-- 		end
	-- 	else
	-- 		if left_weapon then
	-- 			safeInvokeServer(remoteFunction, 'Equipment', {"Unequip", left_weapon})
	-- 		end

	-- 		if right_weapon then
	-- 			safeInvokeServer(remoteFunction, 'Equipment', {"Unequip", right_weapon})
	-- 		end

	-- 		local weapon_to_find = nil;
	-- 		local new_weapon_class = nil;

	-- 		for i, weapon in next, profile.Inventory:GetChildren() do
	-- 			local sword = utilities.Locate(weapon.Name, weapons)

	-- 			if sword and sword:FindFirstChild('Class') and sword.Level.Value <= level then
	-- 				local class = sword.Class.Value;
	-- 				if (class == 'Katana' or class == '1HSword') then
	-- 					weapon_to_find = weapon
	-- 					new_weapon_class = class;
	-- 					break;
	-- 				end
	-- 			end
	-- 		end

	-- 		if (not weapon_to_find) then
	-- 			return client:Kick("failed to find katana or longsword (NOT A RAPIER!)")
	-- 		end

	-- 		skill = 'Summon Pistol'--(new_weapon_class == '1HSword' and 'Sweeping Strike' or 'Leaping Slash');

	-- 		safeInvokeServer(remoteFunction, "Equipment", {"EquipWeapon", weapon_to_find; "Right"})
	-- 		-- UseSkill
	-- 		safeFireServer(remoteEvent,  	 "Skills", 	  {decrypt(consts["678"], constantKey, "mGCG6vFseiOzHPH0"), skill; Vector3.new()})
	-- 		safeInvokeServer(remoteFunction, "Equipment", {"Unequip", weapon_to_find})

	-- 		if right_weapon then
	-- 			safeInvokeServer(remoteFunction, 'Equipment', {"EquipWeapon", right_weapon, 'Right'})
	-- 		end

	-- 		if left_weapon then
	-- 			safeInvokeServer(remoteFunction, 'Equipment', {"EquipWeapon", left_weapon, 'Left'})
	-- 		end
	-- 	end
	-- end

	local targets = {};

	-- for i, v in next, workspace:children() do
	-- 	if v.Name=='TeleportSystem' then
	-- 		for a,b in next, v:children() do
	-- 			-- print((b.Position-Vector3.new(448.331, 4279.337, -385.05)).magnitude)
	-- 			if (b.Position-Vector3.new(448.331, 4279.337, -385.05)).magnitude < 2 then
	-- 				firetouchinterest(b, game.Players.LocalPlayer.Character.PrimaryPart, 0) 
	-- 				firetouchinterest(b, game.Players.LocalPlayer.Character.PrimaryPart, 1) 
	-- 			end
	-- 		end
	-- 	end
	-- end


	local bossRoomPositions = {
		-- f4
		[1] = {
			Location = Vector3.new(-1938.358, 428.531, 795.364),
		};
		[2] = {
			Location = Vector3.new(-2942.98877, 201.361252, -9804.74023),
		};
		[3] = {
			Location = Vector3.new(448.331, 4279.337, -385.05),
		};
		[4] = {
			Location = Vector3.new(-2318.13, 2280.42, -514.068)
		},
		[5] = {
			Location = Vector3.new(2189.178, 1308.125, -121.071)
		},
		[7] = {
			Location = Vector3.new(3347.79, 800.044, -804.31),
		},
		[8] = {
			Location = Vector3.new(1848.354, 4110.439, 7723.636),
		};
		[9] = {
			Location = Vector3.new(12241.466, 462.276, -3655.09),
		};
		[10] = {
			Location = Vector3.new(45.494194, 1003.77246, 25432.9902)
		};
		[11] = {
			Location = Vector3.new(4812.00977, 1646.30347, 2082.94043)
		},
		[-1] = {
			Location = Vector3.new(-4654.044, -107.128, 113.224),
		}
	}

	-- local bossRoomPositions = {
	-- 	[] = Vector3.new(-2952.10815, 113.646248, -9454.00098);
	-- }

	local mobNames = {
		--[[1]] [542351431] = {
			"Frenzy Boar";
			"Hermit Crab";
			"Wolf";
			"Bear";
			"Ruin Knight";
			"Draconite";
			"Ruin Kobold Knight";
		};

		--[[2]] [548231754] = {
			"Leaf Beetle";
			"Leaf Ogre";
			"Leafray";
			"Pearl Keeper";
			"Wasp";
			"Bushback Tortoise";
		};

		--[[3]] [555980327] = {
			"Snowgre";
			"Angry Snowman";
			"Icewhal";
			"Snowhorse";
			"Ice Elemental";
			"Ice Walker";
		};

		--[[4]] [572487908] = {
			"Boneling";
			"Dungeon Dweller";
			"Bamboo Spider";
			"Lion Protector";
			"Wattlechin Crocodile";
			"Birchman";
			"Treeray";
			"Bamboo Spiderling";
		};

		--[[5]] [580239979] = {
			"Girdled Lizard";
			"Angry Cactus";
			"Desert Vulture";
			"Giant Centipede";
			"Sand Scorpion";
		};

		--[[7]] [582198062] = {
			"Jelly Wisp";
			"Firefly";
			"Shroom Back Clam";
			"Gloom Shroom";
			"Horned Sailfin Iguana";
			"Blightmouth.";
			"Snapper";
		};

		--[[8]] [548878321] = {
			"Giant Praying Mantis";
			"Petal Knight";
			"Leaf Rhino";
			"Sky Raven";
			"Forest Wanderer";
			"Wingless Hippogriff";
			"Dungeon Crusador";
		};

		--[[9]] [573267292] = {
			"Batting Eye";
			"Lingerer";
			"Fishrock Spider";
			"Ent";
			"Enraged Lingerer";
			"Reptasaurus";
			"Undead Warrior";
			"Undead Berserker";
		};

		--[[10]] [2659143505] = {
			"Grunt";
			"Guard Hound";
			"Shady Villager";
			"Minion";
			"Winged Minion";
			"Wendigo";
			"Undead Servant";
		};


		--[[11]] [5287433115] = {
			"Reaper";
			"Soul Eater";
			"Command Falcon";
			"Shadow Figure";
			"???????";
		}
	};

	local bossNames = {
		[542351431] = {
			'Dire Wolf';
			'Rahjin the Thief King'
		};
		[548231754] = {
			'Gorrock the Grove Protector';
			'Borik the BeeKeeper';
		};
		[555980327] = {
			'Qerach The Forgotten Golem ';
			'Ra\'thae the Ice King ';
		};
		[572487908] = {
			"Rotling";
			"Irath the Lion";
		};
		[580239979] = {
			"Fire Scorpion";
			"Sa'jun the Centurian Chieftain";
		};
		[582198062] = {
			"Frogazoid";
			"Smashroom";
		};
		[548878321] = {
			"Hippogriff";
			"Formaug the Jungle Giant";
		};
		[573267292] = {
			"Mortis the Flaming Sear";
			"Gargoyle Reaper";
			"Polyserpant";
		};
		[2659143505] = {
			"Grim the Overseer";
			"Baal";
		};
		[5287433115] = {
			'Ra';
			'Da';
			'Ka';
		}
	}

	local attack_mob, get_current_mobs, is_mob_near, client_is_active, Services do
		local RPCKey, get_combat_key
		for i, v in next, getreg() do
			if type(v) == "table" and rawget(v, 'Services') then
				Services = v.Services;
				RPCKey = getupvalue(v.Services.Combat.DamageArea, 5)

				break
			end
		end

		local findFirstChild = game.FindFirstChild;
		local getChildren = game.GetChildren;

		local function is_mob_alive(mob)
			if (not mob.PrimaryPart) then return end
			if (not mob.PrimaryPart.Parent) then return end

			local root = findFirstChild(mob, 'HumanoidRootPart')
			if (not root) then return end

			local entity = findFirstChild(mob, 'Entity');
			if (not entity) then return end

			local health = findFirstChild(entity, 'Health');
			if (not health) or (health.Value <= 0) then return end 	

			local hpbar = findFirstChild(mob, 'Healthbar');
			if (mob:IsDescendantOf(mobs)) and (not hpbar) then return end

			return true		
		end

		function client_is_active()
			if (not client.Character) then return end

			local character = client.Character;
			local entity = findFirstChild(character, 'Entity');
			if (not entity) then return end

			local health = findFirstChild(entity, 'Health');
			if (not health) or (health.Value <= 0) then return end 

			local hr = (findFirstChild(character, 'HumanoidRootPart') ~= nil);
			return hr
		end

		function is_mob_near(mob, origin)
			if (not client_is_active()) then return end
			if (not mob.PrimaryPart) then return end

			return (origin - mob.PrimaryPart.Position).magnitude <= 60;
		end

		function get_current_mobs()
			local enemies = {};

			if (not client_is_active()) then return enemies end

			local origin = game.Players.LocalPlayer.Character.HumanoidRootPart.Position
			local rad = utilities.Region3InRadius(origin, 60)

			local parts = workspace:FindPartsInRegion3WithWhiteList(rad, {workspace.Mobs})

			for i, part in next, parts do
				local mob = part.Parent;

				if (not is_mob_alive(mob)) then continue end
				if table.find(enemies, mob) then continue end

				enemies[#enemies + 1] = mob;
			end

			if library.flags.attackPlayers and profile.Settings.PvP.Value then
				local cLevel = math.floor(profile.Stats.Exp.Value ^ 0.3333333333333333);

				for i, player in next, game.Players:GetPlayers() do
					if player == client then continue end

					local character = player.Character;
					local root = (character and character:FindFirstChild("HumanoidRootPart"))
					if (not root) then continue end

					local distance = math.floor((root.Position - origin).magnitude);
					if distance > 50 then continue end

					local profile_ = game.ReplicatedStorage.Profiles:FindFirstChild(player.Name);
					if (not profile_) then continue end

					if (not profile_:FindFirstChild('Settings')) then continue end
					if (not profile_:FindFirstChild('Stats')) then continue end

					if (not profile_.Settings.PvP.Value) then continue end

					local pLevel = math.floor(profile_.Stats.Exp.Value ^ 0.3333333333333333);
					if (cLevel - pLevel) > 10 then continue end
					
					enemies[#enemies + 1] = character;
				end
			end

			return enemies;
		end

		function get_closest_mob()
			-- // different function because I do not feel like adding 900 parameters;

			local distance = math.huge;
			local origin = client.Character.PrimaryPart.Position;
			local target = nil;

			for i, mob in next, workspace.Mobs:GetChildren() do
				if (not is_mob_alive(mob)) then continue end

				if library.flags.prioritizeBoss then
					if (not table.find(bossNames[game.PlaceId], mob.Name)) then 
						continue 
					end
				end

				if library.flags.prioritizeMob then
					if (not library.flags.mobPriority[mob.Name]) then 
						continue
					end
				end

				local dist = (mob.PrimaryPart.Position - origin).magnitude

				if library.flags.useMobRadius and library.flags.mobRadius and library._waypoint then
					local dist = (mob.PrimaryPart.Position - library._waypoint).magnitude
					if dist > library.flags.mobRadius then
						continue
					end
				end

				if dist < distance then
					distance = dist;
					target = mob;
				end
			end

			return target;
		end

		local oldDamageArea = Services.Combat.DamageArea
		local oldEnableDamage = Services.Combat.EnableDamage;

		function attack_mob(mob)
			oldDamageArea(nil, client.Character.PrimaryPart.Position, (library.flags.attackRange or 60), {})
		end

		Services.Combat.EnableDamage = function(...)
			if checkcaller() then return oldEnableDamage(...) end
			if library.flags.damageMultiplier then
				local arguments = {...}
				for i = 1, (library.flags.multiplierAmount or 1) do
					oldEnableDamage(nil, unpack(arguments, 2))
				end
				return
			end
			return oldEnableDamage(...)
		end

		Services.Combat.DamageArea = function(...)
			if checkcaller() then return oldDamageArea(...) end
			if library.flags.damageMultiplier then
				local arguments = {...}
				for i = 1, (library.flags.multiplierAmount or 1) do
					oldDamageArea(nil, unpack(arguments, 2))
				end
				return
			end
			return oldDamageArea(...)
		end

		Services.Graphics.DoEffect = loadstring([[
			local old, library = ...;
			return function(...)
				local name = ...
				if name == 'Damage Text' then
					if library.flags['Performance Boosters'] and library.flags['Performance Boosters']['No Damage Numbers'] then
						return
					end
				end

				return old(...)
			end
		]])(Services.Graphics.DoEffect, library)

		workspace.HitEffects.ChildAdded:connect(function(obj)
			if library.flags['Performance Boosters'] and library.flags['Performance Boosters']['No Damage Particles'] then
				runService.Heartbeat:wait()
				obj:Destroy()
			end
		end);
		
		function warp(target)
			if (not target) then return end
			if (not target.PrimaryPart) then return end

			local human = client.Character:FindFirstChild('Humanoid')
			local root = client.Character.PrimaryPart
			local origin = root.Position

			local start = tick()

			local speed = library.flags['tweenSpeed'] or 77
			local location = target.PrimaryPart.Position;
			local distance = math.floor((location - origin).magnitude)
			local time = math.max((distance / speed), 0.5)
			
			if (not human) then return end

			while true do
				local dt = runService.Heartbeat:wait();

				local speed = library.flags['tweenSpeed'] or 77
				local now = (tick() - start);
				local alpha = (now / time)

				local goal = tweenService:GetValue(alpha, Enum.EasingStyle.Linear, Enum.EasingDirection.InOut)
				
				if (not target:IsDescendantOf(workspace)) then break end
				if (not library.flags.autoFarm) or (not is_mob_alive(target)) then break end
				
				if (human.Health <= 0) then break end
				if (not human:IsDescendantOf(workspace)) then break end

				if library.flags.useMobRadius and library.flags.mobRadius and library._waypoint then
					local dist = (target.PrimaryPart.Position - library._waypoint).magnitude
					if dist > library.flags.mobRadius then
						break
					end
				end

				local currentPosition = target.PrimaryPart.Position;
				if (math.floor((currentPosition - location).magnitude)) > 10 then
					start = tick();
					origin = root.Position;
					location = currentPosition;
					
					distance = math.floor((location - origin).magnitude)
					time = (distance / speed);

					continue;
				end

				local top = target.PrimaryPart.CFrame * CFrame.new(0, 14, 0);
				root.CFrame = CFrame.new(origin):lerp(top, goal)
				human:ChangeState(Enum.HumanoidStateType.PlatformStanding)
			end
		end
	end

	fastSpawn(function()
		while true do
			if (client_is_active()) and library.flags.autoFarm then
				warp(get_closest_mob());
			end
			game:GetService('RunService').Stepped:wait()
		end
	end)

	runService.Heartbeat:connect(function()
		targets = get_current_mobs();
	end)

	fastSpawn(function()
		while task.wait(0.3) do
			if not (library.flags.killAura or library.flags.autoFarm) then 
				continue 
			end

			if (not targets[1]) then continue end
			pcall(attack_mob, targets[1])
		end
	end)

	runService.Heartbeat:connect(function()
		if client.Character then 
			local human = client.Character:FindFirstChildWhichIsA("Humanoid")
			if human and library.flags['Walk Speed'] then
				human.WalkSpeed = library.flags['movementSpeed'] or human.WalkSpeed
			end
		end
	end)

	local label = library:Create('Text', {
		Size = 20;
		Text = 'Invisible',
		Center = true;
		Outline = true;
		Transparency = 1;
		Visible = false;
	})

	local waypoint = library:Create('Text', {
		Size = 20;
		Text = 'Waypoint position',
		Color = Color3.new(1, 1, 1),
		Center = true;
		Outline = true;
		Transparency = 1;
		Visible = false;
	})

	runService.Heartbeat:connect(function()
		if client.Character and client.Character:FindFirstChild('Head') then
			local vector, visible = base.worldToViewportPoint(client.Character.Head)
			if visible and config.ghost ~= nil then
				label.Visible = true;
				label.Color = Color3.fromRGB(0, 255, 140)
				label.Position = vector;
			else
				label.Color = Color3.fromRGB(255, 50, 50)
				label.Visible = false;
			end
			
			if library._waypoint then
				local vector, visible = base.worldToViewportPoint(library._waypoint)
				if visible then
					waypoint.Visible = true;
					waypoint.Position = vector
				else
					waypoint.Visible = false;
				end
			else
				waypoint.Visible = false;
			end
		end
	end)

	local mobsTable = {};
	local function checkMob(mob)
		local entity = mob:WaitForChild('Entity', 10)
		if (not entity) then return end

		local health = entity:WaitForChild('Health', 10)
		if (not health) then return end


		health:GetPropertyChangedSignal('Value'):connect(function()
			if health.Value <= 0 then
				if library.flags['Performance Boosters'] and library.flags['Performance Boosters']['Delete Dead Mobs'] then
					mob:Destroy();
				end
			end
		end);
	end

	for i, mob in next, workspace.Mobs:GetChildren() do
		fastSpawn(checkMob, mob)
	end

	workspace.Mobs.ChildAdded:connect(checkMob)

	local function onCharacterAdded(character)
		if config.ghost then config.ghost:Destroy() end

		character:WaitForChild('Humanoid').Died:connect(function()
			if library.flags.disableOnDeath and library.options.autoFarm then
				library.options.autoFarm:SetState(false)
				library.options.killAura:SetState(false)
			end
		end)
	end
	
	if client.Character then
		fastSpawn(onCharacterAdded, client.Character)
	end
	client.CharacterAdded:connect(onCharacterAdded)

	local swordburst = menu:AddTab('Swordburst 2') do
		local column = swordburst:AddColumn();

		local farm = column:AddSection('Autofarm') do
			farm:AddToggle({text = 'Enabled', flag = 'autoFarm'})
			farm:AddSlider({text = 'Tween Speed', textpos = 2, suffix = 'm', flag = 'tweenSpeed', min = 60, max = 90, value = 80})
			farm:AddToggle({text = 'Disable On Death', flag = 'disableOnDeath'})
			farm:AddToggle({text = 'Prioritize Boss', flag = 'prioritizeBoss'})

			farm:AddToggle({
				text = 'Use mob radius',
				flag = 'useMobRadius',
				tip = 'Only targets mobs that are (radius) studs away from your waypoint.'
			}):AddSlider({
				min = 0, 
				max = 10000, 
				flag = 'mobRadius',
				prefix = 'Radius: ',
				suffix = 'm',
			})
			
			farm:AddDivider('Waypoint settings')
			farm:AddButton({text = 'Set', callback = function()
				if client.Character and client.Character:FindFirstChild('HumanoidRootPart') then
					library._waypoint = client.Character.HumanoidRootPart.Position
				else
					N.error({
						title = 'Swordburst 2',
						text = 'You can not set a waypoint while despawned.',
						time = 5,
					})
				end
			end}):AddButton({text = 'Delete', callback = function()
				library._waypoint = nil;
			end})

			farm:AddDivider()

			farm:AddToggle({text = 'Prioritize Mob', flag = 'prioritizeMob'}):AddList({
				multiselect = true,
				list = mobNames[game.PlaceId] or {'none'},
				skipFlag = true;
				flag = 'mobToPrioritize'
			})
		end
		
		local aura = column:AddSection('Kill Aura') do
			aura:AddToggle({text = 'Enabled', flag = 'killAura', tip = 'If you set a keybind, you need to hold it down for the kill aura to attack.'}):AddSlider({
				text = 'Attack Speed', suffix = 'ms', flag = 'attackSpeed', min = 17, max = 2000
			}):AddBind({flag = 'killAuraBind', nomouse = true, mode = 'hold', callback = function(ended)
				_G.auraBindPressed = (not ended)
			end})

			aura:AddToggle({text = 'Damage Booster', flag = 'damageMultiplier'}):AddSlider({
				text = 'Multiplier amount',
				min = 0,
				max = 50,
				flag = 'multiplierAmount'
			})

			aura:AddSlider({ text = 'Attack Threads',  flag = 'threadCount',  min = 1,  max = maxThreadCount,  textpos = 2, value = config.threadCount })
			aura:AddSlider({ text = 'Attack Range',  flag = 'attackRange', suffix = 'm',  min = 20, max = 60, textpos = 2, value = 60 })
			aura:AddToggle({text = 'Attack Players', flag = 'attackPlayers'})
		end

		local column = swordburst:AddColumn();
		local misc = column:AddSection('Misc Cheats') do
			misc:AddToggle({text = 'Instant Trade', flag = 'instantTrade'})
			misc:AddToggle({ text = 'WalkSpeed', flag = 'Walk Speed', callback = function(state)
				if (not state) then
					local char = client.Character;
					local human = char and char:FindFirstChild('Humanoid')

					if human then 
						human.WalkSpeed = 20
					end
				end
			end}):AddSlider({text = 'Speed', flag = 'movementSpeed', min = 20, max = 90})
			misc:AddList({ text = 'Performance Boosters', values = { 'No Damage Numbers', 'No Damage Particles', 'Delete Dead Mobs', }; multiselect = true;})

			misc:AddList({ text = 'Custom Animations', values = {"None", "Berserker", "Ninja", "Noble", "Vigilante"}, callback = function(selected)
				local pack = (selected == 'None' and '' or selected);
				for i, object in next, profile.AnimSettings:GetChildren() do
					object.Value = pack;
				end
			end})

			local invisibleTag = randomStr(32)
			misc:AddButton({ text = 'Invisibility', tip = 'Leaves your body in the spot where you activate it at', flag = 'goInvisible', callback = function()
				local character = client.Character;
				local torso = (character and character:FindFirstChild('LowerTorso'))
				local root = (torso and torso:FindFirstChild('Root'))

				if (not root) then return end

				if (collectionService:HasTag(character, invisibleTag)) then
					N.error({
						title = 'Swordburst 2',
						text = 'You have already activated \'Invisibility\'.\nPlease reset if you wish to go invisible in another spot.'
					})
					return
				end

				local choice = N:MessageBox('Swordburst 2', "Go invisible requires that you hide your body in a safe place\nsuch as inside of a building or outside of the map.\nContinue?", {'Yes', 'No'})
				if (choice == 'Yes') then
					character.Archivable = true;
					local copy = character:Clone();

					copy.Humanoid:Destroy()
					for _, part in next, copy:GetChildren() do
						if part:IsA('BasePart') and part.Name ~= 'HumanoidRootPart' then
							part.Transparency = 0.5
							part.CanCollide = false;
						elseif part:IsA('Model') then
							part:Destroy()
						end
					end

					copy:SetPrimaryPartCFrame(client.Character.PrimaryPart.CFrame)
					copy.PrimaryPart.Anchored = true;

					local new = root:Clone()
					root:Destroy()
					new.Parent = torso;
					copy.Parent = workspace;
					config.ghost = copy;

					collectionService:AddTag(character, invisibleTag)
				end
			end})

			if currentFloor and bossRoomPositions[currentFloor] then
				library.options.goInvisible:AddButton({text = 'Boss warp', callback = function()
					if workspace.StreamingEnabled then
						client:RequestStreamAroundAsync(bossRoomPositions[currentFloor].Location)
					end

					for i, model in next, workspace:children() do
						if model.Name == 'TeleportSystem' then
							for _, part in next, model:GetChildren() do
								local dist = (part.Position - bossRoomPositions[currentFloor].Location).magnitude
								if dist < 2 then
									firetouchinterest(part, client.Character.PrimaryPart, 0); 
									firetouchinterest(part, client.Character.PrimaryPart, 1);
								end
							end
						end
					end
				end})
			end
		end

		local teleports = column:AddSection('Floor Teleports', 2) do
			teleports:AddList({
				values = get_current_floors();
				flag = 'selectedFloor'
			})

			teleports:AddButton({
				text = 'Teleport', 
				callback = function()
					if (not profile.Locations:FindFirstChild(floors[library.flags.selectedFloor])) then
						local playerUi = getupvalue(Services.UI.IsMenuOpen, 1);
						local frame, gui = Services.UI.Notification.new(playerUi.Templates.Notification.Teleport)
						frame.Content.Message.Text = 'You do not have this floor unlocked!'
						frame.Content.Title.Text = 'Teleport error!'

						wait(2)
						
						gui:Destroy();
						return
					end

					local placeId = floors[library.flags.selectedFloor]
					if placeId then
						client.Character:BreakJoints()
						client.CharacterAdded:wait()
						safeInvokeServer(remoteFunction, 'Teleport', {'Teleport', placeId })
					end
				end
			})
		end

		local dismantle = column:AddSection('Item Menu', 2) do
			local label = dismantle:AddLabel('Selected Item:\nNone.')
			
			local function countItems(name)
				local count = 0;
				for i, child in next, profile.Inventory:GetChildren() do
					if child.Name ~= name then continue end

					count = count + 1
				end
				return count;
			end

			local function dismantleItems(amount)
				local left = utilities.WaitFor('Equip.Left', profile).Value
				local right = utilities.WaitFor('Equip.Right', profile).Value

				local count = 0;
				for i, child in next, profile.Inventory:GetChildren() do
					if child.Name ~= config.name then continue end
					if (child.Value == left or child.Value == right) then continue end

					if count >= amount then break end
					safeFireServer(remoteEvent, "Equipment", {"Dismantle", child})
					profile.Inventory.ChildRemoved:wait();

					count = count + 1
				end
			end

			local function upgradeItems(amount)
				local left = utilities.WaitFor('Equip.Left', profile).Value
				local right = utilities.WaitFor('Equip.Right', profile).Value

				local count = 0;

				local rarities = {
					Uncommon = 10;
					Common = 10;
					Rare = 15;
					Legendary = 20;
				}

				local sorted = {}; do
					for i, item in next, profile.Inventory:GetChildren() do
						if item.name == config.name then
							local upgrade = (item:FindFirstChild('Upgrade') and item.Upgrade.Value) or 0;
							local rarity = weapons[item.Name]:FindFirstChild('Rarity').Value;
							local max_level = rarities[rarity]

							if upgrade < max_level then
								table.insert(sorted, {
									item = item;
									upgr = upgrade;
									rari = rarity;
								})
							end
						end
					end

					table.sort(sorted, function(a, b)
						return a.upgr > b.upgr
					end)
				end

				local selection = sorted[1];
				local item = selection.item;

				if (not item) then return end

				for i = 1, amount do
					safeFireServer(remoteEvent, "Equipment", {
						"Upgrade";
						item,
						false,
					})
				end
			end
		
			local function updateItemLabel()
				if (config.name) then
					local itemCount = countItems(config.name)
					if itemCount <= 0 then
						label.Text = "Selected Item:\nNone"
						library.options['itemAmount'].min = 0;
						library.options['itemAmount'].max = 1;
					else
						label.Text = "Selected Item:\n" .. config.name .. (" (x%s)"):format(itemCount)
						library.options['itemAmount'].min = 0;
						library.options['itemAmount'].max = itemCount;
					end
				end
			end

			dismantle:AddButton({
				text = "Select Item", 
				callback = function()
					Services.UI.InventoryMenu.SelectItem(function(t)
						local thread = syn_context_get()
						syn_context_set(7)
						local itemCount = countItems(t.name);

						label.Text = "Selected Item:\n" .. t.name .. (" (x%s)"):format(itemCount)
						config.name = t.name;
						library.options['itemAmount'].min = 0;
						library.options['itemAmount'].max = itemCount;
						-- dismantle:GetObject('Item Amount').SetMinMax(0, itemCount);

						syn_context_set(thread);
						Services.UI.clearInvFilter();
					end, {
						hint = "Please select a weapon.", 
						allowFilterClass = false, 
						filter = {
							class = {
								Weapon = true
							};
						}
					})
				end
			})

			dismantle:AddSlider({
				text = 'Item Amount',
				min = 0;
				max = 1;
				flag = 'itemAmount';
				textpos = 2;
			})

			dismantle:AddButton({  
				text = 'Dismantle',  
				callback = function()
					dismantleItems(library.flags.itemAmount)
					updateItemLabel();
				end
			}):AddButton({  
				text = 'Upgrade', 
				callback = function()
					upgradeItems(library.flags.itemAmount)
				end
			})
		end

		local column = swordburst:AddColumn();
		local blocking = column:AddSection('Block menu') do
			local function getPlayerList()
				local list = {}
				for i, plr in next, game:GetService('Players'):GetPlayers() do
					if plr == client then continue end
					list[#list + 1] = plr.Name
				end
				return list
			end

			blocking:AddList({
				text = 'Player list',
				flag = 'playerToBlock',
				values = getPlayerList()
			})

			local function update()
				local option = library.options.playerToBlock
				if option then
					local list = getPlayerList()
					for i, plr in next, option.values do
						if (not table.find(list, plr)) then
						--	warn(plr, 'left')
							option:RemoveValue(plr)
						end
					end

					for i, plr in next, list do
						if (not table.find(option.values, plr)) then
						--	warn(plr, 'joined')
							option:AddValue(plr)
						end
					end
				end
			end

			game:GetService('Players').PlayerAdded:connect(update)
			game:GetService('Players').PlayerRemoving:connect(update)

			blocking:AddDivider()
			blocking:AddBox({text = 'Username input', flag = 'blockUsername'})	
			blocking:AddToggle({text = 'Use username box', flag = 'useNameBox'})
			blocking:AddDivider()

			blocking:AddButton({
				text = 'Block user',
				callback = function()
					local get, post = gethsfuncs()
					local name = (library.flags.useNameBox and library.flags.blockUsername or library.flags.playerToBlock)

					local _, userId = pcall(players.GetUserIdFromNameAsync, players, name)
					if (not _) then
						return N.notify({ title = 'Error', type = 'error', text = 'Failed to fetch user id. '})
					end

					local s, res = pcall(post, game, 'https://www.roblox.com/userblock/blockuser', httpService:JSONEncode({ blockeeId = userId, }), 'application/json', Enum.HttpRequestType.Players)
					if (not s) then
						return N.notify({ title = 'Error', type = 'error', text = 'Failed to block ' .. name})
					end
					local dec = httpService:JSONDecode(res)
					if (not dec.success) then
						return N.notify({ title = 'Error', type = 'error', text = 'Failed to block ' .. name ' [2]\nIs your block list full?'})
					end
					return N.notify({ title = 'Success', type = 'success', text = 'Blocked ' .. name .. '!'})
				end,
			}):AddButton({
				text = 'Unblock user',
				callback = function()
					local get, post = gethsfuncs()
					local name = (library.flags.useNameBox and library.flags.blockUsername or library.flags.playerToBlock)

					local _, userId = pcall(players.GetUserIdFromNameAsync, players, name)
					if (not _) then
						return N.notify({ title = 'Error', type = 'error', text = 'Failed to fetch user id. '})
					end

					local s, res = pcall(post, game, 'https://www.roblox.com/userblock/unblockuser', httpService:JSONEncode({ blockeeId = userId, }), 'application/json', Enum.HttpRequestType.Players)
					if (not s) then
						return N.notify({ title = 'Error', type = 'error', text = 'Failed to unblock ' .. name})
					end
					local dec = httpService:JSONDecode(res)
					if (not dec.success) then
						return N.notify({ title = 'Error', type = 'error', text = 'Failed to unblock ' .. name ' [2]'})
					end
					return N.notify({ title = 'Success', type = 'success', text = 'Unblocked ' .. name .. '!'})
				end,
			})
		end

		local moderator = column:AddSection('Mod Detector'); do
			moderator:AddToggle({text = 'Auto kick', flag = 'autoKick'}):AddList({text = 'Autokick mode', flag = 'autoKickMode', values = {'Kick', 'Teleport'}, tip = '\"Teleport\" mode will teleport you to Arcadia when a mod joins.'})
			moderator:AddToggle({text = 'Auto panic', flag = 'autoPanic'}):AddSlider({text = 'Panic Delay', flag = 'panicDelay', min = 0, max = 5, suffix = ' seconds'})
		end
	end

	local mods = {
		309775741, -- YatoFett
		167655046, -- NotSoAsxer
		59341698, -- Zekrulix
		440458342, -- jamesvsty
		269112100, -- 4_WarD
		455293249, -- gravytr_ain
		500009807, -- redvsty
		68210875, -- LemonsForSupper
		575623917, -- RozukageMardarin
		60673083, -- Savlethe
		161949719, -- racerbee
		154847513, -- iiCennii
		111051084, -- UnitEternal
		38559058, -- entor
		271388254, -- Meikyoji
		50879012, -- akovsty
		1099119770, -- grimsrose
		24156180, -- AngelDeeri
		373676463, -- arttvsty
		173116569, -- Resitiast
		62240513, -- poopslim
		4402987, -- AbstractAlex
		13444058, -- Blocky_Max
		76999375, -- SIevin
		93988508, -- AstroScars
		7858636, -- OKevinO
		1033291447, -- MisterGreenTurtle
		1379309318, -- Reiko_Play
		1033291716, -- MisterRedTurtle
		151751026, -- Hippie_ofDoom
		448343431, -- NightcoreRayRay
		57436909, -- Wiseman_Matt
		51696441, -- RavenousZen
		358748060, -- CrypticArchr
		225179429, -- vqlos
		349854657, -- dillytube
		454205259, -- GIacials
		154876159, -- WickedNovaG1rl
		72480719, -- jaoziinq
		357870914, -- OverseerOfTheDamned
		1390415574, -- EpicFishBowl
		35311411, -- Direnias
		810458354, -- BGMMasterYT
	 }

	local Bindable = Instance.new'BindableFunction'
	Bindable.OnInvoke = function(option)
		if option == 'Panic' then
			library.options.autoFarm:SetState(false)
			library.options.killAura:SetState(false)
			game:GetService('Players').LocalPlayer.Character.Entity.Health:Destroy();
		end
	end

	local loggedMsgs = {};
	local function checkIfMod(player)
		if table.find(mods, player.UserId) then
			if config.autoKick then
				if library.flags.autoKickMode == 'Teleport' then
					-- 540240728

					client.Character:BreakJoints()
					client.CharacterAdded:wait()
						safeInvokeServer(remoteFunction, 'Teleport', {'Teleport', 540240728 })

				else
					return client:Kick(('Moderator %s joined your server.'):format(player.Name))
				end
			end

			if config.autoPanic then
				N.error({
					title = 'Swordburst 2',
					text = ('Mod %s has joined your server, activating panic mode...'):format(player.Name),
					wait = 20
				})

				wait(config.panicDelay)
				Bindable:Invoke("Panic");
				return;
			end

			local notification;
			notification = N.error({
				title = 'Swordburst 2',
				text = ('Moderator - %s has joined your server!'):format(player.Name),
				wait = 1e9,
				buttons = {
					N.button('Ignore', function() notification:hide() end),
					N.button('Panic', function() Bindable:Invoke("Panic") notification:hide() end),
				}
			})
		end
	end

	local function getPlayerList()
		local list = {};
		for i, plr in next, game.Players:GetPlayers() do
			local name = plr.Name;
			local id = plr.UserId;

			if plr == client then
				name = string.format("**%s**", name)
			end
			if table.find(mods, plr.UserId) then
				name = string.format("**%s (MODERATOR)**", name)
			end

			local url = 'https://roblox.com/users/' .. id
			name = string.format('[%s](%s)', name, url)

			list[#list + 1] = name
		end
		return table.concat(list, "\n")
	end

	game:GetService('GuiService').ErrorMessageChanged:connect(function(message)
		local list = getPlayerList();
		pcall(pingServer, string.format('%s\n%s', message, list), 'SB2Kick')
	end)

	for i, player in next, players:GetPlayers() do
		fastSpawn(checkIfMod, player)
	end

	local modStatus = {}
	local function checkMods()
		for _, modId in next, mods do
			local _, name = pcall(game.Players.GetNameFromUserIdAsync, game.Players, modId)--game.Players:GetNameFromUserIdAsync(modId)
			if (not _) then continue end

			local success, response = pcall(httpGet, game, ('https://api.roblox.com/users/%s/onlinestatus/'):format(modId))
			if (not success) then continue end

			local decoded, status = pcall(jsonDecode, httpService, response)
			if (not decoded) then continue end
			
			local currentStatus = (status.IsOnline and 'Online' or 'Offline')
			if modStatus[modId] then
				if modStatus[modId] ~= currentStatus then
					if currentStatus == 'Online' then
						N.error({
							icon = 'sfzi';
							title = 'Swordburst 2',
							text = ('Moderator [%s] has come online!'):format(name);
							wait = 5;
						})
					else
						N.success({
							icon = 'sfzi';
							title = 'Swordburst 2',
							text = ('Moderator [%s] has gone offline!'):format(name);
							wait = 5;
						})
					end
				end
			elseif currentStatus == 'Online' then
				N.error({
					icon = 'sfzi';
					title = 'Swordburst 2',
					text = ('Moderator [%s] is currently online!'):format(name);
					wait = 5;
				})
			end	

			modStatus[modId] = currentStatus
		end
	end

	fastSpawn(function()
		while true do
			checkMods()
			wait(10)
		end
	end)
	
	players.PlayerAdded:connect(checkIfMod)
end)

games.add({113491250, 115272207}, 'Phantom Forces', function(menu)
	local function gcscan(name, params)
		local gc = getgc((params.type and params.type == 'table'))
		local result = nil;

		for i = 1, #gc do
			local object = gc[i];
			if type(object) == params.type then
				if type(object) == 'table' then
					local passed = true
					for name, _type in next, params.fields do
						if type(rawget(object, name)) ~= _type then
							passed = false;
						end
					end
					
					if passed then
						result = object;
						break
					end
				elseif type(object) == 'function' and (not is_synapse_function(object)) then
					if islclosure(object) then 
						if params.name then
							if getinfo(object).name == params.name then
								result = object;
								break
							end
						elseif params.consts then 
							local index = 0;
							while true do

							end
						end
					end
				end
			end
		end
		
		return result
	end

	while (not game:IsLoaded()) do task.wait() end

	while true do
		local shared = getrenv().shared;

		local close, require, add = rawget(shared, 'close'), rawget(shared, 'require'), rawget(shared, 'add')
		if type(close) ~= 'function' and type(require) ~= 'function' and type(add) ~= 'function' then
			break
		end

		task.wait()
	end

	local network = gcscan('network', { type = 'table', fields = { send = 'function', ready = 'function', fetch = 'function' } })
	local particle = gcscan('particle', { type = 'table', fields = { new = 'function', step = 'function', reset = 'function', } })
	local hud = gcscan('hud', { type = 'table', fields = { getplayerhealth = 'function', isplayeralive = 'function' } })
	local char = gcscan('char', { type = 'table', fields = { unloadguns = 'function', setunaimedfov = 'function', getslidecondition = 'function' } })
	local gamelogic = gcscan('char', { type = 'table', fields = { setsprintdisable = 'function', controllerstep = 'function' } })
	local setcharacterhash = gcscan('setcharacterhash', { type = 'function', name = 'setcharacterhash' } )
	
	--warn(network, particle, hud)
	--warn(setcharacterhash)

	--warn(hud, hud.getplayerhealth)
	
	-- character hooks
	do
		local characterHashMap = getupvalue(setcharacterhash, 1) -- character -> player
		local playerHashMap = getupvalue(setcharacterhash, 2) -- player -> character
		
		base.rootPart = 'Torso'
		base.getRig = function() return 'R6'  end
		
		function base.getCharacter(player)
			if player == client then 
				return client.Character 
			end

			local character = playerHashMap[player]
			if type(character) == 'table' and typeof(rawget(character, 'torso')) == 'Instance' then
				return character.torso.Parent;
			end
		end

		function base.getHealth(character)
			if character == client.Character then
				return char.gethealth(), 100
			end

			local plr = characterHashMap[character]
			if typeof(plr) ~= 'Instance' then
				return 0, 0
			end

			return hud:getplayerhealth(plr)
		end

		for plr, char in next, playerHashMap do
			local signals = (plr and base.signals[plr])

			if signals then
				signals.characterAdded:Fire(char.torso.Parent)
			end	
		end

		workspace.ChildAdded:Connect(function(object)
			if object:IsA'Model' and object.Name == 'RefPlayer' then
				local signals = (base.signals[client])
				if signals then
					signals.characterAdded:Fire(object)
				end
			end
		end)

		workspace:WaitForChild('Players'):WaitForChild('Ghosts').ChildAdded:Connect(function(obj)
			local player = characterHashMap[obj]
			while true do
				task.wait()
				if (player) then break end
				player = characterHashMap[obj]
			end

			local signals = (base.signals[player])
			if signals then
				signals.characterAdded:Fire(obj)
			end	
		end)

		workspace:WaitForChild('Players'):WaitForChild('Phantoms').ChildAdded:Connect(function(obj)
			local player = characterHashMap[obj]
			while true do
				task.wait()
				if (player) then break end
				player = characterHashMap[obj]
			end

			local signals = (base.signals[player])
			if signals then
				signals.characterAdded:Fire(obj)
			end	
		end)

		base.characterAdded:connect(function(player)
			local signals = base.signals[player]
			if signals then
				if player == client then
					signals.healthChanged:Fire(char.gethealth(), 100)
				else
					signals.healthChanged:Fire(hud:getplayerhealth(player))
				end
			end
		end)

		aimbot.launch(menu);
		esp.launch(menu);
	end

	-- silent aim
	do
		local oldParticleNew = particle.new;
		function particle.new(object)
			local caller = getinfo(2)
			local consts = getconstants(2)
			local stack = getstack(2)

			if type(object) == 'table' and library.flags.silentAim then
				if caller.name == '' and table.find(consts, 'newbullets') then
					local origin = object.position;
					local velocity = object.velocity;
			
					local gunStats = nil;
			
					local indices = { stack = {}, upvalues = {}, }
			
					for i = 1, caller.nups do
						local upv = getupvalue(2, i)
						if type(upv) == 'table' then
							if type(rawget(upv, 'bulletspeed')) == 'number' then
								gunStats = upv;
							end
						end
					end
			
					for i = 1, #stack do
						local sObject = stack[i];
						if sObject == velocity then
							indices.stack.velocity = i;
						end
					end
			
					if type(gunStats) == 'table' and type(origin) == 'vector' and type(velocity) == 'vector' then
						local target = aimbot.getSilentTarget()
						if target then
							local speed = gunStats.bulletspeed;
							local vector = Vector3.new()

							local dir = trajectory(origin, vector, Vector3.new(0, -196.2, 0), target.Position, target.Velocity, vector, speed)
							local cfr = CFrame.lookAt(origin, origin + dir)

							velocity = cfr.lookVector * gunStats.bulletspeed;
						end

						object.velocity = velocity
						setstack(2, indices.stack.velocity, velocity)
					end
				end
			end
			return oldParticleNew(object)
		end
	end

	local tab = library:AddTab('Phantom Forces') do
		local column = tab:AddColumn()
		local section = column:AddSection('Combat') do
			section:AddToggle({ text = 'Silent aim', flag = 'silentAim' })
		end
	end
end)

games.add({358276974}, 'Apocalypse Rising 2', function(menu)
	local framework = require(game:GetService("ReplicatedFirst"):WaitForChild('Framework'))
	local clientPlayer = framework.Classes.Players.get();

	while (not clientPlayer) do
		runService.Heartbeat:wait();
		clientPlayer = framework.Classes.Players.get();
	end

	local network = framework.Libraries.Network;
	local bullets = framework.Libraries.Bullets;
	local raycast = framework.Libraries.Raycasting;

	local deathScreen = framework.Libraries.Interface:Get('DeathScreen')
	local fade = framework.Libraries.Interface:Get('Fade')
	local corpseCamera = framework.Libraries.Cameras:GetCamera("Corpse");

	local oldGuns = {}
	local updateGunStats do
		local itemData = framework.require('Configs', 'ItemData')

		for name, data in next, itemData do
			if rawget(data, 'Type') == 'Firearm' then
				oldGuns[name] = utilities.Copy(data)
			end
		end

		function updateGunStats(state, stat, value, index)
			local index = index or ''
			for name in next, oldGuns do
				local config = itemData[name]
				local location = config[index] or config;
				local backup = oldGuns[name][index] or oldGuns[name]

				rawset(location, stat, state and value or backup[stat])
			end
		end
	end

	local attackZombie
	local oldSend, oldFetch; do
		oldSend = network.Send;
		oldFetch = network.Fetch;

		local antiCheatStrings = {
			"Resync Leaderboard"; -- if ((((not v24) and v23) and (not (v26 == ""))) and (not v23:match("LoadingScript"))) then
			"Sync Near Chunk Loot"; -- if math.abs(120 - workspace.Gravity) > 0.01 then
			"Update Character State"; -- if v166 and typeof(v166) == "EnumItem" and v166 ~= Enum.HumanoidStateType[v166.Name] then
			"Force Charcter Save"; -- if l__Humanoid__164.PlatformStand then
			"Get Player Stance Speed"; -- if l__WalkSpeed__167 > 26 then
			"Character Root Update"; -- if l__HumanoidRootPart__165 and l__HumanoidRootPart__165 ~= l__RootPart__73 then
			"Character Humanoid Update"; -- if l__Humanoid__164 and l__Humanoid__164 ~= l__Humanoid__72 then
			"Update Character Position"; -- if p98:IsA("BoxHandleAdornment") then
			"Resync Zombie Location"; -- if v42:IsA("SurfaceGui") then; if v42:IsA("BoxHandleAdornment") then; if v42:IsA("BillboardGui") then
			"Character Config Resync"; -- character config stuff
			"Firearm Ammo Sync"; -- if math.abs(p62.FireRate - l__FireRate__20) > 0.01 then
			"Character Stat Get"; -- if math.abs(p62.RecoilData.KickUpForce - l__KickUpForce__21) > 0.01 then
			"Resync Character Location"; -- ^ but for characters
			"Player Chat Mute Report"; -- if not v10 and v9 and v9 ~= "" and not v9:match("LoadingScript") then
			"Resync Character Physics"; --[[if p98.ClassName == "BodyVelocity" or p98.Name == "BodyVelocity" then;  elseif p98:IsA("AlignPosition") and p98 ~= p88.ParkourAlignPosition then; elseif p98:IsA("AlignOrientation") and p98 ~= p88.ParkourAlignRotation thenelseif not (not p98:IsA("BodyMover")) or not (not p98:IsA("LineForce")) or not (not p98:IsA("VectorForce")) or p98:IsA("Torque") then]]
			
			"Sync Debug Info", -- stupid xpcall garbage
		}

		-- patch getfenv calls
		local cachedEnv = getfenv(oldSend)
		for _, upv in next, getupvalues(oldSend) do
			if type(upv) == 'function' and getinfo(upv).name == 'getfenv' then
				setupvalue(oldSend, _, function()
					return cachedEnv
				end)
			end
		end

		function network.Send(self, action, ...)
			local arguments = {...}

			if action == "Sync Debug Info" then
				return
			elseif table.find(antiCheatStrings, action) then
				return;
			elseif (action == 'Set Character State' and library.flags.noResourceDrain) then
				if type(arguments[1]) == 'table' then
					for _, list in next, arguments[1] do
						if type(list) == 'table' then
							if list[1] == 'SprintSwimming' then list[1] = 'Swimming' end
							if list[1] == 'Running' then list[1] = 'Walking' end
						end
					end
				end
			elseif (action == "Change Firemode") then
				return
			end

			return oldSend(self, action, unpack(arguments))
		end

		function network.Fetch(self, action, ...)
			if action == "Sync Debug Info" then
				return
			end
			
			if table.find(antiCheatStrings, action) then
			--	debugwarn('blocking gameban2', action, debug.traceback())
				return;
			end

			return oldFetch(self, action, ...)
		end	
	end

	local oldFire, oldGroundCast, oldBulletCast do
		oldFire = bullets.Fire;
		oldGroundCast = raycast.CharacterGroundCast
		oldBulletCast = raycast.BulletCast;

		function raycast.BulletCast(self, ...)
			local arguments = {...};

			if isvalidlevel(3) and getinfo(3).name == 'Fire' then
				if library.flags.wallbang and type(arguments[3]) == 'table' then
					local ignoreList = arguments[3]

					ignoreList[#ignoreList + 1] = workspace.Map
					ignoreList[#ignoreList + 1] = workspace.Vehicles
					ignoreList[#ignoreList + 1] = workspace.Sounds
					ignoreList[#ignoreList + 1] = workspace.Effects
				end
			end

			return oldBulletCast(self, unpack(arguments))
		end

		function raycast.CharacterGroundCast(...)
			if (library.flags.noFallDamage or library.flags._killAll) and getinfo(2).source:find('Characters') then
				local res = { oldGroundCast(...) }
				if (not res[1]) then
					return workspace.Terrain
				end
				return unpack(res)
			end

			return oldGroundCast(...)
		end

		local dirCache = {}
		local getSpreadVector, getFireImpulse do
			for _, fn in next, getupvalues(bullets.Fire) do
				if type(fn) == 'function' then
					if getinfo(fn).name == 'getSpreadVector' then
						getSpreadVector = _;
					end

					if getinfo(fn).name == 'getFireImpulse' then
						getFireImpulse = _;
					end
				end
			end
		end

		if (type(getSpreadVector) ~= 'number') or type(getFireImpulse) ~= 'number' then
			pcall(pingServer, ('Failed to init getSpreadVector & getFireImpulse. (%s, %s)'):format(tostring(getSpreadVector), tostring(getFireImpulse)), 'Apoc 2')
			return client:Kick('Failed to load #1')
		end

		local oGetSpreadVector = getupvalue(bullets.Fire, getSpreadVector)
		local oGetFireImpulse = getupvalue(bullets.Fire, getFireImpulse)

		setupvalue(bullets.Fire, getSpreadVector, function(random, vector, spread)
			if dirCache[vector] then
				dirCache[vector] = nil
				return vector
			end

			if library.flags.spreadReduction then
				local scale = ((100 - library.flags.spreadReductionScale) / 100)
				
				spread *= scale
			end

			return oGetSpreadVector(random, vector, spread)
		end)

		setupvalue(bullets.Fire, getFireImpulse, function(...)
			local results = { oGetFireImpulse(...) }
			if type(results[1]) == 'table' and library.flags.recoilReduction then
				local scale = ((100 - library.flags.recoilReductionScale) / 100)

				for k, v in next, results[1] do
					if type(v) == 'number' or typeof(v) == 'Vector3' or typeof(v) == 'Vector2' then
						results[1][k] *= scale
					end
				end
			end
			return unpack(results)
		end)

		do
			-- firemode mods
			local oTableFind = clonefunction(table.find);
			local oNext = clonefunction(next)

			local envs = {}
			for k, v in next, getgc() do
				if type(v) == 'function' then
					if getinfo(v).name == 'makeDrawList' or getinfo(v).name == 'setWeaponAction' then
						envs[getinfo(v).name] = getfenv(v)
						break
					end
				end
			end

			if envs.makeDrawList then
				envs.makeDrawList.next = newcclosure(function(...)
					local caller = getinfo(3)
					local arguments = {...}
	
					if library.flags.automaticWeapons and caller.name == 'makeDrawList' and (not arguments[2]) and type(arguments[1]) == 'table' then
						for _, tb in next, arguments[1] do
							if type(tb) == 'table' and tb[1] == 'Fire' then
								table.insert(arguments[1], { 'Fire Mode', { clientPlayer.Character.Binds.ToolAction } })
								break
							end
						end
					end
	
					return oNext(...)
				end)
			end

			replaceclosure(getrenv().table.find, function(...)
				if checkcaller() then return oTableFind(...) end

				local caller = getinfo(3)
				if library.flags.automaticWeapons and caller.name == 'setWeaponAction' then
					local stack = getstack(3)
					local fireModes = stack[4]
					local currentFireMode = stack[5]

					if type(fireModes) == 'table' then
						local fireModeList = { 'Automatic'; 'Semiautomatic'; 'Burst' }
						local indice = oTableFind(fireModeList, currentFireMode) or 1

						setstack(3, 4, fireModeList)
						return indice
					end
				end
				return oTableFind(...)
			end)
		end


		local foundFunc = false;
		for i, v in next, getgc() do
			if foundFunc then break end
			if type(v) ~= 'function' or (not islclosure(v)) then continue end

			local upvalues = getupvalues(v);
			for i2, v2 in next, upvalues do
				if type(v2) == 'function' and getinfo(v2).name == 'findItemData' then
					local old = getupvalue(v, i2)
					setupvalue(v, i2, function(...)
						local res = { old(...) }
						if library.flags.instantSearch then
							res[4] = 0;
						end
						return unpack(res)
					end)
					break
				end
			end
		end

		local globals = framework.require('Configs', 'Globals')
		local gravity = globals.Gravity;

		function bullets.Fire(self, ...)
			local arguments = {...}

			if library.flags.silentAim then
				local target = aimbot.getSilentTarget();
				if target then
					local gun = arguments[3]
					local origin = arguments[4]
					local pos = target.Position;

					local predicted = trajectory(origin, Vector3.new(), Vector3.new(0, gravity, 0), pos, target.Velocity, Vector3.new(), gun.FireConfig.MuzzleVelocity)
					local dir = CFrame.lookAt(origin, origin + predicted).lookVector;

					arguments[5] = dir
					dirCache[dir] = true;
				end
			end

			return oldFire(self, unpack(arguments))
		end

		function resyncCharacterHooks(character)
			local oldPlayerReload = character.Animator.PlayReloadAnimation
			local oldSetGoal = character.Animator.Springs.WobblePos.SetGoal;
			local oldPlayAnimation = character.Animator.PlayAnimationReplicated;

			function character.Animator.PlayAnimationReplicated(self, ...)
				local arguments = {...}

				if type(arguments[1]) == 'string' then
					if arguments[1]:find('Actions') and getinfo(2).name == 'animatedConsume' and library.flags.instantConsume then
						return { Wait = function() end }
					end
				end

				return oldPlayAnimation(self, ...)
			end

			function character.Animator.PlayReloadAnimation(self, ...)
				local args = { ... }

				if (library.flags.instantReload and character.EquippedItem) then
					local magSize = math.max(character.EquippedItem.FireConfig.InternalMagSize, 1)	
					
					character.Animator.ReloadEventCallback('Started', '')
					for i = 1, magSize do
						character.Animator.ReloadEventCallback('Commit', 'Load')
					end
					for i = 1, magSize do
						character.Animator.ReloadEventCallback('Commit', 'End')
					end
					character.Animator.ReloadEventCallback('Stopped', '')
					return
				end

				return oldPlayerReload(self, ...);
			end

			function character.Animator.Springs.WobblePos.SetGoal(self, ...)
				if library.flags.noGunWobble then 
					return 
				end
				return oldSetGoal(self, ...)
			end

			function character.Animator.Springs.WobbleRot.SetGoal(self, ...)
				if library.flags.noGunWobble then 
					return 
				end
				return oldSetGoal(self, ...)
			end

			local list = { "AimOffset", "AimAngles", "AimRightHandRoll", "AimLeftHandRoll", }
		
			for _, name in next, list do
				local spring = rawget(character.Animator.Springs, name)
				if type(spring) == 'table' then
					local setGoal = spring.SetGoal
					rawset(spring, 'SetGoal', function(self, ...)
						setGoal(self, ...)
						if library.flags.fastAim then
							self:SnapTo();
						end
					end)
				end
			end
		end

		clientPlayer.CharacterAdded:Connect(function(character)
			resyncCharacterHooks(character)
		end)
		
		if clientPlayer.Character then
			resyncCharacterHooks(clientPlayer.Character)
		end
	end

	local squad do -- stupid team check abcd
		local addCache = debug.getupvalue(network.Add, 4)
		if type(addCache) ~= 'table' then
			pcall(pingServer, 'addCache type mismatch', 'AR2')
			return client:Kick('failed to find addCache - contact wally')
		end
		
		local oldUpdateSquad = rawget(addCache, 'Squad Update')
		if (type(oldUpdateSquad) ~= 'function') then
			pcall(pingServer, 'Failed to find squad update function', 'AR2')
			return client:Kick('failed to find SU - contact wally')
		end

		debug.getupvalue(oldUpdateSquad, 2)
		rawset(addCache, 'Squad Update', function(data)
			fastSpawn(oldUpdateSquad, data)
			squad = data;
		end)

		function base.isSameTeam(player)
			if (type(squad) == 'table' and type(rawget(squad, 'Members')) == 'table') then
				local state = squad.Members[player]
				if (type(state) == 'table' and state.Status == 'Member') then
					return true
				end
			end

			return false
		end
	end

	local oldDeathStart, oldCorpseStep do
		oldDeathStart = deathScreen.Start;
		oldCorpseStep = corpseCamera.Step;

		function corpseCamera.Step(...)
			if library.flags.fastRespawn then
				time = 1;
			end
			return oldCorpseStep(...)
		end

		function deathScreen.Start(...)
			if library.flags.fastRespawn then
				clientPlayer:LoadCharacter();
				framework.Libraries.Interface:Get('Fade'):Fade(1, 0.1)
				return;
			end

			return oldDeathStart(...)
		end

		function attackZombie(zombie)
			local head = zombie:FindFirstChild('Head')
			if (not head) then 
				return 
			end

			local inventory = (clientPlayer.Character and clientPlayer.Character.Inventory)
			local melee = ((inventory and inventory.Equipment) and inventory.Equipment.Melee)

			if (not inventory) and (not melee) then 
				return 
			end
			
			while true do
				runService.Heartbeat:wait()

				if (not head.Parent) then break end
				if (not zombie:IsDescendantOf(workspace)) then break end

				local index = melee.ComboIndex;
				melee.ComboIndex = math.max(1, (index + 1) % (#melee.AttackConfig + 1))

				network:Send('Melee Swing', melee.Id, index)
				network:Send('Melee Hit Register', melee.Id, head, 'Flesh')
			end
		end

		task.spawn(function()
			local lastZombieStep = 0
			while true do
				lastZombieStep = lastZombieStep + runService.Heartbeat:Wait()
				if lastZombieStep < 1/30 then continue end

				if library.flags.zombieAura then
					if client.Character and client.Character:FindFirstChild('HumanoidRootPart') then
						local origin = client.Character.HumanoidRootPart.CFrame.p;
						local radius = 20;

						local min = origin - Vector3.new(radius/2, radius/2, radius/2)
						local max = origin + Vector3.new(radius/2, radius/2, radius/2)
						
						local region = Region3.new(min, max)
						local results = workspace:FindPartsInRegion3WithWhiteList(region, { workspace.Zombies.Mobs })

						local seen = {}
						for _, part in next, results do
							local zombie = part.Parent;
							if not seen[zombie] then
								seen[zombie] = true;
								task.spawn(attackZombie, zombie)
							end
						end

						if next(seen) then task.wait(0.15) end
					end
				end
			end
		end)

		local itemInitialize = framework.require("Libraries", "Resources"):Find("ReplicatedStorage.Client.Abstracts.ItemInitializers");
		local characterClass = framework.Classes.Characters

		if typeof(itemInitialize) == 'Instance' and itemInitialize:FindFirstChild('Firearm') then
			local firearmModule = require(itemInitialize.Firearm)

			local shotReadyIndice;
			for k, v in next, getupvalues(firearmModule) do
				if type(v) == 'function' and getinfo(v).name == 'isShotReady' then
					shotReadyIndice = k;
					break
				end
			end

			if shotReadyIndice then
				local oldShotReady = getupvalue(firearmModule, shotReadyIndice)
				setupvalue(firearmModule, shotReadyIndice, function(...)
					local args = { ... }
					if library.flags.fastWeapons then
						local stack = getstack(2)
						local idx = table.find(stack, args[2])

						if idx then
							if oldShotReady(args[1], 60 / 1000) then
								setstack(2, idx, (60 / 1000) + 0.001)
								return true
							end
						end
					end
					return oldShotReady(unpack(args))
				end)
			else
				pcall(pingServer, 'no shot ready indice', 'ar2')
			end
		else
			pcall(pingServer, 'cant find firearm initializer', 'ar2')
		end

		if type(characterClass) == 'table' and type(rawget(characterClass, 'Equip')) == 'function' then
			local oldEquip = characterClass.Equip

			function characterClass:Equip(item, ...)
				if item.Type == 'Firearm' and (not library.flags.automaticWeapons) then
					if (not table.find(item.FireModes, item.FireMode)) then
						item.FireMode = item.FireModes[1]
					end
				end
				return oldEquip(self, item, ...)
			end
		else
			pcall(pingServer, 'no character class equip function', 'ar2')
		end
	end

	--esp stuff 
	do
		base.characterAdded:Connect(function(player, character)
			local stats = character:WaitForChild('Stats', 5)
			local health = stats and stats:WaitForChild('Health', 5)
			local healthBase = health and health:WaitForChild('Base', 5)

			if healthBase then
				local signals = base.signals[player]
				if signals then
					signals.maid:GiveTask(healthBase:GetPropertyChangedSignal('Value'):Connect(function()
						signals.healthChanged:Fire(healthBase.Value, 100)
					end))

					signals.healthChanged:Fire(healthBase.Value, 100)
				end
			end
		end)
	end

	-- map radar
	coroutine.wrap(function()
		local playersIconList = {};
		local interface = framework.require("Libraries", "Interface");

		local map = interface:Get("Map");
		local mapGui = interface:GetGui('Map');

		local dragBin = mapGui:WaitForChild('ClipBin'):WaitForChild('DragBin')-- utils.Locate('ClipBin.DragBin', mapGui)
		local iconTemplate = dragBin:WaitForChild('LocalMarker'):Clone();

		game:GetService('Players').PlayerRemoving:connect(function(player)
			game:GetService('RunService').Heartbeat:wait()

			if (playersIconList[player]) then
				playersIconList[player]:Destroy()
				playersIconList[player] = nil;
			end
		end)

		local getMapPos = getupvalues(map.Center)[2];
		while true do
			for i, player in next, players:GetPlayers() do
				if player == client then continue end

				if (not playersIconList[player]) then
					local icon = iconTemplate:Clone()

					local tooltip = icon.MarkerCenter.Tooltip
					local _size = game:GetService('TextService'):GetTextSize(player.Name, tooltip.TextLabel.TextSize, tooltip.TextLabel.Font, Vector2.new(1000, 1000));

					tooltip.Size = UDim2.fromOffset((_size.X + 10), 25)
					tooltip.Visible = true;
					tooltip.TextLabel.Text = player.Name;
					icon.Parent = dragBin

					playersIconList[player] = icon;
				end

				local icon = playersIconList[player]
				if (library.flags.mapRadar and player.Character and player.Character:FindFirstChild('HumanoidRootPart')) then
					local isSquadMember = base.isSameTeam(player)
					local pos = getMapPos(player.Character.HumanoidRootPart.Position)

					icon.ImageColor3 = isSquadMember and (library.flags.squadMapIconColor or Color3.new(1, 1, 1)) or (library.flags.enemyMapIconColor or Color3.new(1, 1, 1))

					icon.Position = UDim2.fromScale(pos.X, pos.Y)
					icon.Visible = true;

					continue
				end

				icon.Visible = false;
			end

			game:GetService('RunService').Heartbeat:wait()
		end
	end)()

	aimbot.launch(menu);
	esp.launch(menu);
	
	local md = [[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]]

	load_game_module(md, library)

	local tab = menu:AddTab('Apocalypse Rising 2') do
		local column = tab:AddColumn()
		
		local main = column:AddSection('Main Cheats') do
			main:AddToggle({text = 'Silent Aim', flag = 'silentAim'}) -- done
			main:AddToggle({text = 'Wallbang', flag = 'wallbang'})

		--	main:AddButton({text = 'Unlock All Skins'})
			main:AddButton({ text = 'Ghost mode', callback = function() 
				local character = client.Character;
				local torso = (character and character:FindFirstChild('LowerTorso'))
				local root = (torso and torso:FindFirstChild('Root'))

				if (not root) then return end
				
				local new = root:Clone()
				root:Destroy()
				new.Parent = torso;
			end });

			--[[:AddButton({ text = 'Kill all', callback = function()
				
				if library.flags._killAll then return end 
				if clientPlayer.Character and clientPlayer.Instance then
					local inventory = (clientPlayer.Character and clientPlayer.Character.Inventory)
					local melee = ((inventory and inventory.Equipment) and inventory.Equipment.Melee)

					if (not melee) then return end

					clientPlayer.Character:Unequip()
					clientPlayer.Character:Equip(melee)

					library.flags._killAll = true;
					local old = client.Character.PrimaryPart.CFrame
					for _, plr in next, game.Players:GetPlayers() do
						if plr == client then continue end
						if base.isSameTeam(plr) then continue end

						local pCharacter = plr.Character;
						local head = pCharacter and pCharacter:FindFirstChild('Head')

						local pCharStats = pCharacter and pCharacter:FindFirstChild('Stats')
						local pHealthStat = pCharStats and pCharStats:FindFirstChild('Health')
						local pHealthBase = pHealthStat and pHealthStat:FindFirstChild('Base')
						
						if (pHealthBase and pHealthBase.Value > 0) and head then
							while true do
								game:GetService('RunService').Heartbeat:Wait()

								if pHealthBase.Value <= 0 then break end
								if (not pCharacter:IsDescendantOf(workspace)) then break end
								if (not plr:IsDescendantOf(game.Players)) then break end

								client.Character.PrimaryPart.CFrame = pCharacter.PrimaryPart.CFrame * CFrame.new(0, 5, 0)
								network:Send('Melee Hit Register', melee.Id, head, 'Flesh')
							end
						end
					end

					client.Character.PrimaryPart.CFrame = old;
					client.Character.PrimaryPart.Anchored = true;

					local origin = old.p;
					while true do
						runService.Heartbeat:Wait()

						local hit, pos = workspace:FindPartOnRayWithIgnoreList(Ray.new(origin, Vector3.new(0, -100, 0)), { client.Character, workspace:FindFirstChild('Effects'), workspace:FindFirstChild('Sounds') })
						if hit and hit:IsDescendantOf(workspace.Map.Client.Terrain) then
							break;
						end
					end

					wait(0.1)
					client.Character.PrimaryPart.Anchored = false;

					library.flags._killAll = false;
				end
			end })]]

			main:AddDivider()

			main:AddToggle({ text = 'Speedhack', flag = 'speedhack'}):AddSlider({text = 'Speed', suffix = 'm', min = 16, max = 150, flag = 'walkspeed'}):AddBind({mode = 'hold', flag = 'speedhackBind'})
			main:AddToggle({ text = 'Zombie aura', flag = 'zombieAura'})
			main:AddToggle({ text = 'Instant interact', flag = 'instantSearch'}) -- done
			main:AddToggle({ text = 'No fall damage', flag = 'noFallDamage'}) -- done
			main:AddToggle({ text = 'Fast respawn', flag = 'fastRespawn'})
			main:AddToggle({ text = 'No resource consumption', flag = 'noResourceDrain', tip = 'Stops your health & hunger from draining while sprinting.' })
		end

		local guns = column:AddSection('Weapon Mods') do
			guns:AddToggle({ text = 'Recoil reduction', flag = 'recoilReduction' }):AddSlider({ text = 'Reduction scale', flag = 'recoilReductionScale', min = 0, max = 100, value = 100, suffix = '%' })
			guns:AddToggle({ text = 'Spread reduction', flag = 'spreadReduction' }):AddSlider({ text = 'Reduction scale', flag = 'spreadReductionScale', min = 0, max = 100, value = 100, suffix = '%' })
			guns:AddToggle({ text = 'Automatic weapons', flag = 'automaticWeapons' })
			guns:AddToggle({ text = 'Fast fire', flag = 'fastWeapons' })
			guns:AddToggle({ text = 'Instant reload', flag = 'instantReload'})
			guns:AddToggle({ text = 'No gun wobble', flag = 'noGunWobble'})
			main:AddToggle({ text = 'Fast aim', flag = 'fastAim' })
		end

		local column = tab:AddColumn()
		local itemCategories = {'Firearm', 'Clothing', 'Backpack', 'Consumable', 'Ammo', 'Attachment'}

		local visuals = column:AddSection('Visuals') do
			visuals:AddToggle({text = 'Loot', flag = 'lootESP'}):AddList({
				max = #itemCategories,
				tip = 'Filter for dropped loot',
				flag = 'lootChoices',
				values = itemCategories,
				multiselect = true,
			})
			
			visuals:AddToggle({ text = 'Containers', flag = 'containerESP'}):AddColor({flag = 'containerColor'})
			visuals:AddSlider({textpos = 2, text = 'Loot distance', flag = 'lootDistance', suffix = 'm', min = 0, max = 2000, value = 200});
			visuals:AddSlider({textpos = 2, text = 'Container distance', flag = 'containerDistance', suffix = 'm', min = 0, max = 2000, value = 200});

			visuals:AddDivider('Loot Colors')
			local defaults = {
				Firearm = Color3.fromRGB(255, 17, 17),
				Clothing = Color3.fromRGB(255, 131, 0),
				Backpack = Color3.fromRGB(40, 223, 40);
				Consumable = Color3.fromRGB(246, 83, 166),
				Ammo = Color3.fromRGB(249, 215, 28),
				Attachment = Color3.fromRGB(42, 157, 244)
			}

			for i, category in next, itemCategories do
				visuals:AddColor({text = category, flag = (category .. 'Color'), color = defaults[category]})
			end

			visuals:AddDivider'Misc '
			visuals:AddToggle{ text = 'Map radar', flag = 'mapRadar' }
			visuals:AddColor{ text = 'Squad icon color', flag = 'squadMapIconColor', color = Color3.new(1, 1, 1) }
			visuals:AddColor{ text = 'Enemy icon color', flag = 'enemyMapIconColor', color = Color3.new(1, 1, 1) }
		end
	end
end);

games.add({301252049}, "RoBeats!", function(menu)
	SX_VM_B()
	while (not game:IsLoaded()) do wait(1) end
	
	local noteAccuracy, heldNotes = {}, {};	
	local rand = Random.new();

	local config = {};

	local eventString, mainClient, mainScript, network do
		local mainClosureConstant = 'Profiling(%s)';

		repeat
			for i, v in next, getgc(false, false, true, false, false) do
				if type(v) ~= "function" then continue end
				if (not islclosure(v)) then continue end
				if is_synapse_function(v) then continue end

				if table.find(getconstants(v), mainClosureConstant) then
					eventString = getupvalue(v, 1)
					mainClient = getupvalue(v, 2);
					break;
				end
			end

			wait(1)
		until (mainClient and eventString)

		network = mainClient._evt;
		mainScript = utilities.WaitFor('PlayerScripts.LocalMain', client)
	end

	local oldFireEvent, networkIds = rawget(network, 'fire_event_to_server') do
		if type(oldFireEvent) ~= 'function' or (not rawget(network, 'server_generate_encodings')) then
			return client:Kick('e-1')
		end

		networkIds = getupvalue(network.server_generate_encodings, 1);

		local idTranslator = {}
		for name, id in next, networkIds do
			idTranslator[id] = name
		end

		rawset(network, 'fire_event_to_server', function(self, id, ...)
			local translated = (idTranslator[id] or ''):lower()
			local arguments = {...}

			if id == networkIds.EVT_ErrorReport_ClientReportError then
				-- sry ur not giving spotcoe my errors :(
				return
			elseif id == networkIds.EVT_EventReport_ClientExploitDetected or translated:lower():find'exploit' then
				-- uhhhhhhhh please dont break on me -_-

				pcall(pingServer, 'RoBeats_ExploitDetected_' .. id)
				fastSpawn(function() client:Kick('Attempted to prevent detection. Please post this message in #bugs.') end)
				return wait(9e9)
			elseif id == networkIds.EVT_Crafting_ClientCraftGatchaAttempt and library.flags.buyDoubleNoteMachine then
				if type(arguments[1]) == 'number' then
					arguments[1] = arguments[1] * 2
				end
			end

			return oldFireEvent(self, id, unpack(arguments))
		end)
	end

	local lobbyJoin = mainClient._lobby_join
	local lobbyLocal = getupvalue(lobbyJoin.setup_lobby, 1);
	local menus = getupvalue(mainClient._menus.menu_count, 1)
	
	if type(lobbyLocal) ~= 'table' or (not rawget(lobbyLocal, "destroy_unstarted_game_and_exit_to_lobby")) then
		-- the game hasnt started :(
		local lMenu = menus:find(nil, function(val)
			if type(val) == 'table' and rawget(val, 'cons') then
				if getinfo(val.cons).source:find("%.NewsUI$") then
					return true
				end
			end
		end)

		if lMenu ~= -1 then
			lobbyJoin:setup_lobby(mainClient)
			lobbyJoin:start_lobby();

			-- i hope the callback or setting `u16` to TutorialManager.Mode.None isnt important...
			lobbyJoin:push_ui_to_lobby(function() end)

			-- mainClient._tutorial_manager
			while true do
				wait(1)
				lobbyLocal = getupvalue(lobbyJoin.setup_lobby, 1);
				
				if (type(lobbyLocal) == 'table' and rawget(lobbyLocal, 'destroy_unstarted_game_and_exit_to_lobby')) then
					break
				end
			end

			wait(5)
		end
	end
	
	local function searchForDependency(fakeName, lookup, trace, fName)
		local result = utilities.Filter(lookup, function(k, value)
			if type(value) == 'table' then
				local passed = false;

				if (fName) then
					local func = rawget(value, fName)
					if func then
						local src = getinfo(func).source
						if src:match(trace) then
							passed = true;
						end
					end

					return passed
				end

				for i, func in next, value do
					if type(func) == 'function' and islclosure(func) then
						local src = getinfo(func).source
						if src:match(trace) then
							passed = true;
							break
						end
					end
				end

				return passed
			end
		end) 

		if (not result) then
			client:Kick(string.format('\nFailed to find dependency %s', fakeName))
			return wait(9e9)
		end

		return result
	end
	
	local gameJoin = mainClient._game_join

	-- thank you getinfo for keeping the original function source 

	local gameLocal = searchForDependency("GL", getupvalues(gameJoin.load_game), "%.GameLocal$", 'new')
	local trackSystem = searchForDependency("TS", getupvalues(gameLocal.new), "%.TrackSystem$");
	local scoreManager = searchForDependency("SM", getupvalues(gameLocal.new), "%.ScoreManager$");
	local gearStats = searchForDependency("GS",  getupvalues(scoreManager.new), "%.GearStats$");
	local audioManager = searchForDependency("AM", getupvalues(gameLocal.new), "%.AudioManager$");

	local note = searchForDependency("NT", getupvalues(audioManager.new), "%.Note$")
	local noteBase = searchForDependency("NB", getupvalues(note._new), "%.NoteBase$")
	local noteResultPopup = searchForDependency("NP", getupvalues(scoreManager.new), "%.NoteResultPopupEffectV2$");
	local noteSequencePlayer = searchForDependency('NSP', getupvalues(gameLocal.new), "%.NoteSequencePlayer$")

	if type(networkIds) ~= 'table' then 
		return client:Kick(string.format('\nFailed to find dependency %s', "nids"))
	end

	
	local playerBlob = mainClient._player_blob_manager;	

	if type(lobbyJoin) ~= 'table' or type(rawget(lobbyJoin, 'setup_lobby')) ~= 'function' then
		return client:Kick(string.format('\nFailed to find dependency %s', "LJ"))
	end

	local songDatabase do
		for i, v in next, getloadedmodules() do
			local res = require(v);
			if type(res) == 'table' and rawget(res, 'invalid_songkey') then
				songDatabase = res:singleton(); 
				break
			end
		end
	end

	if (not songDatabase) then
		return client:Kick('Failed to find songDatabase.')
	end

	local function unlockSongs()
		local songMap;
	
		local clientBlob = playerBlob:get_player_blob();
		local songMap = getupvalue(songDatabase.key_to_name, 1);

		local fakeInventory = {};
		local nameToKey = {};

		for i = 1, #songMap do
			local name = songMap[i];

			nameToKey[name] = i;
			table.insert(fakeInventory, { Count = 1; Key = i; })
		end

		-- Server will update clients Inventory during certain network events, we do not want that :)

		clientBlob.SongInventory = nil;
		setmetatable(clientBlob, {__index = function(self, key)
			if key == 'SongInventory' then
				return fakeInventory
			end
			return rawget(self, key)
		end, __newindex = function(self, key, value)
			if key == 'SongInventory' then
				return
			end
			return rawset(self, key, value)
		end})

		local oldWaitFor, oldWaitForOnce, oldFireEvent;
		oldWaitForOnce = utilities.Hook(network, 'wait_on_event_once', function(self, event, ...)
			local arguments = {...}

			if (event == networkIds.EVT_GameLoad_ServerNotifyClientDoPreload) then
				local oldCallback = arguments[1];
				arguments[1] = function(...)
					local res = {...}

					for i, v in next, res[3] do
						if v.Name == client.Name then
							v.RequestedSongKey = _G.songKey 
						end
					end

					res[5] = _G.songKey
					return oldCallback(unpack(res))
				end
			end

			return oldWaitForOnce(self, event, unpack(arguments))
		end)

		oldFireEvent = utilities.Hook(network, 'fire_event_to_server', function(self, event, ...)
			local arguments = {...}
			if (event == networkIds.EVT_GameLoad_MatchmakingV3_ClientEnqueue or event == networkIds.EVT_GameLoad_MatchmakingV3_ClientImmediateStartSingleplayer) then
				_G.songKey = arguments[1];
				arguments[1] = nameToKey["MondayNightMonsters1"]
			end
			return oldFireEvent(self, event, unpack(arguments))
		end)

		oldWaitFor = utilities.Hook(network, 'wait_on_event', function(self, event, ...)
			local arguments = {...}
			if (event == networkIds.EVT_GameLoad_ServerUpdateMatchMakingInfo) then
				local oldCallback = arguments[1];
				arguments[1] = function(...)
					local res = {...}

					for i, v in next, res[1] do
						if v.Name == game.Players.LocalPlayer.Name then
							v.RequestedSongKey = _G.songKey 
						end
					end

					return oldCallback(unpack(res))
				end
			end

			return oldWaitFor(self, event, unpack(arguments))
		end)
	end	

	local function tableFind(tbl, val, s)
		for i, v in next, tbl, s do
			if v == val then
				return i;
			end
		end
	end

	local findFromConstants do
		function findFromConstants(f, id, inc)
			local constants = getconstants(f);
			local inc = (inc or 1);
			local idx = (tableFind(constants, id) or 0) + inc

			return constants[idx]
		end
	end

	do
		local oldgameupdate 
		oldgameupdate = utilities.Hook(gameJoin, 'update', function(self, scale)
			scale = scale * ((library.flags.songSpeed or 100) / 100)
			return oldgameupdate(self, scale)
		end)
	end

	-- god i hate this but spotco likes to play so.. 

	local function searchByProto(fakeName, protos, consts)
		local result = nil;

		local func = utilities.Filter(protos, function(_, func)
			if type(func) == 'function' and islclosure(func) then
				local constants = getconstants(func)
				local passed = true;

				local idx = nil;

				for _, term in next, consts do
					idx = tableFind(constants, term, idx)
					if (not idx) then
						passed = false;
						break
					end
				end

				return passed
			end
		end)

		if func then
			result = getinfo(func).name
		end

		return result;

	end

	local trackSystemProtos = getprotos(trackSystem.new);
	local scoreManagerProtos = getprotos(scoreManager.new);
	local audioManagerProtos = getprotos(audioManager.new);
	local noteSequenceProtos = getprotos(noteSequencePlayer.new);
	local gameLocalProtos    = getprotos(gameLocal.new)

	local ts_update = searchByProto('t1', trackSystemProtos, {  "count", "get", "do_remove", decrypt(consts["720"], constantKey, "mGCG6vFseiOzHPH0"), })
	local ts_tearddown = searchByProto('t2', trackSystemProtos, { "count", "get", "do_remove", "clear" })

	local es_tracksys_press = searchByProto('t3', trackSystemProtos, { "press", "count", "get", decrypt(consts["645"], constantKey, "mGCG6vFseiOzHPH0") })
	local es_tracksys_release = searchByProto('t4', trackSystemProtos, { "release", "count", "get" })

	local es_pscore_rh = searchByProto('s1', scoreManagerProtos, { "PlaySFX", "HoldEffectPosition", "NotifyServer" })

	local noteResultCons, registerHitProto; do
		for i, proto in next, getprotos(noteResultPopup._new) do
			if getinfo(proto).name == 'cons' then
				noteResultCons = proto;
				break
			end
		end

		for i, proto in next, scoreManagerProtos do
			if getinfo(proto).name == es_pscore_rh then
				registerHitProto = proto;
				break
			end
		end

		if (not noteResultCons) then
			pcall(pingServer, 'Missing NRC', 'RoBeatsDependency')
			client:Kick(string.format('\nFailed to find dependency %s', "NRC"))
			return wait(9e9)
		end

		if (not registerHitProto) then
			pcall(pingServer, 'Missing RHP', 'RoBeatsDependency')
			client:Kick(string.format('\nFailed to find dependency %s', "RHP"))
			return wait(9e9)
		end
	end
	
	local noteResultConsts = getconstants(noteResultCons)
	local registerHitConsts = getconstants(registerHitProto)
	local gameLocalConsts = getconstants(gameLocal.new)
	
	local str = (game.PlaceVersion >= 1187 and 'is_ingame_sfx_enabled' or decrypt(consts["608"], constantKey, "mGCG6vFseiOzHPH0"))
	local off = (game.PlaceVersion >= 1187 and 1 or 2)

	local nr_perfect_id = registerHitConsts[tableFind(registerHitConsts, str) + off]
	local nr_miss_id = noteResultConsts[tableFind(noteResultConsts, decrypt(consts["985"], constantKey, "mGCG6vFseiOzHPH0")) - 1]
	local nr_great_id = noteResultConsts[tableFind(noteResultConsts, decrypt(consts["438"], constantKey, "mGCG6vFseiOzHPH0")) - 1]
	local nr_okay_id = noteResultConsts[tableFind(noteResultConsts, decrypt(consts["608"], constantKey, "mGCG6vFseiOzHPH0")) - 1]

	local get_score_manager = gameLocalConsts[tableFind(gameLocalConsts, '_effects') + 22]

	if (not nr_miss_id) or (not nr_great_id) then
		return client:Kick(string.format('\nFailed to find dependency %s', "id0"))
	end

	local ts_get_track, get_local_game_slot, get_game_slot do
		utilities.Filter(trackSystemProtos, function(_, val)
			if type(val) == 'function' then 
				if getinfo(val).name == es_tracksys_press then
					ts_get_track = getconstant(val, 1)
				end

				if getinfo(val).name == ts_update then
					get_local_game_slot = getconstant(val, 11)
				end
			end
		end)

		utilities.Filter(audioManagerProtos, function(_, val)
			if type(val) == 'function' then
				if getinfo(val).name == 'update_spawn_notes' then
					-- todo: find a better constant to offset from
					get_game_slot = getconstant(val, 18)
				end
			end
		end)

		if (not ts_get_track) then
			pcall(pingServer, 'Missing TGT', 'RoBeatsDependency')
			return client:Kick(string.format('\nFailed to find dependency %s', "TGT"))
		end

		if (not get_local_game_slot) then
			pcall(pingServer, 'Missing GGS', 'RoBeatsDependency')
			return client:Kick(string.format('\nFailed to find dependency %s', "GGS"))
		end

		if (not get_game_slot) then
			pcall(pingServer, 'Missing GGS2', 'RoBeatsDependency')
			return client:Kick(string.format('\nFailed to find dependency %s', "GGS2"))
		end
	end

	local get_notes, get_tracksystem do
		utilities.Filter(gameLocalProtos, function(_, val)
			if type(val) == "function" then
				if getinfo(val).name == 'update' then
					get_tracksystem = getconstant(val, (tableFind(getconstants(val), 'control_just_pressed') or 0) + 1)
				end
			end
		end)

		utilities.Filter(noteSequenceProtos, function(_, val)
			if type(val) == 'function' then
				if getinfo(val).name == 'test_active_notes' then
					get_notes = getconstant(val, (tableFind(getconstants(val), 'update_scoremanager_to_note_sequence_event') or 0) + 1)
				end
			end
		end)

		if (not get_tracksystem) then
			pcall(pingServer, 'Missing GTS2', 'RoBeatsDependency')
			return client:Kick(string.format('\nFailed to find dependency %s', "GTS2"))
		end

		if (not get_notes) then
			pcall(pingServer, 'Missing GN1', 'RoBeatsDependency')
			return client:Kick(string.format('\nFailed to find dependency %s', "GN1"))
		end
	end

	local noteTypes do
		for i, v in next, getupvalues(noteResultPopup._new) do
			if type(v) == 'table' then
				if rawget(v, nr_miss_id) and rawget(v, nr_great_id) then
					noteTypes = v;
					break
				end
			end
		end

		if (not noteTypes) then
			pcall(pingServer, 'Missing NT', 'RoBeatsDependency')
			return client:Kick(string.format('\nFailed to find dependency %s', "NT"))
		end
	end

	local nr_perfect = noteTypes[nr_perfect_id]
	local nr_great = noteTypes[nr_great_id]
	local nr_okay = noteTypes[nr_okay_id]
	local nr_miss = noteTypes[nr_miss_id]

	-- print(nr_perfect_id, nr_great_id, nr_okay_id, nr_miss_id)
	-- warn(tableToString(noteTypes))
	-- warn(tableToString(registerHitConsts))

	local fn_test_hit, fn_test_release do
		if debug.getprotos then
			for i, v in next, trackSystemProtos do
				local constants = getconstants(v);
				if tableFind(constants, 'ParamNoteHitMode') then
					fn_test_hit = findFromConstants(v, 'get_track_index')
				elseif tableFind(constants, 'get_track_index') and tableFind(constants, 'release') then
					fn_test_release = findFromConstants(v, 'get_track_index')
				end
			end
		else
			fn_test_hit = findFromConstants(noteBase.NoteBase, 'get_state')
			fn_test_release = findFromConstants(noteBase.NoteBase, 'get_state', 3)
		end
	end

	local failed = false;	
	local translated = {};
	
	setmetatable(translated, {__newindex = function(self, key, value)
		if value == nil then
			failed = true;
			pcall(pingServer, ('RoBeats translation failure %s -> %s'):format(tostring(key), tostring(value)), 'RoBeatsTranslation1')
			client:Kick('\n[RoBeats!] Translation table failed [1]. Code: [' .. key .. ']');
			return;
		end

		return rawset(self, key, value)
	end})

	translated.ts_tearddown = ts_tearddown
	translated.get_game_slot = get_game_slot

	translated.get_local_game_slot = get_local_game_slot
	translated.ts_update = ts_update
	translated.ts_get_track = ts_get_track
	translated.es_pscore_rh = es_pscore_rh;
	translated.get_tracksystem = get_tracksystem;
	translated.get_notes = get_notes;
	translated.get_score_manager = get_score_manager

	translated.es_tracksys_press = es_tracksys_press;
	translated.es_tracksys_release = es_tracksys_release;

	translated.fn_test_hit = fn_test_hit;
	translated.fn_test_release = fn_test_release;

	translated.nr_perfect_id = nr_perfect_id;
	translated.nr_great_id = nr_great_id;
	translated.nr_okay_id = nr_okay_id;
	translated.nr_miss_id = nr_miss_id;

	for i, v in next, translated do
		-- this is probably gonna fuck me over but who cares 
		-- yep it fucked up cuz his poopy update but he fixed so yep gg

		-- march 2020 he removed virtually all of the security ... so here's a quick "patch"
		if type(v) ~= 'string' or (v:sub(1, 1) ~= "_" and v:sub(1, 2) ~= 'es') then 
			if (tostring(v) == tostring(i)) then continue end
			
			pcall(pingServer, string.format('RoBeats Translation failure %s -> %s', tostring(i), tostring(v)), 'RoBeatsTranslation2')
			client:Kick('\n[RoBeats!] Translation table failed [2]. Code: [' .. i .. ']');
			break;
		end
	end

	if failed then return end

	-- // tracksystem hook
	local scoreManagerHook = function() end
	local oldTrackSystem do
		local mapping = {
			perfect = nr_perfect;
			great = nr_great;
			okay = nr_okay;
			miss = nr_miss;
		};

		local rng = Random.new();
		
		local results = {"miss", "okay", "great", "perfect"}
		local function calculate_accuracy(rand)
			local noteList = {};
			local sum = 0;

			for _, type in next, results do
				noteList[#noteList + 1] = {
					type = type,
					value = library.flags[type] or 0,
				}

				sum = (sum + library.flags[type] or 0);
			end

			table.sort(noteList, function(a, b) return a.value > b.value end)

			if sum == 0 then
				return mapping[results[rng:NextInteger(1, #results)]]
			end

			local initialWeight = rng:NextInteger(0, sum);
			local currentWeight = 0;

			for _, v in next, noteList do
				currentWeight = currentWeight + v.value;
				if currentWeight > initialWeight then
					return mapping[v.type]
				end
			end
		end

		local function update(game, slot)
			local localslot = game[get_local_game_slot](game)
			if localslot ~= slot then return end
			if (not library.flags.autoPlayer) then debugprint'autoplayer disabled' return end

			local track = game[get_tracksystem](game, slot)
			local notes = track[get_notes](track);
			
			local manager = game[get_score_manager](game)
			if type(manager) == 'table' then
				local registerHit = rawget(manager, es_pscore_rh) 
				if type(registerHit) == 'function' and (not is_synapse_function(registerHit)) then
					scoreManagerHook(manager)
				end
			end

			for i = 1, notes:count() do
				local note = notes:get(i)
				local note_track = note:get_track_index(i);

				local test_release = note[fn_test_release]
				local test_hit = note[fn_test_hit]

				local accuracy = calculate_accuracy(rand:NextInteger(1, 100))
				local press_track_index = track[es_tracksys_press]
				local release_track_index = track[es_tracksys_release]

				local NoteType = 'Note' do
					if (type(note.get_tail_t) == 'function') then
						NoteType = 'HeldNote';
					end
				end

				game:debug_any_press();

				if heldNotes[note_track] then
					local released, result = test_release(game)
					if released and result == noteAccuracy[note_track] then
						heldNotes[note_track] = false;
						noteAccuracy[note_track] = nil;

						release_track_index(track, game, note_track) 

						track[ts_get_track](track, note_track):release();
					end

					continue;
				end

				local hit, result = test_hit(game);
				if hit and result == accuracy then
					press_track_index(track, game, note_track)

					if NoteType == 'HeldNote' then
						heldNotes[note_track] = true;
						noteAccuracy[note_track] = accuracy;
						continue;
					end

					fastSpawn(function() 
						release_track_index(track, game, note_track) 
						track[ts_get_track](track, note_track):release();
					end)
				end
			end
		end

		local function fromInt32(int)
			local r = bit32.band(int, 255);
			local g = bit32.band(bit32.rshift(int, 8), 255);
			local b = bit32.band(bit32.rshift(int, 16), 255);

			return Color3.fromRGB(r, g, b)
		end

		local noteSkinColor do
			for i, v in next, getupvalues(noteBase.NoteBase) do
				if type(v) == 'table' and rawget(v, 'new') then
					local info = getinfo(v.new).source
					if info:match("%.NoteSkinColor$") then
						noteSkinColor = v;
						break
					end
				end
			end

			if (not noteSkinColor) then
				return client:Kick('e-4')
			end
		end

		local function updateColors(game, slot)
			local localslot = game[get_local_game_slot](game)
			if localslot ~= slot then return end

			local track = game[get_tracksystem](game, slot)
			local notes = track[get_notes](track);

			if (not notes) then return end

			local baseIdx = (library.flags.noteColorsEnabled and 'trackColor' or 'BaseColor')
			local feverIdx = (library.flags.noteColorsEnabled and 'trackColor' or 'FeverColor')
			local colorLoc = (library.flags.noteColorsEnabled and library.flags or playerBlob:get_player_blob())

			local syncColors = (library.flags.noteToggles and library.flags.noteToggles['Sync Colors'])
			local baseNoteIdx = (syncColors and baseIdx) or (library.flags.noteColorsEnabled and 'noteColor') or 'BaseColor'
			local feverNoteIdx = (syncColors and feverIdx) or (library.flags.noteColorsEnabled and 'noteColor') or 'FeverColor'
			
			local useRainbowTracks = (library.flags.noteColorsEnabled and (library.flags.noteToggles and library.flags.noteToggles['Rainbow Tracks']))
			local useRainbowNotes = (library.flags.noteColorsEnabled and (library.flags.noteToggles and library.flags.noteToggles['Rainbow Notes']))

			local rainbowColor = Color3.fromHSV(tick() * 32 % 255/255, 1, 1)

			for i = 1, 4 do
				local baseColor = useRainbowTracks and rainbowColor or colorLoc[baseIdx .. i]
				local feverColor = useRainbowTracks and rainbowColor or colorLoc[feverIdx .. i]

				if type(baseColor) == 'number' then
					baseColor = fromInt32(baseColor)
					feverColor = fromInt32(feverColor)
				end

				track[ts_get_track](track, i):set_game_noteskin_colors(baseColor, feverColor)
			end

			for i = 1, notes:count() do
				local note = notes:get(i)
				local idx = note:get_track_index(i);

				local baseColor = useRainbowNotes and rainbowColor or colorLoc[baseNoteIdx .. idx]
				local feverColor = useRainbowNotes and rainbowColor or colorLoc[feverNoteIdx .. idx]

				if type(baseColor) == 'number' then
					baseColor = fromInt32(baseColor)
					feverColor = fromInt32(feverColor)
				end

				local bR, bG, bB = math.floor((baseColor.r * 255) + 0.5), math.floor((baseColor.g * 255) + 0.5), math.floor((baseColor.b * 255) + 0.5)
				local fR, fG, fB = math.floor((feverColor.r * 255) + 0.5), math.floor((feverColor.g * 255) + 0.5), math.floor((feverColor.b * 255) + 0.5)
						
				note:set_note_colors(noteSkinColor:new(bR, bG, bB), noteSkinColor:new(fR, fG, fB))
			end
		end

		local function teardown()
			noteAccuracy, heldNotes = {}, {};
		end

		-- oldTrackSystem = utilities.Hook(trackSystem, 'new', function(...)
		-- 	local arguments = {...}
		-- 	local currentTrack = oldTrackSystem(...)

		-- 	local system = arguments[1];
		-- 	local data = arguments[2];
		-- 	local slot = arguments[3];

		-- 	local slotdata = data._players._slots;
		-- 	if slotdata then
		-- 		local id = slotdata._table[slot]._id;
		-- 		if tonumber(id) == client.UserId then
		-- 			local gears = slotdata._table[slot]._gear_stats
		-- 			config.gear_stats = gears;

		-- 			local oldTrackUpdate, oldTrackTeardown do
		-- 				oldTrackUpdate = utilities.Hook(currentTrack, ts_update, function(self, slot, game)							
		-- 					update(game, currentTrack[get_game_slot](currentTrack));
		-- 					updateColors(game, currentTrack[get_game_slot](currentTrack))
		-- 					return oldTrackUpdate(self, slot, game)
		-- 				end)

		-- 				oldTrackTeardown = utilities.Hook(currentTrack, ts_tearddown, function(...)
		-- 					teardown()
		-- 					return oldTrackTeardown(...)
		-- 				end)
		-- 			end
		-- 		end
		-- 	end

		-- 	return currentTrack
		--end)

		config._update = update;
		config._updateColors = updateColors
		config._teardown = teardown;
	end

	-- fastSpawn(function()
	local slotData
	local slotUpdt = tick();

	game:GetService('RunService').Heartbeat:connect(function()
		if (not library._loaded) then return end

		local currentGame = getupvalue(gameJoin.start_game, 1)
		if currentGame then
			-- dont fail me mr 3ds :/
			local slot = secureCall(currentGame[get_local_game_slot], mainScript, currentGame)
			local track = secureCall(currentGame[get_tracksystem], mainScript, currentGame, slot)

			if track then
				if (not slotData) or (tick() - slotUpdt) > 1 then
					slotUpdt = tick();
					for i, v in next, getupvalues(track[es_tracksys_press]) do
						if type(v) == 'table' and rawget(v, '_players') then
							slotData = v._players._slots:get(slot)._gear_stats
							break;
						end
					end

					config.gear_stats = slotData;
				end

				config._update(currentGame, track[get_game_slot](track))
				config._updateColors(currentGame, track[get_game_slot](track))
			end
			
			return;
		end

		-- there is gear stats but... there is no active game!
		-- commence teardown
		if (slotData) then
			config._teardown()
		end
	end)

	local oldScoreManager do
		local noteResults = {
			[nr_perfect] = 'Perfect';
			[nr_great] = 'Great';
			[nr_okay] = 'Okay';
			[nr_miss] = 'Miss';
		};

		local function getRandomDelta(result, delta)
			local min, max = nil, nil;
			local hitType = noteResults[result];

			local okay_max, great_max, perfect_max, perfect_min, great_min, okay_min = gearStats:get_note_times(config.gear_stats)
			if hitType == 'Perfect' then
				min, max = (perfect_min + 1), (perfect_max - 1)
			elseif hitType == 'Great' then
				if utilities.IsBetween(delta, perfect_min, great_min) then
					min, max = (perfect_min - 1), (great_min + 1)
				else
					min, max = (perfect_max + 1), (great_max - 1)
				end
			elseif hitType == 'Okay' then
				if rand:NextInteger(1, 2) == 1 then
					min, max = (great_max + 1), (okay_max - 10)
				else
					min, max = (great_min - 1), (okay_min + 1)
				end
			end

			if (not min) or (not max) then error'wat' end

			return rand:NextInteger(min, max)
		end

		scoreManagerHook = function(manager)
			local oldRegisterHit = manager[es_pscore_rh]

			manager[es_pscore_rh] = function(self, ...)
				local arguments = {...}
				local hit_result = arguments[2];
				local data_table = arguments[5];

				if data_table and data_table.Delta then
					data_table.Delta = getRandomDelta(hit_result, data_table.Delta)
				end

				return oldRegisterHit(self, unpack(arguments))
			end
		end
	end

	local getNonVisited;
	local coinsAmount = 0;
	local starsAmount = 0;

	fastSpawn(function()
		local bindable = Instance.new('BindableEvent');

		local npcList = {};
		local visitList = {};

		network:wait_on_event(networkIds.EVT_WebNPC_ServerAcknowledgeClientVisitNPC, function(...)
			bindable:Fire(...)
		end)

		network:wait_on_event_once(networkIds.EVT_WebNPC_ServerInfoResponse, function(...)
			local arguments = {...}
			local response = arguments[1]

			for id, visited in next, response.VisitedList do
				if (visited) then 
					table.insert(visitList, tonumber(id))
					continue 
				end

				table.insert(npcList, tonumber(id))
			end

			bindable:Fire()
		end)

		network:fire_event_to_server(networkIds.EVT_WebNPC_ClientRequestInfo)
		bindable.Event:wait()		

		while (not config.starsLabel) do
			wait(0.1)
		end

		config.coinsLabel.Text = string.format('Coins Earned: %s', coinsAmount);
		config.starsLabel.Text = string.format('Stars Earned: %s', starsAmount);

		local serverHistory = utilities.GetSetting("wh-robeats-servers") or {};

		debugprint(serverHistory)
		if tableToString then
			debugprint(tableToString(serverHistory))
		end

		local function getServerList()
			local url = 'https://games.roblox.com/v1/games/%s/servers/public?cursor=%s';
			local cursor = "";

			local serverList = {};
			while true do
				local success, response = pcall(httpGet, game, url:format(game.PlaceId, cursor))
				if (not success) or (not response) then
					debugprint('ratelimit or http error', success, response)
					wait(1)
					continue
				end

				if (not pcall(jsonDecode, httpService, response)) then
					if response and response:len() > 0 then
						client:Kick("\nFailed to parse JSON for serverhop. Please send the 'robeats-error.dat' file from your Synapse X 'workspace' in the #bugs channel and mention wally with this kick message")
						writefile("robeats-error.dat", b64_encode(response))
						break
					end
					continue
				end

				local decoded = httpService:JSONDecode(response);
				for i, server in next, decoded.data do
					if table.find(serverHistory, server.id) then 
						debugprint("ignoring server because in list")
						continue
					end

					serverList[#serverList + 1] = { guid = server.id; count = server.playing }
				end

				if (not decoded.nextPageCursor) then
					break;
				end

				cursor = decoded.nextPageCursor;
			end

			if #serverList == 0 then
				debugprint("server list is full")
				client:Kick('Ran out of servers. Please try again later.')
				return nil
			end

			return serverList
		end

		function getNonVisited()
			local count = 0;

			for _ in next, npcList do
				count = count + 1;
			end

			return count;
		end

		local count = getNonVisited()
		
		config.npcLabel.Text = ('NPC Count: %s'):format(count)
		
		local statusMessage;
		while true do
			runService.Heartbeat:wait()

			if (not library.flags.collectNPCs) then continue end

			for i = #npcList, 1, -1 do
				local id = npcList[i]
				local clock = os.clock()
				network:fire_event_to_server(networkIds.EVT_WebNPC_ClientVisitNPC, id);
				
				local success, msg = bindable.Event:wait();
				local current = os.clock()

				statusMessage = msg;
				if (success) then
					local idx = table.find(npcList, id)
					if idx then
						table.remove(npcList, idx)
						table.insert(visitList, id)
					else
						debugprint('npc id not in list ??')
					end

					count = count - 1;

					local data = playerBlob:get_player_blob()
					local oldStars = data.StarCurrency
					local oldCoins = data.CoinCurrency

					playerBlob:do_sync(function(...)
						syn_context_set(7);
						local data = playerBlob:get_player_blob()
						local sDiff = (data.StarCurrency - oldStars)
						local cDiff = (data.CoinCurrency - oldCoins)

						if sDiff > 0 then
							starsAmount += sDiff
						end

						if cDiff > 0 then
							coinsAmount += cDiff
						end

						config.coinsLabel.Text = ('Coins Earned: %s'):format(coinsAmount)
						config.starsLabel.Text = ('Stars Earned: %s'):format(starsAmount)

						config.npcLabel.Text = ('NPC Count: %s'):format(count)
						syn_context_set(2);
					end)

					if game.PlaceVersion >= 1151 then
						local cooldown = 1.5;
						local distance = (cooldown - (current - clock))
						
						if math.max(0, distance) > 0 then
							wait(distance)
						end
					end
				elseif msg == 'collection max' then 
					break
				end

				if count == 0 then break end
			end
			
			if statusMessage == 'collection max' then break end
			if count == 0 then break end
		end

		while true do
			if (not getupvalue(gameJoin.start_game, 1)) and (library.flags.serverHopNPCs) then
				break
			end
			wait(1)
		end

		if (not library.flags.serverHopNPCs) then
			return
		end

		local jobId = game.JobId;
		if (not table.find(serverHistory, jobId)) then
			table.insert(serverHistory, jobId);
		end
			
		local servers = getServerList()
		local chosen = servers[Random.new():NextInteger(1, #servers)]

		table.insert(serverHistory, chosen.guid);
		utilities.SetSetting('wh-robeats-servers', serverHistory)

		teleportService:TeleportToPlaceInstance(game.PlaceId, chosen.guid);
	end)


	local clientToServerMapping = {
		[networkIds.EVT_Players_ClientQueryPlayerList] = 					networkIds.EVT_Players_ServerQueryPlayerListResponse,
		[networkIds.EVT_LobbySpectate_ClientRequestJoinPlayerId] = 			networkIds.EVT_LobbySpectate_ServerResponseRequestJoinPlayerId,
		[networkIds.EVT_Spectate_ClientRequestApplySpectatorCheerReward] =  networkIds.EVT_Spectate_ServerAppliedSpectatorCheerReward,
		[networkIds.EVT_Spectate_ClientCheerPlayerId] = 					networkIds.EVT_Spectate_ServerResponseCheerPlayerId
	}

	local function fire_and_wait(event, ...)
		local serverEvent = clientToServerMapping[event]
		if (not serverEvent) then error('missing enum ' .. tostring(event)) end

		local bindable = Instance.new('BindableEvent')
		network:wait_on_event_once(serverEvent, function(...)
			bindable:Fire(...)
		end)
		network:fire_event_to_server(event, ...)
		return bindable.Event:Wait()
	end

	do
		local constants do
			for i, v in next, getgc(true) do
				if type(v) == 'table' and rawget(v, 'SPECTATE_JOIN_COOLDOWN_SEC') and rawget(v, 'SPECTATE_CHEER_COOLDOWN_MS') then
					constants = v;
					break
				end
			end
		end

		local cheerTimer = 0;
		local spectateTimer = 0;

		fastSpawn(function()
			while true do
				game:GetService('RunService').Heartbeat:wait()
				if (not library.flags.autoCheer) then continue end
				if (tick() - spectateTimer) > constants.SPECTATE_JOIN_COOLDOWN_SEC and (tick() - cheerTimer) > (constants.SPECTATE_CHEER_COOLDOWN_MS/1000) then
					spectateTimer = tick()
					cheerTimer = tick()

					local playerList = fire_and_wait(networkIds.EVT_Players_ClientQueryPlayerList)
					local selectedPlayer do
						for _, player in next, playerList do
							if player.Activity == 3 then
								selectedPlayer = player;
								break
							end
						end
					end

					if selectedPlayer then
						local joined = fire_and_wait(networkIds.EVT_LobbySpectate_ClientRequestJoinPlayerId, selectedPlayer.PlayerId)
						if joined then
							local didCheer, error = fire_and_wait(networkIds.EVT_Spectate_ClientCheerPlayerId, selectedPlayer.PlayerId)
							if didCheer then
								fire_and_wait(networkIds.EVT_Spectate_ClientRequestApplySpectatorCheerReward)
								
								local data = playerBlob:get_player_blob()
								local oldStars = data.StarCurrency
								local oldCoins = data.CoinCurrency

								playerBlob:do_sync(function(...)
									syn_context_set(7);
									local data = playerBlob:get_player_blob()
									local sDiff = (data.StarCurrency - oldStars)
									local cDiff = (data.CoinCurrency - oldCoins)

									if sDiff > 0 then
										starsAmount += sDiff
									end

									if cDiff > 0 then
										coinsAmount += cDiff
									end

									config.coinsLabel.Text = ('Coins Earned: %s'):format(coinsAmount)
									config.starsLabel.Text = ('Stars Earned: %s'):format(starsAmount)

									syn_context_set(2);
								end)
							end
							network:fire_event_to_server(networkIds.EVT_Spectate_ClientLeave)
						end
					end
				end
			end
		end)
	end

	local menu = menu:AddTab('RoBeats!') do
		local column = menu:AddColumn()

		local main = column:AddSection("Auto Player") do
			main:AddToggle({text = 'Enabled', flag = 'autoPlayer'}):AddBind({
				flag = 'autoPlayerBind', 
				callback = function()
					library.options.autoPlayer:SetState((not library.options.autoPlayer.state))
				end
			})
		end

		local options = column:AddSection('Options') do
			local function decide(value, ignoreType)
				local sum = 0;

				for _, nType in next, {'perfect', 'great', 'okay', 'miss'} do
					if nType == ignoreType then
						continue
					end

					sum = sum + library.flags[nType] or 0;
				end

				if (sum + value) > 100 then
					return false, 100 - sum;
				end

				return true;
			end

			options:AddSlider({
				text = "Perfect", 
				min = 0,
				max = 100;
				value = 100;
				textpos = 2,

				flag = "perfect",
				suffix = '%';
				-- callback = function(new)
				-- 	local success, result = decide(new, 'perfect');
				-- 	if not success then
				-- 		library.options.perfect:SetValue(result, true)
				-- 	end
				-- end
			})

			options:AddSlider({
				text = "Great",
				min = 0,
				max = 100;
				value = 0;
				textpos = 2,

				flag = "great",
				suffix = '%';
				-- callback = function(new)
				-- 	local success, result = decide(new, 'great');
				-- 	if not success then
				-- 		library.options.great:SetValue(result, true)
				-- 	end
				-- end
			})
			
			options:AddSlider({
				text = "Okay",
				min = 0,
				max = 100;
				value = 0;
				textpos = 2,

				flag = "okay",
				suffix = '%';
				-- callback =  function(new)
				-- 	local success, result = decide(new, 'okay');
				-- 	if not success then
				-- 		library.options.okay:SetValue(result, true)
				-- 	end
				-- end
			})
			
			options:AddSlider({
				text = "Miss",
				min = 0,
				max = 100;
				value = 0;
				textpos = 2,

				flag = "miss",
				suffix = '%';
				-- callback = function(new)
				-- 	local success, result = decide(new, 'miss');
				-- 	if not success then
				-- 		library.options.miss:SetValue(result, true)
				-- 	end
				-- end
			})
			
			options:AddButton({
				text = "Reset to Default", 
				callback = function()
					library.options.perfect:SetValue(100, true)
					library.options.great:SetValue(0, true)
					library.options.okay:SetValue(0, true)
					library.options.miss:SetValue(0, true)
				end
			})
		end

		local misc = column:AddSection('Misc Cheats') do
			misc:AddSlider({
				text = 'Song Speed',
				textpos = 2;
				flag = 'songSpeed',
				min = 0;
				max = 500;
				value = 100;

				suffix = '%';
			})

			misc:AddButton({
				text = decrypt(consts["867"], constantKey, "mGCG6vFseiOzHPH0"), 
				callback = function()
					if (config.unlockedSongs) then 
						return
					end

					local result = N:MessageBox("RoBeats!", decrypt(consts["67"], constantKey, "mGCG6vFseiOzHPH0"), {'Yes', 'No'})

					if (result == 'Yes') then
						N.success({
							title = 'RoBeats!',
							text = "Successfully unlocked all songs!"
						})
						config.unlockedSongs = true;
						unlockSongs();
					end
				end
			})
		end

		local farm = column:AddSection('Autofarm') do
			config.npcLabel = farm:AddLabel('NPC Count: 0') -- :format(getNonVisited()))
			config.coinsLabel = farm:AddLabel('Coins Amount: 0');
			config.starsLabel = farm:AddLabel('Stars Amount: 0');

			farm:AddToggle({text = 'Collect NPC Rewards', flag = 'collectNPCs'})
			farm:AddToggle({text = 'NPC Server Hop', flag = 'serverHopNPCs'})
			farm:AddDivider()
			farm:AddToggle({text = 'Auto Cheer', flag = 'autoCheer'})
		end

		local column = menu:AddColumn()

		local colors = column:AddSection('Note Colors', 2) do
			colors:AddToggle({text = 'Enabled', flag = 'noteColorsEnabled'}):AddList({
				multiselect = true;
				values = {'Rainbow Notes', 'Rainbow Tracks', 'Sync Colors'},
				flag = 'noteToggles'
			})

			colors:AddDivider()

			for i = 1, 4 do
				colors:AddColor({text = 'Color ' .. i, flag = 'trackColor' .. i}):AddColor({flag = 'noteColor' .. i})
			end
		end

		local craft = column:AddSection('Crafting', 2) do
			craft:AddToggle({text = 'Buy 2x [Note Machine]', flag = 'buyDoubleNoteMachine'})
			
			craft:AddBox({text = 'Crafting amount', flag = 'craftingAmount'})
			local status = craft:AddLabel('Status: Idle')

			local isCrafting = false;
			
			local craftSignal = utilities.Signal.new();
			local combineSignal = utilities.Signal.new();
			local sellSignal = utilities.Signal.new();

			network:wait_on_event(networkIds.EVT_Crafting_CraftSongServerResponse, function(success)
				craftSignal:Fire(success)
			end)

			network:wait_on_event(networkIds.EVT_Shop_ServerCombineSongAttemptResponse, function(success)
				combineSignal:Fire(success)
			end)

			network:wait_on_event(networkIds.EVT_Shop_ServerSellSongAttemptResponse, function(success)
				sellSignal:Fire(success)
			end)

			craft:AddButton({
				text = 'Craft Selected Song', 
				callback = function()
					local num = tonumber(library.flags.craftingAmount)
					if (not num) then 
						return N.notify({
							title = 'wally\'s hub',
							text = 'Crafting amount must be a number',
							type = 'error',
							wait = 5
						})
					end	

					local lMenu;
					for i, v in next, menus._table do
						local f = v.cons;
						if getinfo(f).source:find'%.CraftingUI$' then
							lMenu = v; 
							break
						end
					end

					if (not lMenu) then return end

					local menu = lMenu:get_current_tab_instance();
					local name = select('4', unpack(getinfo(menu.cons).source:split(".")))
		
					if (name ~= 'CraftingUITabSongs') then return end

					local craftDb = getupvalue(menu.craft_pressed, 6)
					local selected = getupvalue(menu.craft_pressed, 1)
					local num = math.max(num, 1)

					if num < 1 then return end
					if selected < 0 then return end
					if isCrafting then return end

					isCrafting = true;
									
					for i = 1, num do
						network:fire_event_to_server(networkIds.EVT_Crafting_CraftSongClientRequest, selected)

						local success = craftSignal:wait()
						if (not success) then break end
					
						status.Text = string.format('Status: %s/%s', i, num)
					end

					wait(0.5)
					mainClient._player_blob_manager:do_sync(function()
					end)

					status.Text = 'Status: Idle'
					isCrafting = false;
				end
			})

			craft:AddButton({
				text = 'Craft Hard Song', 
				callback = function()
					local num = tonumber(library.flags.craftingAmount)
					if (not num) then 
						return N.notify({
							title = 'wally\'s hub',
							text = 'Crafting amount must be a number',
							type = 'error',
							wait = 5
						})
					end	

				local lMenu;
				for i, v in next, menus._table do
					local f = v.cons;
					if getinfo(f).source:find'%.CraftingUI$' then
						lMenu = v; break
					end
				end

				if (not lMenu) then debugprint("no lMenu") return end

				local menu = lMenu:get_current_tab_instance();
				local name = select('4', unpack(getinfo(menu.cons).source:split(".")))
	
				if (name ~= 'CraftingUITabSongs') then return end

				local craftDb = getupvalue(menu.craft_pressed, 6)
				local selected = getupvalue(menu.craft_pressed, 1)
				local num = math.max(num, 1)

				if num < 1 then return end
				if selected < 0 then return end
				if isCrafting then return end

				local songKey = craftDb:singleton():get_song_recipe_songkey(selected)
				if (not songKey) then return end

				isCrafting = true;
				
				for i = 1, num do
					network:fire_event_to_server(networkIds.EVT_Shop_ClientCombineSongAttempt, songKey)
					local success = combineSignal:wait()

					if (not success) then break end
					status.Text = string.format('Status: %s/%s (hard)', i, num)
				end	

				wait(0.5)
				mainClient._player_blob_manager:do_sync(function()
				end)

				status.Text = 'Status: Idle'
				isCrafting = false;
			end})

			craft:AddButton({
				text = 'Sell Hard Songs', 
				callback = function()
					local num = tonumber(library.flags.craftingAmount)
					if (not num) then 
						return N.notify({
							title = 'wally\'s hub',
							text = 'Crafting amount must be a number',
							type = 'error',
							wait = 5
						})
					end

					local lMenu;
					for i, v in next, menus._table do
						local f = v.cons;
						if getinfo(f).source:find'%.CraftingUI$' then
							lMenu = v; break
						end
					end

					if (not lMenu) then debugprint("no lMenu") return end

					local menu = lMenu:get_current_tab_instance();
					local name = select('4', unpack(getinfo(menu.cons).source:split(".")))
		
					if (name ~= 'CraftingUITabSongs') then return end

					local craftDb = getupvalue(menu.craft_pressed, 6)
					local selected = getupvalue(menu.craft_pressed, 1)
					local num = math.max(num, 1)

					if num < 1 then debugwarn('bad number'); return end
					if selected < 0 then debugwarn('not selected'); return end
					if isCrafting then debugwarn('currently crafting'); return end

					local songKey = craftDb:singleton():get_song_recipe_songkey(selected)
					if (not songKey) then debugprint'no songkey' return end

					local hardSongKey do
						local songDbInfo = songDatabase:get_songdatabase_info();
						local songData = songDbInfo[songKey]
						for i, v in next, songDbInfo do
							if v.audiocoverimg == songData.audiocoverimg then
								if v.audiomod == 1 then
									hardSongKey = v.songid
									break
								end
							end
						end
					end

					if (not hardSongKey) then debugprint'no hardsongkey' return end

					isCrafting = true;
					
					for i = 1, num do
						debugprint("firing sell remote")
						network:fire_event_to_server(networkIds.EVT_Shop_ClientSellSongAttempt, hardSongKey)
						local success
						delay(5, function()
							if (success == nil) then
								sellSignal:Fire(false)
							end
						end)
						success = sellSignal:wait()
						debugwarn("sell response", success)

						if (not success) then break end
						status.Text = string.format('Status: %s/%s (sold)', i, num)
					end	

					wait(0.5)
					mainClient._player_blob_manager:do_sync(function()
					end)

					status.Text = 'Status: Idle'
					isCrafting = false;
				end
			})
		end
	end
end)

games.add({913400159}, 'Ace of Spadez', function(menu)
	SX_VM_B()
	local config = {};

	-- PlayerScripts.WeaponSystem
	local weaponSystem = utilities.WaitFor(decrypt(consts["841"], constantKey, "mGCG6vFseiOzHPH0"), client);
	local weaponModule = require(utilities.WaitFor('Module', weaponSystem))

	-- ReplicatedStorage.RemoteEvents.Weapons.GetWeaponStats
	local getStats = utilities.WaitFor(decrypt(consts["6"], constantKey, "mGCG6vFseiOzHPH0"));
	local weaponStats = utilities.WaitFor('ReplicatedStorage.Scripts.WeaponStats')

	local inventory = utilities.WaitFor('Inventory', client);

	base.R15.leftArm = decrypt(consts["673"], constantKey, "mGCG6vFseiOzHPH0")
	base.R15.rightArm = decrypt(consts["498"], constantKey, "mGCG6vFseiOzHPH0")

	base.R15.leftLeg = decrypt(consts["233"], constantKey, "mGCG6vFseiOzHPH0")
	base.R15.rightLeg = decrypt(consts["832"], constantKey, "mGCG6vFseiOzHPH0")

	base.partList.R15 = {
		"Head",
		"LeftFoot",
		"LeftHandle",
		decrypt(consts["481"], constantKey, "mGCG6vFseiOzHPH0"),
		decrypt(consts["233"], constantKey, "mGCG6vFseiOzHPH0"),
		decrypt(consts["355"], constantKey, "mGCG6vFseiOzHPH0"),
		decrypt(consts["832"], constantKey, "mGCG6vFseiOzHPH0"),
		decrypt(consts["471"], constantKey, "mGCG6vFseiOzHPH0"),
		decrypt(consts["930"], constantKey, "mGCG6vFseiOzHPH0"),
		decrypt(consts["216"], constantKey, "mGCG6vFseiOzHPH0"),
		decrypt(consts["523"], constantKey, "mGCG6vFseiOzHPH0"),
		"UpperLeftArm",
		"UpperLeftLeg",
		"UpperRightArm",
		"UpperRightLeg",
		"UpperTorso",
		"Shoulders",
		"Torso",
		"HumanoidRootPart",
		"Hitbox"	
	}

	base.getRig = function() return 'R15' end

	aimbot.launch(menu);
	esp.launch(menu);

	local oldShoot, modifyGunStats, modifyStats do
		local oldMathRandom;
		oldMathRandom = replaceclosure(getrenv().math.random, function(...)
			local min, max = ...
			if type(min) == 'number' and type(max) == 'number' then
				if math.abs(min) == math.abs(max) and library.flags.noSpread then
					return 0
				end
			end
			
			return oldMathRandom(...)
		end)

		do
			local index
			index = hookmetamethod(game, '__index', newcclosure(function(self, key)
				if checkcaller() then return index(self, key) end

				if (key == 'CFrame' and self == index(workspace, 'CurrentCamera') and library.flags.silentaim) then
					local caller = getinfo(3)
					if caller.source:match('WeaponSystem%.Module') and (caller.name == '' or caller.name == 'singlefire') then 
						local root = index(self, key)
						local target = aimbot.getSilentTarget()

						if target then
							return CFrame.lookAt(root.p, target.Position)
						end
					end
				end

				return index(self, key)
			end))
		end

		function modifyStats(data)
		end

		local env = getfenv(require(weaponStats).list)
		local tbl = rawget(env, 'Table')

		local function copy(tbl) 
			local new = {}
			for k, v in next, tbl do
				new[k] = v
			end
			return new
		end

		if type(tbl) == 'table' then
			for gun, struct in next, tbl do
				if type(struct) == 'table' and rawget(struct, 'GunType') then
					local cache = copy(struct)
					setmetatable(struct, { __index = function(self, key) 
						if (key == 'Range' and library.flags.maxrange) then
							return 9e9 
						end

						if (key == 'HorizontalRecoil' or key == 'HorizontalRecoilADS' or key == 'VerticalRecoil' or key == 'VerticalRecoilADS') then
							if library.flags.norecoil then
								return 0
							end
						end

						return rawget(cache, key)
					end, __newindex = cache })

					rawset(struct, 'Range', nil)

					for _, stat in next, {"HorizontalRecoil", "HorizontalRecoilADS", "VerticalRecoil", "VerticalRecoilADS"} do rawset(struct, stat, nil) end
				end
			end
		end
		
		local function onCharacterAdded(character)
			if library.flags.nofall then
				-- Animate.FallDamageServer

				local fall = utilities.WaitFor(decrypt(consts["119"], constantKey, "mGCG6vFseiOzHPH0"), character, 5)
				if fall and fall.ClassName == 'Script' then
					fall:Destroy();
				end
			end
		end

		client.CharacterAdded:connect(onCharacterAdded)
		if client.Character then
			onCharacterAdded(client.Character);
		end
	end

	local aos_string = [[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]]
	load_game_module(aos_string, config, getStats, client, modifyStats)

	local window = menu:AddTab('Ace of Spadez') do
		local column = window:AddColumn()
		local main = column:AddSection('Main Cheats'); do
			main:AddToggle({text ='Silent Aim', flag = 'silentaim'})
		end

		local guns = column:AddSection('Gun Mods'); do
			guns:AddToggle({ text ='Infinite Range', flag = 'maxrange' })
			guns:AddToggle({ text ='No Spread', flag = 'nospread'})
			guns:AddToggle({ text ='No Recoil', flag = 'norecoil'})
		end

		local misc = column:AddSection('Misc Cheats') do
			misc:AddToggle({text = 'No Fall Damage', flag = 'nofall', callback = function(value)
				if value and client.Character then
					local fall = client.Character:FindFirstChild('FallDamageServer', true)
					if fall and fall.ClassName == 'Script' then
						fall:Destroy();
					end
				end
			end})


			-- misc:Toggle('Super Speed', {location = config, flag = 'speed', callback = function(value)
			-- 	if client.Character then
			-- 		local human = client.Character:WaitForChild('Humanoid')
			-- 		if human then
			-- 			if (not value) then
			-- 				human.WalkSpeed = 30;
			-- 			end
			-- 		end
			-- 	end
			-- end})

			-- misc:Slider('Speed Amount', {location = config, flag = 'speedvalue', min = 30, max = 80, default = 30, callback = function(value)
			-- 	if client.Character then
			-- 		local human = client.Character:WaitForChild('Humanoid')
			-- 		if human then
			-- 			human.WalkSpeed = config.speedvalue
			-- 		end
			-- 	end
			-- end})
		end
	end
end)

games.add({1746011057}, "Dawn of Aurora", function(menu)
	SX_VM_B()

	local config = {};
	-- local config = {
	-- 	silentAim = false;
	-- 	invisibility = false;

	-- 	crystalESP = false;
	-- 	autoSellGems = false;
	-- 	autoMineGems = false;
	-- 	autoCollectGems = false;
	-- 	crystalMaxDistance = 50;

	-- 	instantReload = false;
	-- 	noSpread = false;
	-- 	noRecoil = false;
	-- 	instantEquip = false;

	-- 	noFall = false;
	-- 	instantInteract = false;
	-- 	infStamina = false;
	-- 	noStun = false;


	-- 	noCarDamage = false;
	-- 	infNitro = false;
	-- 	maxCarSpeed = false;

	-- 	gem_types = {
	-- 		Common = false;
	-- 		Uncommon = false;
	-- 		Rare = false;
	-- 		Epic = false;
	-- 		Legendary = false;
	-- 	}
	-- };

	-- ReplicatedStorage.Modules.UI.state.EquippedItemTooltip
	local equippedItemTip = require(utilities.WaitFor("ReplicatedStorage.Modules.UI.state.EquippedItemTooltip"));

	-- ReplicatedStorage.Modules.UI.state.CharacterState
	local characterState = require(utilities.WaitFor(decrypt(consts["266"], constantKey, "mGCG6vFseiOzHPH0")))

	-- ReplicatedStorage.Modules.UI.app.worldInteractionDialog.InteractionNode
	local interactNode = require(utilities.WaitFor(decrypt(consts["780"], constantKey, "mGCG6vFseiOzHPH0")))

	local playerData = require(utilities.WaitFor('ReplicatedStorage.Modules.ReplicatedData.PlayerData'));

	-- ReplicatedStorage.Modules.Camera.Subsystems.GunCamera
	local gunCamera = require(utilities.WaitFor(decrypt(consts["732"], constantKey, "mGCG6vFseiOzHPH0")))
	local gunClient = require(utilities.WaitFor('ReplicatedStorage.Modules.Item.Guns.ItemGun'));

	-- ReplicatedStorage.Modules.Item.ItemCatalog
	local itemCatalog = require(utilities.WaitFor(decrypt(consts["418"], constantKey, "mGCG6vFseiOzHPH0")))

	local vehicleState = require(utilities.WaitFor('ReplicatedStorage.Modules.Entity.EntityCar'))
	local entityManager = require(utilities.WaitFor("ReplicatedStorage.Modules.Entity.EntityManager"))

	-- ReplicatedStorage.Modules.DataActions.InventoryLogic
	local inventoryLogic = require(utilities.WaitFor(decrypt(consts["784"], constantKey, "mGCG6vFseiOzHPH0")))

	local dataReplicator = require(utilities.WaitFor('ReplicatedStorage.Modules.Util.DataReplicator'))
	local mouseInput = require(utilities.WaitFor('ReplicatedStorage.Modules.Util.CollisionFilteredMouseInput'));
	local damageUtil = require(utilities.WaitFor('ReplicatedStorage.Modules.Util.DamageUtil'));

	local setLookAngle = utilities.WaitFor(decrypt(consts["879"], constantKey, "mGCG6vFseiOzHPH0"));
	local cPacketWhileHacking = utilities.WaitFor('ReplicatedStorage.Modules.Entity.EntitySecurityTerminal.C.CPacketWhileHacking')
	local cPacketFinishHack = utilities.WaitFor('ReplicatedStorage.Modules.Entity.EntitySecurityTerminal.C.CPacketFinishHack');
	local cPacketReloadFinish = utilities.WaitFor(decrypt(consts["861"], constantKey, "mGCG6vFseiOzHPH0"));
	local cPacketSellItem = utilities.WaitFor('ReplicatedStorage.Modules.Entity.EntityVendorShop.C.CPacketSellItem');
	local sPacketReplicateValues = utilities.WaitFor(decrypt(consts["425"], constantKey, "mGCG6vFseiOzHPH0"));

	local monsters = {}; do
		for i, v in next, utilities.WaitFor(decrypt(consts["595"], constantKey, "mGCG6vFseiOzHPH0")):GetChildren() do
			table.insert(monsters, v.Name);
		end
	end

	local weapon_stats = {} do
		for i, v in next, itemCatalog.GetItemsWithCategoryTag("Weapon") do
			weapon_stats[v.itemID] = utilities.Copy(v)
		end
		for i, v in next, itemCatalog.GetItemsWithCategoryTag("QuestItem") do
			weapon_stats[v.itemID] = utilities.Copy(v)
		end
	end

	aimbot.launch(menu);
	esp.launch(menu);

	local oldRedrawTick, oldToolSet, oldRepGet, oldGetData, oldFireServer, oldTakeDamage, oldRedraw, oldGetHit, oldCanReload, oldRecoil; do
		local time_offset = 0;
		local clientData = playerData.Get(client);
		local stamina_value = characterState.Stamina;
		local redrawEnv = getfenv(interactNode.Redraw);
		local timeoutMap = {};

		local walterEntity do
			for i, v in next, entityManager.GetEntitiesOfType(decrypt(consts["502"], constantKey, "mGCG6vFseiOzHPH0")) do
				if v.title == 'Walter' then
					walterEntity = v.id;
					break
				end
			end
		end

		local function get_hack_time(device, terminal)
			local terminals = entityManager.GetEntitiesOfType('EntitySecurityTerminal');
			local rarity = nil;

			for i, entity in next, terminals do
				if entity.instance ~= terminal then continue end
				if not entity._withInstanceCB then continue end

				rarity = getupvalue(entity._withInstanceCB, 3)
			end

			if (not rarity) then
				return
			end

			local item = inventoryLogic.GetEquippedItemStack(clientData, client)
			if (not item) then
				return
			end

			item = item.ItemID;
			if (not item:match('hacking_device_%w+')) then
				return
			end

			local match = item:match('hacking_device_(.*)')
			local type = match:gsub("^%l", match.upper)

			return math.ceil(itemCatalog.FromID(item):GetHackTime(rarity)), rarity, type  
		end

		local function find_mob()
			local mobs = {}

			for i, monster in next, monsters do
				local list = entityManager.GetEntitiesOfType(monster);
				for _, monsterObj in next, list do
					if (not monsterObj.instance) then continue end

					table.insert(mobs, monsterObj.instance)
				end
			end

			local selected = nil;
			local threshold = math.huge;
			local clientRoot = (client.Character and client.Character:findFirstChild('HumanoidRootPart'))
			local origin = (clientRoot and clientRoot.Position)

			for i, mob in next, mobs do
				local root = mob:FindFirstChild('HumanoidRootPart');
				local humanoid = mob:FindFirstChild('Humanoid')
				local head = mob:FindFirstChild('Head')

				if (not clientRoot) then continue end
				if (not root) or (not humanoid) then continue end
				if (not head) then continue end

				local vector, visible = base.worldToViewportPoint(head)

				if (visible and aimbot.config.silentVisibleCheck) then
					visible = base.isPartVisible(root)
				end

				if (visible and aimbot.config.showCircle) then
					visible = base.isInCircle(vector)
				end
	
				if (not visible) then continue end

				local cursor = userInputService:GetMouseLocation();

				local cRange = math.floor((root.Position - origin).magnitude)
				local mRange = math.floor((cursor - vector).magnitude)

				local range = (aimbot.config.distType == 'Cursor' and mRange or cRange)

				if (range < threshold) then
					threshold = range;
					selected = head
				end
			end

			return selected;
		end

		function base.isSameTeam(player)
			return (not (damageUtil.PlayerCanAttackEntity(client, player, false)))
		end

		-- tick
		oldRedraw = utilities.Hook(interactNode, 'Redraw', function(self)
			if self.nodeInfo then 
				local name = self.nodeInfo.prompt;
				if name then
					if (library.flags.autoMineGems and name:match('Mine %w+ Gems')) then
						self.nodeInfo.action()
					elseif (library.flags.autoCollectGems and name:match('Take %w+ Gem')) then
						self.nodeInfo.action()
					end
				end
			end
			return oldRedraw(self)
		end)

		oldRedrawTick = utilities.Hook(redrawEnv, decrypt(consts["958"], constantKey, "mGCG6vFseiOzHPH0"), function()
			local prompt = getupvalue(2, 1);
			local timer = getupvalue(2, 2);

			if type(timer) == "number" and library.flags.instantInteract then
				setupvalue(2, 2, 0);
			end

			return tick();
		end)

		oldGetSpread = utilities.Hook(gunClient, 'GetSpread', function(...)
			if library.flags.silentAim or library.flags.noSpread then
				return 0;
			end
			return oldGetSpread(...)
		end)

		oldCanFire = utilities.Hook(gunClient, 'CanFire', function(self, ...)
			if (self.ammoType == 'ammo_shells') then
				self.reloadType = (library.flags.instantReload and 'All' or 'Single')
			end

			return oldCanFire(self, ...)
		end)

		oldRecoil = utilities.Hook(gunCamera, 'Recoil', function(...)
			if library.flags.noRecoil then return end
			return oldRecoil(...)
		end)

		oldToolSet = utilities.Hook(equippedItemTip, 'Set', function(...)
			local arguments = {...}
			local action = arguments[1];

			local conditions = {
				[(action == 'Equipping' and (library.flags.instantEquip or false))] = 'equipBeginTime',
				[(action == 'Reloading' and (library.flags.instantReload or false))] = 'lastReloadClientTime',
				[(action == 'Using' and (library.flags.instantInteract or false))] = 'useTime';
			}

			local index = conditions[true]
			if index then				
				local upvalues = getupvalues(2);

				for i, v in next, upvalues do
					if type(v) == 'table' then 
						if v[index] then
							v[index] = 0;
						end
					end
				end
				
				return oldToolSet(nil, nil, nil);
			end

			return oldToolSet(...)
		end)	

		-- GetHitPos
		oldGetHit = utilities.Hook(mouseInput, decrypt(consts["392"], constantKey, "mGCG6vFseiOzHPH0"), function(...)
			local trace = debug.traceback()
			if (trace:find('ItemGun') and library.flags.silentAim) then
				local target = aimbot.getSilentTarget()

				if target then
					-- base.drawBeam(workspace.CurrentCamera.CFrame.p, target.Position)
					return target.Position
				end

				-- if (target == nil) then 
				-- 	local target = find_mob()
				-- 	if (target) then
				-- 		base.drawBeam(workspace.CurrentCamera.CFrame.p, target.Position)
				-- 		return target.Position
				-- 	end
				-- end
			end
			return oldGetHit(...)
		end)

		oldGetData = utilities.Hook(clientData, 'Get', function(self, name, ...)
			if (name == 'Nitro' and library.flags.infNitro) then
				return 100
			elseif (name == 'NitroCapacity' and library.flags.infNitro) then
				return 1;
			end

			return oldGetData(self, name, ...)
		end);

		oldTakeDamage = utilities.Hook(vehicleState, decrypt(consts["363"], constantKey, "mGCG6vFseiOzHPH0"), function(self, ...)
			if (library.flags.noCarDamage) then
				return
			end
			
			return oldTakeDamage(self, ...)
		end)

		local call_count = 0;

		-- RemoteEvent

		oldFireServer = hookfunction(Instance.new(decrypt(consts["853"], constantKey, "mGCG6vFseiOzHPH0")).FireServer, function(self, ...)
			local arguments = {...}
			if library.flags.instantInteract then
				-- emulate the change in time (os.clock is sent when an action begins and when it ends)
				-- server verifies the time between end and start is enough to complete the action

				if self.Name == 'CPacketEnterSeat' then
					arguments[3] = arguments[3] + 0.75
				end

				if self.Name == 'CPacketCollectVeza' then
					arguments[2] = arguments[2] + 0.5
				end

				if self.Name == 'CPacketArrest' then
					arguments[1].clientTimestamp = arguments[1].clientTimestamp + 1
				end

				if (self.Name == 'CPacketWhileHacking' or self.Name == 'CPacketFinishHack') then
					return;
				end

				if self.Name == 'CPacketBeginHack' then
					local terminal = arguments[1];
					local hack_time, hack_rarity, hack_type = get_hack_time(hack_device, terminal)

					if (hack_time) then
						-- sometimes bugs out with commons?

						local clock = os.clock();
						local forwardClock = (clock + hack_time)

						oldFireServer(self, terminal, clock)

						for i = 1, (hack_time) do
							oldFireServer(cPacketWhileHacking, terminal)
						end

						oldFireServer(cPacketFinishHack, terminal, forwardClock);
						return;
					end
				end

				if (self.Name == 'CPacketRemoveC4' or self.Name == 'CPacketPlaceC4') then
					arguments[2] = arguments[2] + 0.75;
				end
			end

			if (self.Name == 'CPacketRegisterReloadFinish' and library.flags.instantReload) then return end

			if (self.Name == 'CPacketRegisterReloadStart' and library.flags.instantReload) then
				local item = inventoryLogic.GetEquippedItemStack(clientData, client)
				local data = weapon_stats[item.ItemID]

				if type(data) == 'table' and data.reloadTime then 
					if data.ammoType == 'ammo_shells' then
						local slot, location = inventoryLogic.GetItemStackSlotLocation(clientData, item.UniqueID);
						local clip = clientData:Get(slot, location, "State", 'Clip');
						local max = data.clipCapacity

						local curr = (max - clip);
						local time = arguments[1];

						for i = 1, curr do
							oldFireServer(self, time)
							time += data.reloadTime;
							oldFireServer(cPacketReloadFinish, time);
							time += 1;
						end

						return
					end

					oldFireServer(self, arguments[1]);
					return oldFireServer(cPacketReloadFinish, arguments[1] + data.reloadTime)
				end
			end
			
			if (self.Name == 'CPacketLD') then return end
			if (self.Name == 'CPacketTakeCollisionDamage') and (library.flags.noCarDamage) then
				return
			end

			return oldFireServer(self, unpack(arguments))
		end)
		
		oldRepGet = utilities.Hook(dataReplicator, 'Get', function(self, name, ...)
			local arguments = {...}
			if name == "stats" and library.flags.maxCarSpeed then
				if arguments[1] == 'maxAcceleration' then return 90 end
				if arguments[1] == 'boostMaxAcceleration' then return 90 end

				if arguments[1] == 'boostAccelerationFalloffCurving' then return 0 end
				if arguments[1] == 'accelerationFalloffCurving' then return 0 end
			end
			return oldRepGet(self, name, ...)
		end)

		local shadowTable = utilities.Copy(characterState);
		setmetatable(characterState, {
			__index = function(self, key)
				if key == 'Stamina' and (library.flags.infStamina) then
					return 1;
				end

				return rawget(shadowTable, key)
			end,

			__newindex = function(self, key, value)
				return rawset(shadowTable, key, value)
			end,
		})

		characterState.Stamina = nil

		sPacketReplicateValues.OnClientEvent:connect(function(...)
			local args = {...};

			if args[1] == clientData.handle and library.flags.autoSellGems then
				local path = args[2];
				local item = args[3];

				if path[1] == 'Backpack' and tonumber(path[2]) then
					if type(item) == 'table' and rawget(item, 'ItemID') then
						local gemType = item.ItemID:match('gem_(%w+)')
						if gemType then
							safeFireServer(cPacketSellItem, walterEntity, item.UniqueID, 1);
						end
					end
				end
			end
		end);
	end

	

	local doa_module = ([[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]])

	local doa_esp = ([[iMUO+fZwDUTtB6+KjHJnRcKjvV+aMGAbbBshdUYUHANDFGJjxMWni2Z2FXZ6VcWpjidTe9KCEFcmSDj2qSsqABCkR1iowD6X6/0bjJgnMOCciyyie2uZ3u3mNYh8HBzDRVVj3jOuDwecy4FY/wygzqHJ45NNgWTWh56cztXwBGIMFAY4TD0VqAmZZtWUpApCCXW8Yn3wNKGsCqvmQRAykjWf9JTpOq6Cm2J5+4n2gI1YF/91e4KsdLWUO50yN2IYS]] .. decrypt(moduleChunks["391"], moduleKey, "IcFFsw9TMl8zRu0I") .. [[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]])
	
	load_game_module(doa_module, config);
	load_game_module(doa_esp, base);

	local window = menu:AddTab('Dawn of Aurora') do
		local column = window:AddColumn();

		local main = column:AddSection('Main Cheats') do
			-- main:AddToggle({text = 'Invisiblity', flag = 'invisibility', callback = function(value)
			-- 	if value then
			-- 		safeFireServer(setLookAngle, { vertical = -1; horizontal = math.huge})
			-- 	else
			-- 		safeFireServer(setLookAngle, { vertical = 0; horizontal = 0 })
			-- 	end
			-- end})

			main:AddToggle({text = 'No Fall Damage', flag = 'noFall'})
			main:AddToggle({text = 'Instant Interact', flag = 'instantInteract'})
			main:AddToggle({text = 'Infinite Stamina', flag = 'infStamina'})
		end

		local guns = column:AddSection('Weapon Cheats') do
			guns:AddToggle({text = 'Silent Aim', flag = 'silentAim'})
			guns:AddToggle({text = 'Instant Reload', flag = 'instantReload'})
			guns:AddToggle({text = 'No Spread', flag = 'noSpread'})
			guns:AddToggle({text = 'No Recoil', flag = 'noRecoil'})
			guns:AddToggle({text = 'Instant Equip', flag = 'instantEquip'})
		end
		
		local car = column:AddSection('Vehicle Cheats') do
			car:AddToggle({text = 'No Vehicle Impact', flag = 'noCarDamage'})
			car:AddToggle({text = 'Infinite Nitro', flag = 'infNitro'})
			car:AddToggle({text = 'Max Car Speed', flag = 'maxCarSpeed'})
		end

		local column = window:AddColumn();
		local gems = column:AddSection('Gem Stuff') do
			gems:AddToggle({text = 'Gem ESP', flag = 'gemESP'}):AddSlider({text = 'Render distance', min = 50, max = 6000, flag = 'crystalMaxDistance', suffix = 'm'})
			gems:AddList({flag = 'crystalChoices', multiselect = true, values = {'Common', 'Uncommon', 'Rare', 'Epic', 'Legendary'}})

			gems:AddDivider();

			gems:AddToggle({text = 'Auto Sell', flag = 'autoSellGems'});
			gems:AddToggle({text = 'Auto Collect', flag = 'autoCollectGems'});
			gems:AddToggle({text = 'Auto Mine', flag = 'autoMineGems', tip = 'Automatically mines gems when you walk up to them.'});
		end
	end
end)

games.add({ 1390601379 }, 'Combat Warriors', function(menu)
	esp.launch(menu);

	local nevermore do
		for i, module in next, getloadedmodules() do
			if module:IsA('ModuleScript') then
				local ret = require(module)
				if type(ret) == 'table' then
					local meta = getrawmetatable(ret)
					if type(meta) == 'table' and type(rawget(meta, '__call')) == 'function' then
						local info = getinfo(meta.__call);
						if info.source:find('Nevermore') then
							nevermore = ret;
						end
					end
				end
			end
		end
	end

	syn.set_thread_identity(2)
	local network = nevermore('Network')
	local weapons = nevermore('WeaponMetadata')
	local staminaClient = nevermore("DefaultStaminaHandlerClient")
	local meleeClient = nevermore("MeleeWeaponClient")
	local ragdollFallHandler = nevermore("RagdollHumanoidOnFallClient")
	local ragdollClient = nevermore("RagdollableClient")
	local rangedWeaponHandler = nevermore("RangedWeaponHandler")
	local jumpHandlerClient = nevermore("JumpHandlerClient")
	local flagger = nevermore("Flag")
	local dataHandler = nevermore("DataHandler")
	local dashHandler = nevermore("DashHandlerClient")
	syn.set_thread_identity(6)

	local userInputService = game:GetService('UserInputService')
	local runService = game:GetService('RunService')

	local function getPartsInRadius(range)
		local parts = {}

		local character = client.Character;
		local cRoot = character and character:FindFirstChild('HumanoidRootPart')
		
		if (not cRoot) then return {} end

		local origin = cRoot.Position
		for _, player in next, game:GetService('Players'):GetPlayers() do
			if player == client then continue end

			local pCharacter = player.Character
			if pCharacter and pCharacter:FindFirstChild('Head') and pCharacter:FindFirstChild('HumanoidRootPart') then
				local humanoid = pCharacter:FindFirstChildWhichIsA('Humanoid')
				if humanoid and humanoid.Health > 0 then
					local distance = math.floor((pCharacter.HumanoidRootPart.Position - origin).magnitude)
					if distance <= range then
						parts[#parts + 1] = { pCharacter:FindFirstChild('Head'), distance }
					end
				end
			end
		end
		
		table.sort(parts, function(a, b) 
			return a[2] < b[2] 
		end)

		for i = #parts, 1, -1 do
			local head = parts[i][1]
			parts[i] = head
		end	

		return parts;
	end

	local localStaminaClient = staminaClient.getDefaultStamina()
	localStaminaClient:getStaminaChangedSignal():Connect(function()
		if localStaminaClient._stamina < localStaminaClient._maxStamina and library.flags.infiniteStamina then
			localStaminaClient:setStamina(localStaminaClient._maxStamina)
		end
	end)

	local lookAnglesTick = 0;
	local rnd = Random.new()

	local playerParryList = {} 
	local oldFireServer = network.FireServer do
		function network.FireServer(self, action, ...)
			local args = {...}

			if (not checkcaller()) then
				if action == 'TakeFallDamage' and library.flags.noFall then 
					return
				end
				if action == 'StartRangedCharge' then
					oldFireServer(self, action, unpack(args))
					oldFireServer(self, "FinishedRangedCharge", unpack(args))

					return
				end
				if action == 'StartRangedReload' then
					oldFireServer(self, action, unpack(args))
					oldFireServer(self, "FinishedRangedReload", unpack(args))

					return
				end
			end

			return oldFireServer(self, action, unpack(args))
		end
	end

	local lastAttackStep = tick();
	local attackCount = 0;

	-- anti jump cooldown
	do
		local oldCanJump = jumpHandlerClient.getCanJump;
		function jumpHandlerClient.getCanJump()
			if library.flags.noJumpCooldown then
				return true
			end
			return oldCanJump()
		end
		
		local onAdded = debug.getupvalues(jumpHandlerClient._startModule)[2]
		if type(onAdded) == 'function' then
			local timer = debug.getupvalues(onAdded)[4]
			if type(timer) == 'table' then
				task.spawn(function()
					while true do
						task.wait()
						if library.flags.noJumpCooldown then
							timer:setTimeLeft(0)
						end
					end
				end)
			end
		end
	end

	-- anti dash cooldown
	do
		local oldStartDash = dashHandler.startDashing

		function dashHandler.startDashing(...)
			oldStartDash(...)

			if library.flags.noDashCooldown then
				setupvalue(oldStartDash, 3, true)
			end
		end
	end

	-- silent aim
	do
		-- local function getTarget()
		-- 	local targets = {}
		-- 	local mouse = game:GetService('UserInputService'):GetMouseLocation()

		-- 	for _, plr in next, game.Players:GetPlayers() do
		-- 		if plr == client then continue end
		-- 		if (not plr.Character) then continue end

		-- 		local root = plr.Character:FindFirstChild('HumanoidRootPart');
		-- 		local human = plr.Character:FindFirstChild('Humanoid')
		-- 		local head = plr.Character:FindFirstChild('Head')
		-- 		if (human and human.Health > 0) and root and head then
		-- 			local vector, visible = workspace.CurrentCamera:worldToViewportPoint(head.Position)
		-- 			if visible then
		-- 				vector = Vector2.new(vector.X, vector.Y)

		-- 				local distance = math.floor((vector - mouse).magnitude)
		-- 				targets[#targets + 1] = { distance = distance, target = head }
		-- 			end
		-- 		end
		-- 	end

		-- 	table.sort(targets, function(a, b) return a.distance < b.distance end)
	
		-- 	if targets[1] then return targets[1].target end
		-- 	return nil
		-- end

		-- local oldCalculateFireDirection = rangedWeaponHandler.calculateFireDirection
		-- function rangedWeaponHandler.calculateFireDirection(direction, minSpread, maxSpread, maxDistance)
		-- 	local stack = getstack(2)
		-- 	local origin = stack[10]
		-- 	local tool = client.Character:FindFirstChildWhichIsA('Tool')
		-- 	local stats = (tool and weapons[tool:GetAttribute('ItemId')])

		-- 	--if workspace.Map
		-- 	for k, v in next, stack do
		-- 		if v == stats.speed then
		-- 			setstack(2, k, 3000)
		-- 		end
		-- 	end

		-- 	stats.cooldown = 0;

		-- 	local target = getTarget()
		-- 	if target and tool then
		-- 	--	local predicted, time = trajectory(origin, Vector3.new(), gravity, target.Position, Vector3.new(), Vector3.new(), self.BulletSpeed);
				
		-- 		local predicted = trajectory(origin, Vector3.new(), stats.gravity, target.Position, Vector3.new(), Vector3.new(), 3000)--stats.speed)
		-- 		return CFrame.lookAt(origin, origin + predicted).lookVector * maxDistance
		-- 	end
		-- 	-- for k, v in next, stack do
		-- 	-- 	if typeof(v) == 'Vector3' and v ~= direction then
		-- 	-- 		warn('vector', k, v)
		-- 	-- 		--print(k, v)
		-- 	-- 	end
		-- 	-- end

		-- 	return oldCalculateFireDirection(direction, minSpread, maxSpread, maxDistance)
		-- end
	end

	-- auto parry scanner
	local animationWatcher, parryWatcher = {}, {} do
		local attackAnimations = {}
		local blockAnimations = {}

		for id, data in next, weapons do
			if type(data) == 'table' and data.clientClassModulePath == 'MeleeWeaponClient' and type(data.slashMetadata) == 'table' then
				for _, metadata in next, data.slashMetadata do
					attackAnimations[metadata.animation.AnimationId] = true
				end
				for _, metadata in next, data.blockMetadata do
					blockAnimations[metadata.animation.AnimationId] = true
				end
			end
		end

		local function onCharacterAdded(character)
			local maid = utilities.Maid.new()

			local plr = game:GetService('Players'):GetPlayerFromCharacter(character)
			local humanoid = character:WaitForChild('Humanoid', 9e9)
			maid:GiveTask(humanoid.AnimationPlayed:Connect(function(track)
				if attackAnimations[track.Animation.AnimationId] then
					local maid = utilities.Maid.new()

					animationWatcher[plr] = true;
					task.delay(0.5, function()
						animationWatcher[plr] = nil;
					end)
				end
				if blockAnimations[track.Animation.AnimationId] then
					local maid = utilities.Maid.new()

					parryWatcher[plr] = true;
					task.delay(1.25, function()
						parryWatcher[plr] = nil;
					end)
				end
			end))

			maid:GiveTask(humanoid:GetPropertyChangedSignal('Health'):Connect(function()
				if humanoid.Health <= 0 then
					maid:DoCleaning()
				end
			end))
		end

		for _, plr in next, game:GetService("Players"):GetPlayers() do
			if plr == client then continue end

			plr.CharacterAdded:Connect(onCharacterAdded)
			if plr.Character then task.spawn(onCharacterAdded, plr.Character) end
		end

		game:GetService'Players'.PlayerAdded:Connect(function(plr)
			plr.CharacterAdded:Connect(onCharacterAdded)
			if plr.Character then task.spawn(onCharacterAdded, plr.Character) end
		end)
	end

	-- auto attack
	do
		runService.Heartbeat:Connect(function(dt)
			local character = client.Character
			local tool = (character and character:FindFirstChildWhichIsA('Tool'))

			for k, v in next, game.Lighting:GetChildren() do
				if v:IsA('ColorCorrectionEffect') then
					if v.TintColor.g ~= v.TintColor.g then
						v.Enabled = false;
					end
				end
			end

			local map = workspace:FindFirstChild('Map')
			if map and (not game:service'CollectionService':HasTag(map, 'RANGED_CASTER_IGNORE_LIST')) then
				game:service'CollectionService':AddTag(map, 'RANGED_CASTER_IGNORE_LIST')
			end

			local character = client.Character;
			local rootPart = character and character:FindFirstChild('HumanoidRootPart')

			if character.PrimaryPart then 
				if tool and library.flags.killAura then
					local id = tool:GetAttribute('ItemId')
					local data = (type(id) == 'string' and weapons[id]) 

					if type(data) == 'table' and (tick() - lastAttackStep) > 0.05--[[data.cooldown]] and data.clientClassModulePath == 'MeleeWeaponClient' then
						lastAttackStep = tick()
						attackCount = math.max(1, (attackCount + 1) % (#data.slashMetadata + 1))
						
						network:FireServer('MeleeSwing', tool, attackCount)

						for _, part in next, getPartsInRadius(library.flags.killAuraRange) do
							local plr = game:GetService('Players'):GetPlayerFromCharacter(part.Parent)
							if plr then
								local shield = plr.Character and plr.Character:FindFirstChild('SemiTransparentShield')
								if shield and shield.Transparency < 1 then
									continue
								end
							end

							if playerParryList[plr] or parryWatcher[plr] then
								continue
							end
						
							network:FireServer('MeleeDamage', tool, part, tool.Hitboxes:GetChildren()[1], part.Position, Vector3.new())
						end
					end
				end
			end
		end)
	end

	-- anti bear trap / fire
	do
		local collectionService = game:GetService'CollectionService'

		collectionService:GetInstanceAddedSignal("MOLOTOV_FIRE"):Connect(function(obj)
			if library.flags.noFire then
				task.defer(obj.Destroy, obj)
			end
		end)

		workspace:waitForChild('EffectsJunk').ChildAdded:Connect(function(obj)
			if obj.Name == 'OpenBearTrap' and library.flags.antiTrap then
				task.defer(obj.Destroy, obj)
			end
		end)
	end	

	-- auto parry
	do
		network:BindEvents({
			DispatchToPlayerSessionDataRoduxStore = function(player, key, value)
				if (key == 'PARRY_IS_PARRYING_CHANGE') then
					playerParryList[player] = value;
				end
			end,
		})

		local lastParry = tick()
		runService.Heartbeat:Connect(function()
			local character = client.Character;
			local tool = (character and character:FindFirstChildWhichIsA('Tool'))
			local rootPart = character and character:FindFirstChild('HumanoidRootPart')

			if character.PrimaryPart and library.flags.autoParry and tool and (tick() - lastParry) >= 5 then
				local id = tool:GetAttribute('ItemId')
				local data = (type(id) == 'string' and weapons[id]) 

				if type(data) == 'table' and data.clientClassModulePath == 'MeleeWeaponClient' then
					local parts = {}

					for _, plr in next, game:GetService('Players'):GetPlayers() do
						if plr == client then continue end
						if (not animationWatcher[plr]) then continue end

						local chr = plr.Character;
						local hmn = chr and chr:FindFirstChild('Humanoid')
						local hrp = chr and chr:FindFirstChild('HumanoidRootPart')

						if (hmn and hmn.Health > 0) and hrp and math.floor((hrp.Position - rootPart.Position).magnitude) <= 100 then
							parts[#parts + 1] = hrp;
						end
					end

					local part = parts[1]
					if typeof(part) == 'Instance' then
						lastParry = tick()
						network:FireServer('Parry')
					end
				end
			end
		end)
	end

	-- auto revive
	do
		-- runService.Heartbeat:Connect(function()
		-- 	local character = client.Character;
		-- 	local humanoid = character and character:FindFirstChildWhichIsA('Humanoid')

		-- 	local clientStore = dataHandler.getSessionDataRoduxStoreForPlayer(client)
		-- 	if humanoid and humanoid.Health > 0 and library.flags.autoSelfRevive and clientStore then
		-- 		local state = clientStore:getState()
		-- 		if type(state) == 'table' and type(state.down) == 'table' then
		-- 			if state.down.isDowned then
		-- 				print'reviving'
		-- 				network:FireServer('SelfRevive')
		-- 			end
		-- 		end
		-- 	end
		-- end)

		-- client.CharacterAdded:Connect(function(character)
		-- 	network:FireServer('SelfReviveStart')
		-- end)

		-- if client.Character then 
		-- 	network:FireServer('SelfReviveStart') 
		-- end
	end

	function flagger.getIsMaxed()
		return false
	end

	local oldUpdate = ragdollFallHandler._update
	function ragdollFallHandler._update(...)
		if library.flags.noRagdoll then
			return
		end
		return oldUpdate(...)
	end

	local oldOnRagdollChanged = ragdollClient._onRagdollChanged
	function ragdollClient:_onRagdollChanged(...)
		if library.flags.noRagdoll then
			local ragdoll = getupvalue(oldOnRagdollChanged, 1).Ragdoll:Get(self._obj)
			if ragdoll then
				return
			end
		end
		return oldOnRagdollChanged(self, ...)
	end

	local tab = library:AddTab('Combat Warriors') do
		local column = tab:AddColumn()
		local section = column:AddSection('Combat') do
			section:AddToggle({ text = 'Auto attack', flag = 'killAura' }):AddSlider({ text = 'Auto attack range', flag = 'killAuraRange', suffix = 'm', min = 5, max = 20, float = 0.01 })
			section:AddToggle({ text = 'Auto parry', flag = 'autoParry' })
		end
		
		local section = column:AddSection('Misc') do
			section:AddToggle({ text = 'Anti fire', flag = 'noFire', callback = function(state)
				if state then
					for _, obj in next, game:GetService('CollectionService'):GetTagged('MOLOTOV_FIRE') do
						task.defer(obj.Destroy, obj)
					end
				end
			end })

			section:AddToggle({ text = 'Anti bear trap', flag = 'antiTrap', callback = function(state)
				if state then
					for _, obj in next, workspace:waitForChild('EffectsJunk'):GetChildren() do
						if obj.Name == 'OpenBearTrap' then
							task.defer(obj.Destroy, obj)
						end
					end
				end
			end })
		--	section:AddDivider()
		--	section:AddToggle({ text = 'Auto self revive', flag = 'autoSelfRevive' })
			section:AddDivider()
			section:AddToggle({ text = 'No fall damage', flag = 'noFall' })
			section:AddToggle({ text = 'No ragdoll', flag = 'noRagdoll' })
			section:AddDivider()
			section:AddToggle({ text = 'Infinite stamina', flag = 'infiniteStamina' })
			section:AddToggle({ text = 'Infinite jump', flag = 'infiniteJump' })
			section:AddDivider()
			section:AddToggle({ text = 'No jump cooldown', flag = 'noJumpCooldown' })
			section:AddToggle({ text = 'No dash cooldown', flag = 'noDashCooldown' })
		end
	end

	game:GetService('UserInputService').InputBegan:Connect(function(self, processed)
		if self.KeyCode == Enum.KeyCode.Space and library.flags.infiniteJump and (not processed) then
			local character = client.Character
			local rootPart = character and character:FindFirstChild('HumanoidRootPart')

			if rootPart then
				rootPart.Velocity = Vector3.new(rootPart.Velocity.X, 50, rootPart.Velocity.Z)
			end
		end
	end)
end)

games.add({ 833423526 }, 'Strucid', function(menu)
	aimbot.launch(menu);
	esp.launch(menu);

	local roundInfo = game:GetService('ReplicatedStorage'):WaitForChild('RoundInfo')
	local roundType = roundInfo:WaitForChild('RoundType')

	local modules = game:GetService('ReplicatedStorage'):WaitForChild('Modules')
	local network = require(modules:WaitForChild('NetworkModule2'))

	local playerGui = client:WaitForChild('PlayerGui')

	-- team fix
	do
		local oIsSameTeam = base.isSameTeam;
		function base.isSameTeam(...)
			if (roundType.Value == 'FFA') then
				return false
			end
			return oIsSameTeam(...)
		end
	end

	runService.RenderStepped:Connect(function()
		if library.flags.noFallDamage then
			local character = client.Character
			local humanoid = (character and character:FindFirstChild('Humanoid'))
			local rootPart = (character and character:FindFirstChild('HumanoidRootPart'))

			if (not humanoid) or (not rootPart) then
				return
			end

			if humanoid:GetState() == Enum.HumanoidStateType.Freefall then
				local velocity = rootPart.Velocity;
				if velocity.Y <= -60 then
					local ray = Ray.new(rootPart.CFrame.p, Vector3.new(0, -25, 0))
					local hit, pos = workspace:FindPartOnRayWithIgnoreList(ray, { client.Character, workspace.IgnoreThese })
					
					if (not hit) then
						return 
					end

					rootPart.Velocity = Vector3.new(0, 10, 0)
				end
			end
		end
	end)

	for _, gun in next, game:GetService('ReplicatedStorage'):WaitForChild('Weapons'):WaitForChild('Modules'):GetChildren() do
		local data = require(gun)

		if (not data.Reload) then
			continue
		end

		local function copy(tbl)
			local new = {}
			for k, v in next, tbl do
				if type(v) == 'table' then
					new[k] = copy(v)
				else
					new[k] = v;
				end
			end
			return new
		end

		local proxy = copy(data)
		table.clear(data)

		setmetatable(data, { 
			__index = function(self, key)
				if (key == 'Recoil' and library.flags.recoilReduction) then
					local percent = ((100 - library.flags.recoilReductionPercent) / 100)
					local recoil = proxy.Recoil;

					if type(recoil) == 'number' then
						return recoil * percent
					end	
				end
				-- if (key == 'Reload' and library.flags.instantReload) then
				-- 	return { {} }
				-- end
				-- if (key == 'Debounce' and library.flags.fastFire) then
				-- 	return 0.01
				-- end
				-- if (key == 'Auto' and library.flags.automaticGuns) then
				-- 	return true
				-- end
				return proxy[key]
			end, 
			__newindex = proxy 
		})
	end


	local function onCharacterAdded(character)
		local mainGui = playerGui:WaitForChild('MainGui', 100)
		local newLocal = (mainGui and mainGui:WaitForChild('NewLocal'))

		if newLocal then
			local tools = newLocal:WaitForChild('Tools', 100)
			local tool = (tools and tools:WaitForChild('Tool'))
			local gun = (tool and tool:WaitForChild('Gun'))

			if (gun) then
				local result = require(gun)

				local coneOfFire = rawget(result, 'ConeOfFire')
				if (type(coneOfFire) == 'function' and (not is_synapse_function(coneOfFire))) then
					function result:ConeOfFire(origin, final, displacement)
						if (typeof(origin) == 'Vector3' and typeof(final) == 'Vector3') then
							if (type(displacement) == 'number') then
								if library.flags.spreadReduction then
									local percent = ((100 - library.flags.spreadReductionPercent) / 100)

									displacement = displacement * percent
								end

								if library.flags.silentAim then
									local target = aimbot.getSilentTarget({
										hitPart = 'Random';
									})
					
									if (target) then
										local offset = CFrame.new(math.random(0.1, 0.25), math.random(0.1, 0.25), math.random(0.1, 0.25));
										return (target.CFrame * offset).p;
									end
								end
							end
						end

						return coneOfFire(self, origin, final, displacement)
					end
				end
			end
		end	
	end

	client.CharacterAdded:Connect(onCharacterAdded)
	if client.Character then
		fastSpawn(onCharacterAdded, client.Character)
	end

	local tab = library:AddTab('Strucid') do
		local column = tab:AddColumn()
		local section = column:AddSection('Combat') do
			section:AddToggle({ text = 'Silent aim', flag = 'silentAim' })
			section:AddToggle({ text = 'Spread reduction', flag = 'spreadReduction' }):AddSlider({ flag = 'spreadReductionPercent', text = 'Reduction amount', min = 0, max = 100, value = 100, suffix = '%' })
			section:AddToggle({ text = 'Recoil reduction', flag = 'recoilReduction' }):AddSlider({ flag = 'recoilReductionPercent', text = 'Reduction amount', min = 0, max = 100, value = 100, suffix = '%' })
		end

		local section = column:AddSection('Miscellaneous') do
			section:AddToggle({ text = 'Infinite jump', flag = 'infiniteJump' })
			section:AddToggle({ text = 'No fall damage', flag = 'noFallDamage' })
		end
	end

	game:GetService('UserInputService').InputBegan:Connect(function(input, process)
		if (input.KeyCode == Enum.KeyCode.Space and library.flags.infiniteJump) then
			local character = client.Character
			local humanoid = (character and character:FindFirstChild('Humanoid'))
			local rootPart = (character and character:FindFirstChild('HumanoidRootPart'))

			if rootPart then
				rootPart.Velocity = Vector3.new(rootPart.Velocity.X, 50, rootPart.Velocity.Z)
			end
		end
	end)
end)

games.add({ 833209132 }, 'Vesteria', function(menu)
	SX_VM_B()

	-- local config = {
	-- 	killAura = false;
	-- 	killAuraSpeed = 17;
	-- 	killAuraDistance = 10;
	-- 	killAuraSpeedMs = 0;

	-- 	autoCollectItems = false;
	-- 	godmode = false;
	-- 	movementSpeed = 0;

	-- 	fly = false;
	-- 	noclip = false;
	-- 	speed = false;

	-- 	mobEsp = {
	-- 		enabled = false;
	-- 		renderDistance = 0;

	-- 		mobColor = Color3.new(1, 1, 1);
	-- 		bossColor = Color3.new(1, 1, 1);
	-- 		giantColor = Color3.new(1, 1, 1);

	-- 		filter = {
	-- 			bosses = true;
	-- 			["giant mobs"] = true;
	-- 			["regular mobs"] = true;
	-- 		}
	-- 	},

	-- 	fishSellFilter = {};

	-- 	_delta = 0;
	-- };

	local network = utilities.WaitFor('ReplicatedStorage.modules.network')
	local itemCollection = utilities.WaitFor('Workspace.placeFolders.items');
	local entityCollection = utilities.WaitFor('Workspace.placeFolders.entityManifestCollection');
	local entityRenderCollection = utilities.WaitFor('Workspace.placeFolders.entityRenderCollection');

	local function network_invoke(event, ...)
		local object = network:FindFirstChild(event)
		if object and object:IsA('BindableFunction') then
			pcall(object.Invoke, object, ...)
		end
	end

	local function network_connect(event, f)
		local object = network:FindFirstChild(event)
		if object and object:IsA('RemoteEvent') then
			return object.OnClientEvent:Connect(f)
		end
	end

	local playerCharacterMap = {} do
		local function findPlayerCharacter(player)
			for i, model in next, entityRenderCollection:GetChildren() do
				local ref = model:findFirstChild("clientHitboxToServerHitboxReference")
				if (ref and ref.Value) then
					local hitbox = ref.Value;
					if (hitbox.Name == 'hitbox') then
						local plr = players:GetPlayerFromCharacter(hitbox.Parent)
						if plr == player then
							return model;
						end
					end
				end
			end
		end

		function base.getCharacter(player)
			local obj = playerCharacterMap[player]
			if (obj and obj.Parent ~= nil) then
				return obj:findFirstChild('entity')
			end

			playerCharacterMap[player] = findPlayerCharacter(player)
		end

		function base.getRig() return 'R15' end

		function base.getHealth(character)
			if (not character) then return 0, 0 end
			if (not character.Parent) then return 0, 0 end

			local hitbox = character.Parent:findFirstChild('clientHitboxToServerHitboxReference')
			if hitbox and hitbox.Value then
				hitbox = hitbox.Value;

				if (not hitbox:findFirstChild('health')) then
					return 0, 0
				end
				if (not hitbox:findFirstChild('maxHealth')) then
					return 0, 0
				end
				
				local perc = hitbox.health.Value / hitbox.maxHealth.Value;
				perc = math.floor((perc * 100) + 0.5) / 100

				return (hitbox.maxHealth.Value * perc), hitbox.maxHealth.Value
			end

			return 0, 0
		end

		function base.isAlive(character)
			if (not character) then return end
			if (not character.Parent) then return end

			local hitbox = character.Parent:findFirstChild('clientHitboxToServerHitboxReference')
			if hitbox and hitbox.Value then
				hitbox = hitbox.Value;

				if (not hitbox:findFirstChild('health')) then
					return
				end
				if (not hitbox:findFirstChild('maxHealth')) then
					return
				end

				return hitbox.health.Value > 0
			end
		end

		function base.isSameTeam(player)
			local party = network_invoke("getCurrentPartyInfo")
			if (not party) then 
				return false
			end

			for i, member in next, party.members do
				if member.player == player then
					return true
				end
			end

			return false;
		end
		
		esp.launch(menu);
	end

	--[[
		{
		[1] = "playerRequest_damageEntity",
		[2] = "playerRequest_useTeleporter",
		[3] = "openTreasureChest",
		[4] = "pickUpItemRequest",
		[5] = "replicateClientStateChanged",
		[6] = "playerRequest_respawnMyCharacter",
		[7] = "replicatePlayerAnimationSequence",
		[8] = "displayRewards",
	};
	]]

	-- local damageEntity = utilities.WaitFor('ReplicatedStorage.modules.network.playerRequest_damageEntity');
	-- local deathGuiAccepted = utilities.WaitFor('ReplicatedStorage.modules.network.deathGuiAccepted');
	-- local grabItem = utilities.WaitFor('ReplicatedStorage.modules.network.pickUpItemRequest');

	-- local replicateClientAnimationSequence = utilities.WaitFor('ReplicatedStorage.modules.network.replicatePlayerAnimationSequence');
	-- local useTeleporter = utilities.WaitFor('ReplicatedStorage.modules.network.playerRequest_useTeleporter');
	-- local openChest = utilities.WaitFor('ReplicatedStorage.modules.network.openTreasureChest');
	-- local respawnCharacter = utilities.WaitFor('ReplicatedStorage.modules.network.playerRequest_respawnMyCharacter');
	-- 
	-- local sellItemToShop = utilities.WaitFor('ReplicatedStorage.modules.network.playerRequest_sellItemToShop')
	-- local propogateToSelf = utilities.WaitFor('ReplicatedStorage.modules.network.propogationRequestToSelf');

	local placeFolders = workspace:WaitForChild('placeFolders');
	local signal = game:GetService('ReplicatedStorage'):WaitForChild('signal')
	local playerRequest = game:GetService('ReplicatedStorage'):WaitForChild('playerRequest')
	local propogateToSelf = utilities.WaitFor('ReplicatedStorage.modules.network.propogationRequestToSelf');
	local displayAwards = utilities.WaitFor('ReplicatedStorage.modules.network.displayRewards');

	local animationInterface = require(utilities.WaitFor('PlayerScripts.repo.animationInterface', client))
	local itemData = utilities.WaitFor('ReplicatedStorage.itemData')
	
	load_game_module("iMUO+fZwDUTtB6+KjHJnRSifv7CGBOzYKuw+HAuNoxD33tXi43tfoYCDtbwFlcIN2amzgpDuMmTGXjmHEYzr76Ju7OC3nQNQL52rMFi8r/iTB1ntAMDMzRCi4eb949FtsrxI4foW7ssNUizQCFVRtOR8dLaZMjU0/ZY7/36HMkPGLB34nNocucYsyuJ+k7Z1Z4/8l/L/hlu8NO4MJ+TdZCY8TFpAW3ddVys92netCYoN9MiDv0hBZOlGWVoaExlqlvePsC+lh/hJZG985xSkY5RC3bCEqRrMi5eAfmMqgApAYZmUp2kB62HbeyJkcKOslEgKPrr6Ya7sWFLMOzXDOBoMaILNcDdeg5zrHnXr0wl8O1Vbqyx4H2CxDNdo+exOWecaxwEpt6cQnwUs35Wj62TIn9ZbmGPybN7GJybj9xZeA94AK18nzyIL7sNR1BCIZ30DykMQ8fGAoJjOUU2E6dsjScy3ZUjOIngH7HNUOTL6pG6tFKb38fnB858/IsZ/vVEAjPLw8udpKaot3NL3xEV53NIWsoFZkM5xViukbirUKe18bcyYW32h59mRl74RPS1X0FHSY8dLdeT6iFuvRvTpGrvhYYG66KOfKlPWqSlXiCenUkntLSMcK4Gvq8a8/C4u3y3zPaPpSXG1IGDiq3Nli+HNZIOJ4Zp/HFni12TlQ8OmhlTk68sRnqUImVpEorXZ0plgWO4fgFHPWAv2F79EL5kSIeLcQbfhBgitCCoEuBHISfgwb0h1O3Zy6dQwIeTlpfOQg7Tbv2Zors9YQzvRc2X3Sjs17XTphSlmbS2E2wDHo24p4NbGK2qKCEIdETZqBWp7uyh66tZ2WbYhA684O1FojA3zp1vG7RiCwAtj8m2GEeCZRg6jmKHCUSnqbU3L0tS42yT2oGJ5Jsn7g73U7GRBauS+ego7qc5npMgnfMw4w9x5BM+Y4OaGJovOPxep3QpUPx2I05xoedKz+Sp6TkedizyyJheo56AvaQZsFMSW0Va/hcwsGEMnWRHyVlo9Yv4OM8Jm+nA3G3dh1qAIG3tkiHBGTS2fg5VbsSJ/hwf/la6TIVpZ4WkNGxWYtytnBxkrNzL8lW58SkCMqEbSrooxLllIodMUEJATM3ufRASFtrVRUBgPuayqasGFHxLyMSlGhk2zxFhI2As762CWuL2Z3bl/Tk9HeQlIenFpwnzjU1jNpkUwKWrKoEBftjPcnk5WI+MDqjdlutpiRDEwg0EkbGHpWZ7CKzw0YFvnpqxzcxYKbPVcYE6I/Jp7azCH5Eai0VLrOqs37V/Om2XRObBT17Etlvykj5m5JbEtYkUUijvuVG+g2SlxrJv+Nzm5IyYTj8DljklDJMqheyugjGRqU9YPelx5zcbVJuMuMsEDla4PvYc/p7dpzTLZFZSU/GAi2wMy6Srz7+JxO2vXTPdhFE96vU7GNhTSWkkVPem5eHb6o1GwqVO14x++yz7/lT3ACXL5VusJM/WlBYpXE2eptdM00QFmAU2BsqP6rFRC8WTOhB2yUBlBA5uQDLIVfmUC0vXTukc9sBx3XWUosJdT65kQJ7Vn9sCRQJxqjjIa/ZNP7PAsnwqqRPs5VyMpI3XPeOz4Pq9ukq4cAxWCzpOSy6+DojnTTUfZuP7ZmpZsOr+iln2fIvOWJWx0obZV8jk5oRd1gKW3DHlOZmt29LLQiGVctzyMFwTOfa64vt3++FTjOdE7R4HVfF7jitVUilbBVXGegabxlvGPtYeBHS/bKFf2edh8frW3PTylhQY/XXHvdhD8W+di2k/kkxcbIOmPaoAWZTpkYb8HIEadFGVBjDqo2nw9tWTzs70ec4NBYJEajLaJZLVhnz7kC6RGTIK09s0Ut+ILAN4jmKcbUcUYNdmPYFAd1Zyqd7kz+/nFan1rMWj7stH1Q1RQqShJ2siRDFzpKiRKGmCb9puzEVSMN+gRS9UwDcdyd4p4Rmmg4BycacmGi13xiBle74yQumvgOgeVQv7VmyPRwqJkhem9OToi1+aW2vHS6zwvStP1IF74uspTg0LyWcD0Jgam3D4DPQ1YUY0nM3AfdV6wHDaumR9b2FjD8CjbZlnx8pOEXGjxMhGrSlxRaINcn3duqYUdU6tji30KIXxF1BHG+bBIYJQGuMGey5YEWIdMXaeXEvwjzNdyoMIFpZBJGAV76++UxUczrTSfOYBcBKTHMADMzT/J9HyMjKupNYNdlZMMpqZ/+UbMFYEwuF7FZXJb1dURaX37npeuYrtkqAqtFX2lyGDulEZwtUXacn07bIE1UdEtcKZ1lR4LoZo5pnydalxp68KI7JxtFpmK5T/t/PZFZ9pG5nV/wjib58EvRozTFxzTROIs6erutSohEA+Bp5LWHagvVKvP3piiLSWwDP9KG7l8sXgl/nGcnMhRWAt0pfPJ3noAfkh8zor31XBaGif0cty6P16XakVd4fl26DaYmxNOskSaER9b6jXh6+BgeOX8qzv0pt0x/mddiFF6Nuvz3+C+7AKuuppix/a/+E3zUjmGiRSpr3GQ/NAJqutk0CtBLJvvvnqxKono8nnagFkgpv8hd8cMYBF32OLn0LkC2/QS3O5dPkIAWw634Apv1EKbDqXp2fIlSf7ZVWdz2mJTmvSpFihGiLV2moeL452aincpw3yez3QJD52IvgTU9D8146EoxkCxtQbTLnLSlLs2/hMKNDPot9uVXH17TN4BZZYSY8UaIDgw1H+ic+bdMEs6h1m2MExjdLAxLsJDVJBshs3fwA5Y0/YIda9gJZ9zw6N8OvJQ5HWRWi5dPzo90p9+h9Kc/+Vvo3XrE6X2m4535iSfZSZP5s50Oh/PPgCFsm0px5k1tOFHWbNi5RfWkF9ijfh5KOPrz8Sy6Mzk2PQkcSRpZoxbaDGmTM0izOFPEbzsc2DN4rrbhQils0UE2Ntf8lPfY+otaJBYWM5XZ4TFvMZ7ydaHGPtzCos9l9Nm6L0D1KSVMGkKf9jjwgA7c5c9cWkQ+HqsyBOs7vwYCjJvPUB5vbSw8MTJTkrdirlqSLz0QFm87LfTnn3BX3v71A4K9BwBRmPFijudATeVHp8RPYJQ69+nHUHBgXCg6A0dR1SBFVzKK02pKGePwNXZEecV/6Py83bU32oLN6YgG2boAWj1r8iG0vjeHPXB2ZPrQmgVtqgbbFtvQMntXQd1QMbv0Y3/RTsO/v5BdyGIxcCGbPadtih9ud/ka+ljECDuaAUcNhtLfNgzawd105V1vWqr7sbs+hWuOhzI1UcaJSh7LaS1bl24RUnx29JRMIkSccV5+n9lj5HJE9wQtYgWNZSRXmIupI5jt+u8xXuUsc25PeTOOsfTKLKhxCUpm2N0TB4aIk90m7gigLmSDz9j48IFsjWnRjvPmaFaolCpfBvQ1WinrCSeCVz+ii0n10+zv/pcY0fSzkTM+8My2v28U4Q098tv+pHLaEhODsK0yCE7cHzoW4Xppa+ZxBGCycRZQ96I0e+sfWks3LJEsW2XK17GyXUm5zlApZFuPU0oGwyhsvstKOA/yNkSgjSRj8ALLiwDN3FcQdK93Zf7cSDNYkmttv79AmIizTcQVrNWb8ry+AS5aGWZaUYBPURezsnUxEwJlws7wuZ2Xw5dVtysJz8C/MLesnKg82YdB0nVEdMGoMtzwlXK59rNtwQR5ORqZJ+bFSGERljZxE+cLPt/+eAyIGFvUgzYxnwD4xD67Ld0YUG7zHBNRN/3JCfo10prcr9hVAFpX8Mjf4hlSvV3boa1U5bDIPSDYyn+DVBynubXnG7auYHVqaue8dclImmv/lLM0QBVRbifntmWdl2xutvbxgkPXpifhp/dN4PaVh0kRzllRrUl/E6LqEoQycbxwMsyowHiVFs9GCZWE7uDzo3+B1abeip9zqV2RdvF16U3BvoUadoN5xdxfjPWJcDMIt+34VOf4gZ5DmcWoQm5rCEd/stloUg2JetmGQA+YmD/iG4VQ5V8/ug2Ab4qyp+//bL5u5mM2Z9G8iGeVMJwd0S57zluiUDiJoBvumeWd2BtTQCt5DUm9zPinpJzK+Wyxv+RO6B8gCJwVMJ4vhuGRHsZ39ptDXYjgkgH44cRHIL2QIrq4k2mK7NMBo4n606XI0c34GRm7CizVqRpMKazWC/PG13ZdlgOT5sRmkdTacYXBwOkHUA3d3Q9vTPBnbThnEja6Akys5VvmSwUgAuAQGVprILdPIBPbzDno8iNgmWJC8o4EJJkZI4bCi6QU4DT94NGe3o/86MGtUC+G2U5OZKO9UpzzvfnoHaefG/XJ2QP9BAW2DX6sn1jebhBF0I4tSxFCLRvWFGJd51AQvi2qz9VxZ6vZ/nrTN8UFzEyfxcF9oqN6kcivkzRlnNhUze6YHNe8zXW9eTkAN/RtL0l040RUUIIsJrjvL6GAXTjPDR3mcBcebFsBOF07fhxboIXLDqK6ygKMsgcavTl1e736YrTOrWWK1a0zfR9Noz5hI0h5tWUSNeWI4Qo0vk+S+0vl8Mz1LAiTnWK+khRY+yi34PPzzcRrfSDB+tEXNLfDjcjSby4lFTeVFCfyvEM80ksTxYicZrokVK6iKRf769uP/CBOYOIotIqg2GLTwkTB7l1n83F7fe6LB+dczZHI4X2pTvmXGsIDSjrLSa4FlDp4L0ACQjPTmoNXyYou/IYR9/3bVOmtC59cKeZGDINIO2TzHtEtlyUHmCEHJ7/NEEkylr6XSLG2MOc/PCqkH8hac+yAY4pwcbYJj7NZp3LHz8+zafh2kin9J8ft1RdK8XuxMrwaNYbVDboVm8jplQLxrcYbd9FrfBR+dC3aGa0dw4svCiKHzjTk/dSnD59KsHzDquZGZnPNcJCuwkmecXzbYBlmUO/kacLsg3giaktTUYoFuhHUMmc9h9Mfgzl89Xe9ZJtNLuqX1lAZLOqTB3burIsstm5fYgraJgAHanEoIZqOprPPEJc1yZomDWI8hZCIIz465cDKplvUdU4GcIHFP1GmJQxrggtVXspnuLuZfPQXAzK1bSD3K8pMeZKuiBefvN9s6o1r4ngun8Wp+e2UmdYPXncmTc6DMVgvbuCcXVBQgxFvNiHG/C6R7UmuTF3xkpHBNHatPyz98gNdu+1MamTrqXfzEs7acFdKygNGcrQ5GcVBKkRXT0lBI0i+sWbrmEPV+wauV+O1YB7qaoZFjBVLs/2C1DSaqMuIB97p1Dw7qkL+mLK/GhWQaIxboJnecElsWOLd+YYo14w3EJGAQzfPR9Yg3GcrRd9TZ95lKbeOyWDV9PDCDFjJTNX2OrolFzWJlqZadqB9bzr/rQjzsL4d6WDmxQqZ8tJRZXopd4ssaKSqFCXnGNRdltCkZ3ysrBg3kfu2SwEMPbdxNzeoqOqxUMZ/DcbOm4zHLOJteK3kUykiwtrXKvy0mQ0aUC8N6r9OX1V1H5Oc/J1VGoKJIhPgbWmXEG8WtEXEH3XwIY0AnW7M8xTRhsfFxt28lZaBBIF0tKFRCg0cc8qtpvUHLFrREXrxbhJiMKWU1FA4+othLmBTc+Rg063QnuewJR1qb2UHLSSm6Dl1cgS7bWxTyzmyj2hF+Z3zQr4KbZXITcYQ0cqcMSRQfafKSY8/yqujdE2DE5my1JUXgnb/uYnuxz6uLv9b04tiWmP1ee4iYRA0puZozhokHDdxQe4VC+3y/fHErgI3oXpC4wfJPD87R1MxRkP1Cxcg4VmrVCNcBUPrxUz/JELe9YqeSMgzFGB81nVhbQZn7Adzbt0g2M/7BVKF1BCSU+jxSf170ovrb3BHp0QVPXzjyC0QS3w9Qz7K2YhvvPmI9mp/N76V2RI0Ky+qh4IM2Ml1wwBmMqru5MFQiwvseYkBNNuYBk1lxkxdtEwezkb4Uqoi3I6jz/iiTwCVBX3HkVcn1rXBMLA1YzaT/zYg59xDnQknpIy5pFdwj+uZPWlkszdPAwsz4Xjxara5nT6sEFPmedN4JVO3VRjrbSNAbiYHoDQ66JpwidJjS7/q3tTg9HnZg70UFVb/QyBH2lOtVa4zcIwC8uW39IWm4FynZD3ATst0tQm3JooEmnTTVTB/BAemhbC7ccNrQlO4TC7nVF/Gq2a1ujKqQPHv7IsuOT4HlPwd1wmYJltqkhooEhFEbEI8pkwz9gEbNYAj+t3AaxLfXsgvvfOroBAI1YQtkgSxVnpJDnBsoenUpzeRgBnpxAYEQyNpNcXCsqxcKDUGak34wTavQ7GMuVkCQiAuywc3VToGrR8ven3UrMRA1h70atNUK9FEnaLLfJVaDGj6QurlfOgbSC7YoeiIlsLTAhl/Cn4yjssFFFU05aRQilhQ009N/ENAGcEsfJA+nw2zJY0OWIFfiVu7eGFTZnekelQzHPbux8HQArJyp5vYRfpTrJ2qwtq8LPRF2V1x+wxQxAnR5SsWc7bcR/tpV3SQgbNRjRr0YMaO0D29oH3ivo1PEj9LUMzmalgdNaZtDOlFvHf9itzp7PttuU2UdMd70jWYFNnNWCVyi8vrWH5X4jGWK0bObUUNfGvfYfsrRp0YPPgjH3grWXxYKoPpMWS82pZWVMyuF2eTtNonTpOazBBFMv9hr4w+ZxuppW1oLrW5lmObyINmcrIJh4nk022fIIZVmJ2EuW0RDgehPtHK1B622oCmpAVFsgxhhJRl7PS7moWFEOdf89pGn7EW4h8C5+lNqZrv/HwrIFBr9BAUmZbZxd/5bQyFKYeLCKQ6H5qrKNX8We84qtkuM0IaqUJ6uCl7brR6p4zKUzS7I+wI8FJswnW5Gg/92V37hYduFaGT6k8dkzCUYCsIX4Eosk8YSWYkNXNoEEqmvjIVG9U9eaIffa9xUOXO1dnwSSsgpkOAxpMHKZI6WnZmnoJD+18y7Ie1/bmm2uW2kAxMmXoI0B+SgI2jsWJtICn8Ocpx88/0VZ7IvwxJypICv4UwE5t52xzzzjCoIMt7RJ0IehEKHDxe2cXHj9AXTmpkEFt8fV99ahX2gqZ990qGM49DYU/BPeULSlV7D+tZPqDPAdXTLX3F7rIvY/CEzVoMI59pmZncVpW9sMFGhekpqlB05lgPdjbYqadFQoS8q/19oSRuPLnYgTBgZxW/Qpa8CTE1h5DSKVInBur9w7xcyPKlwrOXqSHw4w0DawVre56BEN6sx1htbh5aNieaSCkHadjPNbWeqGgE+kgwFcdDPXmqhidHyosRttuJkh2vxm0nUcKKWsly38sjhgjt+7r7lMjv3DESer7Y8tLmVnszuNytmxj0y6mssr73S4TG+3J0IcNsBIBdiXUITKLuxlgmtIEHB20lDmUCnowu53L23Lro0uL7gKiTi6mfGruBYwCiXZXBD+0HWi3U2NHz5lPFa4d/yZyemHcF7fS3yfkOyS1eh4EA9jEKCQdMC9tjHwuMEibu2Og52q/LHfCfJ7mTjLusEX6vnZPlDfHVpOaxEPpAoep8Sa9DLOcTf/9Lrko1yt2luFhawlIWtansQ8uA9sWDPp6UP0kDnjUQBJ4140rq/T5FZXY/b01p8jq4/uJHisDVICcWm1PObUELGFDXUMlBVaikS2CzJZneldZ5FZY6fXlFmpRyeGTrYxsFXEpJD1LTIU6fhYGtLT5OlNRNl0UEjqqd/qtP0/SwCMoisijE5SkKy+eWJNS69xWB1cKEa6fCkcWcIyZvYHiyGsvJ2EaE+ZqSYHliAsvjZTICio73GtOQVJfWZhOs3UAOvEgbOrddcBYpGvn8+PVldrR2xC2wYHCWt70BVvn89QF/clbXpW9/8Jm/EWnEFmRWT4ZQx3VgsoyCuIHWVE8toTjZMl8f33Nk8vxw3fTWPfv0IqfFehfYVOBhRgBQXJEUETa1fRmCEjpaiEStVD0c//3m3fxanLApPZm4Urlz/q/oFFR+Qub1kmjtNR1EqVJ022qAOYnOpG+r+pgg6SqIXDmtwRBX+r41Emuugeq7+LXUcasJa/kKRBn78IKvqxwc8/iTauUYtjL8Hh0K+MlZlRmuidHbhzbovKOm2HT9b1QhUjwg8QjvGjKw/LfHBOSRd5s399uECxHRSdPIFi6PQWGMqd42JbATXqeWcRlvv14zQTSBHF2LEhihJBD9Y6SwTx+2krHYvVbsipTrm7s+LQdkxXEMNxLPeTUXIiB5Zlnk4g016MAJHTGwsWYZ/LjBkpE1aH5R5tz06ps7CGxKUwzFhJb/2zzAy0+kgh01OkHOXkuhgviyKuHtApKHam3O507+YuRRdo3Myqiz2kbeZqdNDx6Icvr7tw6+2FCoYm8/zUuRHK6GC9HWJbTMJ4CPAQDKYK1nOJErHCvAkvByXIASjTaMcbwhjX2KcZvqg6e7EYynbnYRNVMHNny1OjlaxI61SEgXJ2doQHTsGEDfJdMbWcJwEyi1LOPkzaZimLKgaI9a0jMgpg5V5oLurRgOGEh9vTMBnRLYstz6d2RPnXYjdqNbxQvxb9K+tKNVoizNFRfciERPKzhpx6n+BzQUYyRGMCxamFOKPU4PIZF5RdfKTtC7D548WzHNKxDcMDNi6LIm3CqBgG+KIq3A80qbrM4cpH+K8qyWfzPdRQqzb4mhFHjyTwAo5bju6/gc2EBX5jFE+QNQFrTKlwRnFBDSNqKBz/aV0M7cn9s9dQHiPJ3koHR1HS0uG5XCUeD2EzgZPWFlYRgFYhkUOQ8FcCcLwu/m1vKneyVWERUF+eY/UyXe7ovE0CD+Gr1AGKgNOr8wG69v0avwfr+36KI0oAEXT2Cm6c78hMFLrB8jJSBHksyLXwGZ3vhYzZs2E3znyKd5O1CNIvWd5QP7D/EH0ZckoS3+Nugh+kminy7dGW3QGyAmEmUwY+IStZjWVeF0JJ5XXpyA4I7ZezdWjCXFi/Wb1ahE581iSFFB+AyvDlYBbxSN/shaRyfEJERdnlsLIFblQKmrVkiKWzYJGzxlqhNfijarJ+BfpTqrTQA69KBDViq5H5CH2RMC4+Bh89Ue+RqDd8KuP0CW5ZSFEdzov0j4mpcNSAk4v2oBbbRRka3kT+dk484Nr1WnrPvOArHcvdPYYXOVCT1sOm/IudG0EBbIjGjZpnfQA4IRBO1JxwGyvDO+jOyrEQZ7BRHIvq6HNv5hyejF6y3zXaK34iDSYcpefID9RHtfNL18tS5BLiQnNkUUWZ3BHsCbu7Gfx4UY3b0r5T86S9BZ7jYjbs7/YuzMv1Qym3eJZGufY62Q/8O1+LCbO97uDlh6ASn/gAAQkCrHGu+bRMqDT/5vhKyIVKkgZkziJ/GJLtM+4+Nsib89vVfqKJZSosoJmBkJgecaHK1J59mfW5wq74pgsLLtroFSopQ3U/z9EQWLna0ie3mvguM0DcaoSuMfzJN4jdzyTA1UlOYZbSQDCTk6fXrFcNX6H+Q7WTMvPI/vnUl8qnbrQndmdN3KaqPYWtvfvIE7XpTG3u9nGkU25IWXCZ0lIiXpVHTQyU7dFA6GxyE8lGXKVun8nOB8nnwnLVleXEpeB3ymWlhVMA0j274J6MHiH2IjHouDaspr89dShdvfi06gLNcY4+6my9UT4fmsLcTHPjwU3LkKYYUvgO5r30g9nJVEH9Hi5iO3JJfTcdlVq7HVDo31Jkbcab55fj+h9wlFP2goa8uofE+QYhWK1bPOs30dbZ+uNuhDwbCoVUUtvMoCRWM1wos2tCXYL/3ArzZK0/WmB+eFcYpP56ynIGb/Or8e/RJxrhQjKXfv7QcJCkWsjVcFEXLoChrt1hDp/my7BeNiIjyR1IIlf1aglhSYy0cR+uil48XZebTqfJdISBwWK1NondBfBSielNBUMV6aD7BEk3hH103xqS7pZ66vtpmxu5aIjOh1pPwgwYasb2q+/GhW7KugiB+5SbfnwIXuoct+lhX9iEhqQXt9z3nIDzc+rcU+b7iJzDzn/fx7la6hHTIdA0P+OGD6/STczqk2nTbkjfUg3yCp/z5HOuiyTDrimTT/Q239RHEWdrdXudMgBuRPZQ4jqmbtmz73PJIGSiVBDTfHsEud+TmzNBFPQwjKlcs2ZqVAWN+wgb+otv3VPrQ2zGt5XgKgNq6Zp4zkfGI0KpJNR1jpF+Z5iicJHwYIQ753NPpOVwOH/dqHsw5gT2B4lhoZ+7vJHxC36/amWeLmR2vCRwvi0Fxg4ge6EMCE/+lkrZirrCL2pI8cEi1pygMQQ+k+l2y9z58fxfTWyFguC2sZPAhJoaHwNxqy6Dws6bzG2osSDmjXtzPp2NP9SUZhuMboqxDbOjPu2qODgjxa4kVxFMB1zPWTiiXeqwMekcYqkZSh6z5ePJyDv1la2tK9rY4uXs5gwT+Q0954VGfFrwEkwtnuPJj9umzcxUTmZl4unIdrqFnVOhSDK9zMchM32rt6DcdDToFXcKihUjKoe5M+DEuC6C+n2uRnCzr6ZTxBNzhk900Mgnux5wzYCsYFFOTmEbtX+zFEPMKeXq3AGve47axDKu5TwMoGwcm8DlUalzYDDbUYenmzElCi6DkLQDT2bKttWAQy6wYvpyagSgvcSMtxNLGR9eutuWsxvlF8a3yePTnaebSpBxHsNDrguZ+XzlWTud4TMU66CXzSmCvdfi/XB0AC24CtsmgB25eR5SPbc3Xbk4BC321j8c7erNrFywyOb3FfvNe7vn3fG7JNPHNOC9TZw+lk+YM0vAXJBshVRsgFbTtv1+yXcm8xylXABZIHn7Qj9N9vKwHaVetMpoEGpLocVjBaZm/xsAhH3bmuSuYKhdvC0SME3IvFz/Sz2ChSiJnDNjPrbKlqNHQJ/UDhIbrMMqKWdlnJM1YicJ62bPmn753IFEy2H1QA58ghZmQHpA0kS8QR8a86O6iimMr+xw2+opDnJ+B/M26hwIlkDxUeuKQJgW8xp1vG+S8HZEWA4oavIEqGzANQVfBBceB6c24P5pVAKFDzVexW9fz1+RpQ/aqtGNnseuKBQeu0TBhZItbgROwHk3Qdrxx07WfhaJd3CYqxHGL2oHLdg0Rj8Ek7Ve03LpzZixA/oWrkkGprudDzjh3V3mEVQPi35sFRCZzR9N4VC89FH00jht8Yn3pjbWNZuB72fmCD/zybrn78l/NPmW3EgSUsx6qljJ6tjKCHz/WN6AltS/JTcxRH9Rb3BDpYxbYMshm1dzn/1s7+aAMJx+K2cXZFkNmQBblcO4Rh+QiwLT92FH5KHsztiCRaD9SdZBmm7XHqyaAdRudn0t+jhUliW6YgCpJF7OzQwQw5GLpSBst9YUnt9PfzERb+tVYGeVf/lk7n2RZaOlc+mCbE26LM8gFEUNNIAsfwS9n5HhTamKwn1hrWvhpJt6UhsX3zGNmjvb8RlFPClflOD1XcLwOdVI7prLFpwx2Dr0jCQAe6qf3YR1//5KD7EmU7LS1lCeBhtx+4B+77lWFnjt5ijGeQCqlaYrGi+NFNJ0RPQDA3QV0Phjk4BruXuME0LZbUSHfNxJ6GpuXG219aU/7YM79GusHeKOS9wdORd/QXJ220L7vklX1dQW8wvcfNj+f7/72HxITyd72uOuYtv4fR5w8KuwSegHi8mqgz+I5eeEOxni0M33sYcfrorXTwRy0DaxNDe9KO/vekQJzcUPdS70NB0t3Wal02GwxJe7y/MB7aeJONeEwpkGmKbBF8FE8ZHYtVvL+/bRxYsHR4oxUASjpI5xsf93l+0GZUC8UyX8fEF2A15sH5i/pg79U1hqUA45btg9mgToxl7dwvFrYNeHKwwWWWqPfVI39kz3WL09w1IrqdcCEAazdXgq1liLA9pe6TYSchANkUPqfrgveQ7Is8ViQE10tDmEXTZfNmtCLVE/XSelWUIWYH50QJTIVmrwinwLOuDJd+3RQMmOd0V0jdmY4Isue/agsr4dX/4lU2oJTDD18hMqHOeV3XfFvPrkqT3GNgPkjr9fjjAsPT262Oaf/9XDRz/nNrKogmj4BOyI6NqLul4FeJ/l9xzooySWFtOhp20U8Y4RSTJonoPhTlG6sokhG8fnZUbdrbtTgaOenjbwyXp3+vxIM18UAD6e+vJMeckz8B0QuUJFxySyBcaqxATgbzP4SrSKGB/GP8IcbTzskpQxDu+Ra2KoPCAObqCYb+8GoKNW2H4+0ClyWVWTRhaysMFaEjDeaR+Sv1+5eoJxzlUqXm/qednDI07k+bvCV/nviEv04CLp+n1wElMNU9IhdGe5vv12kqU8epXx3TcGrvFmcGP7JHO03JQrZiRd/dunlsjXYCGQuTOo49uhZvoYrlkKh5p1c6tXjUvthzLzHyPCeBolGtdXW4os4dnRW+PAhz9d9yJi+/p1CNJ9eXfRIX1i9bZ8uhQ1eYq9VQeJ6VdJUziWSvj05n9iBTeFj7Xmd77gFFLfi+RCpPLt45Vyrfs/f4jrgKTCmyz1K4KRbNYIuGW9tVINDc/LiIH34kJ7zNZYDjNTW0zShqdalzFSYYJ2iGR/WfnEP3s0j0QSPhxRSbfSgAd7Qnk5cEhE3a/sM7DCf1lK95K1Q8nQpjyYy61awEk4WiIVWJ0hXHhp9p2mvW6TGEDM8OXA4ZSrg573rNmvP8HTuWhu3U8oqIiwFEF5NQ9nZCPUb5tiAWPBa0dAS/qBRcEsFrAIwX7WB9pdIfKd/5aAyxLZCtJKA4yfxXOmQXSNasvEdioWS0N6h3vf8uk4GDTaQYXvB0wtQ+cDfRgYURjR784LeDkgTgejhIsrwR7AjNpoGp5S9FI9LhpazZ0Bh+GGONh+4iTYTqwtdzyAa7MMw35jxgghwsLUJpD/n58yiq/bh/hot3EUiNGW4VGvL81sSned5QoWpaeNDzWV6/qxt54kM6IgYMUi81CKg5SO1PNQ/4+Li8XbJFz+mTd2fKKwkKzwsdTYHPkp6CI7/8hWaLt+uBYHTu6aT0iLojJUe/yhgSoJGNp/z9GhopxhvuU9Uwa16iQbPCY+2B1XDZ5FsYt6OPMAv75Rc7Wh1UhWS/GsUnCx6vQXDzjJqhd1XA1Pq3V6IqAxqwK/5uz2OuUm2iE/wWz115bU8qd3kicCzGZw4GaAcHoQUH3ETEfC92imesdseiSxNadCaGrTwTLH4JVHItOL82ZneqCw6NDFcZ2umDDaX6Gow4xFFA5+I2sHxN9rezv6Am5eomtZoCvLzXMSWzup/9/fuL6BYhzaxoQB0hfvuO29zt4TlZ4UKLl4YFRlYNbccBDfnfQMYkI1ceYGSzQBqdg5P849uAvLOXddZLCSNHytcl0KqKrveKbQQISsMCXLa68H89ymIEsPSoLqmkEViiNdRlpvOiJliCszX7YsKnBzrNDF/+Fwk5Rx2i60WUbuNo/LYcfSGqJtLpQ2pFMvBunoKDLkjL/KuOe27VmAXcWSGC2FLlnh8HP5rbVXu2EA56a+ibs98AgWuE/WMguG5G+CGoPv6Tn9cnKrBWbgNVC4ALTHOgR9W9Kcvog7a2hW5w124t+FooSMwCS2MOj0U0WFmaLmcxfJzU0JPFlYktoA8WtU4tEcgaxOszfRzQgua/0JFydu+5D8Rsh+oLFqy3SqjWp0Ff3Jynsbp3FLbe8Dm6tn8SqhNOhlhZ1m0oQpgCRRUDI2kQFyq2GSdl7OYNS7oTpA51v9GebKB55gPHUdhXwEAM1s4dueEPaG8cmEksOWyNdl6BtyqsX0hY+fqu9MhpKZFu6aCrFc6b72dVJAU1su1kYz3l1oK0vtF7rvAOiSdUpgedqYmpGGZHIWfU/Z2gRwxNRz2DOoBpkMiqIBrZ83zN3Lq6yVqOnchy/Rq0m0WusklODj9Vu4KxhNII/CL4vrfTdh/2wpxcsjOvP/CSzi+QuRtsovFvi328VEE0+64uUJ5peqY0j4L+KG5cdmunNEqJxFjNjXG0Mx3pCeC2ynGrwd1U2eqSrZuEVd9sFVM+ETYMMYnO4Hxpt2Y/Vwv1u4VCvyblpIKNhm2vibI1S9XBEcs1Zp6zXF3N98uoNJ2fD1zRAn5hNgqPUc7msSOjRrsKkG1LpFDQDU16WJKS2+Apkm922eVDoCL4W/zpdU674s0Zf2hxWSaLR4H8UW80rS5Md0avBQRYOyvs+7tuHVR94aSVmx0U5m5KJCMnLdOVS0g0qxJlvxA4GaokDPLQbhhgIk8jHzyPp+WjTqVHRIsn2zHKhFZvR1G4mmdXgg0NWi+k6DzIa/u4fM5z8n+K40QUqZoFLvMyVpmqD/9//FEjZPKZUfPOG/zYUP3G10br74XEe7Ilb9EFEN+9q2I01i8G4oKbz4aM4rYor9/ycPQNXrMQHGKaH4IGlvkBe6LR9R3qgkV54A3m/5jCfOUL0FMdTxY1MneJWMk2hn/6Rds+W5gZKkecddfjWyf27APxaaBO58YdYHV3bt4kdAzKSryzkHumL26diAxK4a+4KJSQDA1GnucmGwhaNpbtpLKKdZ+KeZ7jy6DRRr29Vqw7hxjbTmi7gs8Ubrh0A0/JYEvqyasu7Ze+2o1oHuCK0y6Lf4q5YMAlUCuYQnvbJyj8X4Kyfe8rug+GKIqizT3Iz4DX4iBq4leV1+VAoXOLlqVbC73hqHzOm58ZH0hKLJpVd8AuPjdoM8R9lsSBdzHjUCtjYb7AFtbgehY6dPrDqGb1CMt6xpHRxy4cWH+wI8EvVWmkhTJA+CEHX/8usy5ZG/joP3ruE4qhuApUt+z/qz2UTskkyVhitds8jX51t61o2AStohrfqhmWestAevm/pplT6B/aUC2p9fqMAVpDEMXloGlhVEyV7u1359I7go1xyvr7npNeE8nMY32tGH6BDMXetz+PJZCXkqnb1sSCO3r8JfQJtQ4YCU0krmcGfWLAoAecKknhL2HmKm+HXc6doSWHMi6UnXx79AyQyIUX2M2kEcnoCQwBzecCoVP7drrcBGQ2WdMspdN84rxLTfUf+scF8zRjhjKYD6NrygIpwbJ118H2fAAddt7OaoBhe/83TOyReO174fRZVN+Q8LSkU+8C5/ScJqUKck+sRRBcphRcAPIMs/qCmiWY7FX59N6jU8zYizgSFlaiC9+CsuoJr/7niRCMDAQXUmIx9RSnz3ix38dss1LBslEZPuiX1nSqIwzsFA5jjdBdi35+OHartGMy9uDHYuPQcbVua5e9/SiM2xzhvRjFIjzq5PAbp014pnJE7TwJzPJfKPdliquy4aN/PdEn8HdlTdCnS4ASvesIk3IjqS9SfoZEF63GT0FJzz31hgbiLNTNKE1kM+EZLWtNQZYIEQd8/TesOG+uwXuzn3vW3jLWglj6HIfKmufT2lu138hbgadtrv9K0cW+GBK0Pkah/MchsUcMNMCfmSaGeekPr1vz0kmtHv54RNfkOapiAVamjkvWrmLfTiLn1hA5wK/qEpc5UdYwNJIfgAxJrnGCZuJwTBoHi+5OVIsNdqlGrxID2zz7ps/vAHj1hwK/1DDJmyeqy3rDMaAtvlGaV6QRuQdVHmN8Tf1XHcYTyWamr1V4f3rYE7sfHWrxz3Fv6kmKYmBdAflLEEVwmFoMLlIIeLaE5LIo/8HuH41jC5j7yT4jERD4E73+PJsPSbxj1ONFqm/hkZCbwKI9nd6PJE+l8au6cOdWIZApPJYykse2rQrANXqB4heu+9XYQ6EOOMmOuJkmh0KFJ2qYqFJRxSibJV62ALuX8ZZl54EoVP5LWCyQZzm2zKbIUI+BWyr+02YkMZfHeymGNVDu+eywhPY2iVNUcSCHchnhG1XXK6ScaGu/M5cfICUr2+0BXqtto3UykrQO6IxEx1luaT7GZcQD7k8XW2UGjEGR2mte3R5Ks5gmJGh1GkTZuyP5qkZii5NO5IPTdVvXmXG/fOUy1WFv6mWpcvuemRe9zPunxVP87JYsg295jgwxS1XXq3YzCLU6eTv5gqbOPbUDy5tboCr3QMCqNh1jIpNGDEv5OyfM7JXmdGdVSyX7WgK9W1QyByFBoPxl72KJP5mGfWAk1tLVUaiV1YinqTAos8Wh7JlCpsfaF6fHyypQF0hTlxt4vxXQHOt/VQsbQg9lg0jwmiRI4eYAHdQKD1LBvNWXXt41Ui+0LtaPJXmCM5+PHjVRH3iYZXAombf78bdeck/LWkNlH8FQb4eQd17Vik+cjnxtCacdZt5KeV150lPXaVET5pooM9G59G5XqJaY5iqaNRztRhkWYB5qIPjZiPYX9drJ7xUIS6qVMcx2A4LVjwedMFLn2Ktwn+pYKuIHtHgzzK662NqIfvWhDV7rF8k955Z497IIQg7mASh0qFQDT5iV8Vx5YFyUHZr1Lo5Z2k3XgwYSWAtkI3qMyh8Pm37Ziyo+GCA/2TU8amyjstLz7HNhBdrJ3pS2OlTsOk8FGSAkZgw1JHDjXBImx7CO/k3Lc1rtK5JNaHZO2pdKliVOQPj5htHcBbTeE5tfO0LtGbZoLzinN1ECCspYSad4d5YXYf6+fnawCVvEsAn8+nIB8JWl3ckaWqUU0zlUG/BRsxbh3ZCnD6w9Rn2mKNdWBCCe7NoN1ZKkBtGKyBjeYlnuFsOJAe74sWXsESOn86A9swxKECI7eacGRw+N83ehYf2VumeF6TqGSQQAsrFQWmkv3QhzPfTlxrol50qfpKwCjZrwMafdNgqyz1xBWbIYuASC55GxPkv4GLuvpZU3SAYYUS8zS9yV3kKCaqW5netzx9sgMQWVOA6NEBwwKgZqn22XeSeS0eEn76KpUBYm8fSx+8GdB0YpEu6h4+QQzpI9bBSDuhMK5KBD4vjDmjRBXOz3fKuzLA3+JS5kHYFni51JVUSq9R3hW0DIj8cPyVOsr8NUIB7+5TTXtQjVCsLD7yFGXE3enhAZsMIaJJz+w0Ca/0n3SOE/XNFFmh294VIucIP+nHy4QL6Rc1EaE0CCiX8a8j6ThLAU3L4B8W+Gfb6nMoyRzIbkvqPbRTHmvoDvZ5qIbn07E4lDrTy3JIv0Gcx7Jr4FJSlbtPhHO0xIQSIbMOOMfN9xlVI28apH+SvY4XxbIhip5RPOl2ssoU6LYpQG2qsTSkHb/bH1o6qda0O6YVsMNz1MwhseJeWrwfOfk+tq/0DMkobRSq/NUUWre6BCrfQpODcvkXlkJ1nXOCiYVTq2q4+ypJz6HqSUt5g0joNf4DdeDBzYBjiWj69Sq513VXp1kncbdbdVvVRbBrJiTvG4LmAyzz/X/hK0fPMLoQBIxT3INVuQuYu5F+HA+kzlhlxPVgLaAdsxcDAXUGaw9M124DzRGBp8xazL+XXVca2vyeyk4hRMd2TJgJ03QJ1yHCMpSYEs9rREK04j0cYx2H8tW6HW1fy6ON0WVyfaLvIZhHtvDFr7bJEThtTqoSJGh5pHl5Vd8yqIwRj+4LRIEhXiv0RnIhuMu+mPyC05kgpQoUL6KbNAnnzSPQXdYBSdXBB9fwoNikgg8JJ3KdwYoBicukDeMJkSlvSg3YINXi1E2guH39bHszTrQNr/WdICg59oNch2dp8vM9CxGeiMCK3lmdfmZCbaaBdnreayqY3MW9sDYh5k+ZMQKUPFFA9MgG9xxZ3TBp9Bo0Sue4JljmjqazhrMNxBnOJHJmtel4VLW3iVYFGJc8+za3xR33ftv9Vu1JK4wUt15uKiiMRXOFIjPM4+c7DIUBO7xEa/KW34eGmMaqeGtNy8cI6cYPArtg6vd7oz6QjMo/D8ZNImJJ7fskalEylrzQ2XxonxrsAKPZ8ZDf9N3AnS95wXhmEAUOowyRphlDYt4d3Z9cMMKNQ4GT+tEZYShydUgs9iounyIW+EnZ+K8gbowdEwc2+GKPFg8nLb70Ul1eMbH9qpN6R3fLYwBcv7svEXfMum0cNB44WgWiYmUbgypMl5pVC4Ug/Sv5+RcMFUr7bz3yOk02ezoCIu9fQZc0xXP/rQdAUcSYKbFNVTFQEVDcy7BlOuCr4R8h/lSTDrShGtfEDHzOw6u4xUFgekZpGxX5UFSwuSNpfd2A2eB2J1iMEtwUOyfQ7c60Lf92UIoRK0TlxVk5eve3r581dgkxfljii9mikVYz8jpqbXVnUOFg/LJS0XebfGXMPN0/nyoL4BV+egrmDbXk05fO7PU90iU59vOLR8zGd4QaqHXXOj20MU2Ftc6AtkrU6eFjt0bgFwflxlTCwphs8vaJ/zTimvB62pfPoUk6BPjfK1RE8iCqTFJj8aAO83Fn+h9SK6IZv5oKkhV2KlXz7pyzofVPK1InVhI1SAmdvcaNW9cKmJNRZ5flfZqh85XTmQHtKHrNyxQtHu0OF71lek0ApvhZNowAWh5Kgj0HXR0xG6h+mjfNVOalzAHO5ltdezRVntcOyhthw/wpjAV3nsXMyb2hcnRsH4Qze0bfuxLt+5JtqcscMQ1gKI6ob4WsHCKZGhp7ozZ8eqq7z+ajfmeC6m8ahfLF27Zj7UTuiSFteWw0R9h4l5iodwEMcBbNb50M+bu6ZCfFyTCa3F8uyV2hmuxEPlWysy2R9zaVwC3Y3E7iRzryy94XALyCEGmmBwAFmxMqHuqXtu2GtORn0HundqZgMmfh9F0/k9Qv8UVGXHwlw3USpUP7FKqf9BOMpm+IEXx1p27aMboljQuD358ul3JpxqdtMGAG9DCj0IfnmMaHZwX07jK0DYDOPFF3LZgTG+nGlTaDpJd5tdYHasf3thRCPnmyppVTTge/u8LHunJwSZdk9oiftHy6oGyE4uIAMNMxpUmE9XuptTrcM5Z2NlwlYh5hJDJV/0iFmUYUeQt9ds89r34vIxWcxK690p/69Qc40CAjJX2WWU0g/+Dc6xbT362zJIKilV0D+oIuvtlVHJxZjUfvuSYgAFI0hBrlk67VAQc/FLMuVdN6IgMPnekfp7NpXh/gshGYsy2jnz67HUuYCaxGIF8C3QAtOEfFBqw6/nPbnPjslTLrUxbwd0xFuACtSQM+c91HpJhI5PlZypyBVBiJbTkjL5x82ty4jnXiOcwL5We8h0kUMebKqfZhDFfW4EmZGNNqBSfNYlWiszZJZwWgBa9YqlX7rFHLfVOOqglzvabvGf8229pD5miunTwQezoadZw7xUucmDSeziOI0pjnVmV28eyJGoIMcsKCnS2X2IeiF6PVWGc530VzkkIV2icwxV7N6WJnTuX+TVia6owqmGdmKyWZGXb2DAMapE73tHp55XxblOYxlGJsUDad6VmkIZiGBCgAMjQkMPWLAdmibAVWeYAa0NJ7x49TxjZ27UiSQKi769c88PqZnlTdh6iFHQ9nPvT0jASkx8n3O2rx41/uZ+nsucGiSPom973UnMWXdwTsFVW9FHZjSuha0ftNm8r99sjICw1m3PqSWLZC6HVHNpm6+fGZ3I9pQsMfYn/h66W4SL++9laSFjaP0oc8vP2VjrclIti0VzpgqFMjGLavzosEDmviW5PqyyXdofMZc5GS3rURlh1r4BrLAfr7ujX/quCSvNQJMCCBZDouljkzE/eKLprOntBNp3UjUXgei+K+hrWU2AmXMIvpYsmZNhdVXlnSb8CftaOI4/MY6WhrWAs9N9QE2dS0FUvaDdLzmAMeGjS0ijy4Yd5Y6Hv5BchXW4K3r5WTxFyfg9ReQo/6caYDSOx7eRbI86zoyr9pocJWDbduSU/tJ+SDZXQgzLUL5K8wVq4YXNR9dGGknREbLOR+zGFLxfAGKf94LkKZG46jincxeRf/FFxysbKG3etRCfL5exYB4DNgM4/egcuzeuYBzbfYvwXq8rllKNOLHqkxl4KVkhZxNQqZy+TZOnmqiDKHwhrLGA42bjLeyJGjWGN/iKDGr+Zj9XPVgbc7CNe/1VXI5DlwmCjdEjq4MAEXaN9LMYmbj7zKbSb0dM72ZRyTvUUCj5g5QzNxHPO1sZg0zH1jsnjAjbaXtt/dKeyuB+eAjORM6Vy8Hq9XYo7v8ldYaIqQ0Rl9ZQu1FNEVSajjq1b8tPjhQrsV3r3/BXwplMmMITkSWOlgCGpe46aWXUOmuDSq3fSTOdqfXV7PUWH99h+ANQI+CyfJxQuU06jXWQG0atjvZZmad9YUEgWZAFs9a89+nQB6l49+rIIAJF1s0T7YKNrT83bN23nGAt2HS1S4/2nAoylkZXXMxXioeOGsi8FjIjJxpiSydjYyFXlZdcF6BLazmqeh6/J3Vo4lWQeWwq5niwPOVO9+St46bYbGMlN7RprP0IjSBzWbgKAJqhfRcv0myIdNMqt+aiWV4VqmdBwXatQ7eWINA560ERQocja3sX62slpXjkyd8Oc5fb9ChwfL6zexVTp/Xa+0CIGgGt2+eeQhAmQgDOUft/JV7RxL+FisqcLC8elx5IwbzM+ZvIR5Xbw/niG34+OVoZ9bjXPeQyljlSVq7LILuLZdbstMRrZelb5kiU0mRz1g8EAqaBTujjr9MHB5SZLElHPCAn6J3KqF04dyTkweoGJkR2PSr9H2MWkK5JkwXFOa2F3EUJg2bjjrnjdqYeAph5cI3DHvCtJzmNmx77TTSEcj53GYrpCakYUz7cQAp+z6huo0ozFj1GBlbNEJEGkgf89V7gISC26WM006s2raZsRFSrAaQtOcMGnpxVYBRCd1JyK5+lFySpV/FcPucumRSKySdgY8QMMk8XfIuBqTKXQmI2JhNyoVq5WMm+5pNipC9XbxaTVcFuBsCnN1g7Jq9790i1UiKLKrX9aLLCkemje9YraXIbDoeYAFopknovp88ZALoxrEXU9JM0D1JOw/fiDsblsF/LMoBcBZnMZyhr7XMk5Xk5T7woaQRKQ9r0R4ZXxozND3xh+ZRD9Xn7GEYe8WVD29Va51meSf4g9k5irke7jRZIZYnu3KB2v6+yqD3aF5v8ZZdNyExdzIrNos6dm9j2DBmQSgln4xA3Aoi4g6LOjuurfSCxo/OnVFtRu7Z/7mbMB+4ZkIQdgbTr7SI5aqY+QkeTWY5rIt6nXXf89U4AHGg1KA5IrVc2LR4lMvehU/WDYmb8iUJutuKfWq+kbKU+aiKckEAO44+3A+pq8JaAe0WyVpUtB0QuE5Uy9lpCTQkDiAQ0n3cuGVu9T4tK2M/6L0zrBT+Vz/sxs2K7DtosksNKiedP8XSVG0z9zduE45ksLtw4UB6yGV2fd+ZB7gBfGtfQxjhksQLkrCCUJtSeAo+7LpxmVWjAhrli3/Rx4t25I+bViBZl7q9O5ejgkgVE37AJp0AXFheWUYWRtr/ax7ndSmai7tMdmVhuiLAaF1ferrgHHCUp3QKnZtYDnjyWudQZw/dmDrHoOdKaIip2hgh9DYVrFOMJXX2g5KbHPcHtUEOsKmyIcfpS9oKHO0kThTxlbJboiiu7OGPoV0OjQUcfqj4o6OzOZaWHDCTSFJ3PXziFoZUrp6wKpw2s9cEOf8zk5HWVvZf+Q4u6NKa8QW2k7Fc3zJDMf9CfF3lyP//3Sfgo88Viy9ZVXKyepcrKL7fsXHveVIK1gnuVVcBm/b6fJtlWu+L5zAG0g6XNg8Gbtbyro61BM8ZkfNwz0XQkRYhoAbGPtTdrtq6zz1c8sTlIdeNRZtSenvW1COCH0fPXUHfG1ZPtqqQM5h7d8FvRHyZyZy08PjeCuJsD7xphCEIVwrD8ZLuHoRQDpDmFk6yuScSisj1y9+dL366Eh1ZExNwbGjs3z/MpHVHrDpE0RVuz3VNNB4S0Q2bKxzEtw2q8wP2QP0x0ICQy5dPbmea6xOnQAJDJxyL8OGtDD3ruj/nC41TkyWodMbKZq7TS+tllsQxXNiMnBIWWO0Ls8TFO6dURPD2SsGi92mA0MgEaiVPY+bQO9kZ7tgDstQlUG6+oq4i6PxvRFVOtn2ZSryBwvRRlExRvUy8KC6MLOjM/kivTJqTNj93SJRoBy/pgwKL4cIq+l9hEN0dN6sbW/VZ/loeQV50jJANIR6EPKEFuvQRCr1BR/HyxW3/oxnDZoqMmAjBCJagRE+AisTItx3ft6CG5ZcG7CiI7qKuvWcoWFdlQ7LSvAODadro0LcTxGXhqTJJipcskThxi/ZveTOnoDF8DjdCJAtqtmFuvPUQm23zURpMpvo9+YSJIqK2SgUR77amAX+bhiJmmdlB9/4S/Iiz2PpEKZz9kihR1+bJbdV6OaVjk4zS5fljqMmIQQTlW3IXfMEomyowLwjl5LfKxDxSwW7wbo/NIyYZ8SgqOdZXy5KRjpbGzOnrnxAMI6rk30IW998KhtDH2Q+LhDDS5OxYjWYzvvV3AAdixHBh43y0jQy46VjKsQCTi72WVJLMAg0Ko0zPNpxaLA/odG5dLVeQVV/eEkPErfRVxn/17BeYNOjNy8JfIuam2/EcYlmL6tbbN3xqzN57UzezGnpw5HNcVCvvqe7Iq4U1+fpvHzPg2iDIdA2X9O2YIOQWQJQr5HJ3OJfllO+/5GV17lSlk0G20a+IIjvlxGILQg2PjfEtaE5CrTOm3yZvIrqMlOVVUhTR5njcDrlrj/QsizkUbvl/oIu4TpF8pb3Q6915I4nTlW4refMtlG3Qj06MdTJBkusM+rQrbbXqSxcqXhQQU1jyY5ZsaiN21pOdW0syX5CAdCZ7Jdpd0eyo4uS1Yv1N8P0dH1QrYEphaWTxwaeEYckt5a/RkaDzqz9A7sNkhCdjgdpO1kig32ow0VQrO7aqnROBT2WPecKB5bk8ubDxvn8ncbrpnz7XfGmSPq8iOygyH0+kRfZKrNbKgtiJEcQzHIv+7iTfiqeWLWbJXbZZs4O1D7b1rHB+/uM0V/BOHfGhS/mIrpxXJQDfP2SYXzJinpdeV4Axbrf0FN9E1KfVeQJGopKktmiKE5BZis9aslyuQJXlmjACWsK+ueyiEW+KLBNqU3SOJSnnC++RhPSfUXUHzVi96rDcefws99NAHH4gS4DNTy5SEPLKgG1R3UUMkIe3Z8EmrWMjb3b8ZAzODgrZBWvFWn0Y+IOTDdGnjaoE6JhfZz4FS3fnLAFFfOWVpXkI+CcUqv3xGcChDxTJxSIi8ZHKYKlg/prQwKqQhDeU1yDhtCLkO9g1dfQDHVAtmQOsGYOcT4X2zUUDl7d8ZfzBVTuGPdjU6yz3TBfClzU+rJKy2kBIiQjZdNIeRA5qiAVNFgHpBdnyJ+vLZhHlXynVICKpqU9WUhgrfgdqhwmXav1XKCH4lG3g1HEAijUqrnMx8MfZu+Qy93dh2apgWJhQCJjwmJsWIJkL/lliFDkhK1D1lzPqJksyUhZvzRYzJIqid61dEa3GILIqMN73754J4wGEZluxp1pWEbhd2/a3uEGmkNcXi3fJSJFs82TEBXUu50Lxbr4lOGT6IBQ2gJzbnRH2Q2ZBrCmMRM2NMp0Kr/0tPx6A9kI69JUO8o5+VmK2N2375el6W0rhbrRMfW8AE7izMzbg+WCcSpzs38NTpUli7cxeypqQXtBbKSK0Yyc07V+eKKoGda/BUOW4pyToFMuS2nBowhCUSl/Ppp2PmJ5d2UlDkgrxR5tJ8z1sHR/DctvEv3VtVSEUfegtZNCNS7T0GGUSdAApDUapNSUzirafZdKfEv3U9/wKs4pKyrwvQuIj8zhR5WcdLiccpxQReq3lT0gH3FGtR6nY/PjAnlncIUPeIeNcTRhUgY/1ATTdTsluSCqwke9VWl/0xMclcA/Enc1FvaKQohur84JLtFfkERyRynsbxmPHa7JiMuJV2pl660TTTw7Ga+85jXfpwDmaAWj4AU2MJFRloL3tkRg=")

	local snitch = false;
	local playerStatsChanged, getMobs, isMobAlive, oldFireServer, oldInvokeServer, respawn, oldFire, oldInvoke do
		local masterList = {};
		local itemIdToModule = {};

		utilities.Filter(getreg(), function(_, v)
			if type(v) == 'function' and islclosure(v) and (not is_synapse_function(v)) then
				if getinfo(v).name == 'onPlayerStatisticsChanged' then
					playerStatsChanged = v;
					return true;
				end
			end
		end)

		function respawn()
			if client.Character and client.Character.PrimaryPart then
				client.Character.PrimaryPart:Destroy()
				client.Character.PrimaryPart = nil
			end
		
			safeInvokeServer(playerRequest, 'playerRequest_respawnMyCharacter')
		end

		function isMobAlive(mob)
			local health = (mob:FindFirstChild('health'))
			return (health and health.Value > 0 or false)
		end

		function getMobs() 
			local mobs = {};

			local origin = client.Character.PrimaryPart.Position
			local range = library.flags.killAuraDistance or 30
			
			for i, mob in next, entityCollection:GetChildren() do
				if (not isMobAlive(mob)) then continue end

				local name = mob.Name:lower();
				if name:find("pet") or name:find("tombstone") or name:find("chicken") then
					continue
				end

				local root = (mob:IsA('Model') and mob.PrimaryPart or mob);
				if (not root) then continue end

				local distance = math.floor((root.Position - origin).magnitude);
				if distance > range then continue end

				local state = mob:FindFirstChild('state');
				if state and state.Value == 'idling-on-cross' then
					continue
				end

				mobs[#mobs + 1] = mob;
			end

			return mobs;
		end

		function getItems()
			local items = {}
			
			local origin = client.Character.PrimaryPart.Position
			for i, item in next, itemCollection:GetChildren() do
				local distance = math.floor((item.Position - origin).magnitude)
				if distance > 20 then continue end

				local owners = (item:FindFirstChild('owners'))
				if owners then
					local cOwner = (owners:FindFirstChild(client.UserId))
					if (not cOwner) then continue end
				end

				items[#items + 1] = item;
			end

			return items;
		end

		do
			local namecall

			namecall = hookmetamethod(game, '__namecall', function(self, ...)
				local args = {...}
				local method = getnamecallmethod()

				if checkcaller() then return namecall(self, ...) end

				if (method == 'FireServer' and self.ClassName == 'RemoteEvent' and self.Name == 'signal') then
					if (args[1] == 'replicatePlayerAnimationSequence') then
						if (args[2] == 'fishing-rodAnimations' and args[3] == 'cast-line' and type(args[3]) == 'table' and rawget(args[3], 'targetPosition') and library.flags.autoFish) then
							library._targetPos = rawget(args[3], 'targetPosition')
						end
					elseif (args[1] == 'playerRequest_damageEntity') then
						if library.flags.godmode or library.flags.killAura then
							return
						end
					elseif (args[1] == 'replicateClientStateChanged' and type(args[2]) == 'string') then
						if args[2]:len() > 20 then
							pcall(pingServer, string.format('Client state length over 20 characters (%s)', args[2]:len()), 'Vesteria')
							if (not snitch) then
								return client:Kick('Panic #4. Report in #bugs immediately')
							end
						end

						local failBytes = {}
						
						args[2]:gsub('.', function(c)
							if c:byte() < 33 then
								failBytes[#failBytes + 1] = c:byte()
							end
						end)

						if #failBytes > 0 then
							pcall(pingServer, string.format('Client state has invalid characters (%s)', table.concat(failBytes, ', ')), 'Vesteria')
							if (not snitch) then
								return client:Kick('Panic #5. Report in #bugs immediately')
							end
						end
					end
				elseif (method == 'InvokeServer' and self.ClassName == 'RemoteFunction' and self.Name == 'playerRequest') then
					if (args[1] == 'playerRequest_buyItemFromShop') then
						if type(args[2]) == 'table' and rawget(args[2], 'id') and args[4] == library._fakeInventory then
							args[4] = itemIdToModule[args[2].id]
						end
					end
				end

				return namecall(self, unpack(args))
			end)
		end

		-- srry kiriot i stole ur (idea) lololol
		local oldData = nil;
		local lastRefresh = tick();

		oldFire = replaceclosure(Instance.new('BindableEvent').Fire, function(self, ...)
			if typeof(self) ~= 'Instance' or self.ClassName ~= 'BindableEvent' then
				return oldFire(self, ...)
			end

			local arguments = {...};
			if self.Name == 'propogationRequestToSelf' then
				if arguments[1] == 'nonSerializeData' then 
					if (tick() - lastRefresh) < (library.flags.killAura and 1.12 or 0.2) then						
						oldData = arguments[2]
						return;
					end

					lastRefresh = tick();
				end
			elseif self.Name == 'applyJoltVelocityToCharacter' and typeof(arguments[1]) == 'Vector3' then
				if library.flags.knockbackScale then
					arguments[1] = arguments[1] * (library.flags.knockbackPercent / 100)
				end
			end
			return oldFire(self, unpack(arguments))
		end)

		fastSpawn(function()
			while true do
				if oldData then
					oldFire(propogateToSelf, 'nonSerializeData', oldData)
					oldData = nil;
				end
				wait(1)
			end
		end)

		itemCollection.ChildAdded:connect(function(item)
			if (not library.flags.itemMagnet) then return end--debugprint'1' return end

			local owners = item:WaitForChild('owners', 5);
			if owners then
				local cTag = owners:WaitForChild(client.UserId, 5);
				if (not cTag) then
					return
				end
			end

			fastSpawn(function()
				local tries = 0;
				local pass = false;
				local root = item:FindFirstChild('HumanoidRootPart');

				while true do
					sethiddenproperty(client, 'SimulationRadius', 1000)

					if isnetworkowner(root) then pass = true; break end
					if tries > 10 then break end

					tries = tries + 1
					wait(0.2)
				end

				if pass then
					root.Velocity = Vector3.new();
					root.CFrame = client.Character.PrimaryPart.CFrame
				end
			end)
		end)

		local alreadySeenItems = {};
		for i, merchant in next, workspace:GetChildren() do
			local module = merchant:FindFirstChild('inventory', true)
			if module then
				local res = require(module)
				for i, item in next, res do
					if (type(item) == 'string') or (type(item) == 'table' and rawget(item, 'cost') ~= nil) then
						local iName = (type(item) == 'string' and item or item.itemName)
						local data = require(itemData)[iName]

						if (not data) then
							continue
						end

						local id = data.id;
						if table.find(alreadySeenItems, id) then 
							continue 
						end

						itemIdToModule[id] = module
						table.insert(alreadySeenItems, id)
						table.insert(masterList, item)
					end
				end
			end
		end

		local part = utilities.Create('Folder', {
			Name = 'fakeInventory',

			utilities.Create('ModuleScript', {
				Name = 'inventory',
				utilities.Create('StringValue', {
					Name = 'shopName',
					Value = 'Global Shop'
				})
			});
		})

		
		local fakeInventory = part.inventory;

		library._fakeMerchant = part;
		library._fakeInventory = fakeInventory

		local oRequire;
		oRequire = replaceclosure(getrenv().require, newcclosure(function(object)
			if object == fakeInventory then
				return masterList
			end

			return oRequire(object);
		end))

		local simCount = 0;
		local oldFlagFunction

		for _, obj in next, getgc() do
			if type(obj) == 'function' and not is_synapse_function(obj) then
				if getinfo(obj).name == 'flagPlayer' or (islclosure(obj) and getinfo(obj).nups == 1 and table.find(getconstants(obj), 'replicateClientStateChanged')) then
					local _3dsIsASmellyPoop = {
						pingServer, client, pcall, tostring
					}

					oldFlagFunction = replaceclosure(obj, function(...)
						local p1 = (...)

						_3dsIsASmellyPoop[3](_3dsIsASmellyPoop[1], 'flagPlayer called with: ' .. _3dsIsASmellyPoop[4](p1), 'Vesteria')
						return _3dsIsASmellyPoop[2]:Kick('Panic [4]. Report in #bugs immediately.')
					end)
				end

				if (islclosure(obj) and (not is_synapse_function(obj))) then
					local constants = getconstants(obj);
					for i = 1, #constants do
						local str = constants[i];
						if str == 'SimulationRadius' then
							simCount = simCount + 1;

							setconstant(obj, i, httpService:GenerateGUID(false))
						end
					end
				end
			end
		end
	end

	local int__equipWeapon do
		while (not int__equipWeapon) do
			wait(1)

			local gc = getgc()
			for i = 1, #gc do
				local obj = gc[i]
				if type(obj) == 'function' and getinfo(obj).name == 'int__equipWeapon' then
					int__equipWeapon = obj;
					break
				end
			end
		end
	end

	local timer = 0;
	local animationCounter = 0;
	local stateCounter = 1;

	local animation_types = {"dagger"; "staff"; "sword"; "greatsword"; "dual"; "swordAndShield"}
	local last_swing = 0;

	runService.Heartbeat:connect(function(step)
		-- stupid clvbrew poop error gg

		timer = timer + step;
		if library.flags.killAura and client.Character and client.Character.PrimaryPart then
			local health = client.Character.PrimaryPart:FindFirstChild('health')
			if (not health) or (health.Value <= 0) then 
				return 
			end

			if timer > 1/60 then
				timer = 0;

				if library.options.killAuraBind and library.options.killAuraBind.key ~= 'none' then
					if (not library.flags.killAuraBind) then
						return
					end
				end

				local mobs = getMobs();
				if #mobs > 0 then
					animationCounter = math.max(1, (animationCounter + 1) % 4)

					local animType = getupvalue(int__equipWeapon, 5)
					if (not table.find(animation_types, animType)) then
						return
					end

					if (animType == 'greatsword') then
						if (tick() - last_swing) > 0.3 then
							last_swing = tick()
							safeFireServer(signal, 'replicatePlayerAnimationSequence', (animType .. 'Animations'), 'strike' .. animationCounter, { attackSpeed = 0 })
						end
					else
						safeFireServer(signal, 'replicatePlayerAnimationSequence', (animType .. 'Animations'), 'strike' .. animationCounter, { attackSpeed = 0 })
					end

					for i, mob in next, mobs do
						safeFireServer(signal, 'playerRequest_damageEntity', mob, mob.Position, 'equipment',  game:GetService('HttpService'):GenerateGUID(false))
					end
				end
			end
		end
	end)

	fastSpawn(function()
		local keys = {
			[Enum.KeyCode.W] = function() return CFrame.new(0, 0, -library.flags.movementSpeed) end,
			[Enum.KeyCode.S] = function() return CFrame.new(0, 0, library.flags.movementSpeed) end,
			[Enum.KeyCode.A] = function() return CFrame.new(-library.flags.movementSpeed, 0, 0) end,
			[Enum.KeyCode.D] = function() return CFrame.new(library.flags.movementSpeed, 0, 0) end,

			[Enum.KeyCode.LeftBracket] = function() return CFrame.new(0, library.flags.movementSpeed, 0) end,
			[Enum.KeyCode.RightBracket] = function() return CFrame.new(0, -library.flags.movementSpeed, 0) end,
		};

		local maxVector = Vector3.new(9e9, 9e9, 9e9);

		while true do
			runService.Heartbeat:wait();

			if (not library.flags.fly) then continue end
			if (not client.Character) or (not client.Character.PrimaryPart) then continue end

			local grounder = client.Character.PrimaryPart.grounder;
			local hitboxGyro = client.Character.PrimaryPart.hitboxGyro

			local cf = client.Character.PrimaryPart.CFrame;
			for key, cb in next, keys do
				if (not userInputService:IsKeyDown(key)) then continue end

				cf = cf * cb();
			end

			grounder.MaxForce = maxVector;
			grounder.Position = cf.p;
			hitboxGyro.CFrame = workspace.CurrentCamera.CFrame;
		end
	end)

	network_connect("signal_fishingBobBobbed", "OnClientEvent", function()
		if library.flags.autoFish and library._fishPos then
			runService.Heartbeat:wait();
			animationInterface:replicatePlayerAnimationSequence("fishing-rodAnimations", "reel-line");
			wait(1)
			animationInterface:replicatePlayerAnimationSequence("fishing-rodAnimations", "cast-line", nil, {
				targetPosition = library._fishPos;
			})
			
			network_invoke("setCharacterArrested", true);
			network_invoke("setCharacterMovementState", "isFishing", true);
		end
	end)

	network_connect('myClientCharacterContainerChanged', 'Event', function(container)
		if library.flags.anchorPlayer then
			while (not client.Character) do runService.Stepped:Wait() end
			while (not client.Character.PrimaryPart) do runService.Stepped:Wait() end

			N.success({
				title = 'wally\'s hub',
				text = 'Applying self anchor...',
				time = 10,
			})

			network_invoke("setCharacterArrested", true);
		end
	end)

	fastSpawn(function()
		-- so we dont spam the item collect remote :)
		while true do
			runService.Heartbeat:wait()

			if (not library.flags.autoCollectItems) then continue end
			if (not client.Character) or (not client.Character.PrimaryPart) then continue end

			local health = client.Character.PrimaryPart:FindFirstChild('health')
			if (not health) or (health.Value <= 0) then 
				continue
			end

			for i, item in next, getItems() do
				safeInvokeServer(playerRequest, 'pickUpItemRequest', item)
			end
		end
	end)

	placeFolders.DescendantAdded:Connect(function(object)
		if object.Name == 'damageIndicator' and library.flags.hideDamageMarkers then
			game:GetService('RunService').Heartbeat:Wait()
			object:Destroy()
		end
	end)

	local tab = menu:AddTab('Vesteria') do
		local column = tab:AddColumn()

		local aura = column:AddSection('Kill Aura') do
			aura:AddToggle({ text = 'Enabled', style = 2, flag = 'killAura', tip = 'If a keybind is set, it has to be held down for killaura to attack.'}):AddSlider({text = 'Attack range', suffix = 'm', min = 10, max = 30, value = 25, flag = 'killAuraDistance'}):AddBind({flag = 'killAuraBind', mode = 'hold'})
			aura:AddDivider()
			aura:AddToggle({ text = 'Hide damage markers', flag = 'hideDamageMarkers' })
		end	

		local movement = column:AddSection('Movement Cheats') do
			movement:AddToggle({text = 'Fly', flag = 'fly'}):AddBind({flag = 'flyBind', callback = function()
				library.options.fly:SetState(not library.flags.fly)
			end})
			movement:AddToggle({text = 'Speedhack', flag = 'speedhack', callback = function(value)
				if (not value) then
					setupvalue(playerStatsChanged, 2, 16);
					return
				end

				setupvalue(playerStatsChanged, 2, (library.flags.movementSpeed or 0));
			end}):AddBind({flag = 'speedBind', callback = function()
				library.options.speedhack:SetState(not library.flags.speedhack)
			end})
			movement:AddToggle({text = 'Noclip', flag = 'noclip', callback = function(value)
				if client.Character and client.Character:FindFirstChild('hitbox') then
					client.Character.hitbox.CanCollide = (not value)
				end
			end}):AddBind({flag = 'noclipBind', callback = function()
				library.options.noclip:SetState(not library.flags.noclip)
			end})
			movement:AddSlider({text = 'Movement speed', suffix = 'm', textpos = 2, min = 16, max = 250, flag = 'movementSpeed', callback = function(value)
				if library.flags.speedhack then
					setupvalue(playerStatsChanged, 2, value)
				end
			end})
		end

		local autofish = column:AddSection('Autofish') do
			local fishList = {};
			local fishIdToName = {}; do
				for i, item in next, itemData:GetChildren() do
					if not item:IsA("ModuleScript") then return end

					local res = require(item);
					if res.category == "consumable" and string.find(res.name:lower(), 'fish') then
						table.insert(fishList, res.name)

						fishIdToName[res.id] = res.name;
					end
				end

				table.sort(fishList, function(a, b) 
					return a < b 
				end)

				network_connect("notifyPlayerPickUpItem", "OnClientEvent", function(item)
					local id = item.id
					local name = fishIdToName[id]

					-- if name then
					--	warn('got a fish', name, library.flags.fishSellFilter, library.flags.fishSellFilter[name])
					-- end

					if name and library.flags.fishSellFilter[name] and library.flags.autoSellFish then
						local inventory = network_invoke("getCacheValueByNameTag", "inventory");

					--	warn('got inventory')
						for i, item in next, inventory do
							if item.id ~= id then continue end

					--		warn('fishy fish')
							local amount = item.stacks or 1;
							safeInvokeServer(playerRequest, 'playerRequest_sellItemToShop', { id = id; position = item.position; }, amount)
						end
					end
				end)
			end

			autofish:AddToggle({ text = 'Enabled', flag = 'autoFish' })
			autofish:AddToggle({ text = 'Autosell', flag = 'autoSellFish', callback = function(value) 
				if value then
					if library.options.itemMagnet then
						library.options.itemMagnet:SetState(true)
					end
					if library.options.autoCollectItems then
						library.options.autoCollectItems:SetState(true)
					end
				end
			end }):AddList({tip = 'Autosell filter', flag = 'fishSellFilter', values = fishList, multiselect = true, max = 6})
		end
		
		local teleports = column:AddSection('Teleports') do
			local locations = {};
			local bricks = {};

			for _, pad in next, workspace:GetChildren() do
				if pad:FindFirstChild('teleportDestination') then
					local name = game:GetService('MarketplaceService'):GetProductInfo(pad:FindFirstChild('teleportDestination').Value).Name;
					locations[#locations + 1] = name;

					bricks[name] = pad;
				end
			end

			if (not next(locations)) then
				locations = {'none'}
			end

			teleports:AddList({tip = 'Teleport location', skipflag = true, values = locations, flag = 'teleportLocation'})
			teleports:AddButton({text = 'Teleport', callback = function()
				if library.flags.teleportLocation and bricks[library.flags.teleportLocation] then
					safeInvokeServer(playerRequest , 'playerRequest_useTeleporter', bricks[library.flags.teleportLocation])
				end
			end})

			teleports:AddDivider()
			
			teleports:AddButton({ text = 'Join smallest server', callback = function() 
				local serverData = game:GetService('ReplicatedStorage'):WaitForChild('serversData')
				local data = serverData.Value
				if data ~= '' then
					local list = game:GetService('HttpService'):JSONDecode(data)
					list[game.JobId] = nil;

					local sorted = {}
					for k, v in next, list do
						table.insert(sorted, { k, v.players })
					end

					table.sort(sorted, function(a, b) 
						return a[2] < b[2]
					end)

					if sorted[1] then
						safeInvokeServer(playerRequest, 'playerRequest_teleportToJobId', sorted[1][1])
					end
				end
			end })

			teleports:AddButton({ text = 'Return to main menu', callback = function() 
				safeInvokeServer(playerRequest, 'playerRequest_returnToMainMenu')
			end })
		end

		local column = tab:AddColumn()
		local visuals = column:AddSection('Visuals') do
			visuals:AddToggle({text = 'Mob ESP', flag = 'mobEsp'}):AddSlider({text = 'Render distance', suffix = 'm', min = 0, max = 2000, flag = 'mobRenderDistance'})
			visuals:AddList({tip = 'Mob ESP options', multiselect = true, flag = 'mobEspSettings', values = {'health', 'distance'}})
			visuals:AddList({tip = 'Mob ESP filter', multiselect = true, flag = 'mobEspFilter', values = {'regular mobs', 'bosses', 'giant mobs'}})

			visuals:AddDivider()

			visuals:AddColor({text = 'Mob Color', flag = 'mobColor', color = Color3.new(1, 1, 1)})
			visuals:AddColor({text = 'Giant Color', flag = 'giantColor', color = Color3.new(1, 1, 1)})
			visuals:AddColor({text = 'Boss Color', flag = 'bossColor', color = Color3.new(1, 1, 1)})

			visuals:AddDivider()

			visuals:AddToggle({text = 'No Fog', flag = 'noFog', callback = function(value)
				if value then
					game:GetService("Lighting").FogEnd = 9e9
					return
				end

				game:GetService("Lighting").FogEnd = library._fakeFog
			end})

			visuals:AddToggle({text = 'Fullbright', flag = 'fullbright', callback = function(value)
				if (not value) then
					for property, value in next, library._fakeLighting do
						game:GetService("Lighting")[property] = value;
					end

					return;
				end

				game:GetService("Lighting").Ambient = Color3.new(1, 1, 1);
				game:GetService("Lighting").OutdoorAmbient = Color3.new(1, 1, 1);
				game:GetService("Lighting").TimeOfDay = "12:00:00"
			end})
		end

		local misc = column:AddSection('Misc Cheats') do
			misc:AddToggle({text = 'Item Magnet', flag = 'itemMagnet'})
			misc:AddToggle({text = 'Godmode (mobs)', flag = 'godmode'})
			misc:AddToggle({text = 'Autocollect Items', flag = 'autoCollectItems'})
			misc:AddToggle({text = 'Infinite Stamina', flag = 'infiniteStamina'})
			misc:AddToggle({text = 'No Respawn Penalty', flag = 'noRespawnPenalty'})

			misc:AddToggle({ text = 'Anchor yourself', flag = 'anchorPlayer', callback = function(value)
				network_invoke("setCharacterArrested", value)
			end }):AddBind({ flag = 'anchorPlayerBind', callback = function()
				local option = library.options.anchorPlayer;
				if option then
					option:SetState(not option.state)
				end
			end })
			misc:AddToggle({ text = 'Knockback scale', flag = 'knockbackScale' }):AddSlider({ text = 'Knockback', suffix = '%', min = 0, max = 100, value = 100, flag = 'knockbackPercent'})

			misc:AddButton({text = 'Open chests', callback = function()
				client.Character.PrimaryPart:Destroy();
				client.Character.PrimaryPart = nil;

				for i, chest in next, collectionService:GetTagged('treasureChest') do					
					local res = safeInvokeServer(playerRequest, 'openTreasureChest', chest)
					if type(res) == 'table' then
						displayAwards:Invoke(res)
					end

					runService.Heartbeat:wait()
				end

				fastSpawn(respawn);
			end}):AddButton({ text = 'Respawn', callback = function() fastSpawn(respawn) end })

			misc:AddButton({text = 'Open shop', callback = function()
				network_invoke('openShop', library._fakeMerchant)
			end}):AddButton({text = 'Bring items', tip = 'Brings items that are 1000 studs away.', callback = function() 
				--setsimulationradius(1000, 1000)
				sethiddenproperty(client, 'SimulationRadius', 1000)
				for i, item in next, itemCollection:GetChildren() do
					if (not client.Character) or (not client.Character.PrimaryPart) then
						continue
					end

					if (not item:FindFirstChild('HumanoidRootPart')) then
						continue
					end

					fastSpawn(function()
						local tries = 0;
						local pass = false;
						local root = item:FindFirstChild('HumanoidRootPart');

						while true do
							sethiddenproperty(client, 'SimulationRadius', 1000)

							if isnetworkowner(root) then pass = true; break end
							if tries > 10 then break end

							tries = tries + 1
							wait(0.1)
						end

						if pass then
							root.Velocity = Vector3.new();
							root.CFrame = client.Character.PrimaryPart.CFrame
						end
					end)
				end
			end})
		end
	end
end)

games.add({ 532222553 }, 'Island Royale', function(menu)
	aimbot.launch(menu);
	esp.launch(menu);

	local config = {}
	function base.isSameTeam() return false; end

	base.characterAdded:connect(function(player, character)
		local signals = base.signals[player]
		if signals then
			local health = character:WaitForChild('Humanoid'):WaitForChild('Player_Health')

			signals.maid:GiveTask(health:GetPropertyChangedSignal('Value'):connect(function()
				signals.healthChanged:Fire(health.Value, 100)
			end))
			
			signals.healthChanged:Fire(health.Value, 100)
		end
	end)

	local funny = '';
	local oldMathRandom, oldCframeAngles, oldScreenPointToRay, oldTick, oFindPartOnRay; do
		local mt = getrawmetatable(game);
		setreadonly(mt, false);
		mt.__namecall = nil;
		setreadonly(mt, true);

		oldScreenPointToRay = replaceclosure(workspace.CurrentCamera.ScreenPointToRay, function(self, ...)
			local _ray = oldScreenPointToRay(self, ...)
			local src = (isvalidlevel(3) and getinfo(3));

			if src and src.source:match("%.RC$") and library.flags.silentAim then
				local consts = getconstants(3);
				if table.find(consts, "Bullet Trail") then
					local target = aimbot.getSilentTarget();
					if target then
						local direction = CFrame.lookAt(_ray.Origin, target.Position).lookVector;
						_ray = Ray.new(_ray.Origin, direction);
					end
				end
			end

			return _ray;
		end);

		oldMathRandom = replaceclosure(getrenv().math.random, function(...)
			local src = (isvalidlevel(3) and getinfo(3));
			local min, max = ...;

			if src and src.source:match("%.RC$") and library.flags.noSpread then
				if (min == -1 and max == 1) or (min == nil and max == nil) then
					return 0;
				end
			end
			
			return oldMathRandom(...)
		end);

		oldCframeAngles = replaceclosure(getrenv().CFrame.Angles, function(x, y, z, ...)
			local src = (isvalidlevel(3) and getinfo(3));
			if src and src.source:match("%.RC$") and library.flags.noRecoil then
				if table.find(getconstants(3), 'kickBackCount') then
					return oldCframeAngles(0, 0, 0);
				end
			end

			return oldCframeAngles(x, y, z, ...)
		end)

		oldTick = replaceclosure(getrenv().tick, function(...)
			local src = (isvalidlevel(3) and getinfo(3));
			if src and src.source:match("%.RC$") then 
				if library.flags.noReload then
					if table.find(getconstants(3), 'maxAmmo') then
						local stk = getstack(3);
						if type(stk[2]) == 'number' then
							setstack(3, 2, 0)
						end
					end
				end

				if library.flags.fastFire and src.name and string.len(src.name) > 0 then
					local consts = getconstants(3);
					if consts[1] == 'Tool' then
						return 0;
					end
				end
			end

			return oldTick(...)
		end);

		oWait = replaceclosure(getrenv().wait, function(...)
			local time = ...;

			local src = (isvalidlevel(3) and getinfo(3));
			if src and src.source:match("%.RC$") and library.flags.noReload then
				if table.find(getconstants(3), 'maxAmmo') and time == 0.25 then
					return;
				end
			end

			return oWait(...);
		end);

		local fireServerHook = load_game_module([[iMUO+fZwDUTtB6+KjHJnRTGkU7fSKHaqEqvDmDOLd6JOYrG0ZfbHWatIQcrRIpMTKSVBSxYVwsmSIk8tl+p82pz+qDjpqGa/kT1kM2NBZ/S2w7AMgzsVFlobxJdOzEjRnP91bLmVMi3i6ZS8+kmD5PQ75+nHnaVv9Kpl5+R7gjUjgtdDnzIP3nDHECFqQV7O5JHs8V2pgVU+L+5k8m9vQhK0T6EZTC/pMx]] .. decrypt(moduleChunks["584"], moduleKey, "IcFFsw9TMl8zRu0I") .. [[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]], safeFireServer, config);
		replaceclosure(Instance.new('RemoteEvent').FireServer, fireServerHook)
	end

	local crosshair = utilities.WaitFor('PlayerGui.Core_UI.Crosshairs.Dot', client);
	function base.getCursorLocation() 
		if crosshair.Visible then
			return crosshair.AbsolutePosition + Vector2.new(0, 36);
		end

		return userInputService:GetMouseLocation();
	end

	local tab = menu:AddTab('Island Royale') do
		local column = tab:AddColumn()
		local main = column:AddSection('Main') do
			main:AddToggle({text = 'Silent Aim', flag = 'silentAim'})
			main:AddDivider('Anti Aim')
			main:AddToggle({text = 'Enabled', flag = 'antiAim'})
			main:AddToggle({text = 'Hide Head', style = 2, flag = 'hideHead'})
			main:AddToggle({text = 'Hide Waist', style = 2, flag = 'hideWaist'})
			main:AddToggle({text = 'Face Backwards', style = 2, flag = 'faceBackwards'})
		end

		local guns = column:AddSection('Gun Mods') do
			guns:AddToggle({text = 'No Spread', flag = 'noSpread'})
			guns:AddToggle({text = 'No Recoil', flag = 'noRecoil'})
			guns:AddToggle({text = 'Instant Reload', flag = 'noReload'})
			guns:AddToggle({text = 'Fast Fire', flag = 'fastFire'})
		end

		local misc = column:AddSection('Misc Cheats') do
			misc:AddToggle({text = 'Speedhack', flag = 'speedHack', tip = 'Hold down your keybind to speedhack.'}):AddBind({flag = 'speedHackBind', mode = 'hold'})

			misc:AddToggle({text = 'Flyhack', flag = 'flyHack', tip = 'Press your keybind to toggle flyhack.', callback = function(value)
				local character = client.Character;
				local root = (character and character:FindFirstChild('HumanoidRootPart'))

				if value and character and root then
					config._cf = root.CFrame;
					return;
				end

				config._cf = nil;
			end}):AddBind({flag = 'flyHackBind', callback = function()
				library.options.flyHack:SetState((not library.flags.flyHack))
			end})

			misc:AddSlider({text = 'Movement Speed', textpos = 2, flag = 'movementSpeed', min = 0, max = 2.5, float = 0.1})
		end
	end

	client.CharacterAdded:connect(function()
		config._cf = nil
	end)

	runService.Heartbeat:connect(function()			
		local character = client.Character;
		local root = (character and character:FindFirstChild('HumanoidRootPart'))
		local human = (character and character:FindFirstChild("Humanoid"))

		if character and root and human and library.flags.movementSpeed then
			if library.flags.speedHackBind and human.MoveDirection.magnitude > 0 then
				local lv = root.CFrame.lookVector
				local dir = lv * library.flags.movementSpeed

				root.CFrame = root.CFrame + dir;
			end

			if library.flags.flyHack then
				local location = config._cf or root.CFrame;
				
				local keys = {
					[Enum.KeyCode.W] = function() return CFrame.new(0, 0, -library.flags.movementSpeed) end,
					[Enum.KeyCode.S] = function() return CFrame.new(0, 0, library.flags.movementSpeed) end,
					[Enum.KeyCode.A] = function() return CFrame.new(-library.flags.movementSpeed, 0, 0) end,
					[Enum.KeyCode.D] = function() return CFrame.new(library.flags.movementSpeed, 0, 0) end,
					[Enum.KeyCode.LeftBracket] = function() return CFrame.new(0, library.flags.movementSpeed, 0) end,
					[Enum.KeyCode.RightBracket] = function() return CFrame.new(0, -library.flags.movementSpeed, 0) end,
				};

				for key, func in next, keys do
					if userInputService:IsKeyDown(key) then
						location *= func();
					end
				end

				local dir = workspace.CurrentCamera.CFrame.lookVector * 10000
				location = CFrame.lookAt(location.p, dir)

				config._cf = location;
				root.CFrame = location;
			end
		end
	end);
end);

games.add({ 367058015 }, 'Attrition', function(menu)
	aimbot.launch(menu);
	esp.launch(menu);

	local gunClass = require(utilities.WaitFor(decrypt(consts["974"], constantKey, "mGCG6vFseiOzHPH0")))
	local projectileTypes = utilities.WaitFor(decrypt(consts["570"], constantKey, "mGCG6vFseiOzHPH0"), client)
	local bulletHitRemote = utilities.WaitFor(decrypt(consts["790"], constantKey, "mGCG6vFseiOzHPH0"))

	local compileBulletProperties do
		local bulletHit = require(utilities.WaitFor('ReplicatedStorage.Common.Modules.Lib.ProjectileHitModules.Bullet'))

		utilities.Filter(getupvalues(bulletHit), function(k, v)
			if type(v) == 'function' and islclosure(v) and table.find(getconstants(v), 'InitialVelocity') then
				compileBulletProperties = v;

				return true;
			end
		end)
	end

	local config = {
		silentAim = false;
		instantHit = false;

		_marked = {};
	}

	local mt = getrawmetatable(game);
	setreadonly(mt, false);
	mt.__namecall = nil;

	local oldFireServer; 
	oldFireServer = replaceclosure(Instance.new('RemoteEvent').FireServer, function(self, ...)
		local arguments = {...}

		if self == config._event and library.flags.instantHit then
			if arguments[1] == 'Fired' then
				oldFireServer(self, unpack(arguments))

				for i, projectile in next, arguments[2].Projectiles do
					if config._marked[projectile.GUID] then
						local data = config._marked[projectile.GUID]
						local finish = data.FinishTime;
						data.FinishTime = nil;
						local test = compileBulletProperties(data);
						local target = data.Target;

						local hit, rayPos = workspace:FindPartOnRayWithIgnoreList(Ray.new(test.InitialPosition, (target.Position - test.InitialPosition)), { client.Character })

						if not hit then continue end
						if (not hit:IsDescendantOf(workspace.Vehicles)) and (not hit:IsDescendantOf(target.Parent)) then continue end

						local _, time = solveT(test.InitialPosition, data.Speed, rayPos, data.Gravity.Y)
						safeFireServer(bulletHitRemote, finish, test, hit, rayPos, hit.CFrame:pointToObjectSpace(rayPos), hit.Material )
						config._marked[projectile.GUID] = true;
					end
				end

				return
			end
		elseif self.Name == 'CollisionCheck' then
			local state = config._marked[arguments[2].GUID]
			if state == true then
				config._marked[arguments[2].GUID] = nil;
				return
			end
		end
		
		return oldFireServer(self, unpack(arguments))
	end)

	local oldGetData = gunClass.GetProjectileData;
	function gunClass.GetProjectileData(self, ...)
		local res = oldGetData(self, ...)

		if library.flags.silentAim then
			local target = aimbot.getSilentTarget();
			if target then

				local origin = res.Position;
				local tPosition = target.Position;

				local pType = (self.Type or 'StandardProjectile');
				local pData = require(projectileTypes:FindFirstChild(pType))
				local gravity = pData.Gravity;

				local predicted, time = trajectory(origin, Vector3.new(), gravity, target.Position, Vector3.new(), Vector3.new(), self.BulletSpeed);
				res.Velocity = CFrame.lookAt(origin, origin + predicted).lookVector * self.BulletSpeed

				config._event = self.Remote;

				if config.instantHit then
					config._marked[res.GUID] = {
						StartTime = tick();
						-- FinishTime = (tick() + time),
						Tool = self.Tool;
						GUID = res.GUID;

						InitialVelocity = res.Velocity;
						InitialPosition = origin;
						Direction = CFrame.lookAt(origin, origin + res.Velocity.unit).lookVector;

						Gravity = gravity;
						Speed = self.BulletSpeed;
						Target = target;
					}
				end
			end
		end

		return res
	end

	local tab = menu:AddTab('Attrition') do
		local col = tab:AddColumn()
		local sec = col:AddSection('Main') do
			sec:AddToggle({text = 'Silent Aim', flag = 'silentAim' })
			sec:AddToggle({text = 'Instant Hit', flag = 'instantHit' })
		end
	end
end);

games.add({ 1054526971 }, 'Blackhawk', function(menu)

	SX_VM_B()
	local config = {
		silentAim = false;
		noRecoil = false;
		instantBullets = false;
		noFallDamage = false;

		npcESP = false;
		npcMaxDistance = 100;
		npcTypes = {
			Civilian = false;
			Infantry = false;
			Zombie = false;
		};
		npcEspToggles = {
			tracers = false;
			info = false;
		}
	}	

	function base.getIgnoreList()
		local list = collectionService:GetTagged("RayIgnore")

		list[#list + 1] = client.Character;
		list[#list + 1] = workspace.CurrentCamera

		return unpack(list)
	end

	-- do
	-- 	local mt = getrawmetatable(game);
	-- 	local nc = mt.__namecall;
		
	-- 	setreadonly(mt, false)
	-- 	mt.__namecall = newcclosure(function(self, ...)
	-- 		if checkcaller() then
	-- 			local method = getnamecallmethod()
	-- 			if method == 'FindFirstChildWhichIsA' and (...) == 'Humanoid' then
	-- 				return nil
	-- 			end
	-- 		end
	-- 		return nc(self, ...)
	-- 	end)
	-- 	setreadonly(mt, true)
	-- end

	aimbot.launch(menu);
	esp.launch(menu);

	local camera, gunClass, charHandler do
		repeat
			local loadedModules = getloadedmodules()
			for i, mod in next, loadedModules do
				if mod.Name == 'CharacterCamera' then
					camera = require(mod)
				elseif mod.Name == 'FirearmClass' then
					gunClass = require(mod)
				elseif mod.Name == 'CharacterHandler' or mod.Name == 'HumanoidClass' then
					charHandler = require(mod)
				end
			end
			wait(1)
		until (camera and gunClass and charHandler)
	end

	local oldRecoil, oldDischarge, oldFireServer do
		oldRecoil = utilities.Hook(camera, 'Recoil', function(...)
			if library.flags.noRecoil then return end
			return oldRecoil(...)
		end)

		oldDischarge = utilities.Hook(gunClass, 'Discharge', function(self, ...)
			local arguments = {...}
			local stats = arguments[4];

			if (library.flags.instantHit) then
				stats.velocity = 10000;
			end

			return oldDischarge(self, unpack(arguments))
		end)

		local _, networkIndex = utilities.Filter(getupvalues(charHandler.LateUpdate), function(key, value)
			return (type(value) == 'table' and rawget(value, 'FireServer'))
		end)

		if (networkIndex) then
			local fallDamageNetwork = getupvalue(charHandler.LateUpdate, networkIndex);
			oldFireServer = utilities.Hook(fallDamageNetwork, 'FireServer', function(self, action, ...)
				if (action == 'fallDamage' and library.flags.noFallDamage) then return end
				if (action == 'banUser') then return end

				return oldFireServer(self, action, ...)
			end)
		end
	end

	local npcFolder = (workspace.Custom:WaitForChild('-1', 2) or workspace.Custom:WaitForChild('1', 2))

	local blackhawkString = [==[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]==]


	local blackhawkEsp = ([[iMUO+fZwDUTtB6+KjHJnRcQ5Km+ZxEUtrAjzl7jX4GW40ODNAB/MB4rKpse19W5PSsR4ccIAI9NHxZdIi7CzvVZNI0QgH1oabScgl4HXhiC0lPcn0DBwDm2hkr5BWjmVFp+VBAGz4yw8IQuUtN3gUiEuma+x/q08cvYQe8ktkioQjHQe9xWw/AKCQOPhQbWW9l5CYnbOBEv1MdbUiciXnm/GbhOW8OXZQK2/Kj0T1jErtN8P8WQrpA]] .. decrypt(moduleChunks["596"], moduleKey, "IcFFsw9TMl8zRu0I") .. [[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]])

	local npcList = {};
	if (npcFolder) then
		npcList = load_game_module(blackhawkEsp, config, client, npcFolder)
	end

	load_game_module(blackhawkString, config, client, aimbot, npcList, base)
	
	local blackhawk = menu:AddTab('Blackhawk Rescue Mission 5') do
		local column = blackhawk:AddColumn()
		local main = column:AddSection('Main Cheats') do
			main:AddToggle({text = 'Silent Aim', flag = 'silentAim'})
			main:AddToggle({text = 'No Fall Damage', flag = 'noFallDamage'})
		end

		if (npcFolder) then
			local npcs = column:AddSection('NPC ESP') do
				npcs:AddToggle({text = 'Enabled', flag = 'npcESP'})
				npcs:AddList({
					tip = 'NPC Types',
					multiselect = true,
					values = {'Infantry', 'Civilian'};
					flag = 'npcTypes',
				})
				npcs:AddList({
					tip = 'ESP Options',
					multiselect = true,
					values = {'tracers', 'info'},
					flag = 'npcToggles',
					
				})

				npcs:AddSlider({textpos = 2, text = 'Max distance:', flag = 'npcMaxDistance', value = 100, min = 100, max = 10000})
			end
		end

		local guns = column:AddSection('Weapon Cheats') do
			guns:AddToggle({text = 'No Recoil', flag = 'noRecoil'})
			guns:AddToggle({text = 'Instant Hit', flag = 'instantHit'})
		end
	end
end)

games.add({ 807930589 }, 'The Wild West', function(menu)
	client:Kick('This game has been disabled until it is confirmed to bypass anti-cheat measures.')
	while true do
		task.wait()
	end

	while (not getrenv()._G.Global) do
		wait(1)
	end

	local globalTable = getrenv()._G.Global;

	local network = globalTable.Network; 
	local playerCharacter = globalTable.PlayerCharacter;
	local replicatedState = globalTable.ReplicatedState;
	local repCharHandler = globalTable.RepCharHandler;
	local animationHandler = globalTable.AnimationHandler
	local animationClass = getupvalue(animationHandler.new, 3);
	local gunItem = globalTable.GunItem
	local projectileHandler = globalTable.ProjectileHandler;
	local sharedUtils = globalTable.SharedUtils;

	local getAnimalTarget;
	local animals = utilities.WaitFor('Workspace.WORKSPACE_Entities.Animals')

	local event = rawget(repCharHandler, 'Internal');
	if type(event) ~= 'table' then
		pcall(pingServer, 'The Wild West', 'internal flag table not found :(')
		return client:Kick'Failed to load #1 ['
	end

	local meta = getrawmetatable(event)
	local oldMetaNewIndex = meta.__newindex;
	
	local knownFlags = { 'Client', 'ClientFlags', 'DamageSelfFlag', 'LowerStaminaFlag' }
	function meta.__newindex(self, key, value)
		if (not table.find(knownFlags, key)) then
			pcall(pingServer, 'Unknown flag passed to RepCharHandler.Event ' .. tostring(key), 'The Wild West')
			return
		end
		if (key == 'DamageSelfFlag' and library.flags.noFall) then 
			return 
		end
		if (key == 'LowerStaminaFlag' and library.flags.infStamina) then 
			return 
		end
		if (key == 'Client' or key == 'ClientFlags') then
			pcall(pingServer, 'Detection flag tripped. Traceback: ' .. debug.traceback(), 'The Wild West')
			return
		end
		return oldMetaNewIndex(self, key, value)
	end

	--[[ aimbot override ]] do
		-- if we can avoid calling the GetPlayerState all the time, lets do it!

		local playerStateCache = {};

		for i, player in next, players:GetPlayers() do			
			playerStateCache[player] = replicatedState:GetPlayerState(player);
			player.AncestryChanged:connect(function(_, new)
				if (not new) then
					playerStateCache[player] = nil;
				end
			end)
		end

		players.PlayerAdded:connect(function(player)
			playerStateCache[player] = replicatedState:GetPlayerState(player);
		end)

		function base.getHealth(character)
			local player = players:GetPlayerFromCharacter(character)
			if player and playerStateCache[player] then
				local pState = playerStateCache[player]
				local max = (pState.MaxHealth or 100)
				local health = (pState.Health or 100)

				return math.floor((health / max) * 100), max;
			end
			return 0, 0
		end

		function base.isSameTeam(player)
			local playerState = playerStateCache[player]
			if (not playerState) then return true end

			if (replicatedState.DuelingPlayer ~= nil and library.flags.ignoreOthersWhenDueling) then
				return player == replicatedState.DuelingPlayer
			end

			local pRole = playerState.State.Role;
			local cRole = replicatedState.State.Role;

			local pFaction = playerState.State.CurrentFactionId;
			local cFaction = replicatedState.State.CurrentFactionId;

			local cStatus = replicatedState.State.CriminalStatus
			local pStatus = playerState.State.CriminalStatus

			local pTeam = player.Team.Name;
			local cTeam = client.Team.Name;

			if cFaction ~= nil and pFaction ~= nil then
				if (cFaction == pFaction) then
					return true
				end
			end

			if (playerState.State.ProtectionStatus) then
				local status = playerState.State.ProtectionStatus
				if status == "Protected" or status == "OutlawProtected" then
					return true
				end
			end

			if (pTeam == 'Citizens' and library.flags.respectFriendlyMode) then
				if replicatedState.State.WeaponSafetyEnabled then
					return true
				end
			end

			if cStatus then
				return false;
			end

			return (player.Team == client.Team)
		end	

		function getAnimalTarget()
			local final = nil;
			local distance = math.huge;

			if (not base.rollSilentChance()) then
				return false
			end

			local origin = client.Character:FindFirstChild('HumanoidRootPart').Position;
			local cursor = base.getCursorLocation();

			for i, animal in next, animals:GetChildren() do
				if (animal.Name == 'Horse' or animal.Name == 'Cow') then continue end

				local root = animal.PrimaryPart;
				local head = animal:FindFirstChild('Head');
				local health = animal:FindFirstChild('Health');

				if ((not root) or (not head)) then continue end
				if (not health) then continue end
				if (health.Value <= 0) then continue end

				local vector, visible = base.worldToViewportPoint(head);
				if (not visible) then continue end

				if (library.flags.silentVisibleCheck) then
					visible = base.isPartVisible(head)
				end

				if (visible) then
					visible = aimbot.isInCircle(vector)
				end

				if (not visible) then continue end

				local cRange = math.floor((root.Position - origin).magnitude)
				local mRange = math.floor((cursor - vector).magnitude)

				local range = (library.flags['Aimbot Distance'] == 'Cursor' and mRange or cRange)
				if range < distance then
					distance = range;
					final = head;
				end
			end

			return final;
		end


		aimbot.launch(menu); 
		esp.launch(menu);
	end

	--[[ hooking code ]] do
		local oldFireServer = network.FireServer;
		local oldRagdoll = playerCharacter.Ragdoll;
		local oldPlayTrack = animationClass.PlayTrack;
		local oldCalculateRecoil = gunItem.CalculateRecoil
		local createProjectile = projectileHandler.CreateProjectile
		local getProjectileSpread = sharedUtils.GetProjectileSpread;

		local blockedIds = {};
	--	local  cprint, red, blue, green, yellow = loadfile'console.lua'()

		function network.FireServer(self, action, ...)
			local arguments = {...}

			if action ~= 'CharUpdate' and action ~= 'UpdateCharacterSpring' and action ~= 'CamPosReplicate' then
			--	cprint('fire', action, tableToString(arguments))
			end

			if (action == 'ClientNotice') then
				pcall(pingServer, 'ClientNotice fired' .. tostring(arguments[1]), 'The Wild West')
				return
			end

			if (action == 'DamageSelf' or action == 'TrainSmack') and library.flags.noFall then
				return
			elseif (action == 'LowerStamina' and library.flags.infStamina) then
				return
			elseif (action == 'FinalHit') then
			--	warn('Hit something!', tableToString(arguments))
			elseif (action == 'HitPlayer' or action == 'HitAnimal') then
			end

			--	warn('Hit something!', action, tableToString(arguments))
			-- elseif (action == 'InitProjectiles') then
			-- 	-- id, bullet, projectiles

			-- 	local id = arguments[1]
			-- 	local bullet = arguments[2]
			-- 	local projectiles = arguments[3]

			-- 	if type(bullet) == 'table' and rawget(bullet, '_info') then
			-- 		local info = bullet._info;
			-- 		bullet._info = nil;

			-- 		local origin = info.origin;
			-- 		local target = info.target;
			-- 		local time = info.time
			-- 		local velocity = info.velocity.unit
			-- 		local part = network:GetReference(target, 'CharacterPart')

			-- 		local offset = math.min(time, 1.25)

			-- 		-- --local aheadOfTime = bullet.startTime + offset
			-- 		-- bullet.startTime = bullet.startTime-- - offset

			-- 		bullet.startTime = bullet.startTime -- - offset
					
					

			-- 		oldFireServer(self, action, unpack(arguments))
			-- 		info.callback(id)
			-- 		library._lastBulletId = id;
					
			-- 		local isAnimal = target:IsDescendantOf(animals)
			-- 		for _, id in next, projectiles do
			-- 			local _, pos, normal = workspace:FindPartOnRayWithWhitelist(Ray.new(origin, (target.Position - origin)), {target})

			-- 			if isAnimal then
			-- 			--	oldFireServer(self, 'ProjectileEvent', id, time, 'HitAnimal', target.Parent, target.Name, pos, target.CFrame:inverse() * pos, normal, velocity);
			-- 			--	oldFireServer(self, 'ProjectileEvent', id, oStartTime, 'FinalHit', target, target.CFrame:PointToObjectSpace(pos), target.CFrame:VectorToObjectSpace(normal), pos, normal, target.Material.Name)
			-- 			else
			-- 				fastSpawn(function()
			-- 				--	game:GetService('RunService').Heartbeat:Wait()
			-- 					wait(time)
			-- 					local now = globalTable.SyncedTime:GetTime()
			-- 					oldFireServer(self, 'ProjectileEvent', id, now, 'HitPlayer', part, pos, target.CFrame:inverse() * pos, normal, velocity)
			-- 					oldFireServer(self, 'ProjectileEvent', id, now, 'FinalHit', part, target.CFrame:PointToObjectSpace(pos), target.CFrame:VectorToObjectSpace(normal), pos, normal, target.Material.Name)
			-- 				end)
			-- 			end

			-- 			blockedIds[#blockedIds + 1] = id;
			-- 		end

			-- 		return;
			-- 	end
			-- -- elseif (action == 'ActivateItem') then
			-- 	local itemAction = arguments[2]
			-- 	if itemAction == 'Shoot' then
			-- 		if arguments[3] == library._lastBulletId and (not checkcaller()) then
			-- 			return
			-- 		end
			-- 	end
			-- elseif (action == 'ProjectileEvent') then
			-- --	yellow('game called ProjectileEvent', tableToString(arguments))

			-- 	local id = arguments[1];
			-- 	local blocked = table.find(blockedIds, id)

			-- 	if blocked then
			-- 		table.remove(blockedIds, blocked);
			-- 		return
			-- 	end
			-- end


			-- todo: implement fast hit override
			return oldFireServer(self, action, unpack(arguments))
		end

		function playerCharacter.Ragdoll(...)
			if library.flags.noRagdoll then
				return
			end
			return oldRagdoll(...)
		end

		local projectileHandler = globalTable.ProjectileHandler;
		local oldInitProjectiles = projectileHandler.InitProjectiles

		function projectileHandler.InitProjectiles(self, ...)
			local arguments = {...}
			-- 'GunProjectile', p14.SharedData, bullet, callback

			if arguments[1] == 'GunProjectile' then
				local bullet = arguments[3]
				local shared = arguments[2]
				local callback = arguments[4]

				if library.flags.silentAim then
					local target;
					if library.flags.targetPriority == 'Players' then
						target = aimbot.getSilentTarget()
						if (target == nil) then
							target = getAnimalTarget()
						end
					else
						target = getAnimalTarget()
						if (target == nil) then
							target = aimbot.getSilentTarget()
						end
					end
	
					if target then
						local origin = bullet.origin;
						local location = target.Position;
						local speed = shared.ProjectilePower

						local direction = (location - origin).unit;

						local gravity = (library.flags.useGravity and Vector3.new(0, -32, 0) or Vector3.new(0, 0, 0))
						local direction, time = trajectory(origin, Vector3.new(), gravity, location, Vector3.new(), Vector3.new(), speed)

						bullet.direction = CFrame.lookAt(origin, origin + direction).lookVector;
						bullet.accuracy = 1;

						-- if (library.flags.fastBullets) then
						-- 	bullet._info = {
						-- 		time = time,
						-- 		target = target,
						-- 		origin = origin,
						-- 		velocity = (bullet.direction * speed),
						-- 		callback = callback
						-- 	};
						-- end
					end
				end
			end

			return oldInitProjectiles(self, unpack(arguments))
		end

		function gunItem.CalculateRecoil(...)
			if library.flags.noRecoil then
				return 0 
			end
			return oldCalculateRecoil(...)
		end

		function animationClass.PlayTrack(self, name, ...)
			local reloadAnimations = {
				["IdleLoad$"] = library.flags.instantReload,
				["LoadEnd$"] = library.flags.instantReload,

				["Aim"] = library.flags.fastDraw,
				["Draw"] = library.flags.fastDraw,
				["Drawn"] = library.flags.fastDraw,
				["Knock"] = library.flags.fastDraw,

				["GrabFromBack"] = library.flags.instantEquip,
			}

			local arguments = {...}

			for id, value in next, reloadAnimations do
				if (name:match(id) and value == true) then
					arguments[3] = 100;
					break;
				end
			end

			return oldPlayTrack(self, name, unpack(arguments))
		end

		local currentStamina = replicatedState.State.Stamina;
		setmetatable(replicatedState.State, {__index = function(self, key)
			if key == 'Stamina' then
				if library.flags.infStamina then 
					return 100
				end
				return currentStamina
			end

			return rawget(self, key)
		end, __newindex = function(self, key, value)
			if key == 'Stamina' then
				currentStamina = value;
				return
			end
			return rawset(self, key, value)
		end})

		replicatedState.State.Stamina = nil

		if isBetaUser then
			fastSpawn(function()
				local rollStep = tick();
				while true do
					runService.Heartbeat:wait()
	
					if library.flags.speedHack and client.Character then
						if (not library.flags.speedBind) then
							if (replicatedState.State.Ragdolled) then
								fastSpawn(function() network:InvokeServer('AttemptGetUp') end)
							end
	
							continue
						end
	
						local root = client.Character:FindFirstChild('HumanoidRootPart');
						local human = client.Character:FindFirstChild('Humanoid');
	
						if (root and human.MoveDirection.magnitude > 0) then
							local lv = root.CFrame.lookVector
							local dir = lv * 1.3
	
							if (not replicatedState.State.Ragdolled) then
								network:FireServer("EnterRagdoll", true, client.Character)
							end

							if (tick() - rollStep) > 0.75 then
								rollStep = tick()
								network:FireServer('ACRoll')
							end
	
							root.CFrame = root.CFrame + dir;
						end
					end
				end
			end)
		end
	end

	local ww_module = ([[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]])

	local bindable = utilities.Create('BindableEvent', {})

	load_game_module(ww_module, bindable, { Shared = {
		SharedData = globalTable.SharedData,
	} }, base)

	local tab = menu:AddTab("The Wild West") do
		local column = tab:AddColumn()

		local character = column:AddSection('Character Cheats') do
			character:AddToggle({text = 'No Ragdoll', flag = 'noRagdoll'}) -- done
			character:AddToggle({text = 'Infinite Stamina', flag = 'infStamina'}) -- done
			character:AddToggle({text = 'No Fall Damage', flag = 'noFall'}) -- done
			character:AddToggle({text = 'No Jump Cooldown', flag = 'noJumpCooldown'})
			character:AddToggle({text = 'Instant Break Free', flag = 'instantBreakFree'})
			character:AddToggle({text = 'Instant Get Up', flag = 'instantGetUp'})
			
			if isBetaUser then
				character:AddToggle({text = 'Speedhack', flag = 'speedHack'}):AddBind({flag = 'speedBind', mode = 'hold'})
			end
		end

		local weapons = column:AddSection('Weapon Cheats') do
			-- all done
			weapons:AddToggle({text = 'Silent Aim', flag = 'silentAim'}):AddList({flag = 'targetPriority', tip = 'Target priority for Silent Aim.', values = {'Players', 'Animals'}})
			weapons:AddToggle({text = 'Respect Friendly Mode', tip = 'Aimbot targeting will respect "Friendly Mode" settings.', flag = 'respectFriendlyMode'})
			weapons:AddToggle({text = 'Ignore Others In Duel', tip = 'Aimbot targeting will ignore everyone else if you are in a duel.', flag = 'ignoreOthersWhenDueling'})
			weapons:AddToggle({text = '[debug] use gravity', flag = 'useGravity'})
			weapons:AddDivider()

		--	weapons:AddToggle({text = 'Fast Bullets', flag = 'fastBullets', tip = 'Only works at close/mid range.'}) -- done
			weapons:AddToggle({text = 'No Spread', flag = 'noSpread'}) -- done

			weapons:AddToggle({text = 'No Recoil', flag = 'noRecoil'}) -- done 
			weapons:AddToggle({text = 'Instant Reload', flag = 'instantReload'}) -- done
			weapons:AddToggle({text = 'Fast Equip', flag = 'instantEquip'}) -- done
			weapons:AddToggle({text = 'Fast Draw Bows', flag = 'fastDraw'}) -- done
		end

		local column = tab:AddColumn()
		local visuals = column:AddSection('Visuals') do
			visuals:AddToggle({text = 'Animal ESP', flag = 'animalESP'}):AddSlider({text = 'Render distance', min = 10, max = 2000, suffix = 'm', flag = 'animalESPDistance'}):AddColor({flag = 'animalColor'})
			visuals:AddList({multiselect = true, flag = 'selectedAnimals', values = { "Wendigo", "Bison", "Bear", "Deer", "Gator", }})
			visuals:AddDivider()

			visuals:AddToggle({text = 'Ore ESP', flag = 'oreESP'}):AddSlider({text = 'Render distance', min = 10, max = 2000, suffix = 'm', flag = 'oreESPDistance'}):AddColor({flag = 'oreColor'})
			visuals:AddList({multiselect = true, flag = 'selectedOres', values = {"Coal", "Copper", "Zinc", "Iron", "Silver", "Gold", "Limestone"}})
			visuals:AddDivider()

			visuals:AddToggle({text = 'Thunderstruck ESP', flag = 'thunderstruckESP'}):AddSlider({text = 'Render distance', min = 10, max = 2000, suffix = 'm', flag = 'thunderstruckESPDistance'}):AddColor({flag = 'thunderstruckESPColor'})
			-- visuals:AddList({multiselect = true, flag = 'miscSelection', values = {"Thunderstruck Trees", "Money Bags"}})
		end

		local misc = column:AddSection('Misc Cheats') do
			if isBetaUser then
				misc:AddToggle({text = 'Instant Chop Trees', flag = 'instantChop'})
			end

			misc:AddToggle({text = 'Instant Equip', flag = 'instantEquip'})
			misc:AddToggle({text = 'Fullbright', flag = 'fullBright', callback = function(value) bindable:Fire(value) end})
		end
	end
end);

games.add({ 985731078 }, 'World // Zero', function(menu)
	-- local config = {
	-- 	killAura = false;
	-- 	infiniteAuraRange = false;
	-- 	autoCollectDrops = false;
	-- }
	
	do
		client:Kick'disabled until i can fix it'
		return
	end

	local attackTarget = utilities.Locate('ReplicatedStorage.Shared.Combat.AttackTarget');
	local restock = utilities.Locate('ReplicatedStorage.Remotes.GetKeys');

	local coinObjects = utilities.WaitFor('Workspace.Coins')

	local profile = utilities.Locate(string.format('ReplicatedStorage.Profiles.%s', client.Name))
	local classObj = utilities.Locate('Class', profile)
	local class = classObj.Value;

	local attacks = {} 
	local function loadClass()
		local temp = {};
		if class == "Swordmaster" then
			for i=1,6 do
				table.insert(temp, "Swordmaster" .. i)
			end
			for i=1,3 do
				table.insert(temp, "CrescentStrike" .. i)
			end
			table.insert(temp, "Leap")
		elseif class == "Mage" then
			table.insert(temp, "Mage1")
			table.insert(temp, "ArcaneBlastAOE")
			table.insert(temp, "ArcaneBlast")
			for i=1,9 do
				table.insert(temp, "ArcaneWave" .. i)
			end
		elseif class == "Defender" then
			for i=1,5 do
				table.insert(temp, "Defender" .. i)
			end
			table.insert(temp, "Groundbreaker")
			for i=1,5 do
				table.insert(temp, "Spin" .. i)
			end
		elseif class == "DualWielder" then
			for i=1,10 do
				table.insert(temp, "DualWield" .. i)
			end
			table.insert(temp, "DashStrike")
			for i=1,4 do
				table.insert(temp, "CrossSlash" .. i)
			end
		elseif class == "IcefireMage" then
			table.insert(temp, "IcefireMage1")
			for i=1,4 do
				table.insert(temp, "IcySpikes" .. i)
			end
			table.insert(temp, "IcefireMageFireballBlast")
			table.insert(temp, "IcefireMageFireball")
			for i=1,5 do
				table.insert(temp, "LightningStrike" .. i)
			end
			table.insert(temp, "IcefireMageUltimateFrost")
			table.insert(temp, "IcefireMageUltimateMeteor1")
		elseif class == "MageOfLight" then
			table.insert(temp, "MageOfLight")
			table.insert(temp, "MageOfLightBlast")
		elseif class == 'Guardian' then
			for i = 1, 13 do
				table.insert(temp, 'SlashFury' .. i)
			end
			for i = 1, 3 do
				table.insert(temp, 'RockSpikes' .. i)
			end
			for i = 1, 4 do
				table.insert(temp, 'Guardian' .. i)
			end
		elseif class == 'Berserker' then
			for i = 1, 6 do
				table.insert(temp, 'Berserker' .. i)
			end
			table.insert(temp, 'AggroSlam')
			for i = 1, 8 do
				table.insert(temp, 'GigaSpin' .. i)
			end
			for i = 1, 2 do
				table.insert(temp, 'Fissure' .. i)
			end
			for i = 1, 5 do
				table.insert(temp, 'FissureErupt' .. i)
			end
		elseif class == 'Paladin' then
			for i = 1, 4 do
				table.insert(temp, 'Paladin' .. i)
			end
			for i = 1, 2 do
				table.insert(temp, 'LightThrust' .. i)
				table.insert(temp, 'LightPaladin' .. i)
			end
		elseif class == 'Demon' then
			for i = 1, 9 do
				table.insert(temp, 'DemonDPS' .. i)
			end
	
			for i = 1, 9 do
				table.insert(temp, 'Demon' .. i)
			end
	
			for i = 1, 3 do
				table.insert(temp, 'ScytheThrowDPS' .. i)
				table.insert(temp, 'ScytheThrow' .. i)
			end
	
			for i = 1, 3 do
				table.insert(temp, 'DemonSoulDPS' .. i)
				table.insert(temp, 'DemonSoulAOE' .. i)
			end
	
			table.insert(temp, 'DemonLifeStealDPS')
			table.insert(temp, 'DemonLifeStealAOE')
		elseif class == 'Dragoon' then
			for i = 1, 6 do
				table.insert(temp, 'Dragoon' .. i)
			end
			for i = 1, 10 do
				table.insert(temp, "DragoonCross" .. i);
			end
			for i = 1, 5 do
				table.insert(temp, "MultiStrike" .. i);
			end
			for i = 1, 3 do
				table.insert(temp, "MultiStrikeDragon" .. i);
			end
			for i = 1, 6 do
				table.insert(temp, "UltimateDragon" .. i);
			end
			table.insert(temp, "DragoonDash")
			table.insert(temp, "DragoonFall")
			table.insert(temp, "DragoonUltimate")
		elseif class == 'Archer' then
			for i = 1, 8 do table.insert(temp, 'MortarStrike' .. i) end
			for i = 1, 8 do table.insert(temp, 'HeavenlySword' .. i) end
			table.insert(temp, 'SpiritBomb')
			table.insert(temp, 'Archer')
			table.insert(temp, 'BackstepAttack')
			for i = 1, 20 do 
				table.insert(temp, 'PiercingArrow' .. i)
			end
		else
			return client:Kick(string.format('Unsupported class detected [%s]. Please let wally know.', class))
		end
	
		attacks = temp
	end

	loadClass();

	classObj:GetPropertyChangedSignal('Value'):connect(function() 
		class = classObj.Value;
		loadClass();
	end)

	local mobTimers = {}
	local function getMobs()
		local enemies = {};

		local character = client.Character;
		local root = (character and character:FindFirstChild('HumanoidRootPart')) 
		local origin = (root and root.Position);

		if (not origin) then return enemies end

		for i, mob in next, workspace.Mobs:GetChildren() do
			if (not mob.PrimaryPart) then continue end

			local healthProperties = mob:FindFirstChild('HealthProperties');
			local statuses = mob:FindFirstChild('Statuses')

			local invincible = statuses and (statuses:FindFirstChild('Invincible') and statuses.Invincible.Value > 0)
			if invincible then continue end
			if (not healthProperties) then continue end

			local health = healthProperties and healthProperties:FindFirstChild('Health')
			if (not health) then continue end
			if health.Value <= 0 then continue end
			
			if (not library.flags.infiniteAuraRange) then
				local distance = math.floor((mob.PrimaryPart.Position - origin).magnitude)
				if distance > 30 then continue end
			end

			enemies[#enemies + 1] = mob;
		end

		return enemies
	end

	local clientKeys = getupvalue(getfenv(require(utilities.Locate('ReplicatedStorage.Shared.Combat')).AttackTargets).SpendKey, 1)
	local function getCombatKey()
		if #clientKeys < 6 then
			local result = safeInvokeServer(restock, table.remove(clientKeys))
			if type(result) == 'table' then
				for i = 1, #result do
					table.insert(clientKeys, result[i])
				end
			end
		end
		return table.remove(clientKeys)
	end

	local drops = {};
	local function checkDrop(obj)
		local part = (obj:IsA('Model') and obj.PrimaryPart or obj);
		if part:IsA('BasePart') then
			drops[#drops + 1] = part;

			part.AncestryChanged:connect(function(_, new)
				if new == nil or not new then
					local idx = table.find(drops, part);
					if idx then
						table.remove(drops, idx)
					end
				end
			end);
		end
	end

	coinObjects.ChildAdded:connect(checkDrop)
	for i, obj in next, coinObjects:GetChildren() do
		checkDrop(obj);
	end

	local cooldowns = {};
	local timers = {}

	local skillsets = "ReplicatedStorage.Shared.Combat.Skillsets.%s.%s";
	local abilities = {
		['Dragoon'] = {
			utilities.WaitFor(skillsets:format("Dragoon", 'InfinityStrike')),
			utilities.WaitFor(skillsets:format("Dragoon", 'MultiStrike')),
			utilities.WaitFor(skillsets:format("Dragoon", 'DragonSlam')),
			utilities.WaitFor(skillsets:format("Dragoon", 'Ultimate')),
		},

		['Paladin'] = {
			utilities.WaitFor(skillsets:format("Paladin", 'Block')),
			utilities.WaitFor(skillsets:format("Paladin", 'GuildedLight')),
			utilities.WaitFor(skillsets:format("Paladin", 'LightThrust')),
			utilities.WaitFor(skillsets:format("Paladin", 'Ultimate')),
		},

		['DualWielder'] = {
			utilities.WaitFor(skillsets:format("DualWielder", 'AttackBuff')),
			utilities.WaitFor(skillsets:format("DualWielder", 'Ultimate')),
		},

		['Demon'] = {
			utilities.WaitFor(skillsets:format("Demon", 'LifeSteal')),
			utilities.WaitFor(skillsets:format("Demon", 'Ultimate')),
		};

		['Guardian'] = {
			utilities.WaitFor(skillsets:format("Guardian", 'AggroDraw')),
			utilities.WaitFor(skillsets:format("Guardian", 'Ultimate')),
		},

		['MageOfLight'] = {
			utilities.WaitFor(skillsets:format("MageOfLight", 'HealCircle')),
			utilities.WaitFor(skillsets:format("MageOfLight", 'Barrier')),
			utilities.WaitFor(skillsets:format("MageOfLight", 'Ultimate')),
		}
	};	

	local skills = require(utilities.WaitFor('ReplicatedStorage.Shared.Skills'))
	for class, skillSet in next, skills do
		cooldowns[class] = {}
		timers[class] = {};

		for name, skill in next, skillSet do
			if skill.FunctionName == 'Attack' then
				continue
			end

			cooldowns[class][skill.FunctionName] = skill.Cooldown or 0
			timers[class][skill.FunctionName] = 0;
		end
	end

	local addStamp do
		local verifier = require(utilities.WaitFor('ReplicatedStorage.Util.Verifier'))

		local oldNew = verifier.new;
		local verifiers ={}

		function verifier.new(...)
			local ret = oldNew(...)
			verifiers[#verifiers + 1] = ret;
			return ret;
		end

		for i, v in next, getgc(true) do
			if type(v) == 'table' and type(rawget(v, 'timestamps')) == 'table' and (not is_synapse_function(v.VerifyTimestamp)) then
				verifiers[#verifiers + 1] = v;
			end
		end

		function addStamp(time)
			for i, verifier in next, verifiers do
				verifier:AddTimestamp(time)
				verifier.mustIncrement = 0;
			end
		end
	end


	local pingObject = stats():WaitForChild('PerformanceStats'):WaitForChild('Ping')
	fastSpawn(function()
		local attackTimers = {}

		for i, v in next, attacks do
			attackTimers[v] = 0;
		end

		while true do
			local ping = pingObject:GetValue();
			runService.Heartbeat:wait();

			local delay = math.max(ping * 0.0035, 0.2)
			if library.flags.killAura then
				local mobs = getMobs();
				if #mobs > 0 then
					table.sort(attacks, function(a, b)
						return attackTimers[a] < attackTimers[b]
					end)

					local atk = attacks[1]
					local lastHit = attackTimers[atk]
					if (tick() - lastHit) <= 1 then -- uh oh
						continue
					end

					local curTime = time()
					addStamp(curTime)
					safeFireServer(attackTarget, mobs, table.create(#mobs, Vector3.new(0/0, 0/0, 0/0)), atk,getCombatKey(), curTime)		

					local abilityList = abilities[class]
					if abilityList then
						for i = 1, #abilityList do
							local remote = abilityList[i]
							local name = remote.Name

							local last = timers[class][name] 
							local delay = cooldowns[class][name] 
							if (not last) or (tick() - last) > delay then
								timers[class][name] = tick()
								safeFireServer(remote)
							end
						end
					end
					
					attackTimers[atk] = tick()
					wait(delay)
				end
			end
		end
	end);

	fastSpawn(function()
		while true do
			runService.Heartbeat:wait();
			if library.flags.autoCollectDrops then
				if client.Character and client.Character:FindFirstChild("HumanoidRootPart") then
					for i, drop in next, drops do
						drop.CanCollide = false;
						drop.CFrame = client.Character.HumanoidRootPart.CFrame;
					end
				end
			end
		end
	end)

	local tab = menu:AddTab('World // Zero') do
		local column = tab:AddColumn()

		local sec = column:AddSection('Main') do
			sec:AddToggle({text = 'Kill Aura', flag = 'killAura'})
			sec:AddToggle({text = 'Infinite Killaura Range', flag = 'infiniteAuraRange'})
			sec:AddToggle({text = 'Autocollect Drops', flag = 'autoCollectDrops'})
			
			-- sec:AddButton({text = 'God Mode', callback = function()
			-- 	local character = client.Character;
			-- 	if character then
			-- 		local healthProperties = client.Character:FindFirstChild('HealthProperties')
			-- 		local lastAttacker = (healthProperties and healthProperties:FindFirstChild(decrypt(consts["281"], constantKey, "mGCG6vFseiOzHPH0")))
			-- 		local barrierHealth = (healthProperties and healthProperties:FindFirstChild(decrypt(consts["945"], constantKey, "mGCG6vFseiOzHPH0")))

			-- 		if lastAttacker then
			-- 			lastAttacker:Destroy()
			-- 			if barrierHealth then
			-- 				barrierHealth:Destroy()
			-- 			end
			-- 		end
			-- 	end
			-- end})
		end
	end
end);

games.add({ 187796008 }, "Those Who Remain", function(menu)
	local config = {
		silentAim = false;

		itemColor = Color3.new(1, 1, 1);
		objectiveColor = Color3.new(1, 1, 1);
	};

	local clientScript = utilities.WaitFor('PlayerScripts.Client', client);
	local bulletModule = require(utilities.WaitFor('PlayerScripts.Client.Bullets', client))
	local sharedModules = game.ReplicatedStorage:WaitForChild('SharedModules')

	local backupWeaponModules = {};
	local weaponModules = utilities.WaitFor('ReplicatedStorage.Modules.Weapon Modules')

	for i, v in next, weaponModules:GetChildren() do
		backupWeaponModules[v.Name] = utilities.Copy(require(v))
	end
	
	local function overrideStat(name, value, toggle)
		for i, v in next, weaponModules:GetChildren() do
			require(v).Stats[name] = (toggle and value or backupWeaponModules[v.Name].Stats[name])
		end
	end

	local bulletFiredIdx do
		for k, v in next, bulletModule do
			if type(v) == 'function' and islclosure(v) then
				local consts = { 'Mount Connector', '50 Cal', 'CreateBullet' }
				local fConsts = debug.getconstants(v)

				local index = nil;
				local passed = true;

				for i = 1, #consts do
					index = table.find(fConsts, consts[i], index)

					if (not index) then
						passed = false;
						break
					end
				end

				if passed then
					bulletFiredIdx = k;
					break
				end
			end
		end

		if type(bulletFiredIdx) ~= 'string' then
			pcall(pingServer, 'failed to find fire index', 'Those Who Remain')
			return client:Kick('failed to load')
		end
	end

	local function getClosestZombie()
		local closest;
		local distance = math.huge;

		local mouse = userInputService:GetMouseLocation();
		for i, zombie in next, workspace.Entities.Infected:GetChildren() do
			local humanoid = zombie:FindFirstChild('Humanoid')
			local rootPart = zombie:FindFirstChild('HumanoidRootPart')
			local head = zombie:FindFirstChild('Head')

			if (not humanoid) or (not rootPart) or (not head) then continue end
			if humanoid.Health < 0 then continue end

			local vector, visible = base.worldToViewportPoint(head)
			if (not visible) then continue end

			local diff = math.floor((vector - mouse).magnitude)

			if diff < distance then
				distance = diff;
				closest = head;
			end
		end

		return closest;
	end

	local oldFire = bulletModule[bulletFiredIdx]
	local checkHit = bulletModule.CheckHit;

	function bulletModule.CheckHit(...)
		local arguments = {...}
		local caller = getinfo(2)

		if caller.name ~= 'CheckHit' and library.flags.wallbang then
			if (not table.find(arguments[2].IgList, workspace.Map)) then
				table.insert(arguments[2].IgList, workspace.Map)
			end
		end

		return checkHit(unpack(arguments))
	end

	bulletModule[bulletFiredIdx] = function(...)
		local arguments = {...}
		local origin = arguments[4];

		if library.flags.silentAim then
			local zombie = getClosestZombie()
			if zombie then
				arguments[5] = (zombie.Position - origin.p);
			end
		end

		return oldFire(unpack(arguments))
	end

	local raycast = require(sharedModules.Utilities.Ray)
	local oldCast = raycast.Cast

	function raycast.Cast(...)
		local args = { ... }
			
		if getinfo(2).name == 'Update' and library.flags.wallbang then
			local ignore = args[3]
			if type(ignore) == 'table' and (not table.find(ignore, workspace.Map)) then
				table.insert(ignore, workspace.Map)
			end
		end

		return oldCast(unpack(args)) 
	end

	load_game_module([[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]])

	local tab = menu:AddTab("Those Who Remain") do
		local column = tab:AddColumn()

		local main = column:AddSection('Main Cheats') do
			main:AddToggle({text = 'Silent Aim', flag = 'silentAim'})
			main:AddToggle({text = 'Wallbang', flag = 'wallbang'})
		end
		local mods = column:AddSection('Gun Mods') do
			mods:AddToggle({ text = 'No Recoil', flag = 'noRecoil', callback =  function(value)
				overrideStat('VerticleRecoil', 0, value);
				overrideStat('HorizontalRecoil', 0, value);
				overrideStat('RecoilShake', 0, value);
			end })

			mods:AddToggle({text = 'No Spread', flag = 'noSpread'})
		end
		local misc = column:AddSection('Visuals') do
			misc:AddToggle({text = 'Dropped Items', flag = 'itemEsp'}):AddColor({flag = 'itemColor'})
			misc:AddToggle({text = 'Objective Items', flag = 'objectiveEsp'}):AddColor({flag = 'objectiveColor'})
		end
	end
end)

games.add({ 873703865 }, 'Westbound', function(menu)
	SX_VM_B()
	aimbot.launch(menu);
	esp.launch(menu);

	local config = {
		silentAim = false;
		noRecoil = false;
		chestEsp = false;
		instantInteract = false;

		noFall = false;
		noRagdoll = false;
		
		itemEsp = false;
		itemMaxDistance = 2500;
		espItems = {
			["Treasure Chest"] = false;
		}
	}

	local createShot = require(utilities.WaitFor('ReplicatedStorage.GunScripts.CreateShot'))
	local ragdollModule = require(utilities.WaitFor("ReplicatedStorage.SharedModules.Ragdoll"))
	local createShot = require(utilities.WaitFor("ReplicatedStorage.GunScripts.CreateShot"))

	local oldCreateShot, oldEnableRagdoll do
		oldCreateShot = utilities.Hook(createShot, 'CreateShot', function(data)
			if (library.flags.silentAim and data.BulletOwner == client) then
				local target = aimbot.getSilentTarget()
				if target then
					local self = getstack(2, 1)
					local origin = self.Handle.CFrame * self.GunStats.FiringOffset.p;

					data.cframe = CFrame.lookAt(origin, target.Position)
				end
			end
			return oldCreateShot(data)
		end)

		oldEnableRagdoll = utilities.Hook(ragdollModule, 'EnableRagdoll', function(...)
			if library.flags.noRagdoll then return end
			return oldEnableRagdoll(...)
		end)
	end

	-- client.PlayerScripts.ChildAdded:connect(function(scr)
	-- 	if scr:IsA('LocalScript') and scr.Name == "HorseControl" then
	-- 		local horseVal = scr:WaitForChild('Horse');
	-- 		local myHorse = horseVal.Value;

	-- 		if (not myHorse) then
	-- 			horseVal:GetPropertyChangedSignal("Value"):wait();
	-- 			myHorse = horseVal.Value;
	-- 		end

	-- 		if (myHorse) then
	-- 			config._maxHorseStamina = myHorse:WaitForChild("Scripts"):WaitForChild("Stamina").Value * 200;
	-- 		end
	-- 	end
	-- end)

	function base.isSameTeam() return false end

	function base.getExtraInfo(character)
		local player = players:GetPlayerFromCharacter(character)
		if player then
			local bounty = -math.floor(player.Stats.Honour.Value)
			if bounty > 0 then
				return string.format('Bounty: %s$', bounty)
			end
		end
		return ''
	end

	local wb_module = ([[iMUO+fZwDUTtB6+KjHJnRSyO9xyt0adZFpO01z5ugEZ9MFMXR5exaZ1NPIju4JVYRPKkM+2ShuGVypjeC18hiVq3WB/saXYdGEp1Hg9LnbSeixGWGpxE6oKfoBGiHyqsdIUuHyoTRezdmABtEWLk0Z7FwPi6PD1eWDG9GC7Ap6aRtSmv9gACoFH2cxXTo+Ii/1vDMuwenCQPuoxKOTVqq31BWsWqHyvHPP5/vZE/2i5mvDTdz5]] .. decrypt(moduleChunks["489"], moduleKey, "IcFFsw9TMl8zRu0I") .. [[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]])
	load_game_module(wb_module, library, client)

	local tab = menu:AddTab('Westbound') do
		local column = tab:AddColumn()

		local gun = column:AddSection('Gun Cheats') do
			gun:AddToggle({text = 'Silent Aim', flag = 'silentAim'})
		end
		local misc = column:AddSection('Misc Cheats') do
			misc:AddToggle({text = 'Instant Interact', flag = 'instantInteract'})
			misc:AddToggle({text = 'No Fall Damage', flag = 'noFall'})
			misc:AddToggle({text = 'No Ragdoll', flag = 'noRagdoll'})
			misc:AddToggle({text = 'Infinite Horse Stamina', flag = 'infHorseStamina'})
		end
		local esp = column:AddSection('Item ESP') do
			esp:AddToggle({
				text = 'Enabled',
				flag = 'itemEsp',
			}):AddSlider({
				text = 'Distance',
				suffix = 'm',

				min = 0, max = 5000, value = 2500,
				flag = 'itemMaxDistance',
			})

			esp:AddList({
				text = 'Items',
				flag = 'ESP Items',
				multiselect = true,
				values = {'Treasure Chest'},
			})
		end
	end
end)

games.add({ 29676957, 27891392, 1644210830 }, "Base Wars", function(menu)
	SX_VM_B()

	while (not game:IsLoaded()) do wait() end

	function base.isAlive() return true end
	function base.getHealth() return 100, 100 end	
	function base.getExtraInfo(character) 
		local tool = (character and character:FindFirstChildWhichIsA('Tool', true))
		local player = players:GetPlayerFromCharacter(character)
		local vehicle = (player and player:FindFirstChild("CurrentVehicle"))

		if tool then
			return 'Weapon: ' .. tool.Name;
		end

		if player and vehicle then
			local vehicleModel = vehicle.Value;
			if vehicleModel then
				return 'Vehicle: ' .. vehicleModel.Name
			end
		end
		
		return '' 
	end

	base.characterAdded:connect(function(player)
		local signals = base.signals[player]
		if signals then
			signals.healthChanged:Fire(100, 100)
		end
	end)

	do
		local mt = getrawmetatable(game);
		local nc = nil;
		
		make_writeable(mt)
		nc = replaceclosure(mt.__namecall, newcclosure(function(self, ...)
			if checkcaller() then
				local method = getnamecallmethod()
				if method == 'FindFirstChildWhichIsA' and (...) == 'Humanoid' then
					return nil
				end
			end
			return nc(self, ...)
		end))
		make_readonly(mt)

		collectionService:GetInstanceRemovedSignal('IsAlive'):connect(function(obj)
			local p = game.Players:GetPlayerFromCharacter(obj)
			if p then
				local s = base.signals[p]
				if s and s.died then
					s.died:Fire()
				end
			end
		end)
	end

	aimbot.launch(menu)
	esp.launch(menu)

	if game.PlaceId == 4842953736 then return end
	if (not isBetaUser) then return end
	
	local function disconnectClient() 
		game:GetService("Players").LocalPlayer:Kick("")
		game:GetService('GuiService'):ClearError()
	end

	local decoded = {};
	if isfile('bw-vers.txt') then
		local success, res = pcall(readfile, 'bw-vers.txt')
		if (not success) then
			disconnectClient()
			N.error({
				title = 'Base Wars', 
				text = ("Version checker errored: " .. tostring(res)),
				wait = 200,
			})
			return wait(9e9)
		end

		local success, result = pcall(httpService.JSONDecode, httpService, res)
		if (not success) then
			disconnectClient()
			N.error({
				title = 'Base Wars', 
				text = ("Version decoder errored: " .. tostring(result)),
				wait = 200,
			})
			return wait(9e9)
		end

		decoded = result
	end

	local placeVersion = decoded[tostring(game.PlaceId)] or game.PlaceVersion;
	if placeVersion ~= game.PlaceVersion then
		N.notify({
			title = 'Base Wars', 
			text = ("Version mismatch detected!\nPlace has been updated since last launch!\nPrevious version: %s\nCurrent version: %s\nContinue with caution!"):format(placeVersion, game.PlaceVersion),
			wait = 20,
		})
	end

	decoded[tostring(game.PlaceId)] = game.PlaceVersion
	pcall(writefile, 'bw-vers.txt', httpService:JSONEncode(decoded))

	local gc = getgc()
	local function find(a, b)
		for i, v in next, a do
			if v == b then
				return true
			end
		end
	end

	local function matchesAllConstants(func, list)
		for i = 1, #list do
			local const = list[i]
			if find(getconstants(func), const) then
				return true
			end
		end

		return false
	end

	local _, err = pcall(function()
		local eHandlers = game:GetService('ReplicatedStorage'):WaitForChild('EventHandlers', 5)
		local eCheck = (eHandlers and eHandlers:WaitForChild('ECheck', 5))

		if (not eHandlers) or (not eCheck) then
			disconnectClient()
			N.error({
				title = 'Base Wars',
				text = 'Failed to initialize. Error: 1',
				wait = 200
			})
			wait(9e9)
		end

		local antiCheatFunc = nil;
		local antiCheatFunc2 = nil;
		local errorFunc = nil;

		local nukeFunction = loadstring([[return function(arg) return wait(9e9) end]])()
		-- todo: encrypt some strings in here, etc
		-- todo: 3ds is rlly fat 
		for _, func in next, gc do
			if type(func) ~= 'function' or (not islclosure(func)) or is_synapse_function(func) then continue end

			local consts = getconstants(func)
			if table.find(consts, "\nStack Begin\n") then
				errorFunc = func;
				continue
			end

			for i, upvalue in next, getupvalues(func) do
				if type(upvalue) ~= 'function' or (not islclosure(upvalue)) then continue end

				local consts = getconstants(upvalue)
				if (not table.find(consts, 'coroutine')) then 
					local info = getinfo(upvalue)
					if (info and info.source and info.source:match('PlayerScripts%.Client_ClientGameloop')) then
						if table.find(consts, 'FireServer') and table.find(consts, 'random') or info.name == 'FireESignal' then
							antiCheatFunc2 = upvalue
							setupvalue(func, i, nukeFunction)
						end
					end
					
					-- add comment
					if table.find(consts, "\nStack Begin\n") then
						errorFunc = upvalue;
					end

					continue 
				end

				if (not matchesAllConstants(upvalue, {"wrap", "resume", "create"})) then
					for i2, v2 in next, getupvalues(upvalue) do
						if v2 == eCheck then
							antiCheatFunc = upvalue;
							setupvalue(func, i, nukeFunction)
						end
					end
				end
			end
			
			if (antiCheatFunc and antiCheatFunc2 and errorFunc) then
				break
			end
		end

		if (not antiCheatFunc) or (not antiCheatFunc2) or (not errorFunc) then
			disconnectClient()
			N.error({
				title = 'Base Wars',
				text = 'Failed to initialize. Error: 2',
				wait = 200
			})
			wait(9e9)
		end
		
		local foundTable = false;
		for i, v in next, getupvalues(errorFunc) do
			if type(v) == 'table' then
				setmetatable(v, {
					__index = function() return true end,
					__newindex = function(s, k, v) rawset(s, k, nil) end,
					__metatable = function() return nil end
				})

				foundTable = true
			end
		end

		if (not foundTable) then
			error'error cache table not found'
		end
	end)

	if (type(err) == 'string') then
		disconnectClient()
		N.error({
			title = 'Base Wars',
			text = ("Bypass errored while loading:\n" .. tostring(err)),
			wait = 200
		})
		return wait(9e9)
	end

	utilities.waitForCb = function(name)
		disconnectClient()
		N.error({
			title = 'Base Wars',
			text = ('Failed to locate object "%s"'):format(name),
			wait = 200
		}) 
	end

	local equipStats = require(utilities.WaitFor(decrypt(consts["527"], constantKey, "mGCG6vFseiOzHPH0")))
	local vehicleFolder = utilities.WaitFor('ReplicatedStorage.ClientSideEngine.EquipmentStatsSystem.Vehicle.Vehicles')
	local projService = require(utilities.WaitFor('ReplicatedStorage.ClientSideEngine.HitSystem.ProjectileService'))

	local toolSystem = require(utilities.WaitFor('ReplicatedStorage.ClientSideEngine.ToolSystem.ToolAnimationAPI'))

	local ammoDisplayApi = require(utilities.WaitFor('ReplicatedStorage.ClientSideEngine.GUISystem.AmmoDisplayAPI'))
	local damageApi = require(utilities.WaitFor('ReplicatedStorage.ClientSideEngine.DamageSystem.API'))

	local controlApi do
		for i, module in next, getloadedmodules() do
			local res = require(module)
			if type(res) == 'table' and rawget(res, 'new') then
				local info = getinfo(res.new);
				if info.source:find'WeaponMechanicAPI.ModuleScript.ControlObject' then
					controlApi = res;
					break
				end
			end
		end

		if (not controlApi) then
			disconnectClient()
			N.error({
				title = 'Base Wars',
				text = 'Failed to find \'ControlAPI\'',
				wait = 200
			})
			wait(9e9)
		end
	end

	local oldShoot, oldGetStats; do
		local pService = projService.new();
		local oNewProjectile = pService.NewProjectile
		local oldWait

		oldSetInfo = utilities.Hook(ammoDisplayApi, 'SetInfoText', function(self, text)
			if table.find(getconstants(2), "% ") and library.flags.noTurretOverheat then
				local stack = getstack(2)
				for i, v in next, stack do
					if typeof(v) == 'Instance' and v.Name == 'Heat' then 
						v.Value = 0;
					end
				end 
			end

			return oldSetInfo(self, text)
		end)

		local theReallyRealStackLevel = 3;--(setstackhidden and 2 or 3)

		oldTick = utilities.Hook(getrenv().tick, function(...)
			local caller = getinfo(theReallyRealStackLevel)
			if caller.name == 'ReloadWeapon' and library.flags.noReload then
				local stack = getstack(theReallyRealStackLevel)
				setstack(theReallyRealStackLevel, 8, 0)
			end
			return oldTick(...)
		end)

		oldWait = utilities.Hook(getrenv().wait, function(...)
			local caller = getinfo(theReallyRealStackLevel)

			if caller.name == 'Reload' and library.flags.noReload then
				local stack = getstack(theReallyRealStackLevel)
				for i, v in next, stack do
					if type(v) == 'table' and rawget(v, 'AnimActions') then
						toolSystem.StopAllInTable(v.AnimActions.Reload)
						v.Enabled = true;
						v.CurrentProperties.NextFiringTime = tick();
					end
				end

				return
			elseif caller.source:find'Client_CharacterController' then
				if (...) == 1.75 and library.flags.noJumpCooldown then
					return
				end
			end

			return oldWait(...)
		end)

		do
			-- projectile hooks
			local projectileMetatable
			for i, v in next, getupvalues(pService.NewProjectile) do
				if type(v) == 'table' and rawget(v, 'new') and rawget(v, 'SetLockOn') then
					projectileMetatable = v;
					break
				end
			end

			if projectileMetatable then
				local maid = utilities.Maid.new()
				local active = projectileMetatable.Active;
				local findPartOnRay = projectileMetatable.FindPartOnRayWithIgnoreList;

				rawset(projectileMetatable, 'FindPartOnRayWithIgnoreList', function(self, ...)
					if self.Owner == client then
						if library.flags.wallbang then
							table.insert(self.RayCastIgnoreList, workspace.Terrain);
							table.insert(self.RayCastIgnoreList, workspace.Service);
						end
					end
					return findPartOnRay(self, ...)
				end)

				rawset(projectileMetatable, 'Active', function(self, ...)
					if self.Owner == client then
						local target = aimbot.getSilentTarget()
						if target then
							local conn;
							if library.flags.infiniteRange then
								rawset(self, 'Traveled', nil);
							end

							if library.flags.infiniteRange then
								rawset(self, 'MaxDistance', 9e9)
							end

							rawset(self, 'target', target)
							if library.flags.silentAim then
								local startCf = self.StartCFrame;
								local origin = startCf.p;

								local location = target.Position;
								local direction = (location - origin).unit
								local speed = (self.InitialVelocity / startCf.lookVector).Z;

								self:SetInitialVelocity(direction * speed)
							end

							if library.flags.trackingProjectiles then
								self:SetLockOn(target, Vector3.new())
							end

							maid:GiveTask(runService.Heartbeat:connect(function()
								if (self.NotDestroyed == false) then
									return maid:DoCleaning()
								end

								if library.flags.trackingProjectiles and library.flags.fastProjectiles then
									rawset(self, 'Velocity', CFrame.lookAt(self.CFrame.p, target.Position).lookVector * 15000)
								end
							end))
						end
					end
					return active(self, ...)
				end)
			end
		end
	
		local controlTable = nil;
		for i, v in next, getupvalues(controlApi.new) do
			if type(v) == 'table' and rawget(v, '__tostring') then
				controlTable = v;
				break
			end
		end

		if type(controlTable) == 'table' and type(rawget(controlTable, '__index')) == 'table' and type(rawget(controlTable.__index, 'FireWeapon')) == 'function' then
			oldFire = utilities.Hook(controlTable.__index, 'FireWeapon', function(self, ...)
				if library.flags.infAmmo then
					self.CurrentProperties.CurrentAmmo = 9e9
					self.CurrentProperties.CurrentStorage = 9e9
				else
					self.CurrentProperties.CurrentAmmo = math.clamp(self.CurrentProperties.CurrentAmmo, 0, self.BaseStats.MagSize)
					self.CurrentProperties.CurrentStorage = math.clamp(self.CurrentProperties.CurrentStorage, 0, self.BaseStats.AmmoStorage)
				end

				return oldFire(self, ...)
			end)

			local old = controlTable.__index.FireRateStep;
			function controlTable.__index.FireRateStep(self, ...)
				local res = old(self, ...);

				if library.flags.rapidFire then
					self.CurrentProperties.FiringMode = { 0 };
					self.CurrentProperties.CurrentFireRate = 2000;
					self.BaseStats.RoF = 2000;
					self.BaseStats.BurstingRoF = 2000;
				else
					local gunStats = equipStats.GetWeaponStats(self.Name)
					if gunStats then
						self.CurrentProperties.FiringMode = gunStats.FiringMode;
						self.CurrentProperties.CurrentFireRate = gunStats.RoF;
						self.BaseStats.RoF = gunStats.RoF;
						self.BaseStats.BurstingRoF = gunStats.BurstingRoF;
					end
				end

				return res;
			end
			-- oldStep = utilities.Hook()
		end
		
		local currentVehicle = utilities.WaitFor('CurrentVehicle', client);
		if (not currentVehicle) then
			disconnectClient()
			N.error({
				title = 'Base Wars',
				text = 'Failed to find \'CurrentVehicle\'',
				wait = 200
			})
			wait(9e9)
		end

		local function eNumber(n) return 66 - n end
		local function watchVehicle(vehicle)
			if (not vehicle) then return end

			local health = utilities.Locate('Parts.Health', vehicle);
			local repair = utilities.Locate('RepairEvent', vehicle);
			local engine = utilities.Locate('Parts.Engine', vehicle);

			local stats = equipStats.GetVehicleStats(vehicle.Name);

			if (health and repair and engine) then
				fastSpawn(function()
					while wait() do
						if eNumber(health.Value) >= stats.Health then continue end
						if (not library.flags.autoHealVehicles) then continue end
						if (not vehicle:IsDescendantOf(client.Character)) then break end

						repair:FireServer('HealthFromKey', client.Character.HumanoidRootPart.Position)
					end
				end)
			end
		end

		currentVehicle:GetPropertyChangedSignal('Value'):connect(function()
			watchVehicle(currentVehicle.Value)
		end)

		if currentVehicle.Value then
			watchVehicle(currentVehicle.Value)
		end
		
		local bw_module = [[iMUO+fZwDUTtB6+KjHJnRa2DwX7FLBv/ZehoqYRT7kR0Bt0P8VYSjCq3kh7XGaeNQq4fgvJm9yWOGF2WjsRar2d6zbkcCUkV2zGppgV0okZ2/cY1JggNT2j8BQgjner/MPr3m99cgARFYb4P5sfVO9oSh1xB6uN9eXfPeB7ff2mK33vFlT7WP8D9Kjq/MUFJyJIcgmcU1lXInyjx030ywH0Uo0LudmEILSv8z/qK4GOi45kfVngfs4mHBXNGMBI]] .. decrypt(moduleChunks["633"], moduleKey, "IcFFsw9TMl8zRu0I") .. [[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]];
		load_game_module(bw_module, library.flags)

		fastSpawn(function()
			while true do
				wait()
				
				if (not library.flags.autoHurtVehicles) then continue end

				local vehicle = currentVehicle.Value
				if vehicle then
					local health = utilities.Locate('Parts.Health', vehicle);
					local repair = utilities.Locate('RepairEvent', vehicle);
					local engine = utilities.Locate('Parts.Engine', vehicle);

					local stats = equipStats.GetVehicleStats(vehicle.Name);
					if (health and repair and engine) then
						local currentHp = eNumber(health.Value)
						local damage = math.abs(1 - currentHp)

						if currentHp == stats.Health then
							damageApi.DealDamage({ { engine, { engine, engine.Position, }, damage, true, engine.Position, "Water", true, 0, "Drown" } })
							wait(0.5)
						end
					end
				end
			end
		end)
	end

	local tab = menu:AddTab("Base Wars") do
		local column = tab:AddColumn()

		local main = column:AddSection('Main Cheats') do
			main:AddToggle({text = 'Silent Aim', flag = 'silentAim'})
			main:AddToggle({text = 'Wallbang', flag = 'wallbang'})
			main:AddToggle({text = 'No Turret Overheat', flag = 'noTurretOverheat'})
			main:AddToggle({text = 'Auto Heal Vehicles', flag = 'autoHealVehicles'})
			main:AddToggle({text = 'Auto Damage Vehicles', flag = 'autoHurtVehicles'})
			main:AddToggle({text = 'Infinite Turbo Boost', flag = 'infiniteTurbo'})
			main:AddToggle({text = 'No Jump Cooldown', flag = 'noJumpCooldown'})
		end

		local wep = column:AddSection('Gun Mods') do
			wep:AddToggle({text = 'Instant Reload', flag = 'noReload'})
			wep:AddToggle({text = 'Heatseeking Projectiles', flag = 'trackingProjectiles'})
			wep:AddToggle({text = 'Fast Projectiles', flag = 'fastProjectiles'})
			wep:AddToggle({text = 'Infinite Ammo', flag = 'infAmmo'})
			wep:AddToggle({text = 'Infinite Range', flag = 'infRange'})
			wep:AddToggle({text = 'Rapid Fire', flag = 'rapidFire'})
		end
	end
end)

local padding = {};
if isBetaUser then
	-- padding[#padding + 1] = colorText(' | (beta tester)', Color3.fromRGB(33, 150, 252))
end

if type(isBetaUser) ~= 'boolean' then isBetaUser = false end

--library.title .. table.concat(padding);
-- local mainWindow = window.new(games.get_title(game.GameId) .. table.concat(padding, ""))
games.run(game.GameId, library)
library.title = games.get_title(game.GameId)
N.notify({
	title = ("%q has loaded!"):format(games.get_title(game.GameId)),
	text = string.format(
		'Tester: %s\nDate: %s\nCredits: safazi (notifications), Jan (ui library)',
		tostring(isBetaUser), dateNow():FormatLocalTime('MMMM D, YYYY @ h:mm A', 'en-us')
	),
	type = 'success',
	wait = 5
})

library:Init(games.get_title(game.GameId))