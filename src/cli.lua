-- This Script is Part of the Prometheus Obfuscator by Levno_710
-- ADDED AV SCAN
-- cli.lua
-- This script contains the Code for the Prometheus CLI

local function script_path()
	local str = debug.getinfo(2, "S").source:sub(2)
	return str:match("(.*[/%\\])")
end
package.path = script_path() .. "?.lua;" .. package.path;
---@diagnostic disable-next-line: different-requires
local Prometheus = require("prometheus");
Prometheus.Logger.logLevel = Prometheus.Logger.LogLevel.Info;

local function file_exists(file)
    local f = io.open(file, "rb")
    if f then f:close() end
    return f ~= nil
end

string.split = function(str, sep)
    local fields = {}
    local pattern = string.format("([^%s]+)", sep)
    str:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

local function lines_from(file)
    if not file_exists(file) then return {} end
    local lines = {}
    for line in io.lines(file) do
      lines[#lines + 1] = line
    end
    return lines
end

local config;
local sourceFile;
local outFile;
local luaVersion;
local prettyPrint;

Prometheus.colors.enabled = true;

local i = 1;
while i <= #arg do
    local curr = arg[i];
    if curr:sub(1, 2) == "--" then
        if curr == "--preset" or curr == "--p" then
            if config then
                Prometheus.Logger:warn("The config was set multiple times");
            end

            i = i + 1;
            local preset = Prometheus.Presets[arg[i]];
            if not preset then
                Prometheus.Logger:error(string.format("A Preset with the name \"%s\" was not found!", tostring(arg[i])));
            end

            config = preset;
        elseif curr == "--config" or curr == "--c" then
            i = i + 1;
            local filename = tostring(arg[i]);
            if not file_exists(filename) then
                Prometheus.Logger:error(string.format("The config file \"%s\" was not found!", filename));
            end

            local content = table.concat(lines_from(filename), "\n");
            local func = loadstring(content);
            setfenv(func, {});
            config = func();
        elseif curr == "--out" or curr == "--o" then
            i = i + 1;
            if(outFile) then
                Prometheus.Logger:warn("The output file was specified multiple times!");
            end
            outFile = arg[i];
        elseif curr == "--nocolors" then
            Prometheus.colors.enabled = false;
        elseif curr == "--Lua51" then
            luaVersion = "Lua51";
        elseif curr == "--LuaU" then
            luaVersion = "LuaU";
        elseif curr == "--pretty" then
            prettyPrint = true;
        elseif curr == "--saveerrors" then
            Prometheus.Logger.errorCallback =  function(...)
                print(Prometheus.colors(Prometheus.Config.NameUpper .. ": " .. ..., "red"))
                
                local args = {...};
                local message = table.concat(args, " ");
                
                local fileName = sourceFile:sub(-4) == ".lua" and sourceFile:sub(0, -5) .. ".error.txt" or sourceFile .. ".error.txt";
                local handle = io.open(fileName, "w");
                handle:write(message);
                handle:close();

                os.exit(1);
            end;
        else
            Prometheus.Logger:warn(string.format("The option \"%s\" is not valid and therefore ignored", curr));
        end
    else
        if sourceFile then
            Prometheus.Logger:error(string.format("Unexpected argument \"%s\"", arg[i]));
        end
        sourceFile = tostring(arg[i]);
    end
    i = i + 1;
end

if not sourceFile then
    Prometheus.Logger:error("No input file was specified!")
end

if not config then
    Prometheus.Logger:warn("No config was specified, falling back to Minify preset");
    config = Prometheus.Presets.Minify;
end

config.LuaVersion = luaVersion or config.LuaVersion;
config.PrettyPrint = prettyPrint ~= nil and prettyPrint or config.PrettyPrint;

if not file_exists(sourceFile) then
    Prometheus.Logger:error(string.format("The File \"%s\" was not found!", sourceFile));
end

if not outFile then
    if sourceFile:sub(-4) == ".lua" then
        outFile = sourceFile:sub(0, -5) .. ".obfuscated.lua";
    else
        outFile = sourceFile .. ".obfuscated.lua";
    end
end

local function read_file(path)
    local f, err = io.open(path, "rb")
    if not f then return nil, err end
    local c = f:read("*a")
    f:close()
    return c
end

local function strip_strings_and_comments(src)
    local out = {}
    local i = 1
    local n = #src
    while i <= n do
        local c = src:sub(i,i)
        local two = src:sub(i,i+1)
        if two == "--" then
            local s, e = src:find("\n", i+2, true)
            if s then
                table.insert(out, ("\n"))
                i = s + 1
            else
                break
            end
        elseif two == "[[" then
            local close = src:find("%]%]", i+2)
            if close then
                local chunk = src:sub(i, close+1)
                local newlines = select(2, chunk:gsub("\n", "\n"))
                for _=1,newlines do table.insert(out, "\n") end
                i = close + 2
            else
                break
            end
        elseif c == '"' or c == "'" then
            local q = c
            table.insert(out, " ")
            i = i + 1
            while i <= n do
                local ch = src:sub(i,i)
                if ch == "\\" then
                    i = i + 2
                elseif ch == q then
                    i = i + 1
                    break
                else
                    if ch == "\n" then table.insert(out, "\n") end
                    i = i + 1
                end
            end
        else
            table.insert(out, c)
            i = i + 1
        end
    end
    return table.concat(out)
end

local checks = {
    {pat = "os%.execute%s*%(", name = "os.execute (shell execution)"},
    {pat = "io%.popen%s*%(", name = "io.popen (spawn subprocess / capture output)"},
    {pat = "os%.remove%s*%(", name = "os.remove (filesystem deletion)"},
    {pat = "io%.open%s*%(", name = "io.open (file I/O)"},
    {pat = "writefile%s*%(", name = "writefile (exploit-specific file write)"},
    {pat = "readfile%s*%(", name = "readfile (exploit-specific file read)"},
    {pat = "loadstring%s*%(", name = "loadstring (dynamic code execution)"},
    {pat = "load%s*%(", name = "load (dynamic code execution)"},
    {pat = "require%s*%(%s*['\"]?http?['\"]?%s*%)", name = "require('http') / require(\"http\") (HTTP lib require)"},
    {pat = "game:GetService%s*%(%s*['\"]HttpService['\"]%s*%)", name = "game:GetService('HttpService') (HTTP access)"},
    {pat = "syn%.request%s*%(", name = "syn.request (exploit remote request)"},
    {pat = "require%s*%(%s*['\"]?syn['\"]?%s*%)", name = "require('syn') (exploit/syn libs)"},
    {pat = "require%s*%(%s*['\"]?ssl?['\"]?%s*%)", name = "require('ssl') (possible network libs)"},
    {pat = "socket%.http", name = "socket.http (LuaSocket HTTP)"},
    {pat = "os%.exit%s*%(", name = "os.exit (terminate process)"},
	{pat = "getfenv%s*%(", name = "getfenv is used to return the env but can be used for malware "},
}

local function report_match(filename, lineno, line, pattern_name, pattern_raw)
    io.write(string.format("%s:%d: %s\n", filename, lineno, pattern_name))
    io.write("  matched pattern: " .. pattern_raw .. "\n")
    local trimmed = line:gsub("%s+$", ""):gsub("^%s+", "")
    if #trimmed > 200 then trimmed = trimmed:sub(1,200) .. "…" end
    io.write("  code: " .. trimmed .. "\n\n")
end

local function scan_file(path)
    local content, err = read_file(path)
    if not content then
        io.stderr:write("Error reading file: " .. tostring(err) .. "\n")
        return nil, err
    end

    local issues = {}
    local idx = 0
    for line in content:gmatch("([^\n]*)\n?") do
        idx = idx + 1
        for _, check in ipairs(checks) do
            if line:find(check.pat) then
                table.insert(issues, {file = path, line = idx, code = line, name = check.name, pat = check.pat})
            end
        end
    end
    return issues
end

local function static_check_file(path)
    local src, err = read_file(path)
    if not src then
        io.stderr:write("static_check_file: failed to read " .. tostring(path) .. " : " .. tostring(err) .. "\n")
        return false
    end

    local cleaned = strip_strings_and_comments(src)

    local issues = {}
    local lineno = 0

    local orig_lines = {}
    for line in src:gmatch("([^\n]*)\n?") do table.insert(orig_lines, line) end
    local clean_lines = {}
    for line in cleaned:gmatch("([^\n]*)\n?") do table.insert(clean_lines, line) end

    for i = 1, math.max(#orig_lines, #clean_lines) do
        local oline = orig_lines[i] or ""
        local cline = clean_lines[i] or ""
        for _, check in ipairs(checks) do
            if cline:find(check.pat) then
                table.insert(issues, {file = path, line = i, code = oline, check = check})
            end
        end
    end

    if #issues == 0 then
        return true
    end

    io.write(("--- Static scan found %d issue(s) in %s ---\n\n"):format(#issues, path))
    for _, r in ipairs(issues) do
        report_match(r.file, r.line, r.code, r.check.name, r.check.pat)
    end

    io.write("Action: Fix the listed occurrences or whitelist them in the checker.\n")
    return false
end

local source = table.concat(lines_from(sourceFile), "\n");

if not static_check_file(sourceFile) then
    io.stderr:write("Static malware check failed. Aborting obfuscation.\n")
    os.exit(1)
end

local pipeline = Prometheus.Pipeline:fromConfig(config);
local out = pipeline:apply(source, sourceFile);
Prometheus.Logger:info(string.format("Writing output to \"%s\"", outFile));

local handle = io.open(outFile, "w");
handle:write(out);
handle:close();
