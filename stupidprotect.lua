
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
        elseif two == "[[" or two:match("%[%=+") then

            local start_i = i

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
            -- normal string literal
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
    {pat = "io%.popen%s*%(", name = "io.popen (spawn subprocess)"},
    {pat = "os%.remove%s*%(", name = "os.remove (filesystem deletion)"},
    {pat = "io%.open%s*%(", name = "io.open (file I/O)"},
    {pat = "writefile%s*%(", name = "writefile (exploit-specific file write)"},
    {pat = "readfile%s*%(", name = "readfile (exploit-specific file read)"},
    {pat = "loadstring%s*%(", name = "loadstring (dynamic code execution)"},
    {pat = "load%s*%(", name = "load (dynamic code execution)"},
    {pat = "require%s*%(%s*['\"]?http?['\"]?%s*%)", name = "require('http') (HTTP lib require)"},
    {pat = "game:GetService%s*%(%s*['\"]HttpService['\"]%s*%)", name = "game:GetService('HttpService') (HTTP access)"},
    {pat = "syn%.request%s*%(", name = "syn.request (exploit remote request)"},
    {pat = "require%s*%(%s*['\"]?syn['\"]?%s*%)", name = "require('syn') (exploit/syn libs)"},
    {pat = "socket%.http", name = "socket.http (LuaSocket HTTP)"},
    {pat = "os%.exit%s*%(", name = "os.exit (terminate process)"},
}

local function report_match(filename, lineno, line, check)
    io.write(string.format("%s:%d: %s\n", filename, lineno, check.name))
    io.write("  matched pattern: " .. check.pat .. "\n")
    local trimmed = line:gsub("^%s+", ""):gsub("%s+$", "")
    if #trimmed > 200 then trimmed = trimmed:sub(1,200) .. "…" end
    io.write("  code: " .. trimmed .. "\n\n")
end


local function static_check_file(path)
    local src, err = read_file(path)
    if not src then
        io.stderr:write("static_check_file: failed to read " .. tostring(path) .. " : " .. tostring(err) .. "\n")
        return false, "read_error"
    end

    local cleaned = strip_strings_and_comments(src)

    local issues = {}
    local lineno = 0

    for line in src:gmatch("([^\n]*)\n?") do
        lineno = lineno + 1

        local cleaned_line = cleaned:match("([^\n]*)\n?") -- placeholder; we'll slice per line below
    end


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
    for _, it in ipairs(issues) do
        report_match(it.file, it.line, it.code, it.check)
    end
    io.write("Action: fix or whitelist the listed occurrences.\n")
    return false
end

