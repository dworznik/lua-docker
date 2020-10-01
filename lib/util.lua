-- https://github.com/daurnimator/lua-http/blob/master/http/util.lua

-- decodeURIComponent unescapes *all* url encoded characters
local function decodeURIComponent(str)
  return (str:gsub("%%(%x%x)", pchar_to_char))
end

-- An iterator over query segments (delimited by "&") as key/value pairs
-- if a query segment has no '=', the value will be `nil`
local function query_args(str)
  local iter, state, first = str:gmatch("([^=&]+)(=?)([^&]*)&?")
  return function(state, last) -- luacheck: ignore 431
    local name, equals, value = iter(state, last)
    if name == nil then return nil end
    name = decodeURIComponent(name)
    if equals == "" then
      value = nil
    else
      value = decodeURIComponent(value)
    end
    return name, value
  end, state, first
end

-- Converts a dictionary (string keys, string values) to an encoded query string
local function dict_to_query(form)
  local r, i = {}, 0
  for name, value in pairs(form) do
    i = i + 1
    r[i] = encodeURIComponent(name).."="..encodeURIComponent(value)
  end
  return table.concat(r, "&", 1, i)
end
