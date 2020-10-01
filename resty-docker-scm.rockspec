package = "resty-docker"

version = "scm"

source = {
  url = "git://github.com/dworznik/lua-resty-docker"
}

description = {
  summary = "Docker API wrapper",
  detailed = [[
    This module allows you to manage a Docker Engine
    by writing Lua code. You can do pretty much all
    the things you could do with the docker command-line
    tool.
    https://github.com/rokf/lua-docker modified to work in nginx environment with resty-http
  ]],
  homepage = "https://github.com/dworznik/lua-resty-docker",
  license = "MIT"
}

dependencies = {
  "lua >= 5.1",
  "cjson",
  "basexx",
  ""
}

build = {
  type = "builtin",
  modules = {
    docker = "code/docker.lua"
  }
}
