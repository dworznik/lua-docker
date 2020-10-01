local http = require 'resty.http'
local util = require 'util'

local cjson = require 'cjson.safe'
local basexx = require 'basexx'


local handle_response_body = function (body)
  if type(body) == 'string' then
    local res = cjson.decode(body)
    return res ~= nil and res or body
  else
    return nil
  end
end

local validate_instance = function (instance)
  if type(instance) ~= 'table' then
    return nil, "not a table"
  end

  if instance.host == nil then
    return nil, "missing host"
  end

  if instance.path == nil then
    return nil, "missing path"
  end

  if instance.version == nil then
    return nil, "missing version"
  end

  return true
end

local perform_request = function (instance, method, endpoint, query, authority, body)
  local response_body
  local response_headers
  local err, errn
  local wh_failure, wb_failure
  local connection, stream
  local instance_check

  local httpc = http.new()

  local log = ngx.log
  local ERR = ngx.ERR

  instance_check, err = validate_instance(instance)

  if instance_check == nil then
    return instance_check, err
  end

  if endpoint == nil then
    return endpoint, "endpoint not defined"
  end

  if type(endpoint) ~= 'string' then
    return nil, "endpoint should be a string"
  end

  local ok, err = httpc:connect("unix:" .. instance.path)

  -- error while making connection

  if err then
    log(ERR, 'dupa')
    return nil, err, nil
  end

  local path = string.format(
    '/%s%s%s',
    instance.version,
    endpoint,
    (type(query) == 'table') and '?' .. util.dict_to_query(query) or '')

  local headers = {}
  headers['content-type'] = body and 'application/json' or 'text/plain'
  headers['user-agent'] = 'lua-docker'
  headers['host'] = 'docker'

  -- docker uses a custom authority header

  if authority then
    local json_authority, e = cjson.encode(authority)
    if json_authority == nil then
      return nil, e, nil
    end
    local base64_encoded_authority = basexx.to_base64(json_authority)
    headers['X-Registry-Auth'] = base64_encoded_authority
  end

  local encoded_body, e

  if body ~= nil then
    if type(body) == 'table' then
      encoded_body, e = cjson.encode(body)
      if encoded_body == nil then
        return nil, e, nil
      end
    else
      encoded_body = tostring(body)
    end
    headers['content-length'] = tostring(#encoded_body)
  end


  local res, err = httpc:request {
    method = method,
    path = path,
    headers = headers,
    body = encoded_body
  }

  local res_status, res_body, res_headers
  if res then
    res_status = res.status
    res_body = res:read_body()
    res_headers = res.headers
  end

  log(ERR, 'status: ' .. res_status)

  if err then
    if res then
      return res_body, err, res_status
    end
  end

  -- successfull response
  log(ERR, res_body)
  return {
    body = res_body,
    headers = res_headers,
    status = status
  }
end

local loop_through_entity_endpoints = function (endpoint_data, group, target_table)
  for k, v in pairs(endpoint_data) do
    target_table[k] = function (self, name_or_id, query, authority, body)
      return perform_request(
        self, v.method,
        string.format(
          '/%s/%s%s', group, name_or_id,
          v.endpoint and ('/' .. v.endpoint) or ''
        ),
        query,
        authority,
        body
      )
    end
  end
end

-- @todo handle streaming responses
-- example: functions which return logs
-- also provide a streaming variant
-- those endpoints have a bool follow
-- query parameter set to true

return {
  new = function (host, path, version)
    local d = {
      host = host or 'localhost',
      path = path or '/var/run/docker.sock',
      version = version or 'v1.38',

      custom = perform_request,

      get_version = function (self)
        print('dupa')
        return perform_request(self, 'GET', '/version')
      end,

      list_containers = function (self, query)
        return perform_request(self, 'GET', '/containers/json', query)
      end,

      create_container = function (self, query, body)
        return perform_request(self, 'POST', '/containers/create', query, nil, body)
      end,

      update_container = function (self, name_or_id, body)
        return perform_request(
          self, 'POST',
          string.format('/containers/%s/%s', name_or_id, 'update'),
          nil, nil, body
        )
      end,

      delete_stopped_containers = function (self, query)
        return perform_request(self, 'POST', '/containers/prune', query)
      end,

      -- @todo missing endpoints:
      -- export_container
      -- get_container_stats
      -- attach_to_container
      -- attach_to_container_ws
      -- extract_archive_to_container_dir

      list_images = function (self, query)
        return perform_request(self, 'GET', '/images/json', query)
      end,

      delete_builder_cache = function (self)
        return perform_request(self, 'POST', '/build/prune')
      end,

      create_image = function (self, query, auth, body)
        return perform_request(self, 'POST', '/images/create', query, auth, body)
      end,

      search_image = function (self, query)
        return perform_request(self, 'GET', '/images/search', query)
      end,

      delete_unused_images = function (self, query)
        return perform_request(self, 'POST', '/images/prune', query)
      end,

      create_image_from_container = function (self, query, body)
        return perform_request(self, 'POST', '/commit', query, nil, body)
      end,

      -- @todo missing endpoints:
      -- build_image
      -- export_image
      -- export_images
      -- import_images

      list_networks = function (self, query)
        return perform_request(self, 'GET', '/networks', query)
      end,

      create_network = function (self, body)
        return perform_request(self, 'POST', '/networks/create', nil, nil, body)
      end,

      delete_unused_networks = function (self, query)
        return perform_request(self, 'POST', '/networks/prune', query)
      end,

      list_volumes = function (self, query)
        return perform_request(self, 'GET', '/volumes', query)
      end,

      create_volume = function (self, body)
        return perform_request(self, 'POST', '/volumes/create', nil, nil, body)
      end,

      delete_unused_volumes = function (self, query)
        return perform_request(self, 'POST', '/volumes/prune', query)
      end,

      inspect_swarm = function (self)
        return perform_request(self, 'GET', '/swarm')
      end,

      initialize_swarm = function (self, body)
        return perform_request(self, 'POST', '/swarm/init', nil, nil, body)
      end,

      join_swarm = function (self, body)
        return perform_request(self, 'POST', '/swarm/join', nil, nil, body)
      end,

      leave_swarm = function (self, query)
        return perform_request(self, 'POST', '/swarm/leave', query)
      end,

      update_swarm = function (self, query, body)
        return perform_request(self, 'POST', '/swarm/update', query, nil, body)
      end,

      get_swarm_unlockkey = function (self)
        return perform_request(self, 'GET', '/swarm/unlockkey')
      end,

      unlock_swarm_manager = function (self, body)
        return perform_request(self, 'POST', '/swarm/unlock', nil, nil, body)
      end,

      list_nodes = function (self, query)
        return perform_request(self, 'GET', '/nodes', query)
      end,

      list_services = function (self, query)
        return perform_request(self, 'GET', '/services', query)
      end,

      create_service = function (self, auth, body)
        return perform_request(self, 'POST', '/services/create', nil, auth, body)
      end,

      list_tasks = function (self, query)
        return perform_request(self, 'GET', '/tasks', query)
      end,

      list_secrets = function (self, query)
        return perform_request(self, 'GET', '/secrets', query)
      end,

      create_secret = function (self, body)
        return perform_request(self, 'POST', '/secrets/create', nil, nil, body)
      end,

      list_configs = function (self, query)
        return perform_request(self, 'GET', '/configs', query)
      end,

      create_config = function (self, body)
        return perform_request(self, 'POST', '/configs/create', nil, nil, body)
      end,

      list_plugins = function (self, query)
        return perform_request(self, 'GET', '/plugins', query)
      end,

      get_plugin_privileges = function (self, query)
        return perform_request(self, 'GET', '/plugins/privileges', query)
      end,

      install_plugin = function (self, query, auth, body)
        return perform_request(self, 'POST', '/plugins/pull', query, auth, body)
      end,

      create_plugin = function (self, query, body)
        return perform_request(self, 'POST', '/plugins/create', query, nil, body)
      end,

      check_auth_config = function (self, body)
        return perform_request(self, 'POST', '/auth', nil, nil, body)
      end,

      get_system_info = function (self)
        return perform_request(self, 'GET', '/info')
      end,

      ping_server = function (self)
        return perform_request(self, 'GET', '/_ping')
      end,

      -- @todo missing endpoints:
      -- monitor_events

      get_usage = function (self)
        return perform_request(self, 'GET', '/system/df')
      end,
    }

    loop_through_entity_endpoints({
      ['list_container_processes'] = { method = 'GET', endpoint = 'top' },
      ['inspect_container'] = { method = 'GET', endpoint = 'json' },
      ['get_container_logs'] = { method = 'GET', endpoint = 'logs' },
      ['get_container_fs_changes'] = { method = 'GET', endpoint = 'changes' },
      ['resize_container_tty'] = { method = 'POST', endpoint = 'resize' },
      ['start_container'] = { method = 'POST', endpoint = 'start' },
      ['stop_container'] = { method = 'POST', endpoint = 'stop' },
      ['restart_container'] = { method = 'POST', endpoint = 'restart' },
      ['kill_container'] = { method = 'POST', endpoint = 'kill' },
      ['rename_container'] = { method = 'POST', endpoint = 'rename' },
      ['pause_container'] = { method = 'POST', endpoint = 'pause' },
      ['resume_container'] = { method = 'POST', endpoint = 'unpause' },
      ['wait_for_container'] = { method = 'POST', endpoint = 'wait' },
      ['remove_container'] = { method = 'DELETE' },
      ['get_container_resource_info'] = { method = 'HEAD', endpoint = 'archive' },
      ['get_container_resource_archive'] = { method = 'GET', endpoint = 'archive' },
      ['create_exec_instance'] = { method = 'POST', endpoint = 'exec' },
    }, 'containers', d)

    loop_through_entity_endpoints({
      ['inspect_image'] = { method = 'GET', endpoint = 'json' },
      ['get_image_history'] = { method = 'GET', endpoint = 'history' },
      ['push_image'] = { method = 'POST', endpoint = 'push' },
      ['tag_image'] = { method = 'POST', endpoint = 'tag' },
      ['remove_image'] = { method = 'DELETE' },
    }, 'images', d)

    loop_through_entity_endpoints({
      ['inspect_network'] = { method = 'GET' },
      ['remove_network'] = { method = 'DELETE' },
      ['connect_container_to_network'] = { method = 'POST', endpoint = 'connect' },
      ['disconnect_container_from_network'] = { method = 'POST', endpoint = 'disconnect' },
    }, 'networks', d)

    loop_through_entity_endpoints({
      ['inspect_volume'] = { method = 'GET' },
      ['remove_volume'] = { method = 'DELETE' },
    }, 'volumes', d)

    loop_through_entity_endpoints({
      ['start_exec_instance'] = { method = 'POST', endpoint = 'start' },
      ['resize_exec_instance'] = { method = 'POST', endpoint = 'resize' },
      ['inspect_exec_instance'] = { method = 'GET', endpoint = 'json' },
    }, 'exec', d)

    loop_through_entity_endpoints({
      ['inspect_node'] = { method = 'GET' },
      ['delete_node'] = { method = 'DELETE' },
      ['update_node'] = { method = 'POST', endpoint = 'update' },
    }, 'nodes', d)

    loop_through_entity_endpoints({
      ['inspect_service'] = { method = 'GET' },
      ['delete_service'] = { method = 'DELETE' },
      ['update_service'] = { method = 'POST', endpoint = 'update' },
      ['get_service_logs'] = { method = 'GET', endpoint = 'logs' },
    }, 'services', d)

    loop_through_entity_endpoints({
      ['inspect_task'] = { method = 'GET' },
    }, 'tasks', d)

    loop_through_entity_endpoints({
      ['inspect_secret'] = { method = 'GET' },
      ['delete_secret'] = { method = 'DELETE' },
      ['update_secret'] = { method = 'POST', endpoint = 'update' },
    }, 'secrets', d)

    loop_through_entity_endpoints({
      ['inspect_config'] = { method = 'GET' },
      ['delete_config'] = { method = 'DELETE' },
      ['update_config'] = { method = 'POST', endpoint = 'update' },
    }, 'configs', d)

    loop_through_entity_endpoints({
      ['inspect_plugin'] = { method = 'GET', endpoint = 'json' },
      ['remove_plugin'] = { method = 'DELETE' },
      ['enable_plugin'] = { method = 'POST', endpoint = 'enable' },
      ['disable_plugin'] = { method = 'POST', endpoint = 'disable' },
      ['upgrade_plugin'] = { method = 'POST', endpoint = 'upgrade' },
      ['push_plugin'] = { method = 'POST', endpoint = 'push' },
      ['configure_plugin'] = { method = 'POST', endpoint = 'set' },
    }, 'plugins', d)

    loop_through_entity_endpoints({
      ['get_registry_image_info'] = { method = 'GET', endpoint = 'json' },
    }, 'distribution', d)

    return d
  end
}
