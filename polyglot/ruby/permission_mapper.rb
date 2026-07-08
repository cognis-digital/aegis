# polyglot/ruby/permission_mapper.rb

require 'yaml'
require 'set'

class PermissionMapper
  attr_reader :permissions, :users, :roles, :resources

  def initialize
    @permissions = Set.new
    @users = {}
    @roles = {}
    @resources = Set.new
  end

  def load_from_yaml(file_path)
    data = YAML.load_file(file_path)
    @permissions = data['permissions'] || Set.new
    @users = data['users'] || {}
    @roles = data['roles'] || {}
    @resources = data['resources'] || Set.new
  end

  def map_permissions_to_users
    user_permissions = {}

    users.each do |user, role_names|
      role_names.each do |role_name|
        role_permissions = roles[role_name]&.fetch('permissions', [])
        permissions_to_add = permissions & role_permissions
        user_permissions[user] ||= Set.new
        user_permissions[user].merge!(permissions_to_add)
      end
    end

    user_permissions
  end

  def map_permissions_to_resources
    resource_permissions = {}

    resources.each do |resource|
      resource_permissions[resource] = permissions.select do |perm|
        perm.start_with?("access_#{resource}_")
      end
    end

    resource_permissions
  end

  def find_reachable_resources(user)
    user_perms = map_permissions_to_users[user]
    return [] unless user_perms

    resources.select do |resource|
      user_perms.any? { |perm| perm.start_with?("access_#{resource}_") }
    end
  end

  def run_demo
    # Example data for demonstration
    demo_data = {
      'permissions' => [
        'read_user',
        'write_user',
        'delete_user',
        'read_order',
        'write_order',
        'delete_order'
      ],
      'users' => {
        'alice' => ['admin'],
        'bob' => ['user'],
        'charlie' => ['guest']
      },
      'roles' => {
        'admin' => {
          'permissions' => ['read_user', 'write_user', 'delete_user', 'read_order', 'write_order', 'delete_order']
        },
        'user' => {
          'permissions' => ['read_user', 'read_order']
        },
        'guest' => {
          'permissions' => ['read_order']
        }
      },
      'resources' => ['users', 'orders']
    }

    mapper = PermissionMapper.new
    mapper.load_from_yaml(demo_data)

    puts "=== User Permissions ==="
    user_perms = mapper.map_permissions_to_users
    user_perms.each do |user, perms|
      puts "User: #{user}, Permissions: #{perms.to_a.join(', ')}"
    end

    puts "\n=== Resource Permissions ==="
    resource_perms = mapper.map_permissions_to_resources
    resource_perms.each do |resource, perms|
      puts "Resource: #{resource}, Permissions: #{perms.join(', ')}"
    end

    puts "\n=== Reachable Resources for Alice ==="
    reachable = mapper.find_reachable_resources('alice')
    puts "Alice can access: #{reachable.join(', ')}"

    puts "\n=== Reachable Resources for Bob ==="
    reachable = mapper.find_reachable_resources('bob')
    puts "Bob can access: #{reachable.join(', ')}"

    puts "\n=== Reachable Resources for Charlie ==="
    reachable = mapper.find_reachable_resources('charlie')
    puts "Charlie can access: #{reachable.join(', ')}"
  end
end

if __FILE__ == $0
  mapper = PermissionMapper.new
  mapper.run_demo
end