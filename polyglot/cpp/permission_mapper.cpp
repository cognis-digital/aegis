#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <memory>
#include <stdexcept>

// Forward declarations
class AccessControl;
class Resource;
class Principal;

// Base class for all resources
class Resource {
public:
    virtual ~Resource() = default;
    virtual std::string getType() const = 0;
};

// Base class for all principals (users, services, etc.)
class Principal {
public:
    virtual ~Principal() = default;
    virtual std::string getId() const = 0;
    virtual std::string getName() const = 0;
};

// Concrete resource types
class FileResource : public Resource {
public:
    FileResource(const std::string& path) : path_(path) {}
    std::string getType() const override { return "file"; }
    std::string getPath() const { return path_; }

private:
    std::string path_;
};

class DatabaseResource : public Resource {
public:
    DatabaseResource(const std::string& name, const std::string& schema)
        : name_(name), schema_(schema) {}
    std::string getType() const override { return "database"; }
    std::string getName() const { return name_; }
    std::string getSchema() const { return schema_; }

private:
    std::string name_;
    std::string schema_;
};

// Concrete principal types
class UserPrincipal : public Principal {
public:
    UserPrincipal(const std::string& id, const std::string& name)
        : id_(id), name_(name) {}
    std::string getId() const override { return id_; }
    std::string getName() const override { return name_; }

private:
    std::string id_;
    std::string name_;
};

class ServicePrincipal : public Principal {
public:
    ServicePrincipal(const std::string& id, const std::string& name)
        : id_(id), name_(name) {}
    std::string getId() const override { return id_; }
    std::string getName() const override { return name_; }

private:
    std::string id_;
    std::string name_;
};

// Access control entry
class AccessControlEntry {
public:
    AccessControlEntry(const Principal& principal, const Resource& resource, bool allowed)
        : principal_(principal), resource_(resource), allowed_(allowed) {}

    const Principal& getPrincipal() const { return principal_; }
    const Resource& getResource() const { return resource_; }
    bool isAllowed() const { return allowed_; }

private:
    Principal principal_;
    Resource resource_;
    bool allowed_;
};

// Access control policy
class AccessControl {
public:
    void addEntry(const AccessControlEntry& entry) {
        entries_.push_back(entry);
    }

    std::vector<AccessControlEntry> getEntries() const {
        return entries_;
    }

private:
    std::vector<AccessControlEntry> entries_;
};

// Permission Mapper class
class PermissionMapper {
public:
    PermissionMapper() {}

    void addAccessControl(const AccessControl& control) {
        for (const auto& entry : control.getEntries()) {
            mapPermissions(entry.getPrincipal(), entry.getResource(), entry.isAllowed());
        }
    }

    void mapPermissions(const Principal& principal, const Resource& resource, bool allowed) {
        std::string principalId = principal.getId();
        std::string resourceId = getResourceIdentifier(resource);

        if (allowed) {
            permissions_[principalId][resourceId] = true;
        } else {
            permissions_[principalId][resourceId] = false;
        }
    }

    void printPermissions() const {
        for (const auto& [principalId, resources] : permissions_) {
            std::cout << "Principal: " << principalId << " (" << principalId << ")\n";
            for (const auto& [resourceId, allowed] : resources) {
                std::cout << "  Resource: " << resourceId << " - Allowed: " << (allowed ? "Yes" : "No") << "\n";
            }
        }
    }

private:
    std::map<std::string, std::map<std::string, bool>> permissions_;

    std::string getResourceIdentifier(const Resource& resource) const {
        if (const auto* file = dynamic_cast<const FileResource*>(&resource)) {
            return "file:" + file->getPath();
        } else if (const auto* db = dynamic_cast<const DatabaseResource*>(&resource)) {
            return "database:" + db->getName() + ":" + db->getSchema();
        }
        return "unknown:" + resource.getType();
    }
};

// Demo entry point
int main() {
    // Create some principals
    UserPrincipal user1("user123", "Alice");
    ServicePrincipal service1("svc456", "DataService");

    // Create some resources
    FileResource file1("/etc/passwd");
    DatabaseResource db1("users", "default");

    // Create access control entries
    AccessControl control;

    // Alice can read /etc/passwd
    control.addEntry(AccessControlEntry(user1, file1, true));

    // Alice cannot write to database
    control.addEntry(AccessControlEntry(user1, db1, false));

    // DataService can read and write to database
    control.addEntry(AccessControlEntry(service1, db1, true));
    control.addEntry(AccessControlEntry(service1, file1, false));

    // Create permission mapper and map permissions
    PermissionMapper mapper;
    mapper.addAccessControl(control);

    // Print out the mapped permissions
    std::cout << "Mapped Permissions:\n";
    mapper.printPermissions();

    return 0;
}