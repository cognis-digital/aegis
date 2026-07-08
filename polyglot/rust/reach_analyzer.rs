use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone)]
enum AccessType {
    Read,
    Write,
    Execute,
    Admin,
}

#[derive(Debug, Clone)]
struct Resource {
    name: String,
    access_types: Vec<AccessType>,
}

#[derive(Debug, Clone)]
struct Principal {
    id: String,
    roles: HashSet<String>,
}

#[derive(Debug, Clone)]
struct AccessRule {
    principal: Principal,
    resource: Resource,
    access_type: AccessType,
}

#[derive(Debug, Clone)]
struct ReachableResource {
    name: String,
    principals: HashSet<String>,
}

impl fmt::Display for ReachableResource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Resource: {}", self.name)?;
        for principal in &self.principals {
            write!(f, " Principal: {}", principal)?;
        }
        Ok(())
    }
}

fn analyze_reach(rules: &[AccessRule]) -> Vec<ReachableResource> {
    let mut resource_to_principals = HashMap::new();

    for rule in rules {
        let resource_name = &rule.resource.name;
        let principal_id = &rule.principal.id;

        resource_to_principals
            .entry(resource_name.to_string())
            .or_insert_with(HashSet::new)
            .insert(principal_id.clone());
    }

    let mut reachable_resources = Vec::new();

    for (resource_name, principals) in resource_to_principals {
        reachable_resources.push(ReachableResource {
            name: resource_name,
            principals: principals.clone(),
        });
    }

    reachable_resources
}

fn main() {
    // Example usage of the reach analyzer
    let rules = vec![
        AccessRule {
            principal: Principal {
                id: "user1".to_string(),
                roles: HashSet::from(["admin".to_string()].iter().cloned()),
            },
            resource: Resource {
                name: "database".to_string(),
                access_types: vec![AccessType::Admin],
            },
            access_type: AccessType::Admin,
        },
        AccessRule {
            principal: Principal {
                id: "user2".to_string(),
                roles: HashSet::from(["read".to_string()].iter().cloned()),
            },
            resource: Resource {
                name: "file1".to_string(),
                access_types: vec![AccessType::Read],
            },
            access_type: AccessType::Read,
        },
        AccessRule {
            principal: Principal {
                id: "user3".to_string(),
                roles: HashSet::from(["write".to_string()].iter().cloned()),
            },
            resource: Resource {
                name: "file2".to_string(),
                access_types: vec![AccessType::Write],
            },
            access_type: AccessType::Write,
        },
    ];

    let reachable_resources = analyze_reach(&rules);

    for resource in &reachable_resources {
        println!("{}", resource);
    }
}