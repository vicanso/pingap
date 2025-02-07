use glob::glob;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use substring::Substring;
use toml::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct Cargo {
    package: Package,
    dependencies: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Package {
    name: String,
}

fn main() {
    let prefix = "pingap-";
    let mut deps = HashMap::new();
    for entry in glob(&format!("{prefix}*/Cargo.toml")).unwrap() {
        let e = entry.unwrap();
        let data = fs::read_to_string(e).unwrap();
        let c = toml::from_str::<Cargo>(&data).unwrap();
        let package_name = c.package.name;
        let mut modules: Vec<String> = vec![];
        for name in c.dependencies.keys() {
            if !name.starts_with(prefix) {
                continue;
            }
            modules.push(name.substring(prefix.len(), name.len()).to_string());
        }
        deps.insert(
            package_name
                .substring(prefix.len(), package_name.len())
                .to_string(),
            modules,
        );
    }
    let mut arr = vec![];
    let mut keys = deps.keys().collect::<Vec<_>>();
    keys.sort();
    for name in keys {
        let modules = deps.get(name).unwrap();
        if modules.is_empty() {
            continue;
        }
        for module in modules.iter() {
            arr.push(format!("    {} --> {}", name, module));
        }
        arr.push("".to_string());
    }
    let mermaid = format!(
        r#"```mermaid
graph TD
{}```"#,
        arr.join("\n")
    );
    let re = Regex::new(r#"```mermaid[\s\S]*?```"#).unwrap();
    let mut content =
        fs::read_to_string("docs/module_dependencies.md").unwrap();
    content = re.replace(&content, &mermaid).to_string();
    fs::write("docs/module_dependencies.md", content).unwrap();
}
