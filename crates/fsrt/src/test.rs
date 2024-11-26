use crate::{forge_project::ForgeProjectTrait, scan_directory, Args};
use clap::{Arg, Parser};
use forge_analyzer::definitions::PackageData;
use forge_analyzer::reporter::Report;
use forge_loader::manifest::{ForgeManifest, FunctionMod};
use std::fmt;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use swc_core::common::sync::Lrc;
use swc_core::common::{FileName, SourceFile, SourceMap};

trait ReportExt {
    fn has_no_vulns(&self) -> bool;

    fn contains_secret_vuln(&self, expected_len: usize) -> bool;

    fn contains_perm_vuln(&self, expected_len: usize) -> bool;

    fn contains_vulns(&self, expected_len: i32) -> bool;

    fn contains_authz_vuln(&self, expected_len: usize) -> bool;
}

impl ReportExt for Report {
    #[inline]
    fn has_no_vulns(&self) -> bool {
        self.into_vulns().is_empty()
    }

    #[inline]
    fn contains_authz_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name().starts_with("Authorization-"))
            .count()
            == expected_len
    }

    #[inline]
    fn contains_secret_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name().starts_with("Hardcoded-Secret-"))
            .count()
            == expected_len
    }

    #[inline]
    fn contains_perm_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name() == "Least-Privilege")
            .count()
            == expected_len
    }

    #[inline]
    fn contains_vulns(&self, expected_len: i32) -> bool {
        self.into_vulns().len() == expected_len as usize
    }
}

#[derive(Clone)]
pub(crate) struct MockForgeProject<'a> {
    pub files_name_to_source: HashMap<PathBuf, Arc<SourceFile>>,
    pub test_manifest: ForgeManifest<'a>,
    pub cm: Lrc<SourceMap>,
}

impl fmt::Debug for MockForgeProject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mock Forge Project {:?}", self.files_name_to_source)
    }
}

#[allow(dead_code)]
impl<'a> MockForgeProject<'a> {
    pub fn files_from_string(string: &'a str) -> Self {
        let different_files = string.split("//").filter(|file| !file.is_empty());

        let manifest = if let Some(manifest_string) = different_files.clone().find(|string| {
            string
                .replace("//", "")
                .trim_start()
                .starts_with("manifest.yaml")
                || string
                    .trim_start()
                    .replace("//", "")
                    .starts_with("manifest.yml")
        }) {
            serde_yaml::from_str(manifest_string.split_once('\n').unwrap().1).unwrap_or_default()
        } else {
            ForgeManifest::create_manifest_with_func_mod(FunctionMod {
                key: "main",
                handler: "index.run",
                providers: None,
            })
        };

        let mut mock_forge_project = MockForgeProject {
            files_name_to_source: HashMap::new(),
            test_manifest: manifest.to_owned(),
            cm: Arc::default(),
        };

        for file in different_files {
            let (file_name, file_source) = file.split_once('\n').unwrap();
            mock_forge_project.add_file(
                file_name.replace("//", "").replace('"', "").trim(),
                file_source.replace('"', ""),
            );
        }
        mock_forge_project
    }

    pub fn add_file(&mut self, p: impl Into<PathBuf>, source: impl Into<String>) {
        let file_name = p.into();
        let source_file = self
            .cm
            .new_source_file(FileName::Real(file_name.clone()), source.into());

        self.files_name_to_source.insert(file_name, source_file);
    }
}

impl<'a> ForgeProjectTrait<'a> for MockForgeProject<'a> {
    fn load_file(&self, p: impl AsRef<Path>, _: Arc<SourceMap>) -> Arc<SourceFile> {
        self.files_name_to_source.get(p.as_ref()).unwrap().clone()
    }

    fn get_paths(&self) -> HashSet<PathBuf> {
        self.files_name_to_source
            .keys()
            .map(|file| file.into())
            .collect::<HashSet<_>>()
    }

    #[allow(dead_code)]
    fn get_secret_packages(&self) -> Vec<PackageData> {
        vec![]
    }

    fn get_manifest(&self) -> ForgeManifest<'_> {
        self.test_manifest.clone()
    }
}

pub(crate) fn scan_directory_test(
    forge_test_proj: MockForgeProject<'_>,
) -> forge_analyzer::reporter::Report {
    let secret_packages: Vec<PackageData> = std::fs::File::open("../../secretdata.yaml")
        .map(|f| serde_yaml::from_reader(f).expect("Failed to deserialize packages"))
        .unwrap_or_else(|_| vec![]);

    let mut args = Args::parse();
    args.check_permissions = true;

    match scan_directory(PathBuf::new(), &args, forge_test_proj, &secret_packages) {
        Ok(report) => report,
        Err(err) => panic!("error while scanning {err:?}"),
    }
}

#[test]
fn test_simple() {
    let forge_manifest = ForgeManifest::create_manifest_with_func_mod(FunctionMod {
        key: "main",
        handler: "index.run",
        providers: None,
    });

    let mut test_forge_project = MockForgeProject {
        test_manifest: forge_manifest,
        files_name_to_source: HashMap::new(),
        cm: Lrc::new(SourceMap::default()),
    };
    test_forge_project.add_file(
        "src/index.tsx",
        "import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
            function App() { console.log('test') } \n
            export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.has_no_vulns());
}

#[test]
fn test_secret_vuln() {
    let forge_manifest = ForgeManifest::create_manifest_with_func_mod(FunctionMod {
        key: "main",
        handler: "index.run",
        providers: None,
    });

    let mut test_forge_project = MockForgeProject {
        test_manifest: forge_manifest,
        files_name_to_source: HashMap::new(),
        cm: Lrc::new(SourceMap::default()),
    };
    test_forge_project.add_file(
        "src/index.tsx",
        "import {AES} from 'crypto-js'
        import ForgeUI, { render, Macro } from '@forge/ui';
    
        function App() { 
            AES.encrypt(blah, 'blah');
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn with_multiple_files() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
        import test_function from 'test_function'; \n
        function App() { let test = 'textx'; console.log('test') } \n
        export const run = render(<Macro app={<App />} />); 
        // src/test_function.tsx
        export default function test() { let test1 = 'test_one'; console.log('test_function') }",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.has_no_vulns());
}

// secret checker integrationt tests
#[test]
fn secret_vuln_default_import() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import jwt from 'jsonwebtoken';

        function App() { 
            let a = 'shhhhh';
            let secret = jwt.sign({ foo: 'bar' }, a);
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_named_import() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import {AES} from 'crypto-js'
        import ForgeUI, { render, Macro } from '@forge/ui';

        function App() { 
            AES.encrypt(blah, 'nothing');
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_star_import() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 
            atlassian_jwt.encodeSymmetric(blah, 'blah');
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_global_import() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        let SECRET = 'secret';

        function App() { 
            atlassian_jwt.encodeSymmetric(blah, SECRET);
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn excess_scope() {
    let mut test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 
            
        } 

        export const run = render(<Macro app={<App />} />);
        ",
    );

    test_forge_project
        .test_manifest
        .permissions
        .scopes
        .push("read:component:compass".into());

    let scan_result = scan_directory_test(test_forge_project);
    println!("scan_result {:#?}", scan_result);
    assert!(scan_result.contains_perm_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn correct_scopes() {
    let mut test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 

        const query = `query compass_query($test:CompassSearchTeamsInput!) {
            compass {
                searchTeams(input: $test) {
                    ... on CompassSearchTeamsConnection{
                    nodes {
                    teamId
                    }
                }
                }
            }
            }`
            
            const result = await api
                .asApp()
                .requestGraph(
                query, {}, {}
                );
            const status = result.status;

        } 

        export const run = render(<Macro app={<App />} />);
        ",
    );

    test_forge_project
        .test_manifest
        .permissions
        .scopes
        .push("read:component:compass".into());

    let scan_result = scan_directory_test(test_forge_project);
    println!("scan_result {:#?}", scan_result);
    assert!(scan_result.contains_vulns(0))
}
