// Copyright (c) 2016-2020 Memgraph Ltd. [https://memgraph.com]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate bindgen;

use anyhow::anyhow;
use cmake::Config;
use flate2::read::GzDecoder;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;

#[derive(PartialEq)]
enum HostType {
    Linux,
    MacOS,
    Windows,
    Unknown,
}

// NOTE: The code here is equivalent to [rust-openssl](https://github.com/sfackler/rust-openssl).
// NOTE: We have to build mgclient and link the rust binary with the same SSL and Crypto libs.

fn build_mgclient_macos(mgclient_dir: &PathBuf) -> PathBuf {
    println!("MacOS detected. We will check if you have either the MacPorts or Homebrew package managers.");
    println!("Checking for MacPorts...");
    let output = Command::new("/usr/bin/command")
        .args(["-v", "port"])
        .output()
        .expect("Failed to execute shell command: '/usr/bin/command -v port'")
        .stdout;
    let port_path = String::from_utf8(output).unwrap();
    if !port_path.is_empty() {
        let port_path = &port_path[..port_path.len() - 1];
        println!(
            "'port' binary detected at {:?}. We assume MacPorts is installed and is your primary package manager.",
            &port_path
        );
        let port_binary_path = Path::new(&port_path);
        println!("Checking if the 'openssl' port is installed.");
        let output = String::from_utf8(
            Command::new(port_path)
                .args(["installed", "openssl"])
                .output()
                .expect("Failed to execute shell command 'port installed openssl'")
                .stdout,
        )
        .unwrap();
        if output == "None of the specified ports are installed.\n" {
            panic!("The openssl port does not seem to be installed! Please install it using 'port install openssl'.");
        }
        let openssl_lib_dir = port_binary_path
            .ancestors()
            .nth(2)
            .unwrap()
            .join("libexec")
            .join("openssl3")
            .join("lib");
        // Telling Cargo to tell rustc where to look for the OpenSSL library.
        println!(
            "cargo:rustc-link-search=native={}",
            openssl_lib_dir.display()
        );
        // With MacPorts, you don't need to pass in the OPENSSL_ROOT_DIR,
        // OPENSSL_CRYPTO_LIBRARY, and OPENSSL_SSL_LIBRARY options to CMake, PkgConfig
        // should take care of setting those variables.
        Config::new(mgclient_dir).build()
    } else {
        println!("Macports not found.");
        println!("Checking for Homebrew...");
        let output = Command::new("/usr/bin/command")
            .args(["-v", "brew"])
            .output()
            .expect("Failed to execute shell command: '/usr/bin/command -v brew'")
            .stdout;
        let brew_path = String::from_utf8(output).unwrap();
        if brew_path.is_empty() {
            println!("Homebrew not found.");
            panic!(
                "We did not detect either MacPorts or Homebrew on your machine. We cannot proceed."
            );
        } else {
            println!("'brew' executable detected at {:?}", &brew_path);
            println!("Proceeding with installation assuming Homebrew is your package manager");
        }
        let path_openssl = if cfg!(target_arch = "aarch64") {
            "/opt/homebrew/Cellar/openssl@3"
        } else {
            "/usr/local/Cellar/openssl@3"
        };
        let openssl_path = PathBuf::from(path_openssl);
        if !openssl_path.exists() {
            panic!("openssl@3 is not installed");
        }
        let mut openssl_dirs = std::fs::read_dir(openssl_path)
            .unwrap()
            .map(|r| r.unwrap().path())
            .collect::<Vec<PathBuf>>();
        openssl_dirs.sort_by(|a, b| {
            let a_time = a.metadata().unwrap().modified().unwrap();
            let b_time = b.metadata().unwrap().modified().unwrap();
            b_time.cmp(&a_time)
        });
        let openssl_root_path = openssl_dirs[0].clone();
        println!(
            "cargo:rustc-link-search=native={}",
            openssl_root_path.join("lib").display()
        );
        let openssl_root = openssl_dirs[0].clone();
        Config::new(mgclient_dir)
            .define("OPENSSL_ROOT_DIR", format!("{}", openssl_root.display()))
            .define(
                "OPENSSL_CRYPTO_LIBRARY",
                format!(
                    "{}",
                    openssl_root.join("lib").join("libcrypto.dylib").display()
                ),
            )
            .define(
                "OPENSSL_SSL_LIBRARY",
                format!(
                    "{}",
                    openssl_root.join("lib").join("libssl.dylib").display()
                ),
            )
            .build()
    }
}

fn build_mgclient_linux(mg_client_dir: &PathBuf) -> PathBuf {
    Config::new(mg_client_dir).build()
}

fn build_mgclient_windows(mg_client_dir: &PathBuf) -> PathBuf {
    let openssl_dir = PathBuf::from(
        std::env::var("OPENSSL_LIB_DIR")
            .unwrap_or_else(|_| "C:\\Program Files\\OpenSSL-Win64\\lib".to_string()),
    );
    println!("cargo:rustc-link-search=native={}", openssl_dir.display());
    Config::new(mg_client_dir)
        .define("OPENSSL_ROOT_DIR", format!("{}", openssl_dir.display()))
        .build()
}

fn main() {
    let host_type = if cfg!(target_os = "linux") {
        HostType::Linux
    } else if cfg!(target_os = "windows") {
        HostType::Windows
    } else if cfg!(target_os = "macos") {
        HostType::MacOS
    } else {
        HostType::Unknown
    };

    let mg_client_dir = download_and_unpack_c_client().unwrap();
    let mgclient_out = match host_type {
        HostType::Windows => build_mgclient_windows(&mg_client_dir),
        HostType::MacOS => build_mgclient_macos(&mg_client_dir),
        HostType::Linux => build_mgclient_linux(&mg_client_dir),
        HostType::Unknown => panic!("Unknown operating system"),
    };

    let mgclient_h = mgclient_out.join("include").join("mgclient.h");
    let mgclient_export_h = mgclient_out.join("include").join("mgclient-export.h");
    // Required because of tests that rely on the C struct fields.
    let mgclient_mgvalue_h = mg_client_dir.join("src").join("mgvalue.h");
    println!("cargo:rerun-if-changed={}", mgclient_h.display());
    println!("cargo:rerun-if-changed={}", mgclient_export_h.display());
    let bindings = bindgen::Builder::default()
        .header(format!("{}", mgclient_h.display()))
        .header(format!("{}", mgclient_export_h.display()))
        .header(format!("{}", mgclient_mgvalue_h.display()))
        .clang_arg(format!("-I{}", mgclient_out.join("include").display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let lib_dir = if Path::new(&mgclient_out.join("lib64")).exists() {
        "lib64"
    } else {
        "lib"
    };
    println!(
        "cargo:rustc-link-search=native={}",
        mgclient_out.join(lib_dir).display()
    );
    println!("cargo:rustc-link-lib=static=mgclient");
    // If the following part of the code is pushed inside build_mgclient_xzy, linking is not done
    // properly.
    match host_type {
        HostType::Linux => {
            println!("cargo:rustc-link-lib=dylib=crypto");
            println!("cargo:rustc-link-lib=dylib=ssl");
        }
        HostType::Windows => {
            println!("cargo:rustc-link-lib=dylib=libcrypto");
            println!("cargo:rustc-link-lib=dylib=libssl");
        }
        HostType::MacOS => {
            println!("cargo:rustc-link-lib=dylib=crypto");
            println!("cargo:rustc-link-lib=dylib=ssl");
        }
        HostType::Unknown => panic!("Unknown operating system"),
    }
}

fn download_and_unpack_c_client() -> Result<PathBuf, anyhow::Error> {
    let repo_name = "mgclient";
    let commit = "d57df8aba5d62074c56aced591147e2b2616c4dc";
    let resp = reqwest::blocking::get(format!(
        "https://github.com/memgraph/{}/archive/{}.tar.gz",
        repo_name, commit
    ))?;
    let tar_data = GzDecoder::new(resp);
    let mut archive = Archive::new(tar_data);
    let out_dir = env::var_os("OUT_DIR").ok_or(anyhow!("Failed to get OUT_DIR"))?;
    let archive_dir = PathBuf::from(out_dir).join("mgclient");
    archive.unpack(&archive_dir)?;
    Ok(archive_dir.join(format!("{}-{}", repo_name, commit)))
}
