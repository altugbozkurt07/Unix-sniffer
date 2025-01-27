use bindgen::builder;
use std::{path::Path, process::Command};

fn bindgen<P: AsRef<Path>, Q: AsRef<Path>>(file: P, out_dir: Q) {
    let out_file = out_dir.as_ref().join("gen.rs");

    let bindings = builder()
        .header(file.as_ref().to_string_lossy())
        .layout_tests(false) // --no-layout-tests
        .use_core() // --use-core
        .allowlist_function("shim_.*")
        .size_t_is_usize(false) // --no-size_t-is-usize
        //.clang_arg("-I/usr/include/aarch64-linux-gnu/sys/")
        .clang_arg("-target")
        .clang_arg("bpf")
        .generate()
        .expect("failed at generating bindings");

    std::fs::create_dir_all(out_dir).expect("failed to create Rust shim output directory");

    bindings
        .write_to_file(out_file)
        .expect("failed at writing generated bindings");
}

fn main() {

    let out_dir = std::env::var("OUT_DIR").expect("could not get outdir");
    let shim_dir = Path::new("src/co_re/c-bindings");
    let shim_file = shim_dir.join("shim.c");

    bindgen(&shim_file, "src/co_re");
    println!("shim.o file dir: {}", format!("{out_dir}/c-shim.o"));
    println!("shim file dir {:?}", shim_file.to_str());
    if std::env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "bpf" {
        let c = Command::new("clang")
            .arg("-I")
            .arg("src/")
            .arg("-O2")
            .arg("-emit-llvm")
            .arg("-target")
            .arg("bpf")
            .arg("-c")
            .arg("-g")
            .arg(&shim_file)
            .arg("-o")
            .arg(format!("{out_dir}/c-shim.o"))
            .status()
            .expect("Failed to compile the C-shim");

        if !c.success(){
            panic!("c-shim compilation failed");
        }

        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=link-arg={out_dir}/c-shim.o");
    }

    println!("cargo:rerun-if-changed={}", shim_file.to_string_lossy());

}