// End-to-end exercise of `compiled-set` against a synthetic Kbuild output directory.
//
// A fake `.cmd` file references an in-tree source and header, a toolchain header outside the tree, and a
// generated header under the output directory. The generator must report the first two as tree-relative
// paths and drop the latter two.

use std::path::Path;
use std::process::Command;

fn run_compiled_set(repo: &Path, out_dir: &Path) -> String {
    let bin = env!("CARGO_BIN_EXE_benos-kt");
    let out = Command::new(bin)
        .args(["compiled-set", "--repo"])
        .arg(repo)
        .arg("--out-dir")
        .arg(out_dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "compiled-set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn reports_tree_files_and_drops_the_rest() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("kernel");
    let out = tmp.path().join("out");
    std::fs::create_dir_all(repo.join("kernel/bpf")).unwrap();
    std::fs::create_dir_all(repo.join("include/linux")).unwrap();
    std::fs::create_dir_all(out.join("kernel/bpf")).unwrap();

    // A .cmd mentioning: an in-tree source and header (kept), a toolchain header (absolute, dropped), and
    // a generated header under the output directory (dropped).
    let cmd = "cmd_kernel/bpf/verifier.o := clang -I./include -c verifier.c\n\
         \n\
         source_kernel/bpf/verifier.o := ../kernel/kernel/bpf/verifier.c\n\
         \n\
         deps_kernel/bpf/verifier.o := \\\n\
         \x20 ../kernel/include/linux/bpf.h \\\n\
         \x20 /usr/lib/clang/17/include/stddef.h \\\n\
         \x20 ./include/generated/autoconf.h \\\n\
         \x20 ../kernel/kernel/bpf/verifier.c\n\
         \n\
         kernel/bpf/verifier.o: $(deps_kernel/bpf/verifier.o)\n";
    std::fs::write(out.join("kernel/bpf/.verifier.o.cmd"), cmd).unwrap();

    let stdout = run_compiled_set(&repo, &out);
    let lines: Vec<&str> = stdout.lines().collect();

    assert!(
        lines.contains(&"kernel/bpf/verifier.c"),
        "in-tree source missing:\n{stdout}"
    );
    assert!(
        lines.contains(&"include/linux/bpf.h"),
        "in-tree header missing:\n{stdout}"
    );
    assert!(
        !stdout.contains("stddef.h"),
        "toolchain header should be dropped:\n{stdout}"
    );
    assert!(
        !stdout.contains("autoconf.h"),
        "generated header should be dropped:\n{stdout}"
    );
}
