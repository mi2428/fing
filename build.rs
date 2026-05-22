use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let host = env::var("HOST").unwrap();
    let target = env::var("TARGET").unwrap();
    let profile = env::var("PROFILE").unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    emit_build_metadata(&manifest_dir, &host, &target, &profile);
}

fn emit_build_metadata(manifest_dir: &Path, host: &str, target: &str, profile: &str) {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-env-changed=FING_BUILD_DATE");
    println!("cargo:rerun-if-env-changed=FING_GIT_DESCRIBE");
    println!("cargo:rerun-if-env-changed=FING_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=FING_GIT_COMMIT_DATE");
    emit_git_rerun_instructions(manifest_dir);

    let git_describe = read_nonempty_env("FING_GIT_DESCRIBE")
        .or_else(|| {
            git_output(
                manifest_dir,
                ["describe", "--tags", "--always", "--dirty=-dirty"],
            )
        })
        .unwrap_or_else(|| "unknown".to_string());
    let git_commit = read_nonempty_env("FING_GIT_COMMIT")
        .or_else(|| git_output(manifest_dir, ["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let git_commit_date = read_nonempty_env("FING_GIT_COMMIT_DATE")
        .or_else(|| git_output(manifest_dir, ["show", "-s", "--format=%cI", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string());
    let build_date = read_nonempty_env("FING_BUILD_DATE").unwrap_or_else(build_date);

    println!("cargo:rustc-env=FING_GIT_DESCRIBE={git_describe}");
    println!("cargo:rustc-env=FING_GIT_COMMIT={git_commit}");
    println!("cargo:rustc-env=FING_GIT_COMMIT_DATE={git_commit_date}");
    println!("cargo:rustc-env=FING_BUILD_DATE={build_date}");
    println!("cargo:rustc-env=FING_BUILD_HOST={host}");
    println!("cargo:rustc-env=FING_BUILD_TARGET={target}");
    println!("cargo:rustc-env=FING_BUILD_PROFILE={profile}");
}

fn emit_git_rerun_instructions(manifest_dir: &Path) {
    let git = manifest_dir.join(".git");
    if git.is_file() {
        println!("cargo:rerun-if-changed={}", git.display());
        let Ok(contents) = fs::read_to_string(&git) else {
            return;
        };
        let Some(git_dir) = contents.trim().strip_prefix("gitdir: ") else {
            return;
        };
        emit_git_dir_rerun_instructions(&absolutize_git_path(manifest_dir, git_dir));
    } else if git.is_dir() {
        emit_git_dir_rerun_instructions(&git);
    }
}

fn emit_git_dir_rerun_instructions(git_dir: &Path) {
    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    let Ok(head) = fs::read_to_string(git_dir.join("HEAD")) else {
        return;
    };
    if let Some(ref_name) = head.trim().strip_prefix("ref: ") {
        println!(
            "cargo:rerun-if-changed={}",
            git_dir.join(ref_name).display()
        );
    }
}

fn absolutize_git_path(manifest_dir: &Path, git_dir: &str) -> PathBuf {
    let path = PathBuf::from(git_dir);
    if path.is_absolute() {
        path
    } else {
        manifest_dir.join(path)
    }
}

fn git_output<const N: usize>(manifest_dir: &Path, args: [&str; N]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?;
    let value = value.trim().to_string();
    (!value.is_empty()).then_some(value)
}

fn read_nonempty_env(key: &str) -> Option<String> {
    env::var(key).ok().filter(|value| !value.trim().is_empty())
}

fn build_date() -> String {
    let seconds = read_nonempty_env("SOURCE_DATE_EPOCH")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or_default()
        });
    unix_seconds_to_utc_iso8601(seconds)
}

fn unix_seconds_to_utc_iso8601(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i64, u32, u32) {
    let days = days_since_unix_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_parameter = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_parameter + 2) / 5 + 1;
    let month = month_parameter + if month_parameter < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }

    (year, month as u32, day as u32)
}
