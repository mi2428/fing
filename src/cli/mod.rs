//! Command-line surface for the production `fing` binary.
//!
//! CLI parsing stays close to `ScanConfig` construction so defaults, validation,
//! and the user-visible help text describe the same behavior the scanner runs.

use crate::{
    enrich, net, output,
    scanner::{self, ScanConfig, ScanProfile},
    store, version,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::{io::IsTerminal, path::PathBuf, time::Duration};

#[derive(Debug, Parser)]
#[command(name = "fing")]
#[command(version)]
#[command(long_version = version::LONG_VERSION)]
#[command(about = "Generic Fing - scan local IPv4 networks and enrich device identities")]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generic Fing - scan local IPv4 networks and enrich device identities.
    Scan(Box<ScanArgs>),
    /// Manage local OUI vendor data.
    Oui {
        #[command(subcommand)]
        command: OuiCommand,
    },
}

#[derive(Debug, Subcommand)]
enum OuiCommand {
    /// Download the IEEE OUI database into the local cache.
    Update {
        /// Optional output path for the normalized OUI JSON database.
        #[arg(long = "output.path")]
        path: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputArg {
    Table,
    Json,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LiveOutputArg {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FingerprintSourceArg {
    Oui,
    Rdns,
    Mdns,
    Netbios,
    Upnp,
    Snmp,
    Lldp,
    Cdp,
    Dhcp,
}

#[derive(Debug, Clone, Copy)]
struct FingerprintSelection {
    oui: bool,
    rdns: bool,
    mdns: bool,
    netbios: bool,
    upnp: bool,
    snmp: bool,
    lldp: bool,
    cdp: bool,
    dhcp: bool,
}

impl FingerprintSelection {
    fn from_args(sources: &[FingerprintSourceArg], profile: ScanProfile) -> Self {
        if sources.is_empty() {
            return Self {
                oui: true,
                rdns: true,
                mdns: true,
                netbios: true,
                upnp: true,
                snmp: true,
                lldp: profile.includes_lldp_fingerprints(),
                cdp: profile.includes_cdp_fingerprints(),
                dhcp: true,
            };
        }

        Self {
            oui: sources.contains(&FingerprintSourceArg::Oui),
            rdns: sources.contains(&FingerprintSourceArg::Rdns),
            mdns: sources.contains(&FingerprintSourceArg::Mdns),
            netbios: sources.contains(&FingerprintSourceArg::Netbios),
            upnp: sources.contains(&FingerprintSourceArg::Upnp),
            snmp: sources.contains(&FingerprintSourceArg::Snmp),
            lldp: sources.contains(&FingerprintSourceArg::Lldp),
            cdp: sources.contains(&FingerprintSourceArg::Cdp),
            dhcp: sources.contains(&FingerprintSourceArg::Dhcp),
        }
    }
}

#[derive(Debug, Parser)]
struct ScanArgs {
    /// Limit scanning to one or more IPv4 CIDR ranges. Can be repeated or comma-separated.
    #[arg(long = "scan.range", value_name = "CIDR", value_delimiter = ',')]
    ranges: Vec<String>,

    /// Scan profile.
    #[arg(long = "scan.profile", value_enum, default_value_t = ScanProfile::Normal)]
    profile: ScanProfile,

    /// Delay between continuous scan rounds in milliseconds. Zero starts the next round immediately.
    #[arg(long = "scan.interval", value_name = "MS", default_value_t = 0)]
    scan_interval_ms: u64,

    /// Per-protocol timeout in milliseconds.
    #[arg(long = "scan.timeout", value_name = "MS")]
    timeout_ms: Option<u64>,

    /// Concurrent scan/probe worker limit.
    #[arg(long = "scan.concurrency", default_value_t = 128)]
    concurrency: usize,

    /// Output format.
    #[arg(long = "output.format", value_enum, default_value_t = OutputArg::Table)]
    format: OutputArg,

    /// Live TUI mode: auto uses it only for interactive table output.
    #[arg(long = "output.live", value_enum, default_value_t = LiveOutputArg::Auto)]
    live: LiveOutputArg,

    /// Mask the lower 24 bits of MAC addresses in output.
    #[arg(long = "output.mask-mac")]
    mask_mac: bool,

    /// Limit fingerprint sources. Defaults to profile-appropriate sources when omitted.
    #[arg(
        long = "fingerprint.source",
        value_enum,
        value_name = "SOURCE",
        value_delimiter = ',',
        help_heading = "Fingerprint Options"
    )]
    fingerprints: Vec<FingerprintSourceArg>,

    /// Read DHCP leases from an explicit lease file. Can be repeated.
    #[arg(long = "dhcp.leases", help_heading = "Fingerprint Options")]
    dhcp_leases: Vec<PathBuf>,

    /// SNMP community used when SNMP fingerprinting is enabled.
    #[arg(
        long = "snmp.community",
        default_value = "public",
        help_heading = "Fingerprint Options"
    )]
    snmp_community: String,

    /// Interfaces to scan, such as en0, eth0, or en0.100.
    #[arg(value_name = "Interfaces", required = true, num_args = 1..)]
    interfaces: Vec<String>,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => run_scan(*args).await,
        Commands::Oui { command } => tokio::task::spawn_blocking(move || run_oui(command))
            .await
            .context("OUI update worker failed")?,
    }
}

async fn run_scan(args: ScanArgs) -> Result<()> {
    let format = args.format;
    let output_options = output_options_from_args(&args);

    let timeout = args
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| args.profile.default_timeout());

    let live = should_run_live_tui(format, args.live, std::io::stdout().is_terminal());

    let configs = scan_configs_from_args(&args, timeout)?;

    if live {
        return run_live_scan(
            configs,
            Duration::from_millis(args.scan_interval_ms),
            output_options,
        )
        .await;
    }

    let result = scanner::scan_many(configs).await?;
    for warning in &result.warnings {
        eprintln!("warning: {warning}");
    }

    match format {
        OutputArg::Table => {
            println!("{}", output::to_table(&result.devices, output_options));
        }
        OutputArg::Json => {
            println!("{}", output::to_json(&result, output_options)?);
        }
        OutputArg::Csv => {
            print!("{}", output::to_csv(&result.devices, output_options)?);
        }
    }

    Ok(())
}

async fn run_live_scan(
    configs: Vec<ScanConfig>,
    scan_interval: Duration,
    output_options: output::OutputOptions,
) -> Result<()> {
    let interface_panel = live_interface_panel(&configs);
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let (pause_tx, pause_rx) = tokio::sync::watch::channel(false);
    let scan_handle = tokio::spawn(async move {
        scanner::scan_continuously_with_events(configs, tx, pause_rx, scan_interval).await
    });

    let outcome: output::LiveOutcome =
        output::run_live_table(rx, pause_tx, output_options, interface_panel)
            .await
            .context("live TUI failed")?;

    if outcome.is_cancelled() {
        scan_handle.abort();
        let _ = scan_handle.await;
        return Ok(());
    }

    scan_handle.await.context("scan task failed")??;

    Ok(())
}

fn live_interface_panel(configs: &[ScanConfig]) -> output::LiveInterfacePanel {
    let default_interface = net::default_interface_name();
    let interfaces = net::list_interfaces().unwrap_or_default();
    let mut scan_interfaces = configs
        .iter()
        .filter_map(|config| config.iface.clone())
        .collect::<Vec<_>>();

    if scan_interfaces.is_empty()
        && let Some(default_interface) = &default_interface
    {
        scan_interfaces.push(default_interface.clone());
    }
    scan_interfaces.sort();
    scan_interfaces.dedup();

    output::LiveInterfacePanel {
        interfaces,
        default_interface,
        scan_interfaces,
    }
}

fn should_run_live_tui(
    format: OutputArg,
    live_mode: LiveOutputArg,
    stdout_is_terminal: bool,
) -> bool {
    matches!(format, OutputArg::Table)
        && match live_mode {
            LiveOutputArg::Auto => stdout_is_terminal,
            LiveOutputArg::Always => true,
            LiveOutputArg::Never => false,
        }
}

fn output_options_from_args(args: &ScanArgs) -> output::OutputOptions {
    output::OutputOptions {
        mac: if args.mask_mac {
            output::MacAddressDisplay::MaskLower24
        } else {
            output::MacAddressDisplay::Full
        },
    }
}

fn scan_configs_from_args(args: &ScanArgs, timeout: Duration) -> Result<Vec<ScanConfig>> {
    let cache_path = store::default_scan_cache_path();
    let oui_path = enrich::default_oui_db_path();
    let interfaces = args
        .interfaces
        .iter()
        .cloned()
        .map(Some)
        .collect::<Vec<_>>();
    let targets = scan_targets_from_args(args)?;
    let fingerprints = FingerprintSelection::from_args(&args.fingerprints, args.profile);

    // Build the interface x target matrix explicitly. Each config maps to one
    // L2 interface and one CIDR so evidence never crosses VLAN or range bounds.
    Ok(interfaces
        .into_iter()
        .flat_map(|iface| {
            targets.iter().cloned().map({
                let cache_path = cache_path.clone();
                let oui_path = oui_path.clone();
                let iface = iface.clone();
                move |target| ScanConfig {
                    target,
                    iface: iface.clone(),
                    profile: args.profile,
                    timeout,
                    concurrency: args.concurrency,
                    oui: fingerprints.oui,
                    rdns: fingerprints.rdns,
                    mdns: fingerprints.mdns,
                    netbios: fingerprints.netbios,
                    upnp: fingerprints.upnp,
                    snmp: fingerprints.snmp,
                    snmp_community: args.snmp_community.clone(),
                    lldp: fingerprints.lldp,
                    cdp: fingerprints.cdp,
                    dhcp: fingerprints.dhcp,
                    dhcp_paths: args.dhcp_leases.clone(),
                    cache_enabled: true,
                    cache_path: cache_path.clone(),
                    oui_path: oui_path.clone(),
                }
            })
        })
        .collect())
}

fn scan_targets_from_args(args: &ScanArgs) -> Result<Vec<Option<String>>> {
    if !args.ranges.is_empty() {
        // Each range becomes a separate scan unit. That keeps ARP, multicast,
        // and cache evidence scoped to the same interface/range pair, which is
        // especially important when the same host address exists on different
        // tagged VLANs.
        return args
            .ranges
            .iter()
            .map(|range| net::normalize_cidr_target(range).map(Some))
            .collect();
    }

    Ok(vec![None])
}

fn run_oui(command: OuiCommand) -> Result<()> {
    match command {
        OuiCommand::Update { path } => {
            let path = path.unwrap_or_else(enrich::default_oui_db_path);
            let count = enrich::update_oui_db(&path)?;
            println!("updated {count} OUI prefixes at {}", path.display());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn scan_args() -> ScanArgs {
        ScanArgs {
            dhcp_leases: Vec::new(),
            fingerprints: Vec::new(),
            format: OutputArg::Table,
            live: LiveOutputArg::Auto,
            mask_mac: false,
            concurrency: 128,
            scan_interval_ms: 0,
            profile: ScanProfile::Normal,
            ranges: Vec::new(),
            timeout_ms: None,
            snmp_community: "public".to_string(),
            interfaces: vec!["en0".to_string()],
        }
    }

    #[test]
    fn scan_help_keeps_scan_and_output_in_default_options() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("scan")
            .unwrap()
            .render_help()
            .to_string();

        assert!(
            !help.contains("Scan Options:"),
            "scan options should stay in the default Options section:\n{help}"
        );
        assert!(
            !help.contains("Output Options:"),
            "output options should stay in the default Options section:\n{help}"
        );

        let options = help
            .find("Options:")
            .unwrap_or_else(|| panic!("Options missing from help:\n{help}"));
        let fingerprint = help
            .find("Fingerprint Options:")
            .unwrap_or_else(|| panic!("Fingerprint Options missing from help:\n{help}"));

        assert!(
            options < fingerprint,
            "default options should precede fingerprint options:\n{help}"
        );

        let mut previous = options;
        for option in [
            "--scan.range",
            "--scan.profile",
            "--scan.interval",
            "--scan.timeout",
            "--scan.concurrency",
            "--output.format",
            "--output.live",
            "--output.mask-mac",
        ] {
            let index = help
                .find(option)
                .unwrap_or_else(|| panic!("{option} missing from help:\n{help}"));
            assert!(
                options < index && index < fingerprint,
                "{option} should be in the default Options section:\n{help}"
            );
            assert!(
                previous <= index,
                "{option} should preserve scan-then-output ordering:\n{help}"
            );
            previous = index;
        }
        for option in ["--fingerprint.source", "--dhcp.leases", "--snmp.community"] {
            let index = help
                .find(option)
                .unwrap_or_else(|| panic!("{option} missing from help:\n{help}"));
            assert!(
                fingerprint < index,
                "{option} should be in Fingerprint Options:\n{help}"
            );
        }
    }

    #[test]
    fn version_flags_split_short_and_long_output() {
        let short = Cli::try_parse_from(["fing", "-V"]).unwrap_err();
        let long = Cli::try_parse_from(["fing", "--version"]).unwrap_err();

        assert_eq!(short.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(long.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(
            short.to_string(),
            format!("fing {}\n", env!("CARGO_PKG_VERSION"))
        );

        let long = long.to_string();
        assert!(long.starts_with(&format!("fing {} (git ", env!("CARGO_PKG_VERSION"))));
        assert!(long.contains("; commit "));
        assert!(long.contains("; commit date "));
        assert!(long.contains("; built "));
        assert!(long.contains(") on "));
        assert_ne!(long, short.to_string());
    }

    #[test]
    fn version_flags_propagate_to_subcommands() {
        let short = Cli::try_parse_from(["fing", "scan", "-V"]).unwrap_err();

        assert_eq!(short.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(
            short.to_string(),
            format!("fing-scan {}\n", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn builds_configs_for_every_interface_range_pair() {
        let mut args = scan_args();
        args.interfaces = vec!["en0".to_string(), "en0.100".to_string()];
        args.ranges = vec!["192.168.10.99/24".to_string(), "10.10.40.0/28".to_string()];

        let configs = scan_configs_from_args(&args, Duration::from_millis(1)).unwrap();

        assert_eq!(configs.len(), 4);
        assert_eq!(configs[0].iface.as_deref(), Some("en0"));
        assert_eq!(configs[0].target.as_deref(), Some("192.168.10.0/24"));
        assert_eq!(configs[1].iface.as_deref(), Some("en0"));
        assert_eq!(configs[1].target.as_deref(), Some("10.10.40.0/28"));
        assert_eq!(configs[2].iface.as_deref(), Some("en0.100"));
        assert_eq!(configs[2].target.as_deref(), Some("192.168.10.0/24"));
        assert_eq!(configs[3].iface.as_deref(), Some("en0.100"));
        assert_eq!(configs[3].target.as_deref(), Some("10.10.40.0/28"));
    }

    #[test]
    fn parses_repeated_and_comma_separated_range_options() {
        let cli = Cli::try_parse_from([
            "fing",
            "scan",
            "--scan.range",
            "192.168.10.0/24,192.168.20.0/24",
            "--scan.range",
            "10.0.0.0/30",
            "en0",
        ])
        .unwrap();

        let Commands::Scan(args) = cli.command else {
            panic!("expected scan command");
        };

        assert_eq!(
            args.ranges,
            vec!["192.168.10.0/24", "192.168.20.0/24", "10.0.0.0/30"]
        );
    }

    #[test]
    fn default_scan_has_no_explicit_range() {
        let args = scan_args();

        let configs = scan_configs_from_args(&args, Duration::from_millis(1)).unwrap();

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].iface.as_deref(), Some("en0"));
        assert_eq!(configs[0].target, None);
        assert!(configs[0].oui);
        assert!(configs[0].rdns);
        assert!(configs[0].mdns);
        assert!(configs[0].netbios);
        assert!(configs[0].upnp);
        assert!(configs[0].snmp);
        assert!(!configs[0].lldp);
        assert!(!configs[0].cdp);
        assert!(configs[0].dhcp);
    }

    #[test]
    fn deep_scan_enables_l2_neighbor_protocols_by_default() {
        let mut args = scan_args();
        args.profile = ScanProfile::Deep;

        let configs = scan_configs_from_args(&args, Duration::from_millis(1)).unwrap();

        assert!(configs[0].lldp);
        assert!(configs[0].cdp);
    }

    #[test]
    fn parses_positional_interfaces() {
        let cli = Cli::try_parse_from(["fing", "scan", "en0", "en1", "en0.100"]).unwrap();

        let Commands::Scan(args) = cli.command else {
            panic!("expected scan command");
        };

        assert_eq!(args.interfaces, vec!["en0", "en1", "en0.100"]);
    }

    #[test]
    fn scan_requires_at_least_one_interface() {
        let err = Cli::try_parse_from(["fing", "scan"])
            .unwrap_err()
            .to_string();

        assert!(err.contains("required arguments were not provided"));
    }

    #[test]
    fn parses_canonical_format_option() {
        let cli = Cli::try_parse_from(["fing", "scan", "--output.format", "json", "en0"]).unwrap();

        let Commands::Scan(args) = cli.command else {
            panic!("expected scan command");
        };

        assert!(matches!(args.format, OutputArg::Json));
    }

    #[test]
    fn parses_mac_masking_option() {
        let cli = Cli::try_parse_from(["fing", "scan", "--output.mask-mac", "en0"]).unwrap();

        let Commands::Scan(args) = cli.command else {
            panic!("expected scan command");
        };

        assert!(args.mask_mac);
        assert_eq!(
            output_options_from_args(&args).mac,
            output::MacAddressDisplay::MaskLower24
        );
    }

    #[test]
    fn live_tui_mode_is_one_tristate_option() {
        let cli = Cli::try_parse_from(["fing", "scan", "--output.live", "never", "en0"]).unwrap();

        let Commands::Scan(args) = cli.command else {
            panic!("expected scan command");
        };

        assert_eq!(args.live, LiveOutputArg::Never);
        assert!(should_run_live_tui(
            OutputArg::Table,
            LiveOutputArg::Auto,
            true
        ));
        assert!(!should_run_live_tui(
            OutputArg::Table,
            LiveOutputArg::Auto,
            false
        ));
        assert!(should_run_live_tui(
            OutputArg::Table,
            LiveOutputArg::Always,
            false
        ));
        assert!(!should_run_live_tui(
            OutputArg::Table,
            LiveOutputArg::Never,
            true
        ));
        assert!(!should_run_live_tui(
            OutputArg::Json,
            LiveOutputArg::Always,
            true
        ));
    }

    #[test]
    fn fingerprint_sources_are_an_allowlist_when_specified() {
        let cli = Cli::try_parse_from([
            "fing",
            "scan",
            "--fingerprint.source",
            "dhcp,mdns,lldp,cdp",
            "--fingerprint.source",
            "snmp",
            "en0",
        ])
        .unwrap();

        let Commands::Scan(args) = cli.command else {
            panic!("expected scan command");
        };

        assert_eq!(
            args.fingerprints,
            vec![
                FingerprintSourceArg::Dhcp,
                FingerprintSourceArg::Mdns,
                FingerprintSourceArg::Lldp,
                FingerprintSourceArg::Cdp,
                FingerprintSourceArg::Snmp,
            ]
        );

        let configs = scan_configs_from_args(&args, Duration::from_millis(1)).unwrap();
        assert!(!configs[0].oui);
        assert!(!configs[0].rdns);
        assert!(configs[0].mdns);
        assert!(!configs[0].netbios);
        assert!(!configs[0].upnp);
        assert!(configs[0].snmp);
        assert!(configs[0].lldp);
        assert!(configs[0].cdp);
        assert!(configs[0].dhcp);
    }

    #[test]
    fn parses_scan_interval_option() {
        let cli = Cli::try_parse_from(["fing", "scan", "--scan.interval", "2500", "en0"]).unwrap();

        let Commands::Scan(args) = cli.command else {
            panic!("expected scan command");
        };

        assert_eq!(args.scan_interval_ms, 2500);
    }

    #[test]
    fn default_scan_interval_is_zero_for_continuous_scanning() {
        let cli = Cli::try_parse_from(["fing", "scan", "en0"]).unwrap();

        let Commands::Scan(args) = cli.command else {
            panic!("expected scan command");
        };

        assert_eq!(args.scan_interval_ms, 0);
    }
}
