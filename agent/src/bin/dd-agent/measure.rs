use dd_agent::attestation::tsm;

/// Run the agent in "measure" mode.
///
/// Generates TDX measurements for the currently running VM and prints
/// them to stdout so they can be captured by tooling.
pub fn run_measure_mode() {
    eprintln!("dd-agent: entering measure mode");

    // In a real TDX VM this would generate a live quote.  When running
    // outside a TDX environment the tsm calls will fail, which is
    // expected during development.
    match tsm::generate_tdx_quote_base64(None) {
        Ok(b64_quote) => match tsm::parse_tdx_quote_base64(&b64_quote) {
            Ok(parsed) => {
                println!("mrtd:        {}", parsed.mrtd_hex());
                println!("rtmr0:       {}", parsed.rtmr_hex(0));
                println!("rtmr1:       {}", parsed.rtmr_hex(1));
                println!("rtmr2:       {}", parsed.rtmr_hex(2));
                println!("rtmr3:       {}", parsed.rtmr_hex(3));
                println!("report_data: {}", parsed.report_data_hex());
                println!("quote_b64:   {b64_quote}");
            }
            Err(e) => {
                eprintln!("failed to parse generated quote: {e}");
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("failed to generate TDX quote: {e}");
            eprintln!("(this is expected when not running inside a TDX VM)");
            std::process::exit(1);
        }
    }
}
