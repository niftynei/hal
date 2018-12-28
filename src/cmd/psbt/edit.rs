use std::fs::File;
use std::io::Write;

use clap;
use base64;
use hex;
use secp256k1;

use bitcoin::util::psbt;
use bitcoin::util::bip32;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;

pub fn subcommand<'a>() -> clap::App<'a, 'a> {
	clap::SubCommand::with_name("edit")
		.about("edit a PSBT")
		.arg(
			clap::Arg::with_name("psbt")
				.help("PSBT to edit, either hex or a file reference")
				.takes_value(true)
				.required(true),
		)
		.arg(
			clap::Arg::with_name("input-idx")
				.long("nin")
				.help("the input index to edit")
				.display_order(1)
				.takes_value(true)
				.required(false),
		)
		.arg(
			clap::Arg::with_name("output-idx")
				.long("nout")
				.help("the output index to edit")
				.display_order(2)
				.takes_value(true)
				.required(false),
		)
		.arg(
			clap::Arg::with_name("output")
				.long("output")
				.short("o")
				.help("where to save the resulting PSBT file -- in place if omitted")
				.display_order(3)
				.next_line_help(true)
				.takes_value(true)
				.required(false),
		)
		.arg(
			clap::Arg::with_name("raw-stdout")
				.long("raw")
				.short("r")
				.help("output the raw bytes of the result to stdout")
				.required(false),
		)
		.args(
			// values used in inputs and outputs
			&[
				clap::Arg::with_name("redeem-script")
					.long("redeem-script")
					.help("the redeem script")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				clap::Arg::with_name("witness-script")
					.long("witness-script")
					.help("the witness script")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				clap::Arg::with_name("hd-keypaths")
					.long("hd-keypaths")
					.help("the HD wallet keypaths `<pubkey>:<master-fingerprint>:<path>,...`")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				clap::Arg::with_name("hd-keypaths-add")
					.long("hd-keypaths-add")
					.help("add an HD wallet keypath `<pubkey>:<master-fingerprint>:<path>`")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
			]
		)
		.args(
			// input values
			&[
				clap::Arg::with_name("non-witness-utxo")
					.long("non-witness-utxo")
					.help("the non-witness UTXO field in hex (full transaction)")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				clap::Arg::with_name("witness-utxo")
					.long("witness-utxo")
					.help("the witness UTXO field in hex (only output)")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				clap::Arg::with_name("partial-sigs")
					.long("partial-sigs")
					.help("set partial sigs `<pubkey>:<signature>,...`")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				clap::Arg::with_name("partial-sigs-add")
					.long("partial-sigs-add")
					.help("add a partial sig pair `<pubkey>:<signature>`")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				clap::Arg::with_name("sighash-type")
					.long("sighash-type")
					.help("the sighash type")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				// redeem-script
				// witness-script
				// hd-keypaths
				// hd-keypaths-add
				clap::Arg::with_name("final-script-sig")
					.long("final-script-sig")
					.help("set final script signature")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
				clap::Arg::with_name("final-script-witness")
					.long("final-script-witness")
					.help("set final script witness as comma-separated hex values")
					.display_order(99)
					.next_line_help(true)
					.takes_value(true)
					.required(false),
			]
		)
		.args(
			// output values
			&[
				// redeem-script
				// witness-script
				// hd-keypaths
				// hd-keypaths-add
			]
		)
}

/// Parses a `<pubkey>:<signature>` pair.
fn parse_partial_sig_pair(pair_str: &str) -> (secp256k1::PublicKey, Vec<u8>) {
	let mut pair = pair_str.splitn(2, ":");
	let pubkey = {
		let hex = pair.next().expect("invalid partial sig pair: missing pubkey");
		let raw = hex::decode(&hex).expect("invalid partial sig pubkey hex");
		secp256k1::PublicKey::from_slice(&raw).expect("invalid partial sig pubkey")
	};
	let sig = {
		let hex = pair.next().expect("invalid partial sig pair: missing signature");
		hex::decode(&hex).expect("invalid partial sig signature hex")
	};
	(pubkey, sig)
}

//TODO(stevenroose) replace once PR is merged:
// https://github.com/rust-bitcoin/rust-bitcoin/pull/185
fn parse_child_number(inp: &str) -> bip32::ChildNumber {
	match inp.chars().last().map_or(false, |l| l == '\'' || l == 'h') {
		true => bip32::ChildNumber::from_hardened_idx(
			inp[0..inp.len() - 1].parse().expect("invalid derivation path format")
		),
		false => bip32::ChildNumber::from_normal_idx(
			inp.parse().expect("invalid derivation path format")
		),
	}
}
fn parse_derivation_path(path: &str) -> Vec<bip32::ChildNumber> {
    let mut parts = path.split("/");
    // First parts must be `m`.
    if parts.next().unwrap() != "m" {
		panic!("invalid derivation path format");
    }

    // Empty parts are a format error.
    if parts.clone().any(|p| p.len() == 0) {
		panic!("invalid derivation path format");
    }

    parts.map(parse_child_number).collect()
}

fn parse_hd_keypath_triplet(triplet_str: &str) -> (secp256k1::PublicKey, (bip32::Fingerprint, Vec<bip32::ChildNumber>)) {
	let mut triplet = triplet_str.splitn(3, ":");
	let pubkey = {
		let hex = triplet.next().expect("invalid HD keypath triplet: missing pubkey");
		let raw = hex::decode(&hex).expect("invalid HD keypath pubkey hex");
		secp256k1::PublicKey::from_slice(&raw).expect("invalid HD keypath pubkey")
	};
	let fp = {
		let hex = triplet.next().expect("invalid HD keypath triplet: missing fingerprint");
		let raw = hex::decode(&hex).expect("invalid HD keypath fingerprint hex");
		if raw.len() != 4 {
			panic!("invalid HD keypath fingerprint size: {} instead of 4", raw.len());
		}
		raw[..].into()
	};
	let path = {
		let path = triplet.next().expect("invalid HD keypath triplet: missing HD path");
		parse_derivation_path(path)
	};
	(pubkey, (fp, path))
}

fn edit_input<'a>(idx: usize, matches: &clap::ArgMatches<'a>, psbt: &mut psbt::PartiallySignedTransaction) {
	let input = psbt.inputs.get_mut(idx).expect("input index out of range");

	if let Some(hex) = matches.value_of("non-witness-utxo") {
		let raw = hex::decode(&hex).expect("invalid non-witness-utxo hex");
		let utxo = deserialize(&raw).expect("invalid non-witness-utxo transaction");
		input.non_witness_utxo = Some(utxo);
	}

	if let Some(hex) = matches.value_of("witness-utxo") {
		let raw = hex::decode(&hex).expect("invalid witness-utxo hex");
		let utxo = deserialize(&raw).expect("invalid witness-utxo transaction");
		input.witness_utxo = Some(utxo);
	}

	if let Some(csv) = matches.value_of("partial-sigs") {
		let pairs = csv.split(",").map(parse_partial_sig_pair);
		input.partial_sigs = pairs.collect();
	}
	if let Some(pairs_str) = matches.values_of("partial-sigs-add") {
		let pairs = pairs_str.map(parse_partial_sig_pair);
		for (pk, sig) in pairs {
			if input.partial_sigs.insert(pk, sig).is_some() {
				panic!("public key {} is already in partial sigs", &pk);
			}
		}
	}

	if let Some(sht) = matches.value_of("sighash-type") {
		input.sighash_type = Some(hal::psbt::sighashtype_from_string(&sht));
	}

	if let Some(hex) = matches.value_of("redeem-script") {
		let raw = hex::decode(&hex).expect("invalid redeem-script hex");
		input.redeem_script = Some(raw.into());
	}

	if let Some(hex) = matches.value_of("witness-script") {
		let raw = hex::decode(&hex).expect("invalid witness-script hex");
		input.witness_script = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("hd-keypaths") {
		let triplets = csv.split(",").map(parse_hd_keypath_triplet);
		input.hd_keypaths = triplets.collect();
	}
	if let Some(triplets_str) = matches.values_of("hd-keypaths-add") {
		let triplets = triplets_str.map(parse_hd_keypath_triplet);
		for (pk, pair) in triplets {
			if input.hd_keypaths.insert(pk, pair).is_some() {
				panic!("public key {} is already in HD keypaths", &pk);
			}
		}
	}

	if let Some(hex) = matches.value_of("final-script-sig") {
		let raw = hex::decode(&hex).expect("invalid final-script-sig hex");
		input.final_script_sig = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("final-script-witness") {
		let vhex = csv.split(",");
		let vraw = vhex.map(|h| hex::decode(&h).expect("invalid final-script-witness hex"));
		input.final_script_witness = Some(vraw.collect());
	}
}

fn edit_output<'a>(idx: usize, matches: &clap::ArgMatches<'a>, psbt: &mut psbt::PartiallySignedTransaction) {
	let output = psbt.outputs.get_mut(idx).expect("output index out of range");

	if let Some(hex) = matches.value_of("redeem-script") {
		let raw = hex::decode(&hex).expect("invalid redeem-script hex");
		output.redeem_script = Some(raw.into());
	}

	if let Some(hex) = matches.value_of("witness-script") {
		let raw = hex::decode(&hex).expect("invalid witness-script hex");
		output.witness_script = Some(raw.into());
	}

	if let Some(csv) = matches.value_of("hd-keypaths") {
		let triplets = csv.split(",").map(parse_hd_keypath_triplet);
		output.hd_keypaths = triplets.collect();
	}
	if let Some(triplets_str) = matches.values_of("hd-keypaths-add") {
		let triplets = triplets_str.map(parse_hd_keypath_triplet);
		for (pk, pair) in triplets {
			if output.hd_keypaths.insert(pk, pair).is_some() {
				panic!("public key {} is already in HD keypaths", &pk);
			}
		}
	}
}

pub fn execute<'a>(matches: &clap::ArgMatches<'a>) {
	let (raw, source) = super::file_or_raw(&matches.value_of("psbt").unwrap());
	let mut psbt: psbt::PartiallySignedTransaction =
		deserialize(&raw).expect("invalid PSBT format");

	match (matches.value_of("input-idx"), matches.value_of("output-idx")) {
		(None, None) => panic!("no input or output index provided"),
		(Some(_), Some(_)) => panic!("can only edit an input or an output at a time"),
		(Some(idx), _) => edit_input(idx.parse().expect("invalid input index"), &matches, &mut psbt),
		(_, Some(idx)) => edit_output(idx.parse().expect("invalid output index"), &matches, &mut psbt),
	}

	let edited_raw = serialize(&psbt);
	if let Some(path) = matches.value_of("output") {
		let mut file = File::create(&path).expect("failed to open output file");
		file.write_all(&edited_raw).expect("error writing output file");
	} else if matches.is_present("raw-stdout") {
		::std::io::stdout().write_all(&edited_raw).unwrap();
	} else {
		match source {
			super::PsbtSource::Hex => print!("{}", hex::encode(&edited_raw)),
			super::PsbtSource::Base64 => print!("{}", base64::encode(&edited_raw)),
			super::PsbtSource::File => {
				let path = matches.value_of("psbt").unwrap();
				let mut file = File::create(&path).expect("failed to PSBT file for writing");
				file.write_all(&edited_raw).expect("error writing PSBT file");
			},
		}
	}
}

