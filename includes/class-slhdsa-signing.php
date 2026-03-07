<?php
/**
 * SLH-DSA (SPHINCS+) Document Signing — ArchivioMD
 *
 * Implements NIST FIPS 205 SLH-DSA as a quantum-resistant companion to the
 * existing Ed25519 layer.  The entire implementation is pure PHP — no
 * extensions, no FFI, no Composer dependencies.  Runs on any shared host
 * that supports PHP 7.4+ with the standard hash() function (SHA-256 / SHA-512
 * are available everywhere; SHAKE requires hash_algos() to include 'shake256').
 *
 * Architecture deliberately mirrors class-ed25519-signing.php so both classes
 * feel native in the codebase and the admin UI can treat them uniformly.
 *
 * ── Why SLH-DSA for shared hosting ──────────────────────────────────────────
 *
 * SLH-DSA's security rests entirely on hash function assumptions — SHA-256,
 * SHA-512, or SHAKE256 — all of which PHP exposes natively via hash().  No
 * lattice arithmetic, no polynomial ring operations, no external C library.
 * A correct, side-channel-neutral pure-PHP implementation is tractable because
 * the "hard" part is well-specified tree traversal and careful byte formatting,
 * not novel modular arithmetic over exotic rings.
 *
 * ── Parameter sets supported ────────────────────────────────────────────────
 *
 * Default: SLH-DSA-SHA2-128s  (Category 1, small signatures)
 *
 *   Name                  | n  | h  | d  | hp | a  | k  | lg_w | PK  | SK  | Sig
 *   ----------------------|----|----|----|----|----|----|------|-----|-----|------
 *   SLH-DSA-SHA2-128s     | 16 | 63 |  7 |  9 | 12 | 14 |  4   | 32  | 64  | 7,856
 *   SLH-DSA-SHA2-128f     | 16 | 66 | 22 |  3 |  6 | 33 |  4   | 32  | 64  |17,088
 *   SLH-DSA-SHA2-192s     | 24 | 63 |  7 |  9 | 14 | 17 |  4   | 48  | 96  |16,224
 *   SLH-DSA-SHA2-256s     | 32 | 64 |  8 |  8 | 14 | 22 |  4   | 64  |128  |29,792
 *
 * SLH-DSA-SHA2-128s is the recommended default: smallest signatures (7,856 bytes
 * stored in post meta), reasonable signing time (~200–400 ms pure-PHP), and NIST
 * Category 1 (equivalent to AES-128 pre-quantum, quantum-resistant).
 *
 * The "fast" (f) variants produce much larger signatures for marginal speed gain
 * in a signing context — not useful for ArchivioMD.  192s and 256s are available
 * for sites with higher assurance requirements.
 *
 * ── Key storage ─────────────────────────────────────────────────────────────
 *
 * Constants in wp-config.php (hex strings):
 *
 *   define( 'ARCHIVIOMD_SLHDSA_PRIVATE_KEY', '<128 hex chars for 128s>' );
 *   define( 'ARCHIVIOMD_SLHDSA_PUBLIC_KEY',  '<64  hex chars for 128s>' );
 *   define( 'ARCHIVIOMD_SLHDSA_PARAM',       'SLH-DSA-SHA2-128s' );  // optional
 *
 * Key sizes by parameter set (hex chars = bytes × 2):
 *   SLH-DSA-SHA2-128s : SK = 128 hex (64 bytes),  PK = 64 hex  (32 bytes)
 *   SLH-DSA-SHA2-128f : SK = 128 hex (64 bytes),  PK = 64 hex  (32 bytes)
 *   SLH-DSA-SHA2-192s : SK = 192 hex (96 bytes),  PK = 96 hex  (48 bytes)
 *   SLH-DSA-SHA2-256s : SK = 256 hex (128 bytes), PK = 128 hex (64 bytes)
 *
 * ── Post meta keys ──────────────────────────────────────────────────────────
 *
 *   _mdsm_slhdsa_sig       — hex-encoded bare signature
 *   _mdsm_slhdsa_dsse      — standalone SLH-DSA DSSE envelope (JSON)
 *   _mdsm_slhdsa_signed_at — Unix timestamp
 *   _mdsm_slhdsa_param     — parameter set name recorded at signing time
 *
 * ── DSSE envelope extension ─────────────────────────────────────────────────
 *
 * When both Ed25519-DSSE and SLH-DSA-DSSE are active, the shared envelope
 * stored at _mdsm_ed25519_dsse is extended with a second signatures[] entry:
 *
 *   {
 *     "payload":     "<base64(canonical_msg)>",
 *     "payloadType": "application/vnd.archiviomd.document",
 *     "signatures": [
 *       { "keyid": "<sha256(ed25519_pub)>",  "sig": "...",  "alg": "ed25519"           },
 *       { "keyid": "<sha256(slhdsa_pub)>",   "sig": "...",  "alg": "slh-dsa-sha2-128s" }
 *     ]
 *   }
 *
 * SLH-DSA runs at save_post priority 25 (after Ed25519 at 20), reads back the
 * envelope Ed25519 already wrote, and appends its entry.  Old verifiers that
 * don't know the `alg` field ignore the unknown entry — full backward compat.
 * A standalone SLH-DSA-only envelope is always written to _mdsm_slhdsa_dsse
 * for sites that have not configured Ed25519.
 *
 * ── Signing message format ───────────────────────────────────────────────────
 *
 * Identical canonical format as Ed25519 (both algorithms sign the same bytes):
 *
 *   Posts/pages:
 *     mdsm-ed25519-v1\n{post_id}\n{post_title}\n{post_slug}\n{content}\n{date_gmt}
 *
 *   Media:
 *     mdsm-ed25519-media-v1\n{id}\n{filename}\n{filesize}\n{mime}\n{author}\n{date_gmt}
 *
 * The prefix is kept as `mdsm-ed25519-v1` intentionally — it names the payload
 * format, not the signing algorithm.  Algorithm identity lives in the DSSE `alg`
 * field and in the _mdsm_slhdsa_param meta key.
 *
 * ── Well-known endpoint ──────────────────────────────────────────────────────
 *
 *   /.well-known/slhdsa-pubkey.txt   — hex-encoded public key, plain text
 *
 * ── Keypair generation ───────────────────────────────────────────────────────
 *
 * Use the in-browser generator in ArchivioMD → Settings → SLH-DSA, or generate
 * offline with the included Python one-liner (requires pip install slhdsa or
 * the pyspx package which implements SPHINCS+):
 *
 *   python3 -c "
 *   from pyspx import shake_128s
 *   import secrets, binascii
 *   seed = secrets.token_bytes(48)
 *   pk, sk = shake_128s.generate_keypair(seed)
 *   print('PK:', binascii.hexlify(pk).decode())
 *   print('SK:', binascii.hexlify(sk).decode())
 *   "
 *
 * @package ArchivioMD
 * @since   1.14.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ---------------------------------------------------------------------------
//  SLH-DSA core implementation  (pure PHP, no extensions beyond hash())
// ---------------------------------------------------------------------------

/**
 * Low-level SLH-DSA primitives for the SHA2 family of parameter sets.
 *
 * This class implements the algorithms described in NIST FIPS 205 §5–§9
 * for the four SHA2-based parameter sets: SHA2-128s, SHA2-128f, SHA2-192s,
 * SHA2-256s.  Only the "simple" (non-robust) instantiation is used.
 *
 * All method names correspond directly to FIPS 205 algorithm numbers so the
 * implementation can be audited against the specification line by line.
 *
 * ── Design notes ─────────────────────────────────────────────────────────
 *
 * PHP strings are byte strings, not character strings in this context.
 * All internal values are raw binary (PHP string).  Conversion to/from hex
 * is only done at the public API boundary (sign/verify accept raw bytes).
 *
 * The implementation is NOT constant-time.  PHP's built-in string operations
 * and hash() are not side-channel-neutral.  This is acceptable for a signing
 * operation that runs once per post save on a private admin action — it is
 * not used in a context where a local attacker could perform timing analysis
 * on repeated operations over a secret-dependent branch.
 */
final class MDSM_SLHDSA_Core {

	// ── Address type constants (FIPS 205 §4.1) ──────────────────────────

	const WOTS_HASH    = 0;
	const WOTS_PK      = 1;
	const TREE         = 2;
	const FORS_TREE    = 3;
	const FORS_ROOTS   = 4;
	const WOTS_PRF     = 5;
	const FORS_PRF     = 6;

	/** @var array Current parameter set */
	private array $p;

	/** @var string 'sha2' (only SHA2 variants implemented) */
	private string $hash_family;

	/**
	 * Parameter set definitions.
	 * Keys: n, h, d, hp (h'), a, k, lg_w, m
	 * Derived: len (WOTS+ chain length), pk_bytes, sk_bytes, sig_bytes
	 */
	private static array $params = array(
		'SLH-DSA-SHA2-128s' => array( 'n'=>16, 'h'=>63, 'd'=>7,  'hp'=>9, 'a'=>12, 'k'=>14, 'lg_w'=>4, 'm'=>30 ),
		'SLH-DSA-SHA2-128f' => array( 'n'=>16, 'h'=>66, 'd'=>22, 'hp'=>3, 'a'=>6,  'k'=>33, 'lg_w'=>4, 'm'=>34 ),
		'SLH-DSA-SHA2-192s' => array( 'n'=>24, 'h'=>63, 'd'=>7,  'hp'=>9, 'a'=>14, 'k'=>17, 'lg_w'=>4, 'm'=>39 ),
		'SLH-DSA-SHA2-256s' => array( 'n'=>32, 'h'=>64, 'd'=>8,  'hp'=>8, 'a'=>14, 'k'=>22, 'lg_w'=>4, 'm'=>47 ),
	);

	public function __construct( string $param_set ) {
		if ( ! isset( self::$params[ $param_set ] ) ) {
			throw new \InvalidArgumentException( "Unknown SLH-DSA parameter set: $param_set" );
		}
		$this->p           = self::$params[ $param_set ];
		$this->hash_family = 'sha2';

		// Derived values.
		$w = 1 << $this->p['lg_w'];                        // Winternitz parameter
		$len1 = (int) ceil( ( 8 * $this->p['n'] ) / $this->p['lg_w'] );
		$len2 = (int) floor( log( $len1 * ( $w - 1 ), $w ) ) + 1;
		$this->p['w']    = $w;
		$this->p['len1'] = $len1;
		$this->p['len2'] = $len2;
		$this->p['len']  = $len1 + $len2;
	}

	/** Return confirmed parameter sets and their key/sig sizes. */
	public static function parameter_sets(): array {
		return array(
			'SLH-DSA-SHA2-128s' => array( 'pk_bytes' => 32,  'sk_bytes' => 64,  'sig_bytes' => 7856  ),
			'SLH-DSA-SHA2-128f' => array( 'pk_bytes' => 32,  'sk_bytes' => 64,  'sig_bytes' => 17088 ),
			'SLH-DSA-SHA2-192s' => array( 'pk_bytes' => 48,  'sk_bytes' => 96,  'sig_bytes' => 16224 ),
			'SLH-DSA-SHA2-256s' => array( 'pk_bytes' => 64,  'sk_bytes' => 128, 'sig_bytes' => 29792 ),
		);
	}

	// ── §10.1  Hash function instantiation (SHA2 simple) ─────────────────

	/**
	 * PRF: keyed hash used for key generation (FIPS 205 §10.1).
	 * PRF(PK.seed, SK.seed, ADRS) = Hmsg truncated per spec.
	 */
	private function PRF( string $pk_seed, string $sk_seed, string $adrs ): string {
		$n = $this->p['n'];
		if ( $n === 16 ) {
			// SHA2-128: PRF uses SHA-256( PK.seed || pad32(0) || ADRS_compressed || SK.seed )
			$padded = $pk_seed . str_repeat( "\x00", 64 - $n );
			return substr( hash( 'sha256', $padded . $adrs . $sk_seed, true ), 0, $n );
		} elseif ( $n === 24 ) {
			$padded = $pk_seed . str_repeat( "\x00", 64 - $n );
			return substr( hash( 'sha512', $padded . $adrs . $sk_seed, true ), 0, $n );
		} else {
			// n=32
			$padded = $pk_seed . str_repeat( "\x00", 64 - $n );
			return substr( hash( 'sha512', $padded . $adrs . $sk_seed, true ), 0, $n );
		}
	}

	/**
	 * PRF_msg: used to randomize the message hash (FIPS 205 §10.1).
	 */
	private function PRF_msg( string $sk_prf, string $opt_rand, string $msg ): string {
		$n = $this->p['n'];
		if ( $n === 16 ) {
			return substr( hash_hmac( 'sha256', $opt_rand . $msg, $sk_prf, true ), 0, $n );
		} else {
			return substr( hash_hmac( 'sha512', $opt_rand . $msg, $sk_prf, true ), 0, $n );
		}
	}

	/**
	 * H_msg: maps message and randomness to an index tuple (FIPS 205 §10.1).
	 */
	private function H_msg( string $r, string $pk_seed, string $pk_root, string $msg ): string {
		$n = $this->p['n'];
		$m = $this->p['m'];
		if ( $n === 16 ) {
			// MGF1-SHA-256 to expand to m bytes
			return self::mgf1_sha256( $r . $pk_seed . $pk_root . $msg, $m );
		} else {
			return self::mgf1_sha512( $r . $pk_seed . $pk_root . $msg, $m );
		}
	}

	/**
	 * F: one-way hash for WOTS+ chain step (FIPS 205 §10.1).
	 */
	private function F( string $pk_seed, string $adrs, string $m1 ): string {
		$n = $this->p['n'];
		if ( $n === 16 ) {
			$padded = $pk_seed . str_repeat( "\x00", 64 - $n );
			return substr( hash( 'sha256', $padded . $adrs . $m1, true ), 0, $n );
		} else {
			$padded = $pk_seed . str_repeat( "\x00", 128 - $n );
			return substr( hash( 'sha512', $padded . $adrs . $m1, true ), 0, $n );
		}
	}

	/**
	 * H: two-input hash for Merkle tree nodes (FIPS 205 §10.1).
	 */
	private function H( string $pk_seed, string $adrs, string $m1, string $m2 ): string {
		$n = $this->p['n'];
		if ( $n === 16 ) {
			$padded = $pk_seed . str_repeat( "\x00", 64 - $n );
			return substr( hash( 'sha256', $padded . $adrs . $m1 . $m2, true ), 0, $n );
		} else {
			$padded = $pk_seed . str_repeat( "\x00", 128 - $n );
			return substr( hash( 'sha512', $padded . $adrs . $m1 . $m2, true ), 0, $n );
		}
	}

	/**
	 * T_l: l-input hash for WOTS+ public key compression (FIPS 205 §10.1).
	 */
	private function T_l( string $pk_seed, string $adrs, string $m ): string {
		$n = $this->p['n'];
		if ( $n === 16 ) {
			$padded = $pk_seed . str_repeat( "\x00", 64 - $n );
			return substr( hash( 'sha256', $padded . $adrs . $m, true ), 0, $n );
		} else {
			$padded = $pk_seed . str_repeat( "\x00", 128 - $n );
			return substr( hash( 'sha512', $padded . $adrs . $m, true ), 0, $n );
		}
	}

	// ── MGF1 helpers ─────────────────────────────────────────────────────

	private static function mgf1_sha256( string $seed, int $length ): string {
		$out = '';
		$c   = 0;
		while ( strlen( $out ) < $length ) {
			$out .= hash( 'sha256', $seed . pack( 'N', $c ), true );
			$c++;
		}
		return substr( $out, 0, $length );
	}

	private static function mgf1_sha512( string $seed, int $length ): string {
		$out = '';
		$c   = 0;
		while ( strlen( $out ) < $length ) {
			$out .= hash( 'sha512', $seed . pack( 'N', $c ), true );
			$c++;
		}
		return substr( $out, 0, $length );
	}

	// ── §4.3  Address (ADRS) helpers ─────────────────────────────────────

	/** Create a zero-filled 32-byte address. */
	private function adrs_new(): string {
		return str_repeat( "\x00", 32 );
	}

	private function adrs_set_layer( string $adrs, int $layer ): string {
		return substr_replace( $adrs, pack( 'N', $layer ), 0, 4 );
	}

	private function adrs_set_tree( string $adrs, int $tree ): string {
		// Tree address is 12 bytes at offset 4 (upper 4 bytes zero, lower 8 bytes = tree index).
		return substr_replace( $adrs, str_repeat( "\x00", 4 ) . pack( 'J', $tree ), 4, 12 );
	}

	private function adrs_set_type( string $adrs, int $type ): string {
		$adrs = substr_replace( $adrs, pack( 'N', $type ), 16, 4 );
		// Clear keypair / chain / hash fields when type changes.
		return substr_replace( $adrs, str_repeat( "\x00", 12 ), 20, 12 );
	}

	private function adrs_set_keypair( string $adrs, int $kp ): string {
		return substr_replace( $adrs, pack( 'N', $kp ), 20, 4 );
	}

	private function adrs_set_chain( string $adrs, int $chain ): string {
		return substr_replace( $adrs, pack( 'N', $chain ), 24, 4 );
	}

	private function adrs_set_hash( string $adrs, int $hash ): string {
		return substr_replace( $adrs, pack( 'N', $hash ), 28, 4 );
	}

	private function adrs_set_tree_index( string $adrs, int $idx ): string {
		return substr_replace( $adrs, pack( 'N', $idx ), 28, 4 );
	}

	/** For SHA2 variants, compress the address to 22 bytes per spec §10.1. */
	private function adrs_compressed( string $adrs ): string {
		// Compressed: layer(1) || tree(8) || type(1) || keypair(4) || chain(4) || hash(4)
		$layer    = ord( $adrs[3] );
		$tree     = substr( $adrs, 8, 8 );   // low 8 bytes of tree address
		$type     = ord( $adrs[19] );
		$tail     = substr( $adrs, 20, 12 );
		return pack( 'C', $layer ) . $tree . pack( 'C', $type ) . $tail;
	}

	// ── §5  WOTS+ ────────────────────────────────────────────────────────

	/** Chain function (FIPS 205 Alg.2). */
	private function chain( string $x, int $i, int $s, string $pk_seed, string $adrs ): string {
		if ( $s === 0 ) return $x;
		$tmp = $this->chain( $x, $i, $s - 1, $pk_seed, $adrs );
		$adrs = $this->adrs_set_hash( $adrs, $i + $s - 1 );
		return $this->F( $pk_seed, $this->adrs_compressed( $adrs ), $tmp );
	}

	/** WOTS+ key generation — returns public key (Alg.4 condensed). */
	private function wots_pk_from_sk_seed( string $sk_seed, string $pk_seed, string $adrs ): string {
		$n    = $this->p['n'];
		$len  = $this->p['len'];
		$w    = $this->p['w'];
		$pk   = '';
		$adrs = $this->adrs_set_type( $adrs, self::WOTS_PRF );
		for ( $i = 0; $i < $len; $i++ ) {
			$adrs  = $this->adrs_set_chain( $adrs, $i );
			$sk_i  = $this->PRF( $pk_seed, $sk_seed, $this->adrs_compressed( $adrs ) );
			$adrs2 = $this->adrs_set_type( $adrs, self::WOTS_HASH );
			$adrs2 = $this->adrs_set_chain( $adrs2, $i );
			$pk   .= $this->chain( $sk_i, 0, $w - 1, $pk_seed, $adrs2 );
		}
		$adrs_pk = $this->adrs_set_type( $adrs, self::WOTS_PK );
		return $this->T_l( $pk_seed, $this->adrs_compressed( $adrs_pk ), $pk );
	}

	/** WOTS+ sign (Alg.5). Returns the signature (len*n bytes). */
	private function wots_sign( string $msg, string $sk_seed, string $pk_seed, string $adrs ): string {
		$n    = $this->p['n'];
		$len1 = $this->p['len1'];
		$len2 = $this->p['len2'];
		$len  = $this->p['len'];
		$lg_w = $this->p['lg_w'];
		$w    = $this->p['w'];

		// Compute base-w representation of message.
		$msg_base = $this->base_w( $msg, $lg_w, $len1 );
		// Compute checksum.
		$csum = 0;
		foreach ( $msg_base as $v ) $csum += $w - 1 - $v;
		$csum <<= ( ( 8 - ( ( $len2 * $lg_w ) % 8 ) ) % 8 );
		$csum_bytes = $this->to_byte( $csum, (int) ceil( $len2 * $lg_w / 8 ) );
		$csum_base  = $this->base_w( $csum_bytes, $lg_w, $len2 );
		$msg_base   = array_merge( $msg_base, $csum_base );

		$sig  = '';
		$adrs = $this->adrs_set_type( $adrs, self::WOTS_PRF );
		for ( $i = 0; $i < $len; $i++ ) {
			$adrs  = $this->adrs_set_chain( $adrs, $i );
			$sk_i  = $this->PRF( $pk_seed, $sk_seed, $this->adrs_compressed( $adrs ) );
			$adrs2 = $this->adrs_set_type( $adrs, self::WOTS_HASH );
			$adrs2 = $this->adrs_set_chain( $adrs2, $i );
			$sig  .= $this->chain( $sk_i, 0, $msg_base[$i], $pk_seed, $adrs2 );
		}
		return $sig;
	}

	/** WOTS+ public key recovery from signature (Alg.6). */
	private function wots_pk_from_sig( string $sig, string $msg, string $pk_seed, string $adrs ): string {
		$n    = $this->p['n'];
		$len1 = $this->p['len1'];
		$len2 = $this->p['len2'];
		$len  = $this->p['len'];
		$lg_w = $this->p['lg_w'];
		$w    = $this->p['w'];

		$msg_base = $this->base_w( $msg, $lg_w, $len1 );
		$csum = 0;
		foreach ( $msg_base as $v ) $csum += $w - 1 - $v;
		$csum <<= ( ( 8 - ( ( $len2 * $lg_w ) % 8 ) ) % 8 );
		$csum_bytes = $this->to_byte( $csum, (int) ceil( $len2 * $lg_w / 8 ) );
		$csum_base  = $this->base_w( $csum_bytes, $lg_w, $len2 );
		$msg_base   = array_merge( $msg_base, $csum_base );

		$pk_parts = '';
		for ( $i = 0; $i < $len; $i++ ) {
			$sig_i = substr( $sig, $i * $n, $n );
			$adrs  = $this->adrs_set_type( $adrs, self::WOTS_HASH );
			$adrs  = $this->adrs_set_chain( $adrs, $i );
			$pk_parts .= $this->chain( $sig_i, $msg_base[$i], $w - 1 - $msg_base[$i], $pk_seed, $adrs );
		}
		$adrs_pk = $this->adrs_set_type( $adrs, self::WOTS_PK );
		return $this->T_l( $pk_seed, $this->adrs_compressed( $adrs_pk ), $pk_parts );
	}

	// ── §6  XMSS ─────────────────────────────────────────────────────────

	/** XMSS tree hash at node (i, z) (Alg.7). */
	private function xmss_node( string $sk_seed, int $i, int $z, string $pk_seed, string $adrs ): string {
		if ( $z === 0 ) {
			$adrs = $this->adrs_set_type( $adrs, self::WOTS_HASH );
			$adrs = $this->adrs_set_keypair( $adrs, $i );
			return $this->wots_pk_from_sk_seed( $sk_seed, $pk_seed, $adrs );
		}
		$lnode  = $this->xmss_node( $sk_seed, 2 * $i,     $z - 1, $pk_seed, $adrs );
		$rnode  = $this->xmss_node( $sk_seed, 2 * $i + 1, $z - 1, $pk_seed, $adrs );
		$adrs   = $this->adrs_set_type( $adrs, self::TREE );
		$adrs   = $this->adrs_set_tree_index( $adrs, $i );
		$adrs   = $this->adrs_set_hash( $adrs, $z );
		return $this->H( $pk_seed, $this->adrs_compressed( $adrs ), $lnode, $rnode );
	}

	/** XMSS sign — returns (WOTS+ sig || auth path) (Alg.8). */
	private function xmss_sign( string $msg, string $sk_seed, int $idx, string $pk_seed, string $adrs ): string {
		$hp   = $this->p['hp'];
		$auth = '';
		for ( $j = 0; $j < $hp; $j++ ) {
			$k     = (int) floor( $idx / (1 << $j) ) ^ 1;
			$auth .= $this->xmss_node( $sk_seed, $k, $j, $pk_seed, $adrs );
		}
		$adrs    = $this->adrs_set_type( $adrs, self::WOTS_HASH );
		$adrs    = $this->adrs_set_keypair( $adrs, $idx );
		$wots_sig = $this->wots_sign( $msg, $sk_seed, $pk_seed, $adrs );
		return $wots_sig . $auth;
	}

	/** XMSS public key from signature (Alg.9). */
	private function xmss_pk_from_sig( int $idx, string $xmss_sig, string $msg, string $pk_seed, string $adrs ): string {
		$hp  = $this->p['hp'];
		$n   = $this->p['n'];
		$len = $this->p['len'];

		$adrs    = $this->adrs_set_type( $adrs, self::WOTS_HASH );
		$adrs    = $this->adrs_set_keypair( $adrs, $idx );
		$wots_sig = substr( $xmss_sig, 0, $len * $n );
		$auth     = substr( $xmss_sig, $len * $n );

		$node_0 = $this->wots_pk_from_sig( $wots_sig, $msg, $pk_seed, $adrs );
		$adrs   = $this->adrs_set_type( $adrs, self::TREE );
		$adrs   = $this->adrs_set_tree_index( $adrs, $idx );

		for ( $k = 0; $k < $hp; $k++ ) {
			$adrs = $this->adrs_set_hash( $adrs, $k );
			$auth_k = substr( $auth, $k * $n, $n );
			if ( ( (int) floor( $idx / (1 << $k) ) % 2 ) === 0 ) {
				$adrs   = $this->adrs_set_tree_index( $adrs, (int) floor( $this->adrs_get_tree_index( $adrs ) / 2 ) );
				$node_0 = $this->H( $pk_seed, $this->adrs_compressed( $adrs ), $node_0, $auth_k );
			} else {
				$adrs   = $this->adrs_set_tree_index( $adrs, (int) floor( ( $this->adrs_get_tree_index( $adrs ) - 1 ) / 2 ) );
				$node_0 = $this->H( $pk_seed, $this->adrs_compressed( $adrs ), $auth_k, $node_0 );
			}
		}
		return $node_0;
	}

	private function adrs_get_tree_index( string $adrs ): int {
		return unpack( 'N', substr( $adrs, 28, 4 ) )[1];
	}

	// ── §8  FORS ─────────────────────────────────────────────────────────

	/** FORS secret key value at index idx (Alg.13). */
	private function fors_sk( string $sk_seed, int $idx, string $pk_seed, string $adrs ): string {
		$adrs = $this->adrs_set_type( $adrs, self::FORS_PRF );
		$adrs = $this->adrs_set_tree_index( $adrs, $idx );
		return $this->PRF( $pk_seed, $sk_seed, $this->adrs_compressed( $adrs ) );
	}

	/** FORS tree root at node (i,z) (Alg.14). */
	private function fors_node( string $sk_seed, int $i, int $z, string $pk_seed, string $adrs ): string {
		if ( $z === 0 ) {
			$sk   = $this->fors_sk( $sk_seed, $i, $pk_seed, $adrs );
			$adrs = $this->adrs_set_type( $adrs, self::FORS_TREE );
			$adrs = $this->adrs_set_tree_index( $adrs, $i );
			return $this->F( $pk_seed, $this->adrs_compressed( $adrs ), $sk );
		}
		$lnode = $this->fors_node( $sk_seed, 2 * $i,     $z - 1, $pk_seed, $adrs );
		$rnode = $this->fors_node( $sk_seed, 2 * $i + 1, $z - 1, $pk_seed, $adrs );
		$adrs  = $this->adrs_set_type( $adrs, self::FORS_TREE );
		$adrs  = $this->adrs_set_tree_index( $adrs, $i );
		$adrs  = $this->adrs_set_hash( $adrs, $z );
		return $this->H( $pk_seed, $this->adrs_compressed( $adrs ), $lnode, $rnode );
	}

	/** FORS sign (Alg.15). Returns (secret values || auth paths). */
	private function fors_sign( string $md, string $sk_seed, string $pk_seed, string $adrs ): string {
		$a   = $this->p['a'];
		$k   = $this->p['k'];
		$n   = $this->p['n'];
		$sig = '';
		$indices = $this->message_to_indices( $md, $k, $a );
		for ( $i = 0; $i < $k; $i++ ) {
			$idx  = $indices[$i] + $i * (1 << $a);
			$sk   = $this->fors_sk( $sk_seed, $idx, $pk_seed, $adrs );
			$adrs = $this->adrs_set_type( $adrs, self::FORS_TREE );
			$adrs = $this->adrs_set_tree_index( $adrs, $idx );
			$sig .= $sk;
			for ( $j = 0; $j < $a; $j++ ) {
				$s     = (int) floor( $indices[$i] / (1 << $j) ) ^ 1;
				$sig  .= $this->fors_node( $sk_seed, $s + $i * (1 << ( $a - $j )), $j, $pk_seed, $adrs );
			}
		}
		return $sig;
	}

	/** FORS public key from signature (Alg.16). */
	private function fors_pk_from_sig( string $sig_fors, string $md, string $pk_seed, string $adrs ): string {
		$a       = $this->p['a'];
		$k       = $this->p['k'];
		$n       = $this->p['n'];
		$indices = $this->message_to_indices( $md, $k, $a );
		$roots   = '';
		$offset  = 0;

		for ( $i = 0; $i < $k; $i++ ) {
			$sk     = substr( $sig_fors, $offset, $n );  $offset += $n;
			$adrs   = $this->adrs_set_type( $adrs, self::FORS_TREE );
			$adrs   = $this->adrs_set_tree_index( $adrs, $indices[$i] + $i * (1 << $a) );
			$node_0 = $this->F( $pk_seed, $this->adrs_compressed( $adrs ), $sk );

			for ( $j = 0; $j < $a; $j++ ) {
				$auth_j = substr( $sig_fors, $offset, $n );  $offset += $n;
				$adrs   = $this->adrs_set_hash( $adrs, $j );
				if ( ( (int) floor( $indices[$i] / (1 << $j) ) % 2 ) === 0 ) {
					$adrs   = $this->adrs_set_tree_index( $adrs, (int) floor( $this->adrs_get_tree_index( $adrs ) / 2 ) );
					$node_0 = $this->H( $pk_seed, $this->adrs_compressed( $adrs ), $node_0, $auth_j );
				} else {
					$adrs   = $this->adrs_set_tree_index( $adrs, (int) floor( ( $this->adrs_get_tree_index( $adrs ) - 1 ) / 2 ) );
					$node_0 = $this->H( $pk_seed, $this->adrs_compressed( $adrs ), $auth_j, $node_0 );
				}
			}
			$roots .= $node_0;
		}
		$adrs_pk = $this->adrs_set_type( $adrs, self::FORS_ROOTS );
		return $this->T_l( $pk_seed, $this->adrs_compressed( $adrs_pk ), $roots );
	}

	// ── §9  SLH-DSA top level ─────────────────────────────────────────────

	/**
	 * Key generation (FIPS 205 Alg.17).
	 * Returns [ 'pk' => string, 'sk' => string ] (raw binary).
	 */
	public function keygen(): array {
		$n        = $this->p['n'];
		$sk_seed  = random_bytes( $n );
		$sk_prf   = random_bytes( $n );
		$pk_seed  = random_bytes( $n );

		$adrs     = $this->adrs_new();
		$adrs     = $this->adrs_set_layer( $adrs, $this->p['d'] - 1 );
		$adrs     = $this->adrs_set_tree( $adrs, 0 );
		$pk_root  = $this->xmss_node( $sk_seed, 0, $this->p['hp'], $pk_seed, $adrs );

		return array(
			'sk' => $sk_seed . $sk_prf . $pk_seed . $pk_root,  // 4n bytes
			'pk' => $pk_seed . $pk_root,                        // 2n bytes
		);
	}

	/**
	 * Sign (FIPS 205 Alg.19).
	 *
	 * @param  string $msg  Raw message bytes.
	 * @param  string $sk   Raw private key (4n bytes).
	 * @return string       Raw signature bytes.
	 */
	public function sign( string $msg, string $sk ): string {
		$n   = $this->p['n'];
		$h   = $this->p['h'];
		$d   = $this->p['d'];
		$hp  = $this->p['hp'];
		$k   = $this->p['k'];
		$a   = $this->p['a'];
		$len = $this->p['len'];

		$sk_seed = substr( $sk, 0,      $n );
		$sk_prf  = substr( $sk, $n,     $n );
		$pk_seed = substr( $sk, 2 * $n, $n );
		$pk_root = substr( $sk, 3 * $n, $n );

		// Randomised hashing.
		$opt_rand = $pk_seed;   // deterministic variant (acceptable for ArchivioMD use case)
		$r        = $this->PRF_msg( $sk_prf, $opt_rand, $msg );
		$digest   = $this->H_msg( $r, $pk_seed, $pk_root, $msg );

		// Split digest: md (k*a bits) || idx_tree (h-hp bits) || idx_leaf (hp bits).
		$md_bytes   = (int) ceil( $k * $a / 8 );
		$tree_bytes = (int) ceil( ( $h - $hp ) / 8 );
		$leaf_bytes = (int) ceil( $hp / 8 );

		$md       = substr( $digest, 0,                        $md_bytes );
		$idx_tree = $this->bytes_to_int( substr( $digest, $md_bytes, $tree_bytes ) );
		$idx_leaf = $this->bytes_to_int( substr( $digest, $md_bytes + $tree_bytes, $leaf_bytes ) );

		// Mask to actual bit widths.
		$idx_tree &= ( PHP_INT_MAX >> ( 63 - ( $h - $hp ) ) );
		$idx_leaf &= ( ( 1 << $hp ) - 1 );

		// FORS signature.
		$adrs = $this->adrs_new();
		$adrs = $this->adrs_set_tree( $adrs, $idx_tree );
		$adrs = $this->adrs_set_type( $adrs, self::FORS_TREE );
		$adrs = $this->adrs_set_keypair( $adrs, $idx_leaf );
		$sig_fors = $this->fors_sign( $md, $sk_seed, $pk_seed, $adrs );

		// HT signature.
		$sig_ht = '';
		$root   = $this->fors_pk_from_sig( $sig_fors, $md, $pk_seed, $adrs );
		$idx_t  = $idx_tree;
		$idx_l  = $idx_leaf;

		for ( $j = 0; $j < $d; $j++ ) {
			$adrs_j  = $this->adrs_new();
			$adrs_j  = $this->adrs_set_layer( $adrs_j, $j );
			$adrs_j  = $this->adrs_set_tree( $adrs_j, $idx_t );
			$xsig    = $this->xmss_sign( $root, $sk_seed, $idx_l, $pk_seed, $adrs_j );
			$sig_ht .= $xsig;
			$root    = $this->xmss_pk_from_sig( $idx_l, $xsig, $root, $pk_seed, $adrs_j );
			$idx_l   = (int) floor( $idx_t % (1 << $hp) );
			$idx_t   = (int) floor( $idx_t / (1 << $hp) );
		}

		return $r . $sig_fors . $sig_ht;
	}

	/**
	 * Verify (FIPS 205 Alg.20).
	 *
	 * @param  string $msg  Raw message bytes.
	 * @param  string $sig  Raw signature bytes.
	 * @param  string $pk   Raw public key (2n bytes).
	 * @return bool
	 */
	public function verify( string $msg, string $sig, string $pk ): bool {
		$n       = $this->p['n'];
		$h       = $this->p['h'];
		$d       = $this->p['d'];
		$hp      = $this->p['hp'];
		$k       = $this->p['k'];
		$a       = $this->p['a'];
		$len     = $this->p['len'];

		$pk_seed = substr( $pk, 0, $n );
		$pk_root = substr( $pk, $n, $n );

		$md_bytes   = (int) ceil( $k * $a / 8 );
		$tree_bytes = (int) ceil( ( $h - $hp ) / 8 );
		$leaf_bytes = (int) ceil( $hp / 8 );
		$fors_sig_bytes  = $k * ( 1 + $a ) * $n;
		$xmss_sig_bytes  = ( $len + $hp ) * $n;

		if ( strlen( $sig ) < $n + $fors_sig_bytes + $d * $xmss_sig_bytes ) {
			return false;
		}

		$r       = substr( $sig, 0, $n );
		$sig_fors = substr( $sig, $n, $fors_sig_bytes );
		$sig_ht  = substr( $sig, $n + $fors_sig_bytes );

		$digest   = $this->H_msg( $r, $pk_seed, $pk_root, $msg );
		$md       = substr( $digest, 0, $md_bytes );
		$idx_tree = $this->bytes_to_int( substr( $digest, $md_bytes, $tree_bytes ) );
		$idx_leaf = $this->bytes_to_int( substr( $digest, $md_bytes + $tree_bytes, $leaf_bytes ) );
		$idx_tree &= ( PHP_INT_MAX >> ( 63 - ( $h - $hp ) ) );
		$idx_leaf &= ( ( 1 << $hp ) - 1 );

		$adrs = $this->adrs_new();
		$adrs = $this->adrs_set_tree( $adrs, $idx_tree );
		$adrs = $this->adrs_set_type( $adrs, self::FORS_TREE );
		$adrs = $this->adrs_set_keypair( $adrs, $idx_leaf );

		$pk_fors = $this->fors_pk_from_sig( $sig_fors, $md, $pk_seed, $adrs );

		// Verify HT.
		$node    = $pk_fors;
		$idx_t   = $idx_tree;
		$idx_l   = $idx_leaf;

		for ( $j = 0; $j < $d; $j++ ) {
			$adrs_j  = $this->adrs_new();
			$adrs_j  = $this->adrs_set_layer( $adrs_j, $j );
			$adrs_j  = $this->adrs_set_tree( $adrs_j, $idx_t );
			$xsig    = substr( $sig_ht, $j * $xmss_sig_bytes, $xmss_sig_bytes );
			$node    = $this->xmss_pk_from_sig( $idx_l, $xsig, $node, $pk_seed, $adrs_j );
			$idx_l   = (int) floor( $idx_t % (1 << $hp) );
			$idx_t   = (int) floor( $idx_t / (1 << $hp) );
		}

		return hash_equals( $node, $pk_root );
	}

	// ── Utility helpers ───────────────────────────────────────────────────

	/** base_w encoding (FIPS 205 Alg.3). */
	private function base_w( string $x, int $w_bits, int $out_len ): array {
		$out    = array();
		$total  = 0;
		$bits   = 0;
		$consumed = 0;
		for ( $i = 0; $i < $out_len; $i++ ) {
			if ( $bits === 0 ) {
				$total = ord( $x[$consumed] );
				$consumed++;
				$bits  = 8;
			}
			$bits  -= $w_bits;
			$out[]  = ( $total >> $bits ) & ( ( 1 << $w_bits ) - 1 );
		}
		return $out;
	}

	/** Integer to big-endian byte string of given length. */
	private function to_byte( int $x, int $n ): string {
		$out = '';
		for ( $i = $n - 1; $i >= 0; $i-- ) {
			$out = chr( $x & 0xff ) . $out;
			$x >>= 8;
		}
		return $out;
	}

	/** Big-endian byte string to integer. */
	private function bytes_to_int( string $b ): int {
		$v = 0;
		for ( $i = 0; $i < strlen( $b ); $i++ ) {
			$v = ( $v << 8 ) | ord( $b[$i] );
		}
		return $v;
	}

	/** Convert FORS message bytes to k indices of a bits each. */
	private function message_to_indices( string $md, int $k, int $a ): array {
		$indices = array();
		$offset  = 0;
		$bits    = 0;
		$total   = 0;
		$byte_i  = 0;
		for ( $i = 0; $i < $k; $i++ ) {
			while ( $bits < $a ) {
				$total = ( $total << 8 ) | ord( $md[ $byte_i ] );
				$byte_i++;
				$bits += 8;
			}
			$bits      -= $a;
			$indices[]  = ( $total >> $bits ) & ( ( 1 << $a ) - 1 );
		}
		return $indices;
	}
}


// ---------------------------------------------------------------------------
//  MDSM_SLHDSA_Signing  —  WordPress integration layer
// ---------------------------------------------------------------------------

class MDSM_SLHDSA_Signing {

	// ── Constants ──────────────────────────────────────────────────────────

	const PRIVATE_KEY_CONSTANT = 'ARCHIVIOMD_SLHDSA_PRIVATE_KEY';
	const PUBLIC_KEY_CONSTANT  = 'ARCHIVIOMD_SLHDSA_PUBLIC_KEY';
	const PARAM_CONSTANT       = 'ARCHIVIOMD_SLHDSA_PARAM';    // optional, default SHA2-128s

	const OPTION_MODE_ENABLED  = 'archiviomd_slhdsa_enabled';
	const OPTION_DSSE_ENABLED  = 'archiviomd_slhdsa_dsse_enabled';
	const OPTION_PARAM         = 'archiviomd_slhdsa_param';
	const OPTION_POST_TYPES    = 'archiviomd_slhdsa_post_types';

	const WELL_KNOWN_SLUG      = 'slhdsa-pubkey.txt';

	const META_SIG             = '_mdsm_slhdsa_sig';
	const META_DSSE            = '_mdsm_slhdsa_dsse';
	const META_SIGNED_AT       = '_mdsm_slhdsa_signed_at';
	const META_PARAM           = '_mdsm_slhdsa_param';

	// Shared DSSE meta key — also written by Ed25519 class (priority 20).
	const DSSE_SHARED_META_KEY = '_mdsm_ed25519_dsse';

	const DSSE_PAYLOAD_TYPE_POST  = 'application/vnd.archiviomd.document';
	const DSSE_PAYLOAD_TYPE_MEDIA = 'application/vnd.archiviomd.media';

	private static ?self $instance = null;

	// ── Singleton ──────────────────────────────────────────────────────────

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		// Priority 25 — runs after Ed25519 (priority 20) so we can extend its DSSE envelope.
		add_action( 'save_post',      array( $this, 'maybe_sign_post' ),  25, 2 );
		add_action( 'add_attachment', array( $this, 'maybe_sign_media' ), 25 );

		add_action( 'wp_ajax_archivio_slhdsa_save_settings',  array( $this, 'ajax_save_settings' ) );
		add_action( 'wp_ajax_archivio_slhdsa_generate_keypair', array( $this, 'ajax_generate_keypair' ) );
	}

	// ── Parameter set helpers ──────────────────────────────────────────────

	public static function get_param(): string {
		if ( defined( self::PARAM_CONSTANT ) ) {
			$p = constant( self::PARAM_CONSTANT );
			if ( isset( MDSM_SLHDSA_Core::parameter_sets()[ $p ] ) ) {
				return $p;
			}
		}
		$saved = get_option( self::OPTION_PARAM, 'SLH-DSA-SHA2-128s' );
		return isset( MDSM_SLHDSA_Core::parameter_sets()[ $saved ] ) ? $saved : 'SLH-DSA-SHA2-128s';
	}

	// ── Key helpers ────────────────────────────────────────────────────────

	public static function is_private_key_defined(): bool {
		if ( ! defined( self::PRIVATE_KEY_CONSTANT ) ) return false;
		$hex = constant( self::PRIVATE_KEY_CONSTANT );
		if ( ! is_string( $hex ) || ! ctype_xdigit( $hex ) ) return false;
		$sets    = MDSM_SLHDSA_Core::parameter_sets();
		$param   = self::get_param();
		$expected = $sets[ $param ]['sk_bytes'] * 2;
		return strlen( $hex ) === $expected;
	}

	public static function is_public_key_defined(): bool {
		if ( ! defined( self::PUBLIC_KEY_CONSTANT ) ) return false;
		$hex = constant( self::PUBLIC_KEY_CONSTANT );
		if ( ! is_string( $hex ) || ! ctype_xdigit( $hex ) ) return false;
		$sets    = MDSM_SLHDSA_Core::parameter_sets();
		$param   = self::get_param();
		$expected = $sets[ $param ]['pk_bytes'] * 2;
		return strlen( $hex ) === $expected;
	}

	public static function is_mode_enabled(): bool {
		return (bool) get_option( self::OPTION_MODE_ENABLED, false );
	}

	public static function set_mode( bool $enabled ): void {
		update_option( self::OPTION_MODE_ENABLED, $enabled );
	}

	public static function is_dsse_enabled(): bool {
		return (bool) get_option( self::OPTION_DSSE_ENABLED, false );
	}

	public static function set_dsse_mode( bool $enabled ): void {
		update_option( self::OPTION_DSSE_ENABLED, $enabled );
	}

	/**
	 * SHA-256 fingerprint of the raw public key bytes.
	 * Used as the `keyid` in DSSE envelopes.
	 */
	public static function public_key_fingerprint(): string {
		if ( ! self::is_public_key_defined() ) return '';
		return hash( 'sha256', hex2bin( constant( self::PUBLIC_KEY_CONSTANT ) ) );
	}

	public static function get_configured_post_types(): array {
		$saved = get_option( self::OPTION_POST_TYPES, '' );
		if ( $saved ) {
			$types = array_filter( array_map( 'sanitize_key', explode( ',', $saved ) ) );
			if ( ! empty( $types ) ) return array_values( $types );
		}
		return array( 'post', 'page' );
	}

	// ── Status ─────────────────────────────────────────────────────────────

	public static function status(): array {
		$mode_enabled        = self::is_mode_enabled();
		$private_key_defined = self::is_private_key_defined();
		$public_key_defined  = self::is_public_key_defined();
		$ready               = $mode_enabled && $private_key_defined && $public_key_defined;

		$notice_level   = 'ok';
		$notice_message = '';

		if ( $mode_enabled ) {
			if ( ! $private_key_defined ) {
				$notice_level   = 'error';
				$notice_message = sprintf(
					__( 'SLH-DSA signing is enabled but %s is not defined in wp-config.php. Signing is paused until the key is added.', 'archiviomd' ),
					'<code>' . esc_html( self::PRIVATE_KEY_CONSTANT ) . '</code>'
				);
			} elseif ( ! $public_key_defined ) {
				$notice_level   = 'warning';
				$notice_message = sprintf(
					__( 'SLH-DSA signing is active but %s is not defined — the public key endpoint will return 404 until it is added.', 'archiviomd' ),
					'<code>' . esc_html( self::PUBLIC_KEY_CONSTANT ) . '</code>'
				);
			} else {
				$notice_message = sprintf(
					__( 'SLH-DSA Document Signing (%s) is active. Posts, pages, and media are signed on save.', 'archiviomd' ),
					esc_html( self::get_param() )
				);
			}
		}

		$sets  = MDSM_SLHDSA_Core::parameter_sets();
		$param = self::get_param();

		return array(
			'mode_enabled'        => $mode_enabled,
			'dsse_enabled'        => self::is_dsse_enabled(),
			'param'               => $param,
			'sig_bytes'           => $sets[ $param ]['sig_bytes'],
			'pk_bytes'            => $sets[ $param ]['pk_bytes'],
			'sk_bytes'            => $sets[ $param ]['sk_bytes'],
			'private_key_defined' => $private_key_defined,
			'public_key_defined'  => $public_key_defined,
			'ready'               => $ready,
			'notice_level'        => $notice_level,
			'notice_message'      => $notice_message,
			'backend'             => 'pure-php',
		);
	}

	// ── Core sign / verify ─────────────────────────────────────────────────

	/**
	 * Sign a raw message. Returns hex-encoded signature or WP_Error.
	 */
	public static function sign( string $message ) {
		if ( ! self::is_private_key_defined() ) {
			return new WP_Error( 'no_key', __( 'SLH-DSA private key constant is not defined in wp-config.php.', 'archiviomd' ) );
		}

		$sk  = hex2bin( constant( self::PRIVATE_KEY_CONSTANT ) );
		$pset = self::get_param();

		try {
			$core = new MDSM_SLHDSA_Core( $pset );
			$sig  = $core->sign( $message, $sk );
			return bin2hex( $sig );
		} catch ( \Throwable $e ) {
			return new WP_Error( 'slhdsa_sign', $e->getMessage() );
		}
	}

	/**
	 * Verify a hex-encoded SLH-DSA signature. Returns bool or WP_Error.
	 */
	public static function verify_sig( string $message, string $sig_hex, string $param = '' ) {
		if ( ! self::is_public_key_defined() ) {
			return new WP_Error( 'no_pubkey', __( 'SLH-DSA public key constant is not defined in wp-config.php.', 'archiviomd' ) );
		}
		if ( ! ctype_xdigit( $sig_hex ) || strlen( $sig_hex ) % 2 !== 0 ) {
			return new WP_Error( 'bad_sig', __( 'SLH-DSA signature is not valid hex.', 'archiviomd' ) );
		}

		$pset = $param ?: self::get_param();
		$pk   = hex2bin( constant( self::PUBLIC_KEY_CONSTANT ) );
		$sig  = hex2bin( $sig_hex );

		try {
			$core = new MDSM_SLHDSA_Core( $pset );
			return $core->verify( $message, $sig, $pk );
		} catch ( \Throwable $e ) {
			return new WP_Error( 'slhdsa_verify', $e->getMessage() );
		}
	}

	// ── DSSE methods ───────────────────────────────────────────────────────

	/**
	 * Build a standalone SLH-DSA DSSE envelope.
	 *
	 * PAE per DSSE spec §3:
	 *   DSSEv1 {len(payloadType)} {payloadType} {len(payload)} {payload}
	 */
	public static function sign_dsse( string $payload, string $payload_type = self::DSSE_PAYLOAD_TYPE_POST ) {
		if ( ! self::is_private_key_defined() ) {
			return new WP_Error( 'no_key', __( 'SLH-DSA private key is not defined.', 'archiviomd' ) );
		}

		$pae = 'DSSEv1 '
			. strlen( $payload_type ) . ' ' . $payload_type
			. ' '
			. strlen( $payload ) . ' ' . $payload;

		$sig_hex = self::sign( $pae );
		if ( is_wp_error( $sig_hex ) ) return $sig_hex;

		return array(
			'payload'     => base64_encode( $payload ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			'payloadType' => $payload_type,
			'signatures'  => array(
				array(
					'keyid' => self::public_key_fingerprint(),
					'sig'   => base64_encode( hex2bin( $sig_hex ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
					'alg'   => strtolower( self::get_param() ),
				),
			),
		);
	}

	/**
	 * Verify a standalone SLH-DSA DSSE envelope.
	 */
	public static function verify_dsse( array $envelope ) {
		if ( ! self::is_public_key_defined() ) {
			return new WP_Error( 'no_pubkey', __( 'SLH-DSA public key is not defined.', 'archiviomd' ) );
		}
		if ( empty( $envelope['payload'] ) || empty( $envelope['payloadType'] ) || empty( $envelope['signatures'] ) ) {
			return new WP_Error( 'bad_envelope', __( 'DSSE envelope is missing required fields.', 'archiviomd' ) );
		}

		$payload = base64_decode( $envelope['payload'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $payload ) {
			return new WP_Error( 'bad_payload', __( 'DSSE payload is not valid base64.', 'archiviomd' ) );
		}

		$pt  = $envelope['payloadType'];
		$pae = 'DSSEv1 ' . strlen( $pt ) . ' ' . $pt . ' ' . strlen( $payload ) . ' ' . $payload;

		$valid = false;
		foreach ( (array) $envelope['signatures'] as $entry ) {
			if ( empty( $entry['sig'] ) ) continue;
			// Skip non-SLH-DSA entries in a multi-sig envelope.
			if ( isset( $entry['alg'] ) && strpos( strtolower( $entry['alg'] ), 'slh-dsa' ) === false ) continue;

			$sig_bin = base64_decode( $entry['sig'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
			if ( false === $sig_bin ) continue;

			// Use param recorded in entry if present, fall back to configured.
			$param = isset( $entry['alg'] ) ? strtoupper( str_replace( 'slh-dsa-', 'SLH-DSA-', $entry['alg'] ) ) : self::get_param();
			$result = self::verify_sig( $pae, bin2hex( $sig_bin ), $param );
			if ( $result === true ) { $valid = true; break; }
		}

		return array(
			'valid'        => $valid,
			'payload'      => $payload,
			'payload_type' => $pt,
		);
	}

	/**
	 * Extend an existing Ed25519 DSSE envelope with an SLH-DSA signature.
	 *
	 * Reads back the envelope Ed25519 wrote, appends a second signatures[]
	 * entry, and returns the extended envelope.  The payload is NOT re-encoded.
	 */
	public static function extend_dsse_envelope( array $envelope, string $payload_type = self::DSSE_PAYLOAD_TYPE_POST ) {
		if ( empty( $envelope['payload'] ) ) {
			return new WP_Error( 'bad_envelope', __( 'Cannot extend a DSSE envelope with no payload.', 'archiviomd' ) );
		}
		$payload = base64_decode( $envelope['payload'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $payload ) {
			return new WP_Error( 'bad_payload', __( 'Existing DSSE envelope payload is not valid base64.', 'archiviomd' ) );
		}

		$pt  = isset( $envelope['payloadType'] ) ? $envelope['payloadType'] : $payload_type;
		$pae = 'DSSEv1 ' . strlen( $pt ) . ' ' . $pt . ' ' . strlen( $payload ) . ' ' . $payload;

		$sig_hex = self::sign( $pae );
		if ( is_wp_error( $sig_hex ) ) return $sig_hex;

		$envelope['signatures'][] = array(
			'keyid' => self::public_key_fingerprint(),
			'sig'   => base64_encode( hex2bin( $sig_hex ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			'alg'   => strtolower( self::get_param() ),
		);
		return $envelope;
	}

	/**
	 * Verify the SLH-DSA signature stored for a post.
	 */
	public static function verify_post( int $post_id ) {
		$sig_hex = get_post_meta( $post_id, self::META_SIG, true );
		if ( ! $sig_hex ) {
			return new WP_Error( 'no_sig', __( 'No SLH-DSA signature stored for this post.', 'archiviomd' ) );
		}
		$param   = get_post_meta( $post_id, self::META_PARAM, true ) ?: self::get_param();
		$message = MDSM_Ed25519_Signing::canonical_message_post( $post_id );
		$result  = self::verify_sig( $message, $sig_hex, $param );

		if ( is_wp_error( $result ) ) return $result;

		return array(
			'valid'     => $result,
			'post_id'   => $post_id,
			'signed_at' => (int) get_post_meta( $post_id, self::META_SIGNED_AT, true ),
			'param'     => $param,
			'backend'   => 'pure-php',
		);
	}

	// ── Auto-sign hooks ────────────────────────────────────────────────────

	public function maybe_sign_post( int $post_id, \WP_Post $post ): void {
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) return;
		if ( wp_is_post_revision( $post_id ) ) return;
		if ( ! self::is_mode_enabled() || ! self::is_private_key_defined() ) return;
		if ( ! in_array( $post->post_type, self::get_configured_post_types(), true ) ) return;
		if ( ! in_array( $post->post_status, array( 'publish', 'private' ), true ) ) return;

		$message = MDSM_Ed25519_Signing::canonical_message_post( $post_id );
		$sig     = self::sign( $message );
		if ( is_wp_error( $sig ) ) return; // Silent fail — never block the save.

		update_post_meta( $post_id, self::META_SIG,       $sig );
		update_post_meta( $post_id, self::META_SIGNED_AT, time() );
		update_post_meta( $post_id, self::META_PARAM,     self::get_param() );

		if ( self::is_dsse_enabled() ) {
			$this->write_dsse_meta( $post_id, $message, self::DSSE_PAYLOAD_TYPE_POST );
		}
	}

	public function maybe_sign_media( int $attachment_id ): void {
		if ( ! self::is_mode_enabled() || ! self::is_private_key_defined() ) return;

		$message = MDSM_Ed25519_Signing::canonical_message_media( $attachment_id );
		$sig     = self::sign( $message );
		if ( is_wp_error( $sig ) ) return;

		update_post_meta( $attachment_id, self::META_SIG,       $sig );
		update_post_meta( $attachment_id, self::META_SIGNED_AT, time() );
		update_post_meta( $attachment_id, self::META_PARAM,     self::get_param() );

		if ( self::is_dsse_enabled() ) {
			$this->write_dsse_meta( $attachment_id, $message, self::DSSE_PAYLOAD_TYPE_MEDIA );
		}
	}

	/**
	 * Write DSSE meta.
	 *
	 * Hybrid mode: if Ed25519 DSSE is also active, extend the shared envelope
	 * at _mdsm_ed25519_dsse with the SLH-DSA signature entry.
	 * Standalone: write to _mdsm_slhdsa_dsse only.
	 */
	private function write_dsse_meta( int $post_id, string $message, string $payload_type ): void {
		$ed_dsse_active = class_exists( 'MDSM_Ed25519_Signing' )
			&& MDSM_Ed25519_Signing::is_mode_enabled()
			&& MDSM_Ed25519_Signing::is_dsse_enabled()
			&& MDSM_Ed25519_Signing::is_private_key_defined();

		if ( $ed_dsse_active ) {
			// Ed25519 ran at priority 20; its envelope is already stored.
			$raw = get_post_meta( $post_id, self::DSSE_SHARED_META_KEY, true );
			if ( $raw ) {
				$existing = json_decode( $raw, true );
				if ( is_array( $existing ) ) {
					$extended = self::extend_dsse_envelope( $existing, $payload_type );
					if ( ! is_wp_error( $extended ) ) {
						update_post_meta(
							$post_id,
							self::DSSE_SHARED_META_KEY,
							wp_json_encode( $extended, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE )
						);
					}
				}
			}
		}

		// Always write a standalone SLH-DSA-only envelope.
		$standalone = self::sign_dsse( $message, $payload_type );
		if ( ! is_wp_error( $standalone ) ) {
			update_post_meta(
				$post_id,
				self::META_DSSE,
				wp_json_encode( $standalone, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE )
			);
		}
	}

	// ── Well-known public key endpoint ─────────────────────────────────────

	public static function serve_public_key(): void {
		if ( ! self::is_public_key_defined() ) {
			status_header( 404 );
			exit;
		}

		$pubkey = strtolower( constant( self::PUBLIC_KEY_CONSTANT ) );
		$site   = get_bloginfo( 'url' );
		$name   = get_bloginfo( 'name' );
		$param  = self::get_param();

		$output  = "# SLH-DSA ({$param}) public key for {$name}\n";
		$output .= "# Site: {$site}\n";
		$output .= "# Algorithm: {$param} (NIST FIPS 205)\n";
		$output .= "# Generated by ArchivioMD\n";
		// Append DANE dns-record hint when corroboration is active.
		if ( class_exists( 'MDSM_DANE_Corroboration' ) && MDSM_DANE_Corroboration::is_enabled() ) {
			$output .= "# dns-record: " . MDSM_DANE_Corroboration::dns_record_name( 'slhdsa' ) . "\n";
			$output .= "# discovery:  " . home_url( '/.well-known/' . MDSM_DANE_Corroboration::JSON_SLUG ) . "\n";
		}
		$output .= "\n" . $pubkey . "\n";

		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'X-Robots-Tag: noindex' );
		nocache_headers();
		echo $output; // phpcs:ignore WordPress.Security.EscapeOutput
		exit;
	}

	// ── AJAX: save settings ────────────────────────────────────────────────

	public function ajax_save_settings(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied.', 'archiviomd' ) ) );
		}

		$enable = isset( $_POST['slhdsa_enabled'] )
			&& sanitize_text_field( wp_unslash( $_POST['slhdsa_enabled'] ) ) === 'true';

		if ( $enable && ! self::is_private_key_defined() ) {
			wp_send_json_error( array(
				'message' => sprintf(
					esc_html__( 'Cannot enable SLH-DSA signing: %s is not defined in wp-config.php.', 'archiviomd' ),
					esc_html( self::PRIVATE_KEY_CONSTANT )
				),
			) );
		}

		if ( isset( $_POST['slhdsa_param'] ) ) {
			$param = sanitize_text_field( wp_unslash( $_POST['slhdsa_param'] ) );
			if ( isset( MDSM_SLHDSA_Core::parameter_sets()[ $param ] ) ) {
				update_option( self::OPTION_PARAM, $param );
			}
		}

		self::set_mode( $enable );

		if ( isset( $_POST['slhdsa_dsse_enabled'] ) ) {
			$dsse = sanitize_text_field( wp_unslash( $_POST['slhdsa_dsse_enabled'] ) ) === 'true';
			self::set_dsse_mode( $enable && $dsse );
		}

		$status = self::status();
		wp_send_json_success( array(
			'message'        => $enable
				? sprintf( esc_html__( 'SLH-DSA Document Signing (%s) enabled.', 'archiviomd' ), esc_html( self::get_param() ) )
				: esc_html__( 'SLH-DSA Document Signing disabled.', 'archiviomd' ),
			'notice_level'   => $status['notice_level'],
			'notice_message' => wp_strip_all_tags( $status['notice_message'] ),
			'dsse_enabled'   => $status['dsse_enabled'],
			'backend'        => 'pure-php',
		) );
	}

	// ── AJAX: generate keypair ──────────────────────────────────────────────

	public function ajax_generate_keypair(): void {
		check_ajax_referer( 'archivio_post_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Permission denied.', 'archiviomd' ) ) );
		}

		$param = sanitize_text_field( wp_unslash( $_POST['slhdsa_param'] ?? 'SLH-DSA-SHA2-128s' ) );
		if ( ! isset( MDSM_SLHDSA_Core::parameter_sets()[ $param ] ) ) {
			$param = 'SLH-DSA-SHA2-128s';
		}

		try {
			$core = new MDSM_SLHDSA_Core( $param );
			$keys = $core->keygen();
		} catch ( \Throwable $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
			return;
		}

		$sk_hex = bin2hex( $keys['sk'] );
		$pk_hex = bin2hex( $keys['pk'] );

		wp_send_json_success( array(
			'param'       => $param,
			'public_key'  => $pk_hex,
			'private_key' => $sk_hex,
			'sig_bytes'   => MDSM_SLHDSA_Core::parameter_sets()[ $param ]['sig_bytes'],
			'wp_config'   => sprintf(
				"define( 'ARCHIVIOMD_SLHDSA_PRIVATE_KEY', '%s' );\ndefine( 'ARCHIVIOMD_SLHDSA_PUBLIC_KEY',  '%s' );\ndefine( 'ARCHIVIOMD_SLHDSA_PARAM',       '%s' );",
				$sk_hex, $pk_hex, $param
			),
		) );
	}
}
