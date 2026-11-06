<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# MC/DC residual review

This annex retains every raw missing condition from the isolated default run
`run_111e7b2c800910ab`: **138 residuals**, alongside 4,148/4,286 tool witnesses.
It records feasibility, coupling and scope arguments for every residual.
An explanation receives no coverage credit; all 138 remain in the denominator.
See the [measurement report](mcdc-independence.md) for tool calibration,
source identity, feature profiles and the selected-decision coupling arguments.

The [combined const/macro follow-up](mcdc-expansion.md) maps all 138 identities
to its extended default and lists six additional residuals. This annex remains
the native-source report; its counts are not replaced by an adjusted percentage.

Identities are the repository file, one-based decision line and zero-based
condition index. `-` means an operand was skipped. These are source-level
arguments for this program and its admitted producer/backend contracts; they
are not proofs of arbitrary memory corruption, a faulty crypto backend or
independent enforcement by every predicate. A source, dependency, capacity,
profile or producer change requires reconsidering the affected argument.

The reviewed JSON and exact source hashes are retained in
`target/mcdc-residual-review-20261105/default-final-review.json`. The source
copy and paginated raw queries are in
`target/mcdc-isolated-profiles-20261105/default/`.

## Default residuals

### `crates/rsk-crypto/src/kdf.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 285:0 | `iters > 0` | `F -> F` | infeasible by arithmetic. len is positive in the enclosing branch. Starting at 256, iters subtracts len only while iters>len, preserving iters>0 through loop exit. |

### `crates/rsk-devconf/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 169:0 | `full > 0` | `F -> F` | infeasible under producer contract. stored=Some(full) is constructed at 164-166 only when full>0; no intervening change. |
| 198:0 | `let (Some(dst), Some(src)) = (buf.get_mut(n..n + elen), echoed.get(..elen))` | `F -> F` | infeasible by arithmetic. elen<=stripped<=room. room is bounded by output capacity minus n/reserved flags and by the echo capacity; whole_tlvs returns a prefix of the bounded echo. Both slices exist. |
| 684:2 | `let Some(&mask) = conf.get(i + 2..end).and_then(<[u8]>::first_chunk::<2>)` | `TTF -> F` | infeasible under producer contract. entry_at returns an in-bounds TLV end; the preceding end-i==4 fixes a two-byte value after the two-byte header. The first_chunk of that value cannot be absent. |
| 743:2 | `let Some(mask) = blob .get_mut(i + 2..end) .and_then(<[u8]>::first_chunk_mut::<2>)` | `TTF -> F` | infeasible under producer contract. entry_at returns an in-bounds TLV end; the preceding end-i==4 fixes a two-byte value after the two-byte header. The first_chunk of that value cannot be absent. |

### `crates/rsk-device/src/click.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 57:1 | `self.count > 0` | `TF-- -> F` | infeasible under producer contract. All constructors/consumed_by_ceremony/fire paths set count and last_release to zero together. A first counted release increments count before setting last_release; subsequent releases preserve positive count. Thus last_release>0 implies count>0. |

### `crates/rsk-device/src/mpu_layout.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 84:2 | `start >= end` | `FFT -> T` | infeasible by arithmetic. Checked subtraction of FLASH_STACK_BYTES and outward alignment produce end-start>=FLASH_STACK_BYTES (4096). Overflow exits before the comparison, so start>=end cannot follow successful bounds calculations. |

### `crates/rsk-device/src/usb_epoch.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 107:1 | `self.state == State::Exhausted` | `FT -> T` | infeasible by semantic coupling. State::Exhausted is first produced only when epoch>=LAST_EPOCH. Resume/configure never reduce epoch or create a lower-epoch exhausted state. The preceding atom is already true whenever this state is exhausted. |

### `crates/rsk-display/src/backup.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 47:1 | `st.exportable` | `TF--- -> F` | profile infeasible. backup_status produces exportable=!cfg!(feature="fips-profile"). This is fixed within the measured binary; the FIPS binary is a separate measurement, not a pair in this profile. |

### `crates/rsk-display/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 664:0 | `rsk_ui::render_pin_title(&mut target, title, off).is_ok()` | `F -> F` | infeasible under type contract. This render uses concrete BandCoverage, whose DrawTarget error is core::convert::Infallible (lib 340-357), rather than generic P. Rendering cannot return Err. |

### `crates/rsk-display/src/pin.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 99:1 | `self.group.is_none()` | `FT- -> T` | infeasible under producer contract. T9 pending implies group Some: press sets group before pending, and backspace/settle clear both. Constructors begin with neither; commit does not clear group independently. |

### `crates/rsk-display/src/status.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 433:1 | `!u.asleep` | `TF -> F` | infeasible by semantic coupling. The enclosing branch starts awake. ambient_repaint does not change asleep; every handle_local_input path that can sleep returns true. quiet=false also leaves asleep unchanged. Thus !local_input implies !asleep at this point. |

### `crates/rsk-ec/src/sign_p521_deterministic.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 39:0 | `<NistP521 as ecdsa::EcdsaCurve>::NORMALIZE_S` | `T -> T` | fixed dependency constant. The pinned p521 NistP521 EcdsaCurve implementation defines NORMALIZE_S=false (registry p521/src/ecdsa.rs 57). Scalar/message contents cannot vary this associated constant. |

### `crates/rsk-fido/src/clientpin.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 224:0 | `dec.is_err()` | `T -> T` | infeasible under producer contract. Length gate fixes newPinEnc=64+iv_overhead; ECDH fixes shared-key width; the 64-byte output and block-multiple CBC input cannot fail this backend contract. |
| 391:0 | `pinproto::decrypt(proto, secret, pin_hash_enc, pin_hash.expose_mut()).is_err()` | `T -> T` | infeasible under producer contract. pinHashEnc is 16 or 32, overhead 0 or 16; plaintext 0/16/32 fits 64 and is block aligned; zero CBC succeeds (pinproto_tests::empty_cbc_plaintext_has_only_the_protocol_two_iv). Shared AES key is 32 bytes. |
| 1114:0 | `let Some(rec) = buf.get(..n)` | `F -> F` | infeasible under producer contract. The enclosing (2..=buf.len()).contains(n) fixes n<=buf.len() before get(..n). |

### `crates/rsk-fido/src/credential.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 853:0 | `let Some(stored) = rec.get(..n)` | `F-- -> F` | infeasible under producer contract. n is min(returned_length,rec.len()) at 837-841 before this bounded slice. |
| 1232:2 | `let Some(record) = out.get(..RP_PREFIX + blen)` | `TTF -> F` | infeasible under producer contract. seal_rp_id returns IV_LEN+id.len()+TAG_LEN only after box_windows fits that total in out[RP_PREFIX..]. Hence RP_PREFIX+blen<=out.len(). |

### `crates/rsk-fido/src/credmgmt.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 411:0 | `begin` | `F -> F` | infeasible under producer contract. For begin=false, the first qualifying record sets found then breaks at 407-408, so this later begin test cannot execute false. Begin=true can iterate and count. |
| 520:0 | `begin` | `F -> F` | infeasible under producer contract. For begin=false, the first qualifying record sets found then breaks at 516-517, so this later begin test cannot execute false. |
| 638:1 | `!LARGE_BLOB_EXT` | `TF -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 876:0 | `let Some(c) = record.first_mut()` | `F -> F` | infeasible under producer contract. record was filtered at 856-861 to length>=RP_PREFIX, which is positive. first_mut cannot be None. |

### `crates/rsk-fido/src/getassertion.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 170:0 | `!LARGE_BLOB_EXT` | `F -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 171:0 | `LARGE_BLOB_EXT` | `T -> T` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 425:0 | `cfg!(feature = "strict-up")` | `T- -> T` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 610:0 | `let Some(oldest) = cands.iter_mut().min_by_key(\|c\| (c.1, c.0))` | `F- -> F` | infeasible under producer contract. cands is a fixed MAX_ASSERTION_CREDS array of positive length (state.rs constant); min_by_key cannot return None. |

### `crates/rsk-fido/src/getinfo.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 140:0 | `LARGE_BLOB_EXT` | `T -> T` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 182:0 | `!LARGE_BLOB_EXT` | `F -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 249:0 | `pqc` | `T -> T` | profile infeasible. pqc is cfg!(feature=advertise-pqc), constant within this measured binary. |
| 257:0 | `eddsa` | `F -> F` | profile infeasible. eddsa is cfg!(not(feature=fido-conformance)), constant within this measured binary. |
| 265:0 | `!LARGE_BLOB_EXT` | `F -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |

### `crates/rsk-fido/src/hmacsecret.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 201:0 | `r.is_err()` | `T -> T` | infeasible under producer contract. After protocol validation, valid ECDH, MAC and n_salt in{32,64}, plaintext fits 64 and has block-multiple length with correct AES key/IV widths. |

### `crates/rsk-fido/src/journal.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 461:0 | `hkdf_sha256(serial_hash, devk, &info, scalar.expose_mut()).is_err()` | `T -> T` | infeasible under producer contract. HKDF output is a 32-byte scalar, below the 255*32=8160-byte SHA-256 expand ceiling; that is the backend only error condition. |

### `crates/rsk-fido/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 155:2 | `!consts::LARGE_BLOB_EXT` | `FTF- -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 203:0 | `!consts::LARGE_BLOB_EXT` | `F -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |

### `crates/rsk-fido/src/makecredential.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 123:0 | `cfg!(not(feature = "fips-profile"))` | `F -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 382:0 | `!LARGE_BLOB_EXT` | `F -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 383:0 | `LARGE_BLOB_EXT` | `T -> T` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |

### `crates/rsk-fido/src/pinpolicy.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 32:0 | `PIN_COMPLEXITY_POLICY` | `T- -> T` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |

### `crates/rsk-fido/src/seed.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 423:0 | `derived.is_err()` | `T -> T` | infeasible under producer contract. The fixed-width derived id output is below HKDF SHA-256 expand ceiling 8160; no other expansion error exists. |
| 453:0 | `sealed.is_err()` | `T -> T` | infeasible under producer contract. Fixed AES-128 key 16, IV 16 and plaintext 16 satisfy CBC NoPadding; backend failure cannot be produced by any contents. |

### `crates/rsk-fido/src/u2f.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 251:0 | `!cfg!(feature = "strict-up")` | `F -> F` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |

### `crates/rsk-fido/src/vendor.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 326:0 | `cfg!(feature = "strict-config")` | `T- -> T` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |
| 612:0 | `let Some(seed) = ctx.state.keydev_dec.as_ref()` | `F -> F` | infeasible under producer contract. keydev_dec was assigned Some(seed) at 608 immediately before this as_ref; no intervening writer or concurrency. |
| 871:0 | `cfg!(feature = "fips-profile")` | `T -> T` | profile infeasible. Compile-time policy value is fixed in this binary; alternate profiles are separate measurements, not a pair in this profile. |

### `crates/rsk-mgmt/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 97:0 | `cfg!(feature = "strict-config")` | `TT -> T` | profile infeasible. cfg!(strict-config) is fixed within this measured binary. Alternate profiles must be measured separately, not combined into a runtime pair. |
| 97:1 | `!self.require_presence(Confirm::titled("Write device config?"))` | `TF -> F and TT -> T` | profile gated. Default strict-config=false suppresses evaluation of require_presence. Within a strict-config binary, UserPresence permits both confirmation and refusal. |
| 104:0 | `cfg!(feature = "strict-config")` | `T- -> T` | profile infeasible. cfg!(strict-config) is fixed within this measured binary. Alternate profiles must be measured separately, not combined into a runtime pair. |

### `crates/rsk-mldsa/src/pack.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 75:0 | `e >= -bot` | `F- -> F` | infeasible by arithmetic. For a!=0, e=b-mask with mask in[0,2^bitlen-1]; e is at least b-2^bitlen+1, whose absolute magnitude defines bot. For a=0, e=mask is nonnegative. Under valid shift/size parameters e>=-bot always. |

### `crates/rsk-oath/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 317:0 | `!ok` | `T -> T` | infeasible under producer contract. parse_put accepts at most one of seven allowed fields and bounds NAME 64, KEY 66, three PWS 255. Normalized maximum is 66+68+3+10+3*258=921<CRED_MAX 1024, including HOTP IMF widening. Therefore all emit_tlv calls fit. |

### `crates/rsk-openpgp/src/dobj.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 401:0 | `let Some(att) = ALGO_ATT_SUPPORTED.first()` | `F -> F` | infeasible under producer contract. ALGO_ATT_SUPPORTED is a fixed nonempty table containing ATTR_P384R1. |

### `crates/rsk-openpgp/src/importdata.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 169:0 | `e.is_empty()` | `T-- -> T` | infeasible under producer contract. parse_ehl_body sets Some(offset) only for positive field lengths. Zero-length fields take earlier None-offset refusal; successful get(offset..offset+length) is nonempty. |
| 169:1 | `p.is_empty()` | `FT- -> T` | infeasible under producer contract. parse_ehl_body sets Some(offset) only for positive field lengths. Zero-length fields take earlier None-offset refusal; successful get(offset..offset+length) is nonempty. |
| 169:2 | `q.is_empty()` | `FFT -> T` | infeasible under producer contract. parse_ehl_body sets Some(offset) only for positive field lengths. Zero-length fields take earlier None-offset refusal; successful get(offset..offset+length) is nonempty. |
| 186:0 | `algo.len() < 3` | `T -> T` | infeasible under producer contract. read_advertised_algo returns RSA only after advertised_algo accepts its six-byte attribute, or DEFAULT_ALGO. Short host-stored attributes are rejected before return. |

### `crates/rsk-openpgp/src/keypairgen.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 167:0 | `algo.len() < 3` | `T -> T` | infeasible under producer contract. read_advertised_algo returns RSA only after advertised_algo accepts its six-byte attribute, or DEFAULT_ALGO. An arbitrary Storage cannot make a short RSA slice pass that content/width validator. |
| 303:0 | `algo.len() < 3` | `T -> T` | infeasible under producer contract. read_advertised_algo returns RSA only after advertised_algo accepts its six-byte attribute, or DEFAULT_ALGO. An arbitrary Storage cannot make a short RSA slice pass that content/width validator. |

### `crates/rsk-openpgp/src/keys.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 583:2 | `let Ok((half, _)) = rsk_rsa::crt::parse_rsa_blob(&kd[..n])` | `TTF- -> F` | infeasible under producer contract. crt_from_plain starts with parse_rsa_blob on the same immutable plaintext. Preceding crt.is_ok therefore entails this second parse succeeds. |

### `crates/rsk-openpgp/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 494:1 | `n > 0` | `TF -> F` | infeasible under producer contract. Successful INTERNAL AUTHENTICATE is either positive RSA modulus width or a positive fixed EC/EdDSA signature width; unsupported/failing keys return error. Applet supplies 1024-byte scratch, sufficient for all supported signatures. |

### `crates/rsk-openpgp/src/pin.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 438:0 | `let Some(stage) = stage_fid(fid)` | `F- -> F` | infeasible under producer contract. load_dek selects only EF_DEK_PW1, EF_DEK_PW3 or EF_DEK_RC; stage_fid covers exactly those three. The selected fid is not caller supplied. |
| 735:4 | `p2 == PW3_MODE83` | `F-F-F- -> F` | infeasible by semantic coupling. Earlier mode validation admits exactly 81/82/83. The requested vector with all three p2 selectors false is impossible; varying p2==83 to false necessarily makes one of the earlier selectors true. Do not claim unique-cause independence for the coupled enum selectors. |

### `crates/rsk-otp/src/hid.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 179:0 | `let Some((head, tail)) = self.buf.get_mut(..n + 2).map(\|f\| f.split_at_mut(n))` | `F -> F` | infeasible under producer contract. body.get(..PAYLOAD_SIZE).unwrap_or(body) bounds n<=64 in both cases; self.buf has 72 bytes, so n+2 fits. |
| 196:0 | `let (Some(dst), Some(src)) = (out.get_mut(..n), self.buf.get(off..off + n))` | `F -> F` | infeasible under producer contract. n<=REPORT_DATA 7 fits the 8-byte output. Private seq and remaining derive from the same <=66-byte loaded stream, preserving off+n<=total<=buf.len throughout next calls. |
| 203:1 | `self.seq == self.expected` | `TF -> F` | infeasible under producer contract. When remaining first reaches zero and expected>0, seq equals the total report count computed by load. Emitting the end marker clears expected and seq together; no public state writer breaks this relation. |

### `crates/rsk-otp/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 137:3 | `cfg & CFG_OATH_HOTP8 == 0` | `TFTF -> F` | infeasible by semantic coupling. CHAL_YUBICO 0x20 plus HOTP8 0x02 implies the earlier CFG_CHAL_HMAC 0x22 whole-mask comparison is true, suppressing the later HOTP8==0 false evaluation. |
| 369:0 | `let Some(counter) = self.session_counter.get_mut(idx)` | `F -> F` | infeasible under producer contract. slot is checked 1..=SLOT_COUNT and idx=slot-1. Earlier successful session_counter/advanced gets use the same index and fixed-size arrays, with no resize/intervening index change. |
| 372:1 | `let Some(advanced) = self.advanced.get_mut(idx)` | `TF -> F` | infeasible under producer contract. slot is checked 1..=SLOT_COUNT and idx=slot-1. Earlier successful session_counter/advanced gets use the same index and fixed-size arrays, with no resize/intervening index change. |
| 380:1 | `let Some(typed) = out.get_mut(..len)` | `TF- -> F` | infeasible under producer contract. ticket::build writes a fixed 64-byte output and returns maximum 45 bytes (44 modhex plus CR); the other modes are smaller. Thus out.get_mut(..len) exists. |
| 710:0 | `let Some(advanced) = self.advanced.get_mut(i)` | `F -> F` | infeasible under producer contract. Swap FIDs are checked against EF_OTP_SLOT_LAST, giving ia/ib within SLOT_COUNT. advanced and session_counter arrays share that count. |
| 821:0 | `cfg & CFG_CHAL_YUBICO == 0` | `T- -> T` | infeasible under producer contract. Earlier is_chal_resp_slot succeeds only through alternatives that both require CFG_CHAL_YUBICO. Hence its absence cannot reach this mode arm. |
| 1020:0 | `let Some(code) = scanmap_scancode(&map, *c)` | `F -> F` | infeasible under producer contract. Before rewriting, every byte passed the same pure scanmap_scancode lookup. Each iteration mutates only its own byte, preserving every later byte until its lookup; map is unchanged and complete. |

### `crates/rsk-otp/src/ticket.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 92:1 | `let Some(cr) = out.get_mut(len)` | `TF -> F` | infeasible under producer contract. CR/Enter indices are fixed producer outputs: HOTP 6/8, static 38, Yubico modhex 44. Output type is[u8;64], so all append indices exist. |
| 110:1 | `let Some(enter) = out.get_mut(len)` | `TF -> F` | infeasible under producer contract. CR/Enter indices are fixed producer outputs: HOTP 6/8, static 38, Yubico modhex 44. Output type is[u8;64], so all append indices exist. |
| 143:1 | `let Some(cr) = out.get_mut(len)` | `TF -> F` | infeasible under producer contract. CR/Enter indices are fixed producer outputs: HOTP 6/8, static 38, Yubico modhex 44. Output type is[u8;64], so all append indices exist. |

### `crates/rsk-phy/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 147:0 | `let (Some(dst), Some(src)) = (out.get_mut(..n), s.get(..n))` | `F -> F` | infeasible under producer contract. clamped_len always returns<=source.len and<=supplied max_bytes, including invalid-UTF-8 fallback; supplied byte cap is bounded by output.len. Both slices exist. |
| 554:0 | `let (Some(dst), Some(src)) = (out.get_mut(..n), name.get(..n))` | `F -> F` | infeasible under producer contract. clamped_len always returns<=source.len and<=supplied max_bytes, including invalid-UTF-8 fallback; supplied byte cap is bounded by output.len. Both slices exist. |

### `crates/rsk-piv/src/chuid.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 45:0 | `let Some(entry) = out.get_mut(i..i + 2 + val.len())` | `F- -> F` | infeasible under producer contract. The five literal pushes sum exactly to CHUID_LEN; serial hash has fixed 32-byte type. Each selected entry length is 2+value.len>=2, including empty values, so both range and two-byte header exist. |
| 45:1 | `let Some((head, body)) = entry.split_first_chunk_mut::<2>()` | `TF -> F` | infeasible under producer contract. The five literal pushes sum exactly to CHUID_LEN; serial hash has fixed 32-byte type. Each selected entry length is 2+value.len>=2, including empty values, so both range and two-byte header exist. |

### `crates/rsk-piv/src/info.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 170:2 | `let Some(entry) = out.get_mut(n)` | `T-F -> F` | infeasible under producer contract. The loop breaks on n>=out.len before read_slot/get_mut. n is unchanged between that check and this write. |

### `crates/rsk-piv/src/keygen.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 50:0 | `cfg!(feature = "fips-profile")` | `TT -> T` | profile infeasible. cfg!(fips-profile) is fixed within the binary; alternate profiles are separate measurements. |
| 50:1 | `algo == ALGO_RSA1024` | `TF -> F and TT -> T` | profile gated. Default fips-profile=false suppresses the RSA 1024 atom. In a FIPS binary, both RSA 1024 and other valid algorithm inputs can reach this comparison. |
| 614:0 | `cfg!(feature = "fips-profile")` | `TT -> T` | profile infeasible. cfg!(fips-profile) is fixed within the binary; alternate profiles are separate measurements. |
| 614:1 | `algo == ALGO_RSA1024` | `TF -> F and TT -> T` | profile gated. Default fips-profile=false suppresses the RSA 1024 atom. In a FIPS binary, both RSA 1024 and other valid algorithm inputs can reach this comparison. |

### `crates/rsk-piv/src/lib.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 1084:1 | `tdes` | `TFF -> F` | profile infeasible. tdes is cfg!(not(fips-profile)), fixed true in default and false in the FIPS binary. |
| 1084:2 | `algo != ALGO_3DES` | `TFF -> F and TFT -> T` | profile gated. Default tdes=true suppresses algo!=ALGO_3DES. FIPS tdes=false permits both values with valid mgm_key_len. |
| 1757:1 | `let Some(value) = body.get_mut(5..5 + ts.len())` | `TF -> F` | infeasible under producer contract. Timestamp is clamped to PIVMAN_TS_MAX before body access; body has exactly 5+PIVMAN_TS_MAX bytes, so 5..5+ts.len exists. |
| 1767:0 | `let (Some(dst), Some(src)) = (out.get_mut(2..2 + n), body.get(..n))` | `F -> F` | infeasible under producer contract. n is 3 or 5+timestamp.len<=body.len. Fixed PIVMAN_MAX output holds the maximum body plus 2-byte outer header, so both copies exist. |

### `crates/rsk-rescue/src/keydev.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 131:0 | `r.is_ok()` | `F -> F` | infeasible under producer contract. cbc_open provides valid fixed-width derived AES key, IV 16 and plaintext 32 with NoPadding. This backend fails on width/alignment, not ciphertext contents; those dimensions are fixed. |

### `crates/rsk-rsa/src/crt.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 314:0 | `sb.expose().len() > mlen` | `T -> T` | infeasible by arithmetic. s is reduced modulo n, whose two half-width fields make n fit mlen=2*half bytes. Therefore big-endian s cannot exceed mlen. |

### `crates/rsk-rsa/src/key.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 112:2 | `e.is_even()` | `FFT -> T` | infeasible by semantic coupling. After n.is_even=false, p and q are odd, making lambda=lcm(p-1,q-1) even. An even e cannot have passed mod_inverse(lambda) earlier; if n is even that preceding atom short-circuits first. |
| 116:0 | `de.expose() % p1.expose() != one` | `T- -> T` | infeasible by arithmetic. d was obtained as inverse of e modulo lambda=lcm(p-1,q-1), so d*e=1 mod each divisor. Assumes the bigint backend mathematical contract; no input makes only these checks fail after successful inverse. |
| 116:1 | `de.expose() % q1.expose() != one` | `FT -> T` | infeasible by arithmetic. d was obtained as inverse of e modulo lambda=lcm(p-1,q-1), so d*e=1 mod each divisor. Assumes the bigint backend mathematical contract; no input makes only these checks fail after successful inverse. |
| 210:0 | `mb.expose().len() > k` | `T -> T` | infeasible by arithmetic. m is reduced modulo self.n immediately above; k is self.n byte width. Thus m.to_bytes_be().len<=k. |

### `crates/rsk-sdk/src/apdu.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 67:1 | `let Some(&le) = rest.first()` | `TF -> F` | infeasible under producer contract. Immediately preceding exact length tests(1,2,1 respectively) guarantee first()/first_chunk::<2>() exists on the same immutable slice. |
| 94:1 | `let Some(&le) = after.first_chunk::<2>()` | `TF -> F` | infeasible under producer contract. Immediately preceding exact length tests(1,2,1 respectively) guarantee first()/first_chunk::<2>() exists on the same immutable slice. |
| 112:0 | `let Some((&lc, tail)) = rest.split_first()` | `F -> F` | infeasible under producer contract. Empty rest already completed the first branch. Reaching this fallback implies rest nonempty, so split_first cannot be None. |
| 119:1 | `let Some(&le) = after.first()` | `TF -> F` | infeasible under producer contract. Immediately preceding exact length tests(1,2,1 respectively) guarantee first()/first_chunk::<2>() exists on the same immutable slice. |

### `crates/rsk-sdk/src/applet.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 495:0 | `let Some(held) = self.pending.get_mut(..self.pending_len)` | `F -> F` | infeasible under producer contract. pending_len starts/resets 0 and is assigned tail_len only after pending.get_mut(..tail_len) succeeds in maybe_chain; no other assignment. |
| 512:0 | `let Some(held) = self.chain.get_mut(..self.chain_len)` | `F -> F` | infeasible under producer contract. chain_len starts/resets 0 and advances only after a successful checked slice of self.chain; final assembly clears it. Its private state cannot exceed buffer length through public producers. |

### `crates/rsk-store/src/authenticated/authority.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 236:2 | `snapshot.arm == RootArm::Otp` | `FTF -> F` | infeasible by semantic coupling. RootArm has exactly PreOtp and Otp. When target!=base and base==PreOtp, target must be Otp. The requested FTF enum vector is impossible. |

### `crates/rsk-store/src/authenticated/bank.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 61:1 | `F::READ_SIZE == 0` | `FT----------- -> T` | infeasible under compile time contract. RawBank::new instantiates VerifiedFlash::new, whose inline const requires 0 < READ_SIZE <= READBACK_BYTES (256). READ_SIZE=0 and 512 constructor controls both fail compilation with E0080 at that exact assertion, even though the outer range guard could return first. No admitted monomorphization supplies this requested runtime outcome. This is compile-contract evidence, not a runtime pair. |
| 61:2 | `F::READ_SIZE > IO_CHUNK` | `FFT---------- -> T` | infeasible under compile time contract. RawBank::new instantiates VerifiedFlash::new, whose inline const requires 0 < READ_SIZE <= READBACK_BYTES (256). READ_SIZE=0 and 512 constructor controls both fail compilation with E0080 at that exact assertion, even though the outer range guard could return first. No admitted monomorphization supplies this requested runtime outcome. This is compile-contract evidence, not a runtime pair. |
| 102:0 | `start < self.range.start` | `T- -> T` | infeasible by arithmetic. start is range.start.checked_add(offset)? using unsigned operands. Overflow exits earlier; successful addition cannot make start<range.start. |

### `crates/rsk-store/src/authenticated/counter_bank.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 283:0 | `entry.length().is_none()` | `T-- -> T` | infeasible under producer contract. Directory.apply removes deletions instead of inserting them; push_snapshot rejects lengthNone. Entries storage is private with immutable slice access, so admitted Directory constructors cannot retain tombstones. |

### `crates/rsk-store/src/authenticated/counter_read.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 150:0 | `entry != other` | `T- -> T` | helper mismatch feasible but semantically coupled. Production resolved/confirmed mounts carry coherent mirror entries. Differing helper scans can make entry!=other, but successful read_bound_frame verifies each encoded Entry in its frame. Distinct Some entries imply distinct encoded frames; None versus Some also differs from the zero-initialized absent frame. Thus the following raw-frame equality comparison would also reject. |

### `crates/rsk-store/src/authenticated/counter_read_tags.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 23:0 | `self.entry != entry` | `T-- -> T` | producer invariant and authentication coupling. Production ReadCache::verify obtains the cached ValueTag through find(entry), which already requires self.entry==entry. Direct ValueTag::verify can receive another same-width Entry, but payload_tag also authenticates the encoded entry; ordinary constructed tags couple that mismatch to tag failure under the cryptographic assumption. |

### `crates/rsk-store/src/authenticated/counter_scan.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 19:0 | `length > rsk_fs::MAX_VALUE_BYTES` | `T -> T` | infeasible under producer contract. Entry length is private. Entry::live refuses length>MAX_VALUE_BYTES; Entry::decode refuses every larger length except deletion sentinel. Deleted Entry gives unwrap_or 0 here. All admitted Entry constructors preserve this bound. |
| 195:0 | `directory.apply(entry).is_err()` | `T -> T` | infeasible under producer contract. Directory remains sorted with unique FIDs. Every admitted entry passes counter_index, whose universe is ordinary COUNTER_FIDS plus bound buckets; MAX_COUNTER_ENTRIES equals that universe size. Replacement/removal cannot overflow, and insertion of a distinct accepted FID means existing count<capacity. Valid Entry decoding and binary-search indices preserve remaining apply invariants. |

### `crates/rsk-store/src/authenticated/counters.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 189:0 | `length != Some(out.len())` | `T -> T` | infeasible under producer contract. Repair snapshot iterates the selected source directory. counter_snapshot::write_entries gives the loader exactly Entry.length bytes; source.read_value uses the unchanged corresponding scan location and returns that same remembered length, or errors before a successful result. None/different successful length cannot arise from media bytes alone. |
| 307:0 | `source.read_value(source_scan, old, entry.fid(), out)? != Some(out.len())` | `T -> T` | infeasible under producer contract. Rekey replacement Entries are constructed from lengths just returned by the same unchanged source scan, then the snapshot loader reads those same FIDs/metadata. Successful source.read_value returns remembered length; media faults can Err but cannot alter a successful Some length. |
| 397:0 | `source.read_value(source_scan, key, owner.fid(), out)? != Some(out.len())` | `T -> T` | infeasible under producer contract. Rollover handles the changed FID in the earlier owner.fid==fid branch. Every other directory entry is unchanged from source_scan; loader output has that entry length, and successful source read returns exactly remembered source length. |

### `crates/rsk-store/src/authenticated/journal.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 243:0 | `entry.length().is_none()` | `T-- -> T` | infeasible under producer contract. Directory.apply removes tombstones and push_snapshot rejects them. The private entries Vec cannot contain lengthNone through admitted construction methods; entries() exposes only an immutable slice. |

### `crates/rsk-store/src/authenticated/main.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 387:0 | `!current.scans.iter().all(\|scan\| { scan.status == JournalStatus::Complete && scan.state.is_some_and(\|state\| { state.sequence() == current.sequence && state.pending().is_none() }) })` | `T -> T` | infeasible under producer contract. resolve_inner returns existing Current scans only in its synchronized branch: both Complete with selected sequence, after pending recovery handling. Other successful branches return snapshots; Journal::write_snapshot explicitly constructs Complete/stateSome(TransactionState::new(sequence)), which has no pending entry. Thus successful produced Current obeys all five checks. Fabricated Current tests are separate private-helper prestates, not media-produced counterexamples. |
| 388:0 | `scan.status == JournalStatus::Complete` | `F- -> F` | infeasible under producer contract. resolve_inner returns existing Current scans only in its synchronized branch: both Complete with selected sequence, after pending recovery handling. Other successful branches return snapshots; Journal::write_snapshot explicitly constructs Complete/stateSome(TransactionState::new(sequence)), which has no pending entry. Thus successful produced Current obeys all five checks. Fabricated Current tests are separate private-helper prestates, not media-produced counterexamples. |
| 388:1 | `scan.state.is_some_and(\|state\| { state.sequence() == current.sequence && state.pending().is_none() })` | `TF -> F` | infeasible under producer contract. resolve_inner returns existing Current scans only in its synchronized branch: both Complete with selected sequence, after pending recovery handling. Other successful branches return snapshots; Journal::write_snapshot explicitly constructs Complete/stateSome(TransactionState::new(sequence)), which has no pending entry. Thus successful produced Current obeys all five checks. Fabricated Current tests are separate private-helper prestates, not media-produced counterexamples. |
| 390:0 | `state.sequence() == current.sequence` | `F- -> F` | infeasible under producer contract. resolve_inner returns existing Current scans only in its synchronized branch: both Complete with selected sequence, after pending recovery handling. Other successful branches return snapshots; Journal::write_snapshot explicitly constructs Complete/stateSome(TransactionState::new(sequence)), which has no pending entry. Thus successful produced Current obeys all five checks. Fabricated Current tests are separate private-helper prestates, not media-produced counterexamples. |
| 390:1 | `state.pending().is_none()` | `TF -> F` | infeasible under producer contract. resolve_inner returns existing Current scans only in its synchronized branch: both Complete with selected sequence, after pending recovery handling. Other successful branches return snapshots; Journal::write_snapshot explicitly constructs Complete/stateSome(TransactionState::new(sequence)), which has no pending entry. Thus successful produced Current obeys all five checks. Fabricated Current tests are separate private-helper prestates, not media-produced counterexamples. |
| 398:0 | `self.authority.established()` | `T -> T` | infeasible under producer contract. resolve_inner returns None only for all-Empty journals after explicitly rejecting established authority at 424-428. No writer changes authority between that result and this check. |
| 451:1 | `zero_seq == Some(sequence)` | `TF- -> F` | infeasible by semantic coupling. When zero_seq==one_seq, bothNone already returned error in the sequence-selection match. EqualSome values select exactly that same sequence, so zero_seq==Some(sequence) cannot be false when evaluated. |
| 464:1 | `self.directory.digest(self.identity, key, 0)? != zero_digest.ok_or(Error::MemoryFatal)?` | `FT -> T` | infeasible under cryptographic assumption. Equal COMPLETE JournalScans include equal fingerprints covering header, entries and applied deltas. A different reconstructed Directory digest while rescanned==selected_scan would require a fingerprint collision (or private RAM corruption), rather than a normal media replay. This is an explicit cryptographic assumption, not unconditional type/mathematical infeasibility. |
| 749:0 | `scan.status == JournalStatus::Complete` | `F-- -> F` | infeasible under producer contract. cache_resolved/history_reclaimable actual callers supply successful resolved Current, whose scans are Complete with stateSome and no pending entry. Snapshot-produced fingerprintNone is reachable but is a different atom. Direct fabricated/incomplete Current belongs only to a separately declared private-helper contract. |
| 749:2 | `scan.state.is_some_and(\|state\| state.pending().is_none())` | `TTF -> F` | infeasible under producer contract. cache_resolved/history_reclaimable actual callers supply successful resolved Current, whose scans are Complete with stateSome and no pending entry. Snapshot-produced fingerprintNone is reachable but is a different atom. Direct fabricated/incomplete Current belongs only to a separately declared private-helper contract. |
| 795:0 | `!current .scans .iter() .all(\|scan\| scan.status == JournalStatus::Complete)` | `T -> T` | infeasible under producer contract. cache_resolved/history_reclaimable actual callers supply successful resolved Current, whose scans are Complete with stateSome and no pending entry. Snapshot-produced fingerprintNone is reachable but is a different atom. Direct fabricated/incomplete Current belongs only to a separately declared private-helper contract. |
| 886:0 | `data.is_some()` | `TTT -> T` | infeasible due to earlier refusal. The only true vector is a new live FID with directory lengthMAX. Earlier digest_replacing at 859-861 computes countMAX+1 and returns NoMemory in directory.rs 98-101, before this guard. Hence deciding TTT vector and all three requested independent true pairs cannot reach 886. Existing full-directory refusal tests exercise the earlier guard. |
| 886:1 | `self.directory.find(fid).is_none()` | `TTT -> T` | infeasible due to earlier refusal. The only true vector is a new live FID with directory lengthMAX. Earlier digest_replacing at 859-861 computes countMAX+1 and returns NoMemory in directory.rs 98-101, before this guard. Hence deciding TTT vector and all three requested independent true pairs cannot reach 886. Existing full-directory refusal tests exercise the earlier guard. |
| 886:2 | `self.directory.entries().len() == MAX_MAIN_ENTRIES` | `TTT -> T` | infeasible due to earlier refusal. The only true vector is a new live FID with directory lengthMAX. Earlier digest_replacing at 859-861 computes countMAX+1 and returns NoMemory in directory.rs 98-101, before this guard. Hence deciding TTT vector and all three requested independent true pairs cannot reach 886. Existing full-directory refusal tests exercise the earlier guard. |

### `crates/rsk-store/src/authenticated/managed.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 239:0 | `state.sequence() > 0` | `T- -> T` | infeasible by semantic coupling. Journal.scan has stateSome only after setting lower_bound to that state sequence; each successful delta updates both together. A positive state sequence already makes the preceding lower_bound>0 atom true, suppressing this atom. |

### `crates/rsk-store/src/authenticated/read_tags.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 70:0 | `let Some(slot) = self.records.get_mut(self.next)` | `F -> F` | infeasible under producer contract. Private next begins/resets 0 and advances modulo the same nonzero array length 32. No other assignment exists. Thus records.get_mut(next) cannot returnNone through admitted methods. |

### `crates/rsk-store/src/authenticated/storage.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 360:0 | `let Some(present) = legacy_pins.get_mut(index)` | `F -> F` | infeasible under producer contract. Index comes from PUBLIC_PINS.iter().position, so index<PUBLIC_PINS.len. legacy_pins is created with exactly that array length immediately before the iteration. |

### `crates/rsk-ui/src/aa.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 356:0 | `local_x < corner` | `F- -> F` | infeasible by arithmetic. In fixed_round_supported geometry, a local pixel distance>=ceil(diameter/2) satisfies one of the full horizontal/vertical strip cases returned at 345-349. Reaching the corner lookup implies both local comparisons true; earlier bounds reject outside pixels. |
| 356:1 | `local_y < corner` | `TF -> F` | infeasible by arithmetic. In fixed_round_supported geometry, a local pixel distance>=ceil(diameter/2) satisfies one of the full horizontal/vertical strip cases returned at 345-349. Reaching the corner lookup implies both local comparisons true; earlier bounds reject outside pixels. |

### `crates/rsk-ui/src/font.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 219:1 | `glyph.height > 0` | `TF -> F` | infeasible under producer contract. All 686 generated glyphs were checked: no glyph has width>0 and height==0. The fixed font lookup therefore cannot evaluate a false height atom after true width. |
| 236:1 | `top >= bottom` | `FT -> T` | infeasible by semantic coupling. Any glyph updating left/right has positive width and height and simultaneously updates top/bottom. Therefore left<right implies top<bottom; no glyph updates yields left>=right and short-circuits. |

### `crates/rsk-ui/src/scene.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 570:0 | `let Some(hit) = intersection(rect, tile)` | `F -> F` | infeasible under producer contract. Produced command rectangles are nonempty and clipped. Loops choose first..=last tile rows and columns from each rectangle bounds; every selected tile intersects that rectangle. |

### `crates/rsk-usb/src/ccid.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 328:0 | `let Some(protocol) = out.get_mut(9)` | `F -> F` | infeasible under producer contract. process_message returns before dispatch if out.len()<HEADER 10. Index 9 therefore exists for this branch, independently of body size. |
| 750:0 | `w == self.rx.len()` | `T -> T` | infeasible under producer contract. With compliant EndpointOut returned lengths, w<=MAX_CCID_MSG. At equality, either dw>MAX-HEADER already refused or HEADER+dw<=w already completed, before 750. Backend over-reporting violates read length contract and may panic earlier, not witness this guard. |

### `crates/rsk-usb/src/ctaphid.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 773:0 | `let (Some(dst), Some(src)) = (resp.get_mut(..k), nonce.get(..k))` | `F -> F` | infeasible by arithmetic. k=min(nonce.len,8), with resp.len 17. Both resp[..k] and nonce[..k] always exist. |

### `crates/rsk-usb/src/transport_assurance.rs`

| Decision:condition | Predicate | Missing vector | Disposition and reason |
|---|---|---|---|
| 75:2 | `self.cur <= self.msg.len()` | `TTF -> F` | infeasible by semantic coupling. cur<=bcnt<=CTAP_MAX_MESSAGE and msg.len()==CTAP_MAX_MESSAGE imply cur<=msg.len. This is transitive even for arbitrary verification mid_transaction prestates, so the third false atom cannot have first two true. |

## Additional profile residuals

The following identities have missing pairs in an alternate profile while
the default identity is covered or absent. They are an inventory for review,
not a cross-profile coverage union. Each listed profile retains its own raw
vector, denominator and report in `target/mcdc-isolated-profiles-20261105/`.
Complete per-profile reviewed rows are retained there as `residual-review.json`.

| Source decision:condition | Profiles | Predicate | Scope argument |
|---|---|---|---|
| `crates/rsk-display/src/backup.rs:47:0` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `st.has_seed` | In every listed FIPS profile backup_status constructs exportable=false. load_backup obtains its status only from this producer, so can_reveal is false regardless of storage, seed, seal, lock or PIN. Consequently the reveal/seal block and its asleep check are not reached. The required true decision cannot be obtained while FIPS remains enabled. |
| `crates/rsk-display/src/backup.rs:47:2` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `!st.sealed` | In every listed FIPS profile backup_status constructs exportable=false. load_backup obtains its status only from this producer, so can_reveal is false regardless of storage, seed, seal, lock or PIN. Consequently the reveal/seal block and its asleep check are not reached. The required true decision cannot be obtained while FIPS remains enabled. |
| `crates/rsk-display/src/backup.rs:47:3` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `!st.locked` | In every listed FIPS profile backup_status constructs exportable=false. load_backup obtains its status only from this producer, so can_reveal is false regardless of storage, seed, seal, lock or PIN. Consequently the reveal/seal block and its asleep check are not reached. The required true decision cannot be obtained while FIPS remains enabled. |
| `crates/rsk-display/src/backup.rs:47:4` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `device_pin_set` | In every listed FIPS profile backup_status constructs exportable=false. load_backup obtains its status only from this producer, so can_reveal is false regardless of storage, seed, seal, lock or PIN. Consequently the reveal/seal block and its asleep check are not reached. The required true decision cannot be obtained while FIPS remains enabled. |
| `crates/rsk-display/src/backup.rs:73:0` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `view.can_reveal` | In every listed FIPS profile backup_status constructs exportable=false. load_backup obtains its status only from this producer, so can_reveal is false regardless of storage, seed, seal, lock or PIN. Consequently the reveal/seal block and its asleep check are not reached. The required true decision cannot be obtained while FIPS remains enabled. |
| `crates/rsk-display/src/backup.rs:73:1` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `let Some(k) = rsk_ui::hit_backup(p)` | In every listed FIPS profile backup_status constructs exportable=false. load_backup obtains its status only from this producer, so can_reveal is false regardless of storage, seed, seal, lock or PIN. Consequently the reveal/seal block and its asleep check are not reached. The required true decision cannot be obtained while FIPS remains enabled. |
| `crates/rsk-display/src/backup.rs:80:0` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `self.asleep` | In every listed FIPS profile backup_status constructs exportable=false. load_backup obtains its status only from this producer, so can_reveal is false regardless of storage, seed, seal, lock or PIN. Consequently the reveal/seal block and its asleep check are not reached. The required true decision cannot be obtained while FIPS remains enabled. |
| `crates/rsk-display/src/pin.rs:858:0` | `fips-profile`, `fips-profile,advertise-pqc`, `strong-pin`, `strong-pin,advertise-pqc`, `display,strong-pin`, `display,fips-profile` | `complexity` | Every listed profile sets PIN_COMPLEXITY_POLICY=true. Policy::decode ORs that constant into complexity for every record, including empty or malformed records; Policy::read always decodes through this function. Device PIN scope uses the same strong-pin/FIPS cfg directly; FIDO scope uses the decoded policy. The missing false complexity value (and the OR independence requiring it) cannot be supplied by a record or backend. |
| `crates/rsk-fido/src/arkg.rs:124:0` | `preview-sign`, `preview-sign,largeblob-ext` | `cat(wide.expose_mut(), &[&lead, b1.expose(), tail])?.len() != WIDE_LEN` | After all prior checked slices and cat succeed, lead has16 bytes, b1 is32 bytes and tail is16 bytes. cat returns exactly their64-byte prefix in the64-byte wide array; its length cannot differ from WIDE_LEN. Arbitrary msg/DST inputs can fail earlier but cannot change those array lengths. |
| `crates/rsk-fido/src/clientpin.rs:1051:0` | `fips-profile`, `fips-profile,advertise-pqc`, `strong-pin`, `strong-pin,advertise-pqc`, `display,strong-pin`, `display,fips-profile` | `policy.complexity` | Every listed profile sets PIN_COMPLEXITY_POLICY=true. Policy::decode ORs that constant into complexity for every record, including empty or malformed records; Policy::read always decodes through this function. Device PIN scope uses the same strong-pin/FIPS cfg directly; FIDO scope uses the decoded policy. The missing false complexity value (and the OR independence requiring it) cannot be supplied by a record or backend. |
| `crates/rsk-fido/src/clientpin.rs:1359:0` | `fips-profile`, `fips-profile,advertise-pqc`, `strong-pin`, `strong-pin,advertise-pqc`, `display,strong-pin`, `display,fips-profile` | `policy.complexity` | Every listed profile sets PIN_COMPLEXITY_POLICY=true. Policy::decode ORs that constant into complexity for every record, including empty or malformed records; Policy::read always decodes through this function. Device PIN scope uses the same strong-pin/FIPS cfg directly; FIDO scope uses the decoded policy. The missing false complexity value (and the OR independence requiring it) cannot be supplied by a record or backend. |
| `crates/rsk-fido/src/config.rs:521:0` | `fips-profile`, `fips-profile,advertise-pqc`, `strong-pin`, `strong-pin,advertise-pqc`, `display,strong-pin`, `display,fips-profile` | `policy.complexity` | Every listed profile sets PIN_COMPLEXITY_POLICY=true. Policy::decode ORs that constant into complexity for every record, including empty or malformed records; Policy::read always decodes through this function. Device PIN scope uses the same strong-pin/FIPS cfg directly; FIDO scope uses the decoded policy. The missing false complexity value (and the OR independence requiring it) cannot be supplied by a record or backend. |
| `crates/rsk-fido/src/config.rs:521:1` | `fips-profile`, `fips-profile,advertise-pqc`, `strong-pin`, `strong-pin,advertise-pqc`, `display,strong-pin`, `display,fips-profile` | `pin_complexity` | Every listed profile sets PIN_COMPLEXITY_POLICY=true. Policy::decode ORs that constant into complexity for every record, including empty or malformed records; Policy::read always decodes through this function. Device PIN scope uses the same strong-pin/FIPS cfg directly; FIDO scope uses the decoded policy. The missing false complexity value (and the OR independence requiring it) cannot be supplied by a record or backend. |
| `crates/rsk-fido/src/credmgmt.rs:638:0` | `largeblob-ext`, `preview-sign,largeblob-ext` | `cred.ext.large_blob_key` | LARGE_BLOB_EXT=true in both listed profiles. credmgmt constructs large_blob_key only when cred.ext.large_blob_key && !LARGE_BLOB_EXT, so the Option is always None even for an authenticated older credential with its stored opt-in true. Neither the true decision at638 nor Some at708 is feasible. |
| `crates/rsk-fido/src/credmgmt.rs:708:0` | `largeblob-ext`, `preview-sign,largeblob-ext` | `let Some(k) = large_blob_key` | LARGE_BLOB_EXT=true in both listed profiles. credmgmt constructs large_blob_key only when cred.ext.large_blob_key && !LARGE_BLOB_EXT, so the Option is always None even for an authenticated older credential with its stored opt-in true. Neither the true decision at638 nor Some at708 is feasible. |
| `crates/rsk-fido/src/getassertion.rs:369:0` | `largeblob-ext`, `preview-sign,largeblob-ext` | `req.ext_large_blob_key == Some(false)` | Request initializes ext_large_blob_key=None; parse_extensions assigns it only behind !LARGE_BLOB_EXT. Both listed profiles disable that assignment and treat the withdrawn largeBlobKey request as unknown, so public get_assertion never receives Some(false) here. Storage/backend faults cannot change this local Request field. |
| `crates/rsk-fido/src/getassertion.rs:404:0` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `want_up(&req)` | strict-up is enabled in all listed profiles (fido-conformance implies strict-up). want_up(req) is cfg!(strict-up) \|\| req.up and therefore true for every Request; req.up cannot independently affect that OR. No direct helper Request or UserPresence backend can make want_up false with this profile fixed. |
| `crates/rsk-fido/src/getassertion.rs:425:1` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `req.up` | strict-up is enabled in all listed profiles (fido-conformance implies strict-up). want_up(req) is cfg!(strict-up) \|\| req.up and therefore true for every Request; req.up cannot independently affect that OR. No direct helper Request or UserPresence backend can make want_up false with this profile fixed. |
| `crates/rsk-fido/src/getassertion.rs:695:0` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `want_up(req)` | strict-up is enabled in all listed profiles (fido-conformance implies strict-up). want_up(req) is cfg!(strict-up) \|\| req.up and therefore true for every Request; req.up cannot independently affect that OR. No direct helper Request or UserPresence backend can make want_up false with this profile fixed. |
| `crates/rsk-fido/src/getassertion.rs:803:0` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `ask.is_some()` | With strict-up fixed true, want_up at695 equals needs_confirm(shows_confirm)=!up_collected \|\| shows_confirm. ask.is_some() equals that boolean. Therefore ask=None implies up_collected=true, and ask.is_some() \|\| up_collected is always true. The FF vector is impossible even for an arbitrarily constructed UvOutcome and arbitrary shows_confirm backend. |
| `crates/rsk-fido/src/getassertion.rs:803:1` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `verified.up_collected` | With strict-up fixed true, want_up at695 equals needs_confirm(shows_confirm)=!up_collected \|\| shows_confirm. ask.is_some() equals that boolean. Therefore ask=None implies up_collected=true, and ask.is_some() \|\| up_collected is always true. The FF vector is impossible even for an arbitrarily constructed UvOutcome and arbitrary shows_confirm backend. |
| `crates/rsk-fido/src/lib.rs:155:1` | `largeblob-ext`, `preview-sign,largeblob-ext` | `cmd == consts::CTAP_LARGE_BLOBS` | LARGE_BLOB_EXT=true makes the CTAP_LARGE_BLOBS && !LARGE_BLOB_EXT subexpression false for every command byte. The required vector needs !LARGE_BLOB_EXT true; changing a command/body cannot do that within either listed profile. |
| `crates/rsk-fido/src/makecredential.rs:490:0` | `largeblob-ext`, `preview-sign,largeblob-ext` | `req.ext_large_blob_key == Some(false)` | The command parses a local Request initialized with ext_large_blob_key=None; only the !LARGE_BLOB_EXT match arm can populate it. Both listed profiles suppress that arm, so both Some comparisons are false and the !req.rk condition is short-circuited. This guard is in the public bytes-taking command, not in the Request-accepting inner helper. |
| `crates/rsk-fido/src/makecredential.rs:490:1` | `largeblob-ext`, `preview-sign,largeblob-ext` | `req.ext_large_blob_key == Some(true)` | The command parses a local Request initialized with ext_large_blob_key=None; only the !LARGE_BLOB_EXT match arm can populate it. Both listed profiles suppress that arm, so both Some comparisons are false and the !req.rk condition is short-circuited. This guard is in the public bytes-taking command, not in the Request-accepting inner helper. |
| `crates/rsk-fido/src/makecredential.rs:490:2` | `largeblob-ext`, `preview-sign,largeblob-ext` | `!req.rk` | The command parses a local Request initialized with ext_large_blob_key=None; only the !LARGE_BLOB_EXT match arm can populate it. Both listed profiles suppress that arm, so both Some comparisons are false and the !req.rk condition is short-circuited. This guard is in the public bytes-taking command, not in the Request-accepting inner helper. |
| `crates/rsk-fido/src/pinpolicy.rs:32:1` | `fips-profile`, `fips-profile,advertise-pqc`, `strong-pin`, `strong-pin,advertise-pqc`, `display,strong-pin`, `display,fips-profile` | `record.get(1).is_some_and(\|flags\| flags & COMPLEXITY != 0)` | Every listed profile sets PIN_COMPLEXITY_POLICY=true. Policy::decode ORs that constant into complexity for every record, including empty or malformed records; Policy::read always decodes through this function. Device PIN scope uses the same strong-pin/FIPS cfg directly; FIDO scope uses the decoded policy. The missing false complexity value (and the OR independence requiring it) cannot be supplied by a record or backend. |
| `crates/rsk-fido/src/previewsign.rs:544:2` | `preview-sign`, `preview-sign,largeblob-ext` | `d.position() != params.len()` | params.len is41 at529. Holding alg==-65539 and aux.len==32 at544 requires at least1 byte for the array head,5 for the signed algorithm,1 for u8 flags,2 for the byte-string head,32 data=41. Decoder success cannot read past params; nonminimal CBOR encodings can only increase these sizes and then fail earlier. Therefore d.position==params.len at this guard even for a MAC-valid manually fabricated malformed handle; a trailing byte cannot coexist with the preceding predicates false. |
| `crates/rsk-fido/src/u2f.rs:329:0` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `tup` | strict-up makes the NO_ENFORCE match arm unavailable; only CHECK_ONLY and ENFORCE set tup=true, and CHECK_ONLY returns before these decisions. Thus every signing path has tup=true, owes=true, and TUP=true. The right operand of tup \|\| BuiltinUv is not evaluated, and all required tup=false/owes=false vectors are infeasible even with arbitrary presence/storage backends. |
| `crates/rsk-fido/src/u2f.rs:329:1` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `u2f_gate(ctx.fs, ctx.presence) == U2fGate::BuiltinUv` | strict-up makes the NO_ENFORCE match arm unavailable; only CHECK_ONLY and ENFORCE set tup=true, and CHECK_ONLY returns before these decisions. Thus every signing path has tup=true, owes=true, and TUP=true. The right operand of tup \|\| BuiltinUv is not evaluated, and all required tup=false/owes=false vectors are infeasible even with arbitrary presence/storage backends. |
| `crates/rsk-fido/src/u2f.rs:330:0` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `owes` | strict-up makes the NO_ENFORCE match arm unavailable; only CHECK_ONLY and ENFORCE set tup=true, and CHECK_ONLY returns before these decisions. Thus every signing path has tup=true, owes=true, and TUP=true. The right operand of tup \|\| BuiltinUv is not evaluated, and all required tup=false/owes=false vectors are infeasible even with arbitrary presence/storage backends. |
| `crates/rsk-fido/src/u2f.rs:343:0` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `tup` | strict-up makes the NO_ENFORCE match arm unavailable; only CHECK_ONLY and ENFORCE set tup=true, and CHECK_ONLY returns before these decisions. Thus every signing path has tup=true, owes=true, and TUP=true. The right operand of tup \|\| BuiltinUv is not evaluated, and all required tup=false/owes=false vectors are infeasible even with arbitrary presence/storage backends. |
| `crates/rsk-fido/src/u2f.rs:373:0` | `strict-up`, `strict-up,advertise-pqc`, `fido-conformance` | `owes` | strict-up makes the NO_ENFORCE match arm unavailable; only CHECK_ONLY and ENFORCE set tup=true, and CHECK_ONLY returns before these decisions. Thus every signing path has tup=true, owes=true, and TUP=true. The right operand of tup \|\| BuiltinUv is not evaluated, and all required tup=false/owes=false vectors are infeasible even with arbitrary presence/storage backends. |
| `crates/rsk-fido/src/vendor.rs:326:1` | `strict-config` | `presence.request_ceremony(LOCK_SET_CONFIRM) == Presence::Confirmed` | strict-config is true in the sole listed profile. The closure begins with cfg!(strict-config) \|\| ..., so it returns true without evaluating the presence operand. Neither a backend refusal nor a caller changes that fixed-profile constant; the preceding strict-config touch already gates the write. |
| `crates/rsk-fido/src/vendor.rs:874:0` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `try_backup_sealed(ctx.fs).map_err(\|_\| CtapError::Other)?` | Every listed profile has fips-profile=true. backup_export returns NotAllowed at871-872 before reading the sealed state, before encryption/output, and before r.is_ok. No request, storage result, output size or generic backend reaches these later decisions in this profile. |
| `crates/rsk-fido/src/vendor.rs:898:0` | `fips-profile`, `fips-profile,advertise-pqc`, `display,fips-profile` | `r.is_ok()` | Every listed profile has fips-profile=true. backup_export returns NotAllowed at871-872 before reading the sealed state, before encryption/output, and before r.is_ok. No request, storage result, output size or generic backend reaches these later decisions in this profile. |
| `crates/rsk-mgmt/src/lib.rs:104:1` | `strict-config` | `self.require_presence(LOCK_SET_CONFIRM)` | strict-config is true in the sole listed profile. The closure begins with cfg!(strict-config) \|\| ..., so it returns true without evaluating the presence operand. Neither a backend refusal nor a caller changes that fixed-profile constant; the preceding strict-config touch already gates the write. |

## Additional const-generator residuals

The separate const/runtime adapter exposes 98 additional conditions: 94 have
runtime pairs and four retain missing outcomes: three assertions and the
tail-run guard in the parameterless `fixed_masks` generator. These are not
additional host inputs.
The adapter run is `run_427f12ad219317b2`; its earlier test snapshot and
transformed denominator are kept separate from the default score above.

Independent replay of the current fixed artwork reads 24 glyphs, 144 source
bitmaps and 187 selected masks. It emits 37,670 inner flushes plus 187 tail
flushes, exactly **37,857 bytes**, with pre-emission indices 0..37,856 and
final runs 1..16. The recomputation and dataset hashes are retained in
`glyph-fixed-data-recompute.json` in the residual-review directory. This
argument does not apply to a changed bitmap set, capacity or generic sampler.

| Original decision | Missing predicate outcome | Reason |
|---|---|---|
| `crates/rsk-ui/src/glyph.rs:283` | `write < FIXED_MASK_BYTES` false | Every emitted token has an index below the fixed 37,857-byte output size |
| `crates/rsk-ui/src/glyph.rs:292` | `run != 0` false | Every enabled mask has positive pixel count; each iteration leaves run in 1..16 |
| `crates/rsk-ui/src/glyph.rs:293` | `write < FIXED_MASK_BYTES` false | The tail flush is included in the same exact output-size calculation |
| `crates/rsk-ui/src/glyph.rs:302` | `write == FIXED_MASK_BYTES` false | The current deterministic generator emits exactly the declared output size |

## Macro and generated-source scope

The native frontend declares 79 limitations in 75 files. These declarations
remain in its raw report; targeted experiments supplement rather than delete
them. The following inventory explains the runtime surfaces checked.

| Surface | Evidence and remaining boundary |
|---|---|
| Qualified `core::pin::pin!` / `std::pin::pin!` | The expression-view patch exposes the async body. Calibration crosses `Pending`; the USB run adds two statements and five branches, with no new Boolean condition. Unqualified user macros stay opaque |
| EC `brainpool!` / `comb_mul_fn!` | Four explicitly expanded instantiations pass 108 EC tests and yield 20/25 pairs. Two new Brainpool signature-selection conditions have pairs. The two comb `n>=256` outcomes are infeasible because `n=j*COMB_D+t<=255`; a P-521 normalization policy is fixed. Two pre-existing key-helper gaps in the EC-only selection rely on FIDO consumers measured separately |
| Literal `include!("ecdh_brainpool.rs")` | The frontend already follows this file: 89/89 lines, zero Boolean conditions. A parent macro limitation does not discard its probes |
| AES implementation macros | Reviewed expansions are straight-line crypto calls and Result propagation; no Boolean decision is hidden in the macro templates. Backend implementation and `?` branches remain separate scopes |
| SHA-256 implementation macros | Integer bitwise operations and unrolled arithmetic do not introduce Boolean decisions. This is source-template review, not MC/DC of assembly or dependencies |
| `cfg!` and derived policy constants | Fixed in each measured binary. Alternate feature builds are separate scopes; rows from different binaries are never paired |
| `env!`, generated `OUT_DIR` tables and fixed bitmap data | Build metadata or immutable data; checked separately from runtime decision instrumentation. This does not grant coverage to arbitrary generated Rust |
| Assertion, `matches!` and other macros | Frontend limitations remain explicit. Supported expressions exposed by the const/EC experiments are recorded there; branch tests and assertion failures are not silently counted as source MC/DC pairs |

EC expansion templates, bindings, hashes and run `run_e45fe68a05590951`
are retained in `target/mcdc-ec-expanded-20261105/`. Expression metavariables
are parenthesized before substitution to preserve macro grouping. Ordinary
and measured builds must both compile before a coverage verdict is accepted.

Uncompiled proof/device modules, firmware glue, dependencies, C and assembly
remain outside this host-source denominator. The ARM worker experiment is a
separate 4/35 pilot. This annex closes the residual review for its declared
inputs; it does not establish whole-firmware 100% MC/DC.
