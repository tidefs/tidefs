#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tidefs_binary_schema_core::*;

// Generate a random LE scalar, encode it, decode it, and assert
// the result is bit-exact with the original.
#[derive(Arbitrary, Debug)]
enum LeScalar {
    U16(u16),
    U32(u32),
    U64(u64),
    I32(i32),
    I64(i64),
}

fuzz_target!(|scalars: Vec<LeScalar>| {
    for s in &scalars {
        match s {
            LeScalar::U16(v) => {
                let le = U16Le::from_le(*v);
                let decoded = U16Le::from_le_bytes(le.encode());
                assert_eq!(le, decoded, "U16Le round-trip failed for {v}");
                // Deterministic encoding
                assert_eq!(le.encode(), U16Le::from_le(*v).encode());
            }
            LeScalar::U32(v) => {
                let le = U32Le::from_le(*v);
                let decoded = U32Le::from_le_bytes(le.encode());
                assert_eq!(le, decoded, "U32Le round-trip failed for {v}");
                assert_eq!(le.encode(), U32Le::from_le(*v).encode());
            }
            LeScalar::U64(v) => {
                let le = U64Le::from_le(*v);
                let decoded = U64Le::from_le_bytes(le.encode());
                assert_eq!(le, decoded, "U64Le round-trip failed for {v}");
                assert_eq!(le.encode(), U64Le::from_le(*v).encode());
            }
            LeScalar::I32(v) => {
                let le = I32Le::from_le(*v);
                let decoded = I32Le::from_le_bytes(le.encode());
                assert_eq!(le, decoded, "I32Le round-trip failed for {v}");
                assert_eq!(le.encode(), I32Le::from_le(*v).encode());
            }
            LeScalar::I64(v) => {
                let le = I64Le::from_le(*v);
                let decoded = I64Le::from_le_bytes(le.encode());
                assert_eq!(le, decoded, "I64Le round-trip failed for {v}");
                assert_eq!(le.encode(), I64Le::from_le(*v).encode());
            }
        }
    }

    // Also exercise SchemaVersion round-trip with arbitrary bytes
    if scalars.len() >= 2 {
        let major = match &scalars[0] {
            LeScalar::U16(v) => *v,
            _ => 0,
        };
        let minor = match &scalars[1] {
            LeScalar::U16(v) => *v,
            _ => 0,
        };
        let sv = SchemaVersion::new(major, minor);
        let decoded = SchemaVersion::decode(sv.encode());
        assert_eq!(sv, decoded, "SchemaVersion round-trip failed");

        // can_read is reflexive for same version
        assert!(sv.can_read(&sv));

        // compatibility_matrix should not panic
        let _ = compatibility_matrix();
    }
});
