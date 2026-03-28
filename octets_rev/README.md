# octets-rev

A fork of [quiche's octets crate](https://github.com/cloudflare/quiche) with backward processing logic added.

This crate provides a set of types for safely and efficiently reading from and writing to byte buffers, designed for performance-critical applications like network protocol implementations where minimizing copies is essential.

## Key Difference: Backward Processing

Unlike the original octets crate, this fork adds support for **backward (right-to-left) processing** in addition to the standard forward (left-to-right) processing. This is particularly useful for:

- Protocols that define fields relative to the end of a packet
- Building packets from both ends to avoid moving data
- Parsing protocols where headers or metadata appear at the end

The crate provides four types:
- `Octets` / `OctetsMut`: Forward processing (beginning → end)
- `OctetsRev` / `OctetsMutRev`: Backward processing (end → beginning)

## Examples

### Reading from a buffer

```rust
use octets_rev::Octets;

let data = [0x01, 0x00, 0x42, 0x05, b'h', b'e', b'l', b'l', b'o'];
let mut b = Octets::with_slice(&data);

assert_eq!(b.get_u8(), Ok(1));
assert_eq!(b.get_u16(), Ok(0x0042));

let mut sub = b.get_bytes_with_u8_length().unwrap();
assert_eq!(sub.as_ref(), b"hello");
```

### Forward and Backward Processing

```rust
use octets_rev::{OctetsMut, OctetsMutRev, Octets, OctetsRev};

let mut data = [0; 10];

// Write 0x01 at the beginning
{
    let mut b = OctetsMut::with_slice(&mut data);
    b.put_u8(0x01).unwrap();
}

// Write 0xFE at the end
{
    let mut b = OctetsMutRev::with_slice(&mut data);
    b.put_u8(0xFE).unwrap();
}

assert_eq!(data[0], 0x01);
assert_eq!(data[9], 0xFE);

// Read them back
let mut forward = Octets::with_slice(&data);
assert_eq!(forward.get_u8(), Ok(0x01));

let mut backward = OctetsRev::with_slice(&data);
assert_eq!(backward.get_u8(), Ok(0xFE));
```

### Generic Processing with Traits

By using the [`OctetsRead`] and [`OctetsWrite`] traits, you can write generic code that works identically for both forward and backward buffers. This is possible because `OctetsRev` and `OctetsMutRev` ensure that "reading the next integer" always moves the cursor in the "natural" direction for that buffer.

```rust
use octets_rev::{OctetsRead, Octets, OctetsRev, Result};

struct Frame {
    ty: u8,
    id: u16,
}

impl Frame {
    /// This code is oblivious to whether R is forward or backward.
    /// It just reads the "next" fields in the defined logical order.
    fn parse<R: OctetsRead>(r: &mut R) -> Result<Self> {
        let ty = r.get_u8()?;
        let id = r.get_u16()?;
        Ok(Frame { ty, id })
    }
}

// Forward processing: Type=1, ID=0x0042.
// Data is physically [0x01, 0x00, 0x42].
{
    let data = [0x01, 0x00, 0x42];
    let mut forward = Octets::with_slice(&data);
    let f_frame = Frame::parse(&mut forward).unwrap();
    assert_eq!(f_frame.ty, 0x01);
    assert_eq!(f_frame.id, 0x0042);
}

// Backward processing: Type=1, ID=0x0042.
// Data is physically [0x00, 0x42, 0x01] because OctetsRev reads from the end.
{
    let data = [0x00, 0x42, 0x01];
    let mut backward = OctetsRev::with_slice(&data);
    let b_frame = Frame::parse(&mut backward).unwrap();
    assert_eq!(b_frame.ty, 0x01);
    assert_eq!(b_frame.id, 0x0042);
}
```
